//! Small native Windows boundary for process, window, and UIA data.
//!
//! Inspection reads UIA Value only after an exact request-scoped self-target
//! binding and reduces it to an empty/nonempty bit; the private BSTR is scrubbed
//! in place. Inspection never mutates UI state. Production SetValue and the
//! single profile-bound submit call exist only with the `windows-ui-write`
//! build feature and behind the transaction state machine. Submission sends
//! one synchronous Enter window message to the exact composer HWND; it never
//! changes focus/Z-order, global keyboard state, or the clipboard. COM objects
//! stay on the dedicated MTA thread that created them.

use std::ffi::{c_void, OsStr, OsString};
use std::mem::{align_of, size_of};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::ptr;
#[cfg(feature = "windows-ui-write")]
use std::time::Instant;

use windows::core::BSTR;
use windows::core::{w, Error as WindowsError, BOOL, HRESULT, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, SetLastError, ERROR_SUCCESS, E_ACCESSDENIED, FILETIME, HANDLE, HWND,
    LPARAM, RPC_E_CALL_CANCELED, RPC_E_CALL_COMPLETE, RPC_E_CHANGED_MODE, WPARAM,
};
#[cfg(feature = "windows-ui-write")]
use windows::Win32::Foundation::{WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsValidSid,
    TokenIntegrityLevel, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO,
};
use windows::Win32::System::Com::{
    CoCancelCall, CoCreateInstance, CoDisableCallCancellation, CoEnableCallCancellation,
    CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
#[cfg(feature = "windows-ui-write")]
use windows::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, GetProcessTimes, OpenProcess,
    OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::System::Variant::VARIANT;
#[cfg(feature = "windows-ui-write")]
use windows::Win32::UI::Accessibility::IUIAutomationInvokePattern;
use windows::Win32::UI::Accessibility::{
    CUIAutomation8, IUIAutomation, IUIAutomationCondition, IUIAutomationElement,
    IUIAutomationValuePattern, TreeScope_Descendants, UIA_AutomationIdPropertyId,
    UIA_ClassNamePropertyId, UIA_ControlTypePropertyId, UIA_DocumentControlTypeId,
    UIA_ValuePatternId, UIA_E_ELEMENTNOTAVAILABLE, UIA_E_TIMEOUT,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetAncestor, GetClassNameW, GetWindow, GetWindowLongPtrW,
    GetWindowThreadProcessId, IsWindowVisible, SendMessageTimeoutW, GA_ROOTOWNER, GWL_STYLE,
    GW_OWNER, SEND_MESSAGE_TIMEOUT_FLAGS, SMTO_ABORTIFHUNG, SMTO_BLOCK, SMTO_ERRORONEXIT,
    WM_GETTEXTLENGTH, WS_DISABLED,
};
#[cfg(feature = "windows-ui-write")]
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, WM_KEYDOWN};

use zeroize::Zeroize;
#[cfg(any(feature = "windows-ui-write", test))]
use zeroize::Zeroizing;

use super::executable_trust_native::verify_accepted_x64_process;
use super::{
    bound_snapshot_authorizes_draft_read, classify_read_only_windows, profile_for,
    ComposerDiscovery, FileVersion, FingerprintKey, NativeComposer, NativeInspection,
    NativeProcess, NativeWindow, ReadOnlyCandidateBlockers, ReadOnlyComposerSelectorEvidence,
    ReadOnlyWindowAmbiguity, ReadOnlyWindowSelection, UiProfile, WindowDiscovery, TOP_LEVEL_CLASS,
};
#[cfg(feature = "windows-ui-write")]
use super::{
    executable_trust::ExecutableTrustBoundary,
    ledger::{LedgerRecord, MutationLedger, RecordCorrelation},
    ledger_native::LazyProductionLedger,
    transaction::{self, CommitSelectorState, DraftState, ExpectedState, FreshState, MutationPort},
    unix_now_ms, SubmitStrategy, KNOWN_PROFILE,
};
use crate::platform::contract::MAX_TARGET_LABEL_UTF16_UNITS;
#[cfg(feature = "windows-ui-write")]
use crate::platform::{ApprovedSend, SendOutcome};
use crate::platform::{UiError, UiErrorKind, UiSnapshot};

const CLASS_BUFFER_UNITS: usize = 256;
const PROCESS_PATH_BUFFER_UNITS: usize = 32_768;
const FIXED_FILE_INFO_SIGNATURE: u32 = 0xFEEF_04BD;
const MAX_READ_ONLY_WINDOW_CANDIDATES: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ComposerNearMatchDiagnostics {
    Skip,
    Collect,
}

struct ReadOnlyTargetContext {
    hwnd: HWND,
    pid: u32,
    creation_time_100ns: u64,
    executable_fingerprint: String,
    session_id: u32,
    composer: NativeComposer,
    profile: &'static UiProfile,
}

pub(super) fn inspect(
    fingerprints: FingerprintKey,
    observe_target_label: bool,
    await_inspection_permit: impl FnOnce(u32) -> Result<(), UiError>,
    finish: impl FnOnce(NativeInspection, Option<&[u16]>) -> UiSnapshot,
    rebind_after_draft: impl FnOnce(UiSnapshot, &[u16]) -> Result<UiSnapshot, UiError>,
) -> Result<UiSnapshot, UiError> {
    // The caller creates a fresh, windowless worker thread for every probe.
    // Every successful S_OK/S_FALSE initialization is balanced by this guard,
    // and no COM interface leaves the scope guarded by `_apartment`.
    let _apartment = ComApartment::initialize_mta()?;
    let cancellation = ComCallCancellation::enable()?;
    // SAFETY: GetCurrentThreadId has no failure result and returns the ID of
    // this still-live worker. The caller pins this thread until completion or
    // its single cancellation request, preventing ID reuse during CoCancelCall.
    let thread_id = unsafe { GetCurrentThreadId() };
    if thread_id == 0 {
        return Err(UiError::new(
            UiErrorKind::UnsupportedCapability,
            "windows_probe_thread_failed",
        ));
    }
    await_inspection_permit(thread_id)?;

    let inspection = (|| {
        let windows = enumerate_read_only_top_level_windows()?;

        let (window, selected_hwnd) = match windows.len() {
            0 => (WindowDiscovery::Absent, None),
            count if count > MAX_READ_ONLY_WINDOW_CANDIDATES => (
                WindowDiscovery::Ambiguous {
                    count,
                    reason: ReadOnlyWindowAmbiguity::CandidateLimit,
                },
                None,
            ),
            _ => {
                let mut inspected = Vec::with_capacity(windows.len());
                for hwnd in windows.iter().copied() {
                    inspected.push(inspect_unique_window(
                        hwnd,
                        fingerprints,
                        ComposerNearMatchDiagnostics::Collect,
                    )?);
                }
                match classify_read_only_windows(&inspected) {
                    ReadOnlyWindowSelection::Absent => (WindowDiscovery::Absent, None),
                    ReadOnlyWindowSelection::Unique(index) => {
                        let hwnd = windows[index];
                        (
                            WindowDiscovery::Unique(inspected.swap_remove(index)),
                            Some(hwnd),
                        )
                    }
                    ReadOnlyWindowSelection::Ambiguous { count, reason } => {
                        (WindowDiscovery::Ambiguous { count, reason }, None)
                    }
                }
            }
        };

        let target_context = if observe_target_label {
            selected_hwnd.and_then(|hwnd| read_only_target_context(hwnd, &window))
        } else {
            None
        };
        let inspection = NativeInspection { window };
        match target_context {
            Some(context) => with_read_only_target_label(&context, fingerprints, |label| {
                let mut snapshot = finish(inspection, Some(label));
                if bound_snapshot_authorizes_draft_read(&snapshot) {
                    snapshot.input.draft_empty =
                        read_exact_composer_draft_empty(&context, fingerprints)?;
                    // Target evidence commits the complete snapshot. Read and
                    // bind the root Name again after CurrentValue so a room
                    // switch during the draft read cannot reuse the first
                    // label. Both scrubbed BSTRs remain alive only inside the
                    // worker and are released before this inspection returns.
                    snapshot = with_read_only_target_label(
                        &context,
                        fingerprints,
                        |label_after_draft| rebind_after_draft(snapshot, label_after_draft),
                    )??;
                }
                Ok(snapshot)
            })?,
            None => Ok(finish(inspection, None)),
        }
    })();

    // Disable while the apartment is still initialized. A disable failure
    // overrides apparent inspection success; CoUninitialize still resets the
    // fresh worker thread during scope exit.
    cancellation.disable()?;
    inspection
}

pub(super) fn cancel_read_only_call(thread_id: u32) -> bool {
    if thread_id == 0 {
        return false;
    }

    // SAFETY: the reserved pointer is null. Temporarily initialize an
    // uninitialized caller thread as MTA because CoCancelCall is itself a COM
    // API. RPC_E_CHANGED_MODE proves that the caller already has another valid
    // apartment, which is also sufficient for this call.
    let initialization = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
    let _owned_apartment = if initialization.is_ok() {
        Some(ComApartment)
    } else if initialization == RPC_E_CHANGED_MODE {
        None
    } else {
        return false;
    };

    // SAFETY: `thread_id` was reported by a cancellation-enabled worker and
    // remains pinned by the caller's release channel. A zero-second timeout
    // requests cancellation without waiting for provider-side completion.
    match unsafe { CoCancelCall(thread_id, 0) } {
        Ok(()) => true,
        Err(error) => cancellation_error_is_terminal(error.code()),
    }
}

fn cancellation_error_is_terminal(code: HRESULT) -> bool {
    code == RPC_E_CALL_COMPLETE || code == RPC_E_CALL_CANCELED
}

struct ComCallCancellation {
    active: bool,
}

impl ComCallCancellation {
    fn enable() -> Result<Self, UiError> {
        // SAFETY: the reserved pointer is null as required, and the worker's
        // COM apartment is already initialized. A successful enable is paired
        // with one disable or the Drop fallback on unwind.
        unsafe { CoEnableCallCancellation(None) }
            .map(|()| Self { active: true })
            .map_err(|_| {
                UiError::new(
                    UiErrorKind::UnsupportedCapability,
                    "windows_com_call_cancellation_enable",
                )
            })
    }

    fn disable(mut self) -> Result<(), UiError> {
        // Consume the one allowed disable attempt before entering native code;
        // CoUninitialize resets cancellation when this fresh worker exits even
        // if the call itself reports failure.
        self.active = false;
        // SAFETY: the reserved pointer is null, this is the enabling thread,
        // and the COM apartment remains initialized until after this returns.
        unsafe { CoDisableCallCancellation(None) }.map_err(|_| {
            UiError::new(
                UiErrorKind::UnsupportedCapability,
                "windows_com_call_cancellation_disable",
            )
        })
    }
}

impl Drop for ComCallCancellation {
    fn drop(&mut self) {
        if self.active {
            self.active = false;
            // SAFETY: Drop runs on the same fresh worker before its apartment
            // guard. This fallback is used only during early return or unwind.
            let _ = unsafe { CoDisableCallCancellation(None) };
        }
    }
}

struct ComApartment;

impl ComApartment {
    fn initialize_mta() -> Result<Self, UiError> {
        // SAFETY: `pvreserved` is null as required. This runs on a newly
        // created thread with no prior apartment. Both S_OK and S_FALSE are
        // success values that require a matching `CoUninitialize`.
        let result = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if result.is_ok() {
            Ok(Self)
        } else {
            Err(UiError::new(
                UiErrorKind::UnsupportedCapability,
                "windows_com_initialize",
            ))
        }
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        // SAFETY: constructed only after successful `CoInitializeEx`, dropped
        // once on the same worker thread, after all later COM locals.
        unsafe { CoUninitialize() };
    }
}

struct EnumContext {
    handles: Vec<HWND>,
    callback_panicked: bool,
    scope: WindowEnumerationScope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WindowEnumerationScope {
    ReadOnlyVisible,
    #[cfg(any(feature = "windows-ui-write", test))]
    RawExactClass,
}

fn enumerate_read_only_top_level_windows() -> Result<Vec<HWND>, UiError> {
    enumerate_top_level_windows(WindowEnumerationScope::ReadOnlyVisible)
}

#[cfg(feature = "windows-ui-write")]
fn enumerate_raw_top_level_windows() -> Result<Vec<HWND>, UiError> {
    enumerate_top_level_windows(WindowEnumerationScope::RawExactClass)
}

fn enumerate_top_level_windows(scope: WindowEnumerationScope) -> Result<Vec<HWND>, UiError> {
    let mut context = EnumContext {
        handles: Vec::new(),
        callback_panicked: false,
        scope,
    };
    let context_ptr = ptr::from_mut(&mut context);

    // SAFETY: `context_ptr` remains valid and exclusively borrowed for the
    // synchronous duration of `EnumWindows`. The callback stores borrowed
    // HWND values only; it never owns, destroys, activates, or reorders them.
    let result = unsafe {
        EnumWindows(
            Some(enum_window_callback),
            LPARAM(context_ptr.cast::<c_void>() as isize),
        )
    };

    if context.callback_panicked {
        return Err(UiError::new(
            UiErrorKind::UnsupportedCapability,
            "windows_enumeration_callback",
        ));
    }
    result.map_err(|error| map_windows_error(error, "windows_enumeration"))?;
    Ok(context.handles)
}

unsafe extern "system" fn enum_window_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let context_ptr = lparam.0 as *mut EnumContext;
    if context_ptr.is_null() {
        return BOOL(0);
    }

    // No Rust panic may cross this system callback. The pointer was supplied
    // by `enumerate_top_level_windows` and is valid only for this call.
    let callback_result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: see the callback lifetime invariant above. EnumWindows is
        // synchronous and does not invoke this callback concurrently.
        let context = unsafe { &mut *context_ptr };
        let exact_class = window_has_exact_class(hwnd);
        let visible = if exact_class && context.scope == WindowEnumerationScope::ReadOnlyVisible {
            // SAFETY: `hwnd` is borrowed from EnumWindows for this synchronous
            // callback. IsWindowVisible is a read-only state query and neither
            // activates nor reorders the window.
            unsafe { IsWindowVisible(hwnd).as_bool() }
        } else {
            false
        };
        if window_matches_enumeration_scope(context.scope, exact_class, visible) {
            context.handles.push(hwnd);
        }
    }));

    if callback_result.is_err() {
        // SAFETY: same exclusive callback context invariant as above.
        unsafe { (*context_ptr).callback_panicked = true };
        BOOL(0)
    } else {
        BOOL(1)
    }
}

const fn window_matches_enumeration_scope(
    scope: WindowEnumerationScope,
    exact_class: bool,
    visible: bool,
) -> bool {
    match scope {
        WindowEnumerationScope::ReadOnlyVisible => exact_class && visible,
        #[cfg(any(feature = "windows-ui-write", test))]
        WindowEnumerationScope::RawExactClass => exact_class,
    }
}

#[cfg(any(feature = "windows-ui-write", test))]
fn select_unique_matching_candidate<T: Copy>(
    candidates: impl IntoIterator<Item = (T, bool)>,
) -> Option<T> {
    let mut selected = None;
    for (candidate, matches) in candidates {
        if !matches {
            continue;
        }
        if selected.is_some() {
            return None;
        }
        selected = Some(candidate);
    }
    selected
}

#[derive(Clone, Copy)]
struct WindowOwnerGroup {
    hwnd: usize,
    pid: u32,
    root_owner: usize,
}

#[derive(Clone, Copy)]
struct OwnedPopupObservation {
    hwnd: usize,
    pid: u32,
    visible: bool,
    owner: Option<usize>,
    root_owner: Option<usize>,
}

fn owned_popup_blocks_selected(
    selected: WindowOwnerGroup,
    candidate: OwnedPopupObservation,
) -> Result<bool, ()> {
    if selected.hwnd == 0 || selected.pid == 0 || selected.root_owner == 0 {
        return Err(());
    }
    if candidate.hwnd == selected.hwnd
        || candidate.pid != selected.pid
        || !candidate.visible
        || candidate.owner.is_none_or(|owner| owner == 0)
    {
        return Ok(false);
    }

    candidate
        .root_owner
        .filter(|root_owner| *root_owner != 0)
        .map(|root_owner| root_owner == selected.root_owner)
        .ok_or(())
}

struct ModalEnumContext {
    selected: WindowOwnerGroup,
    modal_present: bool,
    query_uncertain: bool,
    callback_panicked: bool,
}

fn query_window_owner(hwnd: HWND) -> Result<Option<usize>, ()> {
    // A null GW_OWNER result is the normal representation of an unowned
    // top-level window. Clearing last-error lets the windows crate distinguish
    // that result (S_OK) from an actual query failure.
    // SAFETY: this worker owns its thread-local last-error slot, and both calls
    // only inspect the borrowed HWND.
    unsafe { SetLastError(ERROR_SUCCESS) };
    match unsafe { GetWindow(hwnd, GW_OWNER) } {
        Ok(owner) => Ok(Some(owner.0 as usize)),
        Err(error) if error.code().is_ok() => Ok(None),
        Err(_) => Err(()),
    }
}

fn query_root_owner(hwnd: HWND) -> Option<usize> {
    // SAFETY: this is a read-only relationship query over a borrowed HWND.
    let root_owner = unsafe { GetAncestor(hwnd, GA_ROOTOWNER) };
    (!root_owner.0.is_null()).then_some(root_owner.0 as usize)
}

fn process_modal_present(
    selected_hwnd: HWND,
    selected_pid: u32,
    selected_enabled: bool,
) -> Result<bool, UiError> {
    revalidate_window(selected_hwnd, selected_pid)?;
    if !selected_enabled {
        return Ok(true);
    }

    // GA_ROOTOWNER follows the parent/owner chain without reading any window
    // title or UIA content. A null result for a freshly revalidated HWND is
    // treated as concurrent state change, never as evidence that no modal is
    // present.
    let Some(selected_root_owner) = query_root_owner(selected_hwnd) else {
        return Err(stale_window_error());
    };

    let mut context = ModalEnumContext {
        selected: WindowOwnerGroup {
            hwnd: selected_hwnd.0 as usize,
            pid: selected_pid,
            root_owner: selected_root_owner,
        },
        modal_present: false,
        query_uncertain: false,
        callback_panicked: false,
    };
    let context_ptr = ptr::from_mut(&mut context);

    // SAFETY: the context remains exclusively borrowed for this synchronous
    // enumeration. The callback retains no candidate HWND and collects only
    // booleans beyond the fixed selected-window metadata.
    let result = unsafe {
        EnumWindows(
            Some(enum_modal_window_callback),
            LPARAM(context_ptr.cast::<c_void>() as isize),
        )
    };
    if context.callback_panicked {
        return Err(UiError::new(
            UiErrorKind::UnsupportedCapability,
            "windows_enumeration_callback",
        ));
    }
    result.map_err(|error| map_windows_error(error, "windows_enumeration"))?;
    if context.query_uncertain {
        return Err(stale_window_error());
    }

    revalidate_window(selected_hwnd, selected_pid)?;
    if query_root_owner(selected_hwnd) != Some(context.selected.root_owner) {
        return Err(stale_window_error());
    }
    Ok(context.modal_present || !window_enabled(selected_hwnd)?)
}

unsafe extern "system" fn enum_modal_window_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let context_ptr = lparam.0 as *mut ModalEnumContext;
    if context_ptr.is_null() {
        return BOOL(0);
    }

    let callback_result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: see `process_modal_present`; EnumWindows is synchronous and
        // does not invoke this callback concurrently.
        let context = unsafe { &mut *context_ptr };
        if context.modal_present
            || context.query_uncertain
            || hwnd.0 as usize == context.selected.hwnd
        {
            return;
        }

        let mut candidate_pid = 0_u32;
        let thread_id =
            unsafe { GetWindowThreadProcessId(hwnd, Some(ptr::from_mut(&mut candidate_pid))) };
        if thread_id == 0 || candidate_pid == 0 || candidate_pid != context.selected.pid {
            return;
        }
        let candidate_visible = unsafe { IsWindowVisible(hwnd).as_bool() };
        if !candidate_visible {
            return;
        }

        let candidate_owner = match query_window_owner(hwnd) {
            Ok(owner) => owner,
            Err(()) => {
                context.query_uncertain = true;
                return;
            }
        };
        let candidate_root_owner = candidate_owner.and_then(|_| query_root_owner(hwnd));

        // Revalidate the candidate after walking its owner chain. A vanished
        // or recycled HWND is no longer present evidence and is ignored.
        let mut revalidated_pid = 0_u32;
        let thread_id =
            unsafe { GetWindowThreadProcessId(hwnd, Some(ptr::from_mut(&mut revalidated_pid))) };
        if thread_id == 0
            || revalidated_pid != candidate_pid
            || !unsafe { IsWindowVisible(hwnd).as_bool() }
        {
            return;
        }
        let revalidated_owner = match query_window_owner(hwnd) {
            Ok(owner) => owner,
            Err(()) => {
                context.query_uncertain = true;
                return;
            }
        };
        if revalidated_owner != candidate_owner {
            context.query_uncertain = true;
            return;
        }
        let Some(candidate_owner) = revalidated_owner else {
            return;
        };
        let revalidated_root_owner = query_root_owner(hwnd);
        if revalidated_root_owner != candidate_root_owner {
            context.query_uncertain = true;
            return;
        }

        match owned_popup_blocks_selected(
            context.selected,
            OwnedPopupObservation {
                hwnd: hwnd.0 as usize,
                pid: candidate_pid,
                visible: candidate_visible,
                owner: Some(candidate_owner),
                root_owner: revalidated_root_owner,
            },
        ) {
            Ok(true) => context.modal_present = true,
            Ok(false) => {}
            Err(()) => context.query_uncertain = true,
        }
    }));

    if callback_result.is_err() {
        // SAFETY: same exclusive callback context invariant as above.
        unsafe { (*context_ptr).callback_panicked = true };
        BOOL(0)
    } else {
        BOOL(1)
    }
}

fn window_has_exact_class(hwnd: HWND) -> bool {
    let mut buffer = [0_u16; CLASS_BUFFER_UNITS];
    // SAFETY: `buffer` is writable for its full reported length. HWND is a
    // borrowed value from EnumWindows and is never retained beyond the worker.
    let length = unsafe { GetClassNameW(hwnd, &mut buffer) };
    length > 0
        && String::from_utf16(&buffer[..length as usize])
            .is_ok_and(|class_name| class_name == TOP_LEVEL_CLASS)
}

fn inspect_unique_window(
    hwnd: HWND,
    fingerprints: FingerprintKey,
    composer_diagnostics: ComposerNearMatchDiagnostics,
) -> Result<NativeWindow, UiError> {
    if !window_has_exact_class(hwnd) {
        return Err(stale_window_error());
    }

    let mut pid = 0_u32;
    // SAFETY: `pid` is a valid writable u32. The HWND is borrowed and this call
    // neither owns nor mutates the target window.
    let thread_id = unsafe { GetWindowThreadProcessId(hwnd, Some(ptr::from_mut(&mut pid))) };
    if thread_id == 0 || pid == 0 {
        return Err(stale_window_error());
    }

    // Read-only state queries; no focus or window ordering calls are present.
    let visible = unsafe { IsWindowVisible(hwnd).as_bool() };
    let enabled = window_enabled(hwnd)?;

    let process_handle = OwnedHandle::open_process(pid)?;
    let image = query_process_image(process_handle.raw())?;
    let creation_time_100ns = process_creation_time(process_handle.raw())?;
    let executable_name_matches =
        image.path.is_absolute() && image.path.file_name() == Some(OsStr::new("KakaoTalk.exe"));
    let executable_verified = executable_name_matches
        && verify_accepted_x64_process(hwnd, pid, creation_time_100ns, process_handle.raw())
            .is_ok();
    let executable_fingerprint = fingerprints.executable(&image.utf16, creation_time_100ns);
    let version = executable_verified
        .then(|| query_file_version(&image.path))
        .flatten();

    let session_id = process_session_id(pid)?;
    let caller_session_id = process_session_id(unsafe { GetCurrentProcessId() })?;
    let interactive_session_match = session_id == caller_session_id;

    // A caller at an equal or higher integrity RID can inspect the target.
    // Any token-query uncertainty is represented as incompatible and prevents
    // UIA traversal; it is never guessed as compatible.
    let caller_integrity = token_integrity_rid(unsafe { GetCurrentProcess() }).ok();
    let target_integrity = token_integrity_rid(process_handle.raw()).ok();
    let integrity_compatible = matches!(
        (caller_integrity, target_integrity),
        (Some(caller), Some(target)) if caller >= target
    );

    // Do not enumerate another process's owned-window relationships until the
    // selected executable has passed the existing exact executable-name gate.
    let modal_present = if executable_verified {
        process_modal_present(hwnd, pid, enabled)?
    } else {
        false
    };

    let profile = executable_verified.then(|| profile_for(version)).flatten();
    let blockers = ReadOnlyCandidateBlockers::from_observation(
        executable_verified,
        profile.is_some(),
        visible,
        enabled,
        modal_present,
        interactive_session_match,
        integrity_compatible,
    );
    let composer = if blockers.is_empty() {
        discover_composer(
            hwnd,
            pid,
            fingerprints,
            profile.expect("empty composer blockers require a known UI profile"),
            composer_diagnostics,
        )?
    } else {
        ComposerDiscovery::NotInspected(blockers)
    };

    revalidate_window(hwnd, pid)?;

    Ok(NativeWindow {
        fingerprint: fingerprints.window(hwnd.0 as usize, pid),
        visible,
        enabled,
        modal_present,
        process: NativeProcess {
            pid,
            executable_fingerprint,
            creation_time_100ns,
            executable_verified,
            version,
            session_id,
            interactive_session_match,
            integrity_compatible,
        },
        composer,
    })
}

fn read_only_target_context(
    hwnd: HWND,
    selection: &WindowDiscovery,
) -> Option<ReadOnlyTargetContext> {
    let WindowDiscovery::Unique(window) = selection else {
        return None;
    };
    let profile = window
        .process
        .executable_verified
        .then(|| profile_for(window.process.version))
        .flatten()?;
    let ComposerDiscovery::Unique(composer) = &window.composer else {
        return None;
    };
    if !window.visible
        || !window.enabled
        || window.modal_present
        || !window.process.interactive_session_match
        || !window.process.integrity_compatible
    {
        return None;
    }

    Some(ReadOnlyTargetContext {
        hwnd,
        pid: window.process.pid,
        creation_time_100ns: window.process.creation_time_100ns,
        executable_fingerprint: window.process.executable_fingerprint.clone(),
        session_id: window.process.session_id,
        composer: composer.clone(),
        profile,
    })
}

fn revalidate_read_only_target_context(
    context: &ReadOnlyTargetContext,
    fingerprints: FingerprintKey,
) -> Result<(), UiError> {
    revalidate_window(context.hwnd, context.pid)?;
    if !unsafe { IsWindowVisible(context.hwnd).as_bool() }
        || !window_enabled(context.hwnd)?
        || process_modal_present(context.hwnd, context.pid, true)?
    {
        return Err(stale_window_error());
    }

    let process = OwnedHandle::open_process(context.pid)?;
    let creation_time_100ns = process_creation_time(process.raw())?;
    let image = query_process_image(process.raw())?;
    if creation_time_100ns != context.creation_time_100ns
        || fingerprints.executable(&image.utf16, creation_time_100ns)
            != context.executable_fingerprint
        || process_session_id(context.pid)? != context.session_id
    {
        return Err(stale_window_error());
    }

    match discover_composer(
        context.hwnd,
        context.pid,
        fingerprints,
        context.profile,
        ComposerNearMatchDiagnostics::Skip,
    )? {
        ComposerDiscovery::Unique(composer) if composer == context.composer => Ok(()),
        _ => Err(stale_window_error()),
    }
}

fn with_read_only_target_label<T>(
    context: &ReadOnlyTargetContext,
    fingerprints: FingerprintKey,
    consume: impl FnOnce(&[u16]) -> T,
) -> Result<T, UiError> {
    revalidate_read_only_target_context(context, fingerprints)?;

    // SAFETY: the selected HWND, process instance, exact UI profile, and exact
    // unique composer were validated immediately above. CurrentName is a
    // read-only UIA property. The returned BSTR is never decoded or formatted.
    let automation: IUIAutomation =
        unsafe { CoCreateInstance(&CUIAutomation8, None, CLSCTX_INPROC_SERVER) }
            .map_err(|error| map_windows_error(error, "windows_target_uia_create"))?;
    let root = unsafe { automation.ElementFromHandle(context.hwnd) }
        .map_err(|error| map_windows_error(error, "windows_target_uia_window"))?;
    let root_pid = unsafe { root.CurrentProcessId() }
        .map_err(|error| map_windows_error(error, "windows_target_uia_process"))?;
    let root_hwnd = unsafe { root.CurrentNativeWindowHandle() }
        .map_err(|error| map_windows_error(error, "windows_target_uia_handle"))?;
    if u32::try_from(root_pid).ok() != Some(context.pid) || root_hwnd != context.hwnd {
        return Err(stale_window_error());
    }

    let label = ScrubbedBstr::new(
        unsafe { root.CurrentName() }
            .map_err(|error| map_windows_error(error, "windows_target_uia_name"))?,
    );
    if label.units().len() > MAX_TARGET_LABEL_UTF16_UNITS {
        return Err(UiError::new(
            UiErrorKind::TargetNotFound,
            "windows_target_label_too_long",
        ));
    }

    // Recheck the complete non-content path while the private BSTR is still
    // owned. `label` is declared after the COM interfaces, so its Drop scrubs
    // the allocation before either interface is released on scope exit.
    revalidate_read_only_target_context(context, fingerprints)?;
    Ok(consume(label.units()))
}

fn read_exact_composer_draft_empty(
    context: &ReadOnlyTargetContext,
    fingerprints: FingerprintKey,
) -> Result<bool, UiError> {
    revalidate_read_only_target_context(context, fingerprints)?;

    // Reopen only the exact profile-bound composer after the target label has
    // matched its request-scoped permit. No neighboring element or UI tree
    // property is materialized in this process.
    let automation: IUIAutomation =
        unsafe { CoCreateInstance(&CUIAutomation8, None, CLSCTX_INPROC_SERVER) }
            .map_err(|error| map_windows_error(error, "windows_draft_uia_create"))?;
    let class_value = VARIANT::from(context.profile.composer_class);
    let automation_id_value = VARIANT::from(context.profile.composer_automation_id);
    let control_type_value = VARIANT::from(context.profile.composer_control_type);
    let class_condition =
        unsafe { automation.CreatePropertyCondition(UIA_ClassNamePropertyId, &class_value) }
            .map_err(|error| map_windows_error(error, "windows_draft_uia_class_condition"))?;
    let id_condition = unsafe {
        automation.CreatePropertyCondition(UIA_AutomationIdPropertyId, &automation_id_value)
    }
    .map_err(|error| map_windows_error(error, "windows_draft_uia_id_condition"))?;
    let type_condition = unsafe {
        automation.CreatePropertyCondition(UIA_ControlTypePropertyId, &control_type_value)
    }
    .map_err(|error| map_windows_error(error, "windows_draft_uia_type_condition"))?;
    let class_and_id = unsafe { automation.CreateAndCondition(&class_condition, &id_condition) }
        .map_err(|error| map_windows_error(error, "windows_draft_uia_selector"))?;
    let selector = unsafe { automation.CreateAndCondition(&class_and_id, &type_condition) }
        .map_err(|error| map_windows_error(error, "windows_draft_uia_selector"))?;
    let root = unsafe { automation.ElementFromHandle(context.hwnd) }
        .map_err(|error| map_windows_error(error, "windows_draft_uia_window"))?;
    let elements = unsafe { root.FindAll(TreeScope_Descendants, &selector) }
        .map_err(|error| map_windows_error(error, "windows_draft_uia_find_composer"))?;
    let raw_count = unsafe { elements.Length() }
        .map_err(|error| map_windows_error(error, "windows_draft_uia_composer_count"))?;
    if raw_count != 1 {
        return Err(stale_window_error());
    }
    let element = unsafe { elements.GetElement(0) }
        .map_err(|error| map_windows_error(error, "windows_draft_uia_composer"))?;

    let class_name = unsafe { element.CurrentClassName() }
        .map_err(|error| map_windows_error(error, "windows_draft_uia_composer_class"))?;
    let automation_id = unsafe { element.CurrentAutomationId() }
        .map_err(|error| map_windows_error(error, "windows_draft_uia_composer_id"))?;
    let control_type = unsafe { element.CurrentControlType() }
        .map_err(|error| map_windows_error(error, "windows_draft_uia_composer_type"))?;
    let element_pid = unsafe { element.CurrentProcessId() }
        .map_err(|error| map_windows_error(error, "windows_draft_uia_composer_process"))?;
    let element_hwnd = unsafe { element.CurrentNativeWindowHandle() }
        .map_err(|error| map_windows_error(error, "windows_draft_uia_composer_handle"))?;
    if !context.profile.matches_selector(
        &class_name.to_string(),
        &automation_id.to_string(),
        control_type.0,
    ) || control_type != UIA_DocumentControlTypeId
        || u32::try_from(element_pid).ok() != Some(context.pid)
        || element_hwnd.0.is_null()
        || fingerprints.composer(element_hwnd.0 as usize, context.pid)
            != context.composer.fingerprint
    {
        return Err(stale_window_error());
    }

    let enabled = unsafe { element.CurrentIsEnabled() }
        .map_err(|error| map_windows_error(error, "windows_draft_uia_composer_enabled"))?
        .as_bool();
    let focused = unsafe { element.CurrentHasKeyboardFocus() }
        .map_err(|error| map_windows_error(error, "windows_draft_uia_composer_focus"))?
        .as_bool();
    let pattern =
        unsafe { element.GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId) }
            .map_err(|error| map_windows_error(error, "windows_draft_uia_value_pattern"))?;
    let read_only = unsafe { pattern.CurrentIsReadOnly() }
        .map_err(|error| map_windows_error(error, "windows_draft_uia_read_only"))?
        .as_bool();
    if !enabled || focused || read_only {
        return Err(UiError::new(
            UiErrorKind::UserActive,
            "windows_draft_uia_state_changed",
        ));
    }

    // KakaoTalk exposes a nonempty UI-chrome placeholder when the composer is
    // empty. Accept either a zero native length or the exact source-static
    // placeholder digest for this version. The BSTR is never decoded,
    // retained, or formatted and is scrubbed before release.
    let empty = if composer_native_text_empty(element_hwnd)? {
        true
    } else {
        let current = ScrubbedBstr::new(
            unsafe { pattern.CurrentValue() }
                .map_err(|error| map_windows_error(error, "windows_draft_uia_current_value"))?,
        );
        context.profile.matches_empty_placeholder(current.units())
    };
    revalidate_read_only_target_context(context, fingerprints)?;
    Ok(empty)
}

fn composer_native_text_empty(composer_hwnd: HWND) -> Result<bool, UiError> {
    composer_native_text_empty_with(
        composer_hwnd,
        |hwnd, message, wparam, lparam, flags, timeout_ms, message_result| {
            // SAFETY: `hwnd` was just revalidated as the exact composer. The
            // query copies no text; `message_result` remains valid through the
            // synchronous call and is not retained by user32.
            unsafe {
                SendMessageTimeoutW(
                    hwnd,
                    message,
                    wparam,
                    lparam,
                    flags,
                    timeout_ms,
                    Some(ptr::from_mut(message_result)),
                )
                .0 != 0
            }
        },
    )
}

fn composer_native_text_empty_with(
    composer_hwnd: HWND,
    query_once: impl FnOnce(
        HWND,
        u32,
        WPARAM,
        LPARAM,
        SEND_MESSAGE_TIMEOUT_FLAGS,
        u32,
        &mut usize,
    ) -> bool,
) -> Result<bool, UiError> {
    const TEXT_LENGTH_TIMEOUT_MS: u32 = 1_000;

    let mut native_length = 0_usize;
    let delivered = query_once(
        composer_hwnd,
        WM_GETTEXTLENGTH,
        WPARAM(0),
        LPARAM(0),
        SMTO_ABORTIFHUNG | SMTO_BLOCK | SMTO_ERRORONEXIT,
        TEXT_LENGTH_TIMEOUT_MS,
        &mut native_length,
    );
    if delivered {
        Ok(native_length == 0)
    } else {
        Err(UiError::new(
            UiErrorKind::Timeout,
            "windows_draft_native_length",
        ))
    }
}

#[cfg(feature = "windows-ui-write")]
fn with_mutation_target_label<T>(
    hwnd: HWND,
    expected_pid: u32,
    consume: impl FnOnce(&[u16]) -> T,
) -> Result<T, UiError> {
    revalidate_window(hwnd, expected_pid)?;

    // SAFETY: the mutation transaction selected exactly one raw top-level
    // window and just revalidated its class/PID. CurrentName is read-only; its
    // BSTR is kept opaque and scrubbed before the COM interfaces are released.
    let automation: IUIAutomation =
        unsafe { CoCreateInstance(&CUIAutomation8, None, CLSCTX_INPROC_SERVER) }
            .map_err(|error| map_windows_error(error, "windows_mutation_target_uia_create"))?;
    let root = unsafe { automation.ElementFromHandle(hwnd) }
        .map_err(|error| map_windows_error(error, "windows_mutation_target_uia_window"))?;
    let root_pid = unsafe { root.CurrentProcessId() }
        .map_err(|error| map_windows_error(error, "windows_mutation_target_uia_process"))?;
    let root_hwnd = unsafe { root.CurrentNativeWindowHandle() }
        .map_err(|error| map_windows_error(error, "windows_mutation_target_uia_handle"))?;
    if u32::try_from(root_pid).ok() != Some(expected_pid) || root_hwnd != hwnd {
        return Err(stale_window_error());
    }

    let label = ScrubbedBstr::new(
        unsafe { root.CurrentName() }
            .map_err(|error| map_windows_error(error, "windows_mutation_target_uia_name"))?,
    );
    if label.units().len() > MAX_TARGET_LABEL_UTF16_UNITS {
        return Err(UiError::new(
            UiErrorKind::TargetNotFound,
            "windows_mutation_target_label_too_long",
        ));
    }
    revalidate_window(hwnd, expected_pid)?;
    Ok(consume(label.units()))
}

fn revalidate_window(hwnd: HWND, expected_pid: u32) -> Result<(), UiError> {
    if !window_has_exact_class(hwnd) {
        return Err(stale_window_error());
    }
    let mut observed_pid = 0_u32;
    // SAFETY: writable PID pointer, borrowed HWND, read-only query.
    let thread_id =
        unsafe { GetWindowThreadProcessId(hwnd, Some(ptr::from_mut(&mut observed_pid))) };
    if thread_id == 0 || observed_pid != expected_pid {
        Err(stale_window_error())
    } else {
        Ok(())
    }
}

fn window_enabled(hwnd: HWND) -> Result<bool, UiError> {
    // SAFETY: clearing last-error is required to distinguish a valid zero style
    // from GetWindowLongPtrW failure. This worker thread owns its last-error
    // slot, and the borrowed HWND is not mutated by the style query.
    unsafe { SetLastError(ERROR_SUCCESS) };
    let style = unsafe { GetWindowLongPtrW(hwnd, GWL_STYLE) };
    let error = unsafe { GetLastError() };
    if style == 0 && error != ERROR_SUCCESS {
        Err(map_windows_error(
            WindowsError::from_hresult(error.to_hresult()),
            "windows_window_enabled",
        ))
    } else {
        Ok((style as u32) & WS_DISABLED.0 == 0)
    }
}

fn stale_window_error() -> UiError {
    UiError::new(
        UiErrorKind::StaleSnapshot,
        "windows_window_changed_during_inspect",
    )
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn open_process(pid: u32) -> Result<Self, UiError> {
        // SAFETY: the PID comes from GetWindowThreadProcessId. Only the minimum
        // query right is requested; inheritance is disabled.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
            .map_err(|error| map_windows_error(error, "windows_process_open"))?;
        if handle.is_invalid() {
            Err(UiError::new(
                UiErrorKind::PermissionDenied,
                "windows_process_open",
            ))
        } else {
            Ok(Self(handle))
        }
    }

    fn open_token(process: HANDLE) -> Result<Self, UiError> {
        let mut token = HANDLE(ptr::null_mut());
        // SAFETY: `token` is a writable out parameter. `process` is either a
        // live owned process handle or GetCurrentProcess's valid pseudo-handle.
        unsafe { OpenProcessToken(process, TOKEN_QUERY, ptr::from_mut(&mut token)) }
            .map_err(|error| map_windows_error(error, "windows_token_open"))?;
        if token.is_invalid() {
            Err(UiError::new(
                UiErrorKind::PermissionDenied,
                "windows_token_open",
            ))
        } else {
            Ok(Self(token))
        }
    }

    const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: each wrapper owns exactly one non-pseudo handle returned by
        // OpenProcess/OpenProcessToken. Close errors cannot be recovered here.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

struct ProcessImage {
    path: PathBuf,
    utf16: Vec<u16>,
}

fn query_process_image(process: HANDLE) -> Result<ProcessImage, UiError> {
    let mut utf16 = vec![0_u16; PROCESS_PATH_BUFFER_UNITS];
    let mut length = utf16.len() as u32;
    // SAFETY: buffer and in/out character count are valid for the entire call;
    // the process handle has PROCESS_QUERY_LIMITED_INFORMATION only.
    unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(utf16.as_mut_ptr()),
            ptr::from_mut(&mut length),
        )
    }
    .map_err(|error| map_windows_error(error, "windows_process_image"))?;
    let length = usize::try_from(length).map_err(|_| {
        UiError::new(
            UiErrorKind::UnsupportedCapability,
            "windows_process_image_length",
        )
    })?;
    if length == 0 || length > utf16.len() {
        return Err(UiError::new(
            UiErrorKind::UnsupportedCapability,
            "windows_process_image_length",
        ));
    }
    utf16.truncate(length);
    let path = PathBuf::from(OsString::from_wide(&utf16));
    Ok(ProcessImage { path, utf16 })
}

fn process_session_id(pid: u32) -> Result<u32, UiError> {
    let mut session_id = 0_u32;
    // SAFETY: `session_id` is a valid writable out parameter.
    unsafe { ProcessIdToSessionId(pid, ptr::from_mut(&mut session_id)) }
        .map_err(|error| map_windows_error(error, "windows_process_session"))?;
    Ok(session_id)
}

fn process_creation_time(process: HANDLE) -> Result<u64, UiError> {
    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = creation;
    let mut kernel = creation;
    let mut user = creation;
    // SAFETY: all four FILETIME out parameters are writable for the duration
    // of the call; `process` has PROCESS_QUERY_LIMITED_INFORMATION. Only the
    // creation time is retained, and only inside the native worker.
    unsafe {
        GetProcessTimes(
            process,
            ptr::from_mut(&mut creation),
            ptr::from_mut(&mut exit),
            ptr::from_mut(&mut kernel),
            ptr::from_mut(&mut user),
        )
    }
    .map_err(|error| map_windows_error(error, "windows_process_creation_time"))?;
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

fn token_integrity_rid(process: HANDLE) -> Result<u32, UiError> {
    let token = OwnedHandle::open_token(process)?;
    let mut required = 0_u32;
    // SAFETY: the first call intentionally supplies no buffer to obtain the
    // required byte count. The returned error is expected and ignored only if
    // Windows supplied a nonzero size.
    let _ = unsafe {
        GetTokenInformation(
            token.raw(),
            TokenIntegrityLevel,
            None,
            0,
            ptr::from_mut(&mut required),
        )
    };
    if required < size_of::<TOKEN_MANDATORY_LABEL>() as u32 {
        return Err(UiError::new(
            UiErrorKind::PermissionDenied,
            "windows_token_integrity_size",
        ));
    }

    // `Vec<usize>` gives the buffer pointer sufficient alignment for
    // TOKEN_MANDATORY_LABEL. Its byte length remains at least `required`.
    let words = (required as usize).div_ceil(size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    let mut returned = 0_u32;
    // SAFETY: buffer is writable for `required` bytes and remains alive while
    // all pointers into TOKEN_MANDATORY_LABEL and its SID are dereferenced.
    unsafe {
        GetTokenInformation(
            token.raw(),
            TokenIntegrityLevel,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            required,
            ptr::from_mut(&mut returned),
        )
    }
    .map_err(|error| map_windows_error(error, "windows_token_integrity"))?;
    if returned < size_of::<TOKEN_MANDATORY_LABEL>() as u32
        || returned as usize > buffer.len() * size_of::<usize>()
        || !(buffer.as_ptr() as usize).is_multiple_of(align_of::<TOKEN_MANDATORY_LABEL>())
    {
        return Err(UiError::new(
            UiErrorKind::PermissionDenied,
            "windows_token_integrity_layout",
        ));
    }

    // SAFETY: layout, size, and buffer lifetime are established above. The SID
    // pointer is produced by the kernel and validated before subauthority use.
    let sid = unsafe {
        (*(buffer.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()))
            .Label
            .Sid
    };
    if sid.is_invalid() || !unsafe { IsValidSid(sid).as_bool() } {
        return Err(UiError::new(
            UiErrorKind::PermissionDenied,
            "windows_token_integrity_sid",
        ));
    }
    // SAFETY: IsValidSid succeeded and the token buffer remains alive.
    let count_ptr = unsafe { GetSidSubAuthorityCount(sid) };
    if count_ptr.is_null() {
        return Err(UiError::new(
            UiErrorKind::PermissionDenied,
            "windows_token_integrity_sid",
        ));
    }
    // SAFETY: valid SID guarantees the count byte is readable.
    let count = unsafe { *count_ptr };
    if count == 0 {
        return Err(UiError::new(
            UiErrorKind::PermissionDenied,
            "windows_token_integrity_sid",
        ));
    }
    // SAFETY: index is the final valid subauthority of the validated SID.
    let rid_ptr = unsafe { GetSidSubAuthority(sid, u32::from(count - 1)) };
    if rid_ptr.is_null() {
        return Err(UiError::new(
            UiErrorKind::PermissionDenied,
            "windows_token_integrity_sid",
        ));
    }
    // SAFETY: pointer belongs to the validated SID within the live buffer.
    Ok(unsafe { *rid_ptr })
}

fn query_file_version(path: &Path) -> Option<FileVersion> {
    let mut path_utf16: Vec<u16> = path.as_os_str().encode_wide().collect();
    path_utf16.push(0);
    let path_ptr = PCWSTR(path_utf16.as_ptr());

    // SAFETY: NUL-terminated path remains alive throughout all version calls.
    let size = unsafe { GetFileVersionInfoSizeW(path_ptr, None) };
    if size == 0 {
        return None;
    }
    let mut data = vec![0_u8; size as usize];
    // SAFETY: data is writable for exactly `size` bytes; no pointer escapes.
    unsafe {
        GetFileVersionInfoW(path_ptr, None, size, data.as_mut_ptr().cast::<c_void>()).ok()?;
    }

    let mut fixed_ptr = ptr::null_mut::<c_void>();
    let mut fixed_len = 0_u32;
    // SAFETY: the version block stays alive; `\\` requests VS_FIXEDFILEINFO;
    // output pointers are validated before an unaligned copy.
    let found = unsafe {
        VerQueryValueW(
            data.as_ptr().cast::<c_void>(),
            w!("\\"),
            ptr::from_mut(&mut fixed_ptr),
            ptr::from_mut(&mut fixed_len),
        )
        .as_bool()
    };
    if !found || fixed_ptr.is_null() || fixed_len < size_of::<VS_FIXEDFILEINFO>() as u32 {
        return None;
    }
    let start = data.as_ptr() as usize;
    let end = start.checked_add(data.len())?;
    let fixed_start = fixed_ptr as usize;
    let fixed_end = fixed_start.checked_add(size_of::<VS_FIXEDFILEINFO>())?;
    if fixed_start < start || fixed_end > end {
        return None;
    }
    // SAFETY: range lies fully inside the live version buffer; read_unaligned
    // avoids assuming the resource block's alignment.
    let fixed = unsafe { ptr::read_unaligned(fixed_ptr.cast::<VS_FIXEDFILEINFO>()) };
    if fixed.dwSignature != FIXED_FILE_INFO_SIGNATURE {
        return None;
    }
    Some(FileVersion {
        major: (fixed.dwFileVersionMS >> 16) as u16,
        minor: fixed.dwFileVersionMS as u16,
        patch: (fixed.dwFileVersionLS >> 16) as u16,
        build: fixed.dwFileVersionLS as u16,
    })
}

fn discover_composer(
    hwnd: HWND,
    pid: u32,
    fingerprints: FingerprintKey,
    profile: &UiProfile,
    diagnostics: ComposerNearMatchDiagnostics,
) -> Result<ComposerDiscovery, UiError> {
    // SAFETY: COM is initialized MTA on this thread; no aggregation is used.
    // Every returned interface remains local to this function/apartment.
    let automation: IUIAutomation =
        unsafe { CoCreateInstance(&CUIAutomation8, None, CLSCTX_INPROC_SERVER) }
            .map_err(|error| map_windows_error(error, "windows_uia_create"))?;

    let class_value = VARIANT::from(profile.composer_class);
    let automation_id_value = VARIANT::from(profile.composer_automation_id);
    let control_type_value = VARIANT::from(profile.composer_control_type);
    // SAFETY: input VARIANTs own their values for each synchronous call. UIA
    // copies condition data; all returned conditions stay in this apartment.
    let class_condition =
        unsafe { automation.CreatePropertyCondition(UIA_ClassNamePropertyId, &class_value) }
            .map_err(|error| map_windows_error(error, "windows_uia_class_condition"))?;
    let automation_id_condition = unsafe {
        automation.CreatePropertyCondition(UIA_AutomationIdPropertyId, &automation_id_value)
    }
    .map_err(|error| map_windows_error(error, "windows_uia_id_condition"))?;
    let control_type_condition = unsafe {
        automation.CreatePropertyCondition(UIA_ControlTypePropertyId, &control_type_value)
    }
    .map_err(|error| map_windows_error(error, "windows_uia_type_condition"))?;
    let class_and_id =
        unsafe { automation.CreateAndCondition(&class_condition, &automation_id_condition) }
            .map_err(|error| map_windows_error(error, "windows_uia_selector_condition"))?;
    let selector = unsafe { automation.CreateAndCondition(&class_and_id, &control_type_condition) }
        .map_err(|error| map_windows_error(error, "windows_uia_selector_condition"))?;

    // SAFETY: HWND was revalidated and belongs to the selected PID. The bridge
    // and descendant query are read-only; the server-side exact condition means
    // no raw UI tree or unrelated element metadata is returned to this process.
    let root = unsafe { automation.ElementFromHandle(hwnd) }
        .map_err(|error| map_windows_error(error, "windows_uia_window"))?;
    let elements = unsafe { root.FindAll(TreeScope_Descendants, &selector) }
        .map_err(|error| map_windows_error(error, "windows_uia_find_composer"))?;
    let raw_count = unsafe { elements.Length() }
        .map_err(|error| map_windows_error(error, "windows_uia_composer_count"))?;
    let count = usize::try_from(raw_count).map_err(|_| {
        UiError::new(
            UiErrorKind::UnsupportedCapability,
            "windows_uia_composer_count",
        )
    })?;
    if count == 0 {
        if diagnostics == ComposerNearMatchDiagnostics::Skip {
            return Ok(ComposerDiscovery::Absent(None));
        }
        // The exact selector failed, so query only the three exact two-property
        // combinations. Retain existence booleans only: no element, count,
        // property value, Name, Value, or candidate association escapes.
        let class_and_type =
            unsafe { automation.CreateAndCondition(&class_condition, &control_type_condition) }
                .map_err(|error| map_windows_error(error, "windows_uia_selector_condition"))?;
        let id_and_type = unsafe {
            automation.CreateAndCondition(&automation_id_condition, &control_type_condition)
        }
        .map_err(|error| map_windows_error(error, "windows_uia_selector_condition"))?;
        let evidence = ReadOnlyComposerSelectorEvidence::from_near_matches(
            exact_condition_has_any_descendant(&root, &class_and_id)?,
            exact_condition_has_any_descendant(&root, &class_and_type)?,
            exact_condition_has_any_descendant(&root, &id_and_type)?,
        );
        return Ok(ComposerDiscovery::Absent(Some(evidence)));
    }
    if count > 1 {
        return Ok(ComposerDiscovery::Ambiguous(count));
    }

    let element = unsafe { elements.GetElement(0) }
        .map_err(|error| map_windows_error(error, "windows_uia_composer"))?;

    // Defense-in-depth: re-read only the three non-content selector properties
    // and require exact/case-sensitive equality. Name and Value are never read.
    let class_name = unsafe { element.CurrentClassName() }
        .map_err(|error| map_windows_error(error, "windows_uia_composer_class"))?;
    let automation_id = unsafe { element.CurrentAutomationId() }
        .map_err(|error| map_windows_error(error, "windows_uia_composer_id"))?;
    let control_type = unsafe { element.CurrentControlType() }
        .map_err(|error| map_windows_error(error, "windows_uia_composer_type"))?;
    if !profile.matches_selector(
        &class_name.to_string(),
        &automation_id.to_string(),
        control_type.0,
    ) || control_type != UIA_DocumentControlTypeId
        || profile.top_level_class != TOP_LEVEL_CLASS
    {
        return Err(UiError::new(
            UiErrorKind::UnknownUiProfile,
            "windows_uia_selector_validation",
        ));
    }

    let element_pid = unsafe { element.CurrentProcessId() }
        .map_err(|error| map_windows_error(error, "windows_uia_composer_process"))?;
    let element_pid = u32::try_from(element_pid)
        .map_err(|_| UiError::new(UiErrorKind::StaleSnapshot, "windows_uia_composer_process"))?;
    let composer_hwnd = unsafe { element.CurrentNativeWindowHandle() }
        .map_err(|error| map_windows_error(error, "windows_uia_composer_handle"))?;
    if element_pid != pid || composer_hwnd.0.is_null() {
        return Err(UiError::new(
            UiErrorKind::StaleSnapshot,
            "windows_uia_composer_identity",
        ));
    }

    let enabled = unsafe { element.CurrentIsEnabled() }
        .map_err(|error| map_windows_error(error, "windows_uia_composer_enabled"))?
        .as_bool();
    let focused = unsafe { element.CurrentHasKeyboardFocus() }
        .map_err(|error| map_windows_error(error, "windows_uia_composer_focus"))?
        .as_bool();

    // GetCurrentPatternAs and CurrentIsReadOnly inspect metadata only. This
    // discovery pass never calls CurrentValue or SetValue. Any pattern
    // uncertainty becomes unwritable.
    let (value_pattern_present, writable) = match unsafe {
        element.GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId)
    } {
        Ok(pattern) => match unsafe { pattern.CurrentIsReadOnly() } {
            Ok(read_only) => (true, !read_only.as_bool()),
            Err(_) => (true, false),
        },
        Err(_) => (false, false),
    };

    Ok(ComposerDiscovery::Unique(NativeComposer {
        fingerprint: fingerprints.composer(composer_hwnd.0 as usize, pid),
        enabled,
        value_pattern_present,
        writable,
        focused,
    }))
}

fn exact_condition_has_any_descendant(
    root: &IUIAutomationElement,
    condition: &IUIAutomationCondition,
) -> Result<bool, UiError> {
    // SAFETY: root and condition remain in this MTA apartment. FindAll applies
    // an exact server-side condition and returns no property values. Length is
    // reduced immediately to one boolean and the element array is discarded.
    let elements = unsafe { root.FindAll(TreeScope_Descendants, condition) }
        .map_err(|error| map_windows_error(error, "windows_uia_find_composer"))?;
    let raw_count = unsafe { elements.Length() }
        .map_err(|error| map_windows_error(error, "windows_uia_composer_count"))?;
    if raw_count < 0 {
        return Err(UiError::new(
            UiErrorKind::UnsupportedCapability,
            "windows_uia_composer_count",
        ));
    }
    Ok(raw_count != 0)
}

#[cfg(feature = "windows-ui-write")]
pub(super) fn stage(
    fingerprints: FingerprintKey,
    approved: &ApprovedSend,
    expected: &ExpectedState<'_>,
) -> Result<SendOutcome, UiError> {
    ensure_mutation_time(approved, expected.expires_at_unix_ms)?;
    let _apartment = ComApartment::initialize_mta()?;
    let _mutex = NamedMutationMutex::acquire()?;
    ensure_mutation_time(approved, expected.expires_at_unix_ms)?;
    let correlation = RecordCorrelation::from_policy(approved.take_transaction_correlation()?)?;
    let message_utf16 = encode_secret_utf16(approved.message());
    let mut port = NativeMutationPort::new(
        fingerprints,
        approved,
        expected,
        &message_utf16,
        correlation,
    );
    transaction::run_stage(expected, &message_utf16, approved, &mut port)
}

#[cfg(feature = "windows-ui-write")]
pub(super) fn commit(
    fingerprints: FingerprintKey,
    approved: &ApprovedSend,
    expected: &ExpectedState<'_>,
) -> Result<SendOutcome, UiError> {
    ensure_mutation_time(approved, expected.expires_at_unix_ms)?;
    let _apartment = ComApartment::initialize_mta()?;
    let _mutex = NamedMutationMutex::acquire()?;
    ensure_mutation_time(approved, expected.expires_at_unix_ms)?;
    let correlation = RecordCorrelation::from_policy(approved.take_transaction_correlation()?)?;
    let message_utf16 = encode_secret_utf16(approved.message());
    let mut port = NativeMutationPort::new(
        fingerprints,
        approved,
        expected,
        &message_utf16,
        correlation,
    );
    transaction::run_commit(expected, &message_utf16, approved, &mut port)
}

#[cfg(feature = "windows-ui-write")]
fn ensure_mutation_time(approved: &ApprovedSend, expires_at_unix_ms: u64) -> Result<(), UiError> {
    let now_unix_ms = unix_now_ms();
    let monotonic_deadline_reached = approved.monotonic_deadline_reached_at(Instant::now());
    if mutation_time_expired(monotonic_deadline_reached, now_unix_ms, expires_at_unix_ms) {
        Err(UiError::new(
            UiErrorKind::StaleSnapshot,
            "windows_mutation_staleness",
        ))
    } else {
        Ok(())
    }
}

#[cfg(any(feature = "windows-ui-write", test))]
const fn mutation_time_expired(
    monotonic_deadline_reached: bool,
    now_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> bool {
    monotonic_deadline_reached || now_unix_ms >= expires_at_unix_ms
}

/// Encodes directly into its final zeroizing allocation. A valid UTF-8
/// string's byte length is an upper bound for its UTF-16 code-unit length, so
/// reserving that many units prevents a reallocating growth path from leaving
/// an unscrubbed freed copy of the secret.
#[cfg(any(feature = "windows-ui-write", test))]
fn encode_secret_utf16(message: &str) -> Zeroizing<Vec<u16>> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(message.len()));
    let initial_capacity = encoded.capacity();
    encoded.extend(message.encode_utf16());
    debug_assert_eq!(encoded.capacity(), initial_capacity);
    encoded
}

#[cfg(any(feature = "windows-ui-write", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MutationMutexWait {
    Acquired,
    Contended,
    Abandoned,
    Failed,
}

#[cfg(any(feature = "windows-ui-write", test))]
fn mutation_mutex_wait_error(outcome: MutationMutexWait) -> Option<UiError> {
    let operation = match outcome {
        MutationMutexWait::Acquired => return None,
        MutationMutexWait::Contended => "windows_mutation_mutex_contended_uncertain",
        MutationMutexWait::Abandoned => "windows_mutation_mutex_abandoned_uncertain",
        MutationMutexWait::Failed => "windows_mutation_mutex_wait_uncertain",
    };
    Some(UiError::new(UiErrorKind::SubmissionUncertain, operation))
}

/// Process-global serialization for the final observation, write, readback,
/// and restore/Invoke sequence. The mutex is deliberately zero-wait: another
/// transaction, including an abandoned owner, is a refusal rather than a cue
/// to wait and act on older evidence.
#[cfg(feature = "windows-ui-write")]
struct NamedMutationMutex {
    handle: OwnedHandle,
}

#[cfg(feature = "windows-ui-write")]
impl NamedMutationMutex {
    fn acquire() -> Result<Self, UiError> {
        // SAFETY: the fixed name contains no user data, security attributes are
        // defaulted, and initial ownership is false. The returned kernel handle
        // is uniquely owned by `OwnedHandle`.
        let handle =
            unsafe { CreateMutexW(None, false, w!("Local\\OpenKakaoCli.WindowsMutation.v1")) }
                .map(OwnedHandle)
                .map_err(|error| map_windows_error(error, "windows_mutation_mutex_create"))?;

        // SAFETY: `handle` is a live mutex handle. A zero timeout guarantees
        // there is no hidden wait during which approval evidence can age.
        match unsafe { WaitForSingleObject(handle.raw(), 0) } {
            WAIT_OBJECT_0 => {
                debug_assert!(mutation_mutex_wait_error(MutationMutexWait::Acquired).is_none());
                Ok(Self { handle })
            }
            WAIT_TIMEOUT => Err(mutation_mutex_wait_error(MutationMutexWait::Contended)
                .expect("contended mutex has a fixed error")),
            WAIT_ABANDONED => {
                // WAIT_ABANDONED grants ownership. Release it before refusing;
                // stale transaction state is never adopted or recovered.
                let abandoned = Self { handle };
                drop(abandoned);
                Err(mutation_mutex_wait_error(MutationMutexWait::Abandoned)
                    .expect("abandoned mutex has a fixed error"))
            }
            WAIT_FAILED => {
                let _ = unsafe { GetLastError() };
                Err(mutation_mutex_wait_error(MutationMutexWait::Failed)
                    .expect("failed mutex wait has a fixed error"))
            }
            _ => Err(mutation_mutex_wait_error(MutationMutexWait::Failed)
                .expect("unknown mutex wait has a fixed error")),
        }
    }
}

#[cfg(feature = "windows-ui-write")]
impl Drop for NamedMutationMutex {
    fn drop(&mut self) {
        // SAFETY: this guard is constructed only for WAIT_OBJECT_0 or
        // WAIT_ABANDONED, both of which grant ownership on this same thread.
        // CloseHandle runs later when the `OwnedHandle` field is dropped.
        unsafe {
            let _ = ReleaseMutex(self.handle.raw());
        }
    }
}

#[cfg(feature = "windows-ui-write")]
struct NativeMutationIdentity {
    hwnd: HWND,
    composer_hwnd: HWND,
    pid: u32,
    creation_time_100ns: u64,
    executable_fingerprint: String,
    session_id: u32,
}

#[cfg(feature = "windows-ui-write")]
struct NativeMutationPort<'operation> {
    ledger: LazyProductionLedger,
    approved: &'operation ApprovedSend,
    fingerprints: FingerprintKey,
    expected_pid: u32,
    expected_window_fingerprint: String,
    expires_at_unix_ms: u64,
    message_utf16: &'operation [u16],
    identity: Option<NativeMutationIdentity>,
    composer_element: Option<IUIAutomationElement>,
    value_pattern: Option<IUIAutomationValuePattern>,
    invoke_pattern: Option<IUIAutomationInvokePattern>,
    submit_strategy: Option<SubmitStrategy>,
    prepared: PreparedMutation,
}

#[cfg(feature = "windows-ui-write")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum PreparedMutation {
    None,
    SetMessage,
    Clear,
    Invoke,
}

#[cfg(feature = "windows-ui-write")]
impl<'operation> NativeMutationPort<'operation> {
    fn new(
        fingerprints: FingerprintKey,
        approved: &'operation ApprovedSend,
        expected: &ExpectedState<'_>,
        message_utf16: &'operation [u16],
        correlation: RecordCorrelation,
    ) -> Self {
        Self {
            ledger: LazyProductionLedger::new(correlation),
            approved,
            fingerprints,
            expected_pid: expected.pid,
            expected_window_fingerprint: expected.window_fingerprint.to_string(),
            expires_at_unix_ms: expected.expires_at_unix_ms,
            message_utf16,
            identity: None,
            composer_element: None,
            value_pattern: None,
            invoke_pattern: None,
            submit_strategy: None,
            prepared: PreparedMutation::None,
        }
    }

    fn select_approved_window(&self, windows: &[HWND]) -> Result<HWND, UiError> {
        let mut candidates = Vec::with_capacity(windows.len());
        for &hwnd in windows {
            let mut pid = 0_u32;
            // SAFETY: `pid` is a writable out parameter and `hwnd` came from
            // the synchronous top-level enumeration immediately above.
            let thread_id =
                unsafe { GetWindowThreadProcessId(hwnd, Some(ptr::from_mut(&mut pid))) };
            if thread_id == 0 || pid == 0 {
                return Err(stale_window_error());
            }
            let matches = pid == self.expected_pid
                && self.fingerprints.window(hwnd.0 as usize, pid)
                    == self.expected_window_fingerprint;
            candidates.push((hwnd, matches));
        }
        select_unique_matching_candidate(candidates).ok_or_else(stale_window_error)
    }

    fn revalidate_before_mutation(&self, required_draft: DraftState) -> Result<(), UiError> {
        ensure_mutation_time(self.approved, self.expires_at_unix_ms)?;
        let identity = self.identity.as_ref().ok_or_else(|| {
            UiError::new(
                UiErrorKind::StaleSnapshot,
                "windows_mutation_identity_missing",
            )
        })?;
        let element = self.composer_element.as_ref().ok_or_else(|| {
            UiError::new(
                UiErrorKind::ComposerNotFound,
                "windows_mutation_composer_missing",
            )
        })?;
        let pattern = self.value_pattern.as_ref().ok_or_else(|| {
            UiError::new(
                UiErrorKind::PermissionDenied,
                "windows_mutation_value_pattern_missing",
            )
        })?;

        let windows = enumerate_raw_top_level_windows()?;
        if self.select_approved_window(&windows)? != identity.hwnd {
            return Err(stale_window_error());
        }
        ensure_mutation_modal_clear(identity.hwnd, identity.pid)?;
        if foreground_indicates_user_activity(identity.hwnd, identity.pid)? {
            return Err(UiError::new(
                UiErrorKind::UserActive,
                "windows_mutation_foreground",
            ));
        }

        let process = OwnedHandle::open_process(identity.pid)?;
        let creation_time_100ns = process_creation_time(process.raw())?;
        let image = query_process_image(process.raw())?;
        if creation_time_100ns != identity.creation_time_100ns
            || !image.path.is_absolute()
            || image.path.file_name() != Some(OsStr::new("KakaoTalk.exe"))
            || self
                .fingerprints
                .executable(&image.utf16, creation_time_100ns)
                != identity.executable_fingerprint
            || process_session_id(identity.pid)? != identity.session_id
        {
            return Err(UiError::new(
                UiErrorKind::StaleSnapshot,
                "windows_mutation_process_recycled",
            ));
        }
        let caller_session_id = process_session_id(unsafe { GetCurrentProcessId() })?;
        if identity.session_id != caller_session_id {
            return Err(UiError::new(
                UiErrorKind::SessionMismatch,
                "windows_mutation_process_session",
            ));
        }
        let caller_integrity = token_integrity_rid(unsafe { GetCurrentProcess() }).ok();
        let target_integrity = token_integrity_rid(process.raw()).ok();
        if !matches!(
            (caller_integrity, target_integrity),
            (Some(caller), Some(target)) if caller >= target
        ) {
            return Err(UiError::new(
                UiErrorKind::IntegrityMismatch,
                "windows_mutation_integrity",
            ));
        }
        validate_mutation_composer_element(element, identity, &KNOWN_PROFILE)?;
        let enabled = unsafe { element.CurrentIsEnabled() }
            .map_err(|error| map_windows_error(error, "windows_mutation_composer_enabled"))?
            .as_bool();
        let focused = unsafe { element.CurrentHasKeyboardFocus() }
            .map_err(|error| map_windows_error(error, "windows_mutation_composer_focus"))?
            .as_bool();
        let read_only = unsafe { pattern.CurrentIsReadOnly() }
            .map_err(|error| map_windows_error(error, "windows_mutation_composer_read_only"))?
            .as_bool();
        if !enabled || read_only {
            return Err(UiError::new(
                UiErrorKind::PermissionDenied,
                "windows_mutation_composer_writable",
            ));
        }
        if focused {
            return Err(UiError::new(
                UiErrorKind::UserActive,
                "windows_mutation_composer_focus",
            ));
        }

        // Bracket CurrentValue with two independent scrub-on-drop root-Name
        // comparisons. A room switch during the read must fail before the
        // resulting draft classification can influence a mutation decision.
        ensure_self_target(identity.hwnd, identity.pid, self.approved)?;
        let draft = classify_current_value(
            pattern,
            identity.composer_hwnd,
            self.message_utf16,
            &KNOWN_PROFILE,
        )?;
        ensure_self_target(identity.hwnd, identity.pid, self.approved)?;
        if draft != required_draft {
            return Err(UiError::new(
                UiErrorKind::ExistingDraft,
                "windows_mutation_draft_changed",
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "windows-ui-write")]
impl ExecutableTrustBoundary for NativeMutationPort<'_> {
    fn verify_executable_trust(&mut self) -> Result<(), UiError> {
        let windows = enumerate_raw_top_level_windows()?;
        let hwnd = self.select_approved_window(&windows)?;
        if !window_has_exact_class(hwnd) {
            return Err(stale_window_error());
        }
        let mut pid = 0_u32;
        // SAFETY: `pid` is a writable out parameter and the exact-class HWND
        // came from the bounded top-level enumeration above.
        let thread_id = unsafe { GetWindowThreadProcessId(hwnd, Some(ptr::from_mut(&mut pid))) };
        if thread_id == 0 || pid == 0 || pid != self.expected_pid {
            return Err(stale_window_error());
        }
        let process = OwnedHandle::open_process(pid)?;
        let creation_time_100ns = process_creation_time(process.raw())?;
        verify_accepted_x64_process(hwnd, pid, creation_time_100ns, process.raw())
    }
}

#[cfg(feature = "windows-ui-write")]
impl MutationLedger for NativeMutationPort<'_> {
    fn recoverable_indeterminate_stage(&mut self) -> Result<Option<LedgerRecord>, UiError> {
        self.ledger.recoverable_indeterminate_stage()
    }

    fn ensure_clear(&mut self) -> Result<(), UiError> {
        self.ledger.ensure_clear()
    }

    fn begin_stage(&mut self) -> Result<LedgerRecord, UiError> {
        self.ledger.begin_stage()
    }

    fn mark_commit(&mut self, stage: LedgerRecord) -> Result<LedgerRecord, UiError> {
        self.ledger.mark_commit(stage)
    }

    fn mark_recovery_commit(
        &mut self,
        indeterminate_stage: LedgerRecord,
    ) -> Result<LedgerRecord, UiError> {
        self.ledger.mark_recovery_commit(indeterminate_stage)
    }

    fn mark_indeterminate(
        &mut self,
        correlation: RecordCorrelation,
    ) -> Result<LedgerRecord, UiError> {
        self.ledger.mark_indeterminate(correlation)
    }

    fn resolve_restored_stage(&mut self, stage: LedgerRecord) -> Result<(), UiError> {
        self.ledger.resolve_restored_stage(stage)
    }
}

#[cfg(feature = "windows-ui-write")]
impl MutationPort for NativeMutationPort<'_> {
    fn observe(&mut self, expected_message_utf16: &[u16]) -> Result<FreshState, UiError> {
        ensure_mutation_time(self.approved, self.expires_at_unix_ms)?;
        if expected_message_utf16 != self.message_utf16 {
            return Err(UiError::new(
                UiErrorKind::InvalidInput,
                "windows_mutation_message_identity",
            ));
        }
        self.identity = None;
        self.composer_element = None;
        self.value_pattern = None;
        self.invoke_pattern = None;
        self.submit_strategy = None;
        self.prepared = PreparedMutation::None;

        let now_unix_ms = unix_now_ms();
        let windows = enumerate_raw_top_level_windows()?;
        let hwnd = self.select_approved_window(&windows)?;
        let mut fresh = FreshState::unavailable(now_unix_ms, 1);
        let NativeWindow {
            fingerprint,
            visible,
            enabled,
            modal_present,
            process,
            composer,
        } = inspect_unique_window(hwnd, self.fingerprints, ComposerNearMatchDiagnostics::Skip)?;
        let profile = process
            .executable_verified
            .then(|| profile_for(process.version))
            .flatten();
        fresh.pid = Some(process.pid);
        fresh.executable_fingerprint = Some(process.executable_fingerprint.clone());
        fresh.executable_verified = process.executable_verified;
        fresh.version = process.version;
        fresh.session_id = Some(process.session_id);
        fresh.interactive_session_match = process.interactive_session_match;
        fresh.integrity_compatible = process.integrity_compatible;
        fresh.known_ui_profile = profile.is_some();
        fresh.window_visible = visible;
        fresh.window_enabled = enabled;
        fresh.modal_present = modal_present;
        fresh.window_fingerprint = Some(fingerprint);
        fresh.selector_profile_id = profile.map(|profile| profile.id.to_string());
        if modal_present {
            return Ok(fresh);
        }
        fresh.user_active = foreground_indicates_user_activity(hwnd, process.pid)?;

        match composer {
            ComposerDiscovery::NotInspected(_) | ComposerDiscovery::Absent(_) => return Ok(fresh),
            ComposerDiscovery::Ambiguous(count) => {
                fresh.composer_count = count;
                return Ok(fresh);
            }
            ComposerDiscovery::Unique(metadata) => {
                fresh.composer_count = 1;
                fresh.composer_fingerprint = Some(metadata.fingerprint.clone());
                fresh.composer_enabled = metadata.enabled;
                fresh.composer_writable = metadata.value_pattern_present && metadata.writable;
                fresh.composer_focused = metadata.focused;
            }
        }

        let profile = match profile {
            Some(profile) => profile,
            None => return Ok(fresh),
        };
        let opened = match open_mutation_composer(hwnd, process.pid, self.fingerprints, profile)? {
            MutationComposerDiscovery::Absent => {
                fresh.composer_count = 0;
                fresh.composer_fingerprint = None;
                return Ok(fresh);
            }
            MutationComposerDiscovery::Ambiguous(count) => {
                fresh.composer_count = count;
                fresh.composer_fingerprint = None;
                return Ok(fresh);
            }
            MutationComposerDiscovery::Unique(opened) => opened,
        };
        if fresh.composer_fingerprint.as_deref() != Some(&opened.fingerprint) {
            return Err(UiError::new(
                UiErrorKind::StaleSnapshot,
                "windows_mutation_composer_changed",
            ));
        }

        fresh.composer_enabled = opened.enabled;
        fresh.composer_writable = opened.writable;
        fresh.composer_focused = opened.focused;

        // Process, window, and composer claims come from fresh native evidence.
        // Target identity additionally requires an exact ephemeral UIA Name
        // match against this request-scoped approval binding.
        let target = observe_self_target(hwnd, process.pid, self.approved)?;
        fresh.self_chat_verified = target.self_chat_verified;
        fresh.target_binding_verified = target.target_binding_verified;
        fresh.exact_target = target.exact;
        fresh.unique_target = target.unique;
        fresh.draft = if target.authorizes_target_access() {
            let draft = classify_current_value(
                &opened.value_pattern,
                opened.hwnd,
                self.message_utf16,
                profile,
            )?;
            ensure_self_target(hwnd, process.pid, self.approved)?;
            draft
        } else {
            DraftState::Unobserved
        };

        self.submit_strategy = profile.submit_strategy;
        fresh.commit_selector = match self.submit_strategy {
            Some(SubmitStrategy::ComposerEnterMessageV1) => {
                CommitSelectorState::UniqueSynchronousComposerEnter
            }
            None => CommitSelectorState::Unconfigured,
        };
        self.identity = Some(NativeMutationIdentity {
            hwnd,
            composer_hwnd: opened.hwnd,
            pid: process.pid,
            creation_time_100ns: process.creation_time_100ns,
            executable_fingerprint: process.executable_fingerprint,
            session_id: process.session_id,
        });
        self.composer_element = Some(opened.element);
        self.value_pattern = Some(opened.value_pattern);
        Ok(fresh)
    }

    fn prepare_set_value(&mut self, value_utf16: &[u16]) -> Result<(), UiError> {
        self.prepared = PreparedMutation::None;
        let (required_draft, prepared) = if value_utf16.is_empty() {
            (DraftState::ExactMessage, PreparedMutation::Clear)
        } else {
            if value_utf16 != self.message_utf16 {
                return Err(UiError::new(
                    UiErrorKind::InvalidInput,
                    "windows_mutation_message_identity",
                ));
            }
            (DraftState::Empty, PreparedMutation::SetMessage)
        };
        self.revalidate_before_mutation(required_draft)?;
        self.prepared = prepared;
        Ok(())
    }

    fn set_value(&mut self, value_utf16: &[u16]) -> Result<(), UiError> {
        let (required_preparation, required_draft) = if value_utf16.is_empty() {
            (PreparedMutation::Clear, DraftState::ExactMessage)
        } else if value_utf16 == self.message_utf16 {
            (PreparedMutation::SetMessage, DraftState::Empty)
        } else {
            return Err(UiError::new(
                UiErrorKind::InvalidInput,
                "windows_mutation_message_identity",
            ));
        };
        if std::mem::replace(&mut self.prepared, PreparedMutation::None) != required_preparation {
            return Err(UiError::new(
                UiErrorKind::StaleSnapshot,
                "windows_mutation_preflight_missing",
            ));
        }
        // The transaction claim and durable-ledger transition occur after
        // prepare_set_value. Repeat the complete process/window/composer/focus/
        // draft/target preflight at the actual Value boundary rather than
        // treating the earlier preparation as current state.
        self.revalidate_before_mutation(required_draft)?;
        let pattern = self.value_pattern.as_ref().ok_or_else(|| {
            UiError::new(
                UiErrorKind::PermissionDenied,
                "windows_mutation_value_pattern_missing",
            )
        })?;
        let identity = self.identity.as_ref().ok_or_else(|| {
            UiError::new(
                UiErrorKind::StaleSnapshot,
                "windows_mutation_identity_missing",
            )
        })?;
        ensure_mutation_modal_clear(identity.hwnd, identity.pid)?;
        ensure_mutation_time(self.approved, self.expires_at_unix_ms)?;
        ensure_self_target(identity.hwnd, identity.pid, self.approved)?;
        let value = ScrubbedBstr::from_wide(value_utf16);
        // SAFETY: the exact writable ValuePattern was freshly revalidated in
        // this MTA apartment while the named mutex is held. The BSTR remains
        // alive through the synchronous call and is scrubbed before free.
        unsafe { pattern.SetValue(value.as_bstr()) }
            .map_err(|error| map_windows_error(error, "windows_mutation_set_value"))
    }

    fn prepare_invoke(&mut self) -> Result<(), UiError> {
        self.prepared = PreparedMutation::None;
        if self.invoke_pattern.is_none() && self.submit_strategy.is_none() {
            return Err(UiError::new(
                UiErrorKind::UnsupportedCapability,
                "windows_commit_selector_unconfigured",
            ));
        }
        self.revalidate_before_mutation(DraftState::ExactMessage)?;
        self.prepared = PreparedMutation::Invoke;
        Ok(())
    }

    fn invoke_verified(&mut self) -> Result<(), UiError> {
        if std::mem::replace(&mut self.prepared, PreparedMutation::None) != PreparedMutation::Invoke
        {
            return Err(UiError::new(
                UiErrorKind::StaleSnapshot,
                "windows_commit_preflight_missing",
            ));
        }
        // A durable commit marker exists between prepare_invoke and this call.
        // Repeat the complete bracketed target/draft preflight immediately at
        // the Invoke boundary before borrowing the selector interface.
        self.revalidate_before_mutation(DraftState::ExactMessage)?;
        let submit_strategy = self.submit_strategy;
        let identity = self.identity.as_ref().ok_or_else(|| {
            UiError::new(
                UiErrorKind::StaleSnapshot,
                "windows_mutation_identity_missing",
            )
        })?;
        ensure_mutation_modal_clear(identity.hwnd, identity.pid)?;
        ensure_mutation_time(self.approved, self.expires_at_unix_ms)?;
        ensure_self_target(identity.hwnd, identity.pid, self.approved)?;
        if let Some(pattern) = self.invoke_pattern.as_ref() {
            // SAFETY: a future InvokePattern can be stored only after an exact,
            // unique, profile-bound send selector is verified.
            return unsafe { pattern.Invoke() }
                .map_err(|error| map_windows_error(error, "windows_commit_invoke"));
        }
        match submit_strategy {
            Some(SubmitStrategy::ComposerEnterMessageV1) => {
                submit_profile_bound_composer_enter(identity.composer_hwnd)
            }
            None => Err(UiError::new(
                UiErrorKind::UnsupportedCapability,
                "windows_commit_selector_unconfigured",
            )),
        }
    }
}

#[cfg(feature = "windows-ui-write")]
fn submit_profile_bound_composer_enter(composer_hwnd: HWND) -> Result<(), UiError> {
    submit_profile_bound_composer_enter_with(
        composer_hwnd,
        |hwnd, message, wparam, lparam, flags, timeout_ms, message_result| {
            // SAFETY: the caller established that `hwnd` is the freshly
            // revalidated composer. `message_result` remains valid for this
            // synchronous call and no pointer is retained by user32.
            unsafe {
                SendMessageTimeoutW(
                    hwnd,
                    message,
                    wparam,
                    lparam,
                    flags,
                    timeout_ms,
                    Some(ptr::from_mut(message_result)),
                )
                .0 != 0
            }
        },
    )
}

#[cfg(feature = "windows-ui-write")]
fn submit_profile_bound_composer_enter_with(
    composer_hwnd: HWND,
    dispatch_once: impl FnOnce(
        HWND,
        u32,
        WPARAM,
        LPARAM,
        SEND_MESSAGE_TIMEOUT_FLAGS,
        u32,
        &mut usize,
    ) -> bool,
) -> Result<(), UiError> {
    const VK_RETURN_WPARAM: usize = 0x0D;
    const RETURN_SCAN_CODE: isize = 0x1C;
    const ENTER_KEYDOWN_LPARAM: isize = 1 | (RETURN_SCAN_CODE << 16);
    const SUBMIT_TIMEOUT_MS: u32 = 1_000;

    let mut message_result = 0_usize;
    // `composer_hwnd` was freshly revalidated as the exact profile-bound
    // RICHEDIT50W/1006 Document composer in this process, with matching PID,
    // target permit, draft, focus, modal, and executable evidence. The FnOnce
    // seam structurally permits exactly one synchronous dispatch.
    let delivered = dispatch_once(
        composer_hwnd,
        WM_KEYDOWN,
        WPARAM(VK_RETURN_WPARAM),
        LPARAM(ENTER_KEYDOWN_LPARAM),
        SMTO_ABORTIFHUNG | SMTO_BLOCK | SMTO_ERRORONEXIT,
        SUBMIT_TIMEOUT_MS,
        &mut message_result,
    );
    if !delivered {
        Err(UiError::new(
            UiErrorKind::SubmissionUncertain,
            "windows_commit_enter_message_uncertain",
        ))
    } else {
        Ok(())
    }
}

#[cfg(feature = "windows-ui-write")]
fn ensure_mutation_modal_clear(hwnd: HWND, expected_pid: u32) -> Result<(), UiError> {
    revalidate_window(hwnd, expected_pid)?;
    if !unsafe { IsWindowVisible(hwnd).as_bool() } {
        return Err(UiError::new(
            UiErrorKind::TargetNotFound,
            "windows_mutation_window_state",
        ));
    }

    let enabled = window_enabled(hwnd)?;
    if process_modal_present(hwnd, expected_pid, enabled)? {
        return Err(UiError::new(
            UiErrorKind::ModalPresent,
            "windows_mutation_modal",
        ));
    }
    if !unsafe { IsWindowVisible(hwnd).as_bool() } {
        return Err(UiError::new(
            UiErrorKind::TargetNotFound,
            "windows_mutation_window_state",
        ));
    }
    Ok(())
}

#[cfg(any(feature = "windows-ui-write", test))]
fn classify_foreground_activity(
    selected_hwnd: usize,
    foreground_hwnd: usize,
    foreground_pid: Option<u32>,
    expected_pid: u32,
) -> bool {
    foreground_hwnd != 0
        && (foreground_hwnd == selected_hwnd || foreground_pid == Some(expected_pid))
}

#[cfg(feature = "windows-ui-write")]
fn foreground_indicates_user_activity(
    selected_hwnd: HWND,
    expected_pid: u32,
) -> Result<bool, UiError> {
    // SAFETY: both calls are read-only queries and never activate a window.
    let foreground = unsafe { GetForegroundWindow() };
    let selected_raw = selected_hwnd.0 as usize;
    let foreground_raw = foreground.0 as usize;
    if foreground_raw == 0 || foreground_raw == selected_raw {
        return Ok(classify_foreground_activity(
            selected_raw,
            foreground_raw,
            None,
            expected_pid,
        ));
    }

    let mut foreground_pid = 0;
    let thread_id = unsafe { GetWindowThreadProcessId(foreground, Some(&mut foreground_pid)) };
    if thread_id == 0 || foreground_pid == 0 {
        return Err(UiError::new(
            UiErrorKind::StaleSnapshot,
            "windows_mutation_foreground_process",
        ));
    }
    Ok(classify_foreground_activity(
        selected_raw,
        foreground_raw,
        Some(foreground_pid),
        expected_pid,
    ))
}

#[cfg(any(feature = "windows-ui-write", test))]
struct TargetEvidence {
    self_chat_verified: bool,
    target_binding_verified: bool,
    exact: bool,
    unique: bool,
}

#[cfg(any(feature = "windows-ui-write", test))]
#[cfg_attr(not(test), allow(dead_code))] // Only Absent is reachable before selector review.
enum ObservedTargetSelection<'label> {
    Absent,
    UniqueInexact,
    AmbiguousInexact,
    AmbiguousExact,
    ExactUnique(&'label [u16]),
}

#[cfg(any(feature = "windows-ui-write", test))]
impl TargetEvidence {
    fn authorizes_target_access(&self) -> bool {
        self.self_chat_verified && self.target_binding_verified && self.exact && self.unique
    }
}

#[cfg(any(feature = "windows-ui-write", test))]
fn target_evidence_from_observation(
    selection: ObservedTargetSelection<'_>,
    verify_binding: impl FnOnce(&[u16]) -> bool,
) -> TargetEvidence {
    let (target_binding_verified, exact, unique) = match selection {
        ObservedTargetSelection::Absent => (false, false, false),
        ObservedTargetSelection::UniqueInexact => (false, false, true),
        ObservedTargetSelection::AmbiguousInexact => (false, false, false),
        ObservedTargetSelection::AmbiguousExact => (false, true, false),
        ObservedTargetSelection::ExactUnique(observed_label_utf16) => {
            (verify_binding(observed_label_utf16), true, true)
        }
    };
    TargetEvidence {
        self_chat_verified: target_binding_verified,
        target_binding_verified,
        exact,
        unique,
    }
}

#[cfg(feature = "windows-ui-write")]
fn observe_self_target(
    hwnd: HWND,
    expected_pid: u32,
    approved: &ApprovedSend,
) -> Result<TargetEvidence, UiError> {
    let windows = enumerate_raw_top_level_windows()?;
    if windows.is_empty() || !windows.contains(&hwnd) {
        return Ok(target_evidence_from_observation(
            ObservedTargetSelection::Absent,
            |_| false,
        ));
    }
    if windows
        .iter()
        .filter(|candidate| **candidate == hwnd)
        .count()
        != 1
    {
        return Ok(target_evidence_from_observation(
            ObservedTargetSelection::AmbiguousExact,
            |_| false,
        ));
    }

    with_mutation_target_label(hwnd, expected_pid, |observed_label_utf16| {
        target_evidence_from_observation(
            ObservedTargetSelection::ExactUnique(observed_label_utf16),
            |label| approved.target_binding_matches_observed_utf16(label),
        )
    })
}

#[cfg(feature = "windows-ui-write")]
fn verify_self_target(
    hwnd: HWND,
    expected_pid: u32,
    approved: &ApprovedSend,
) -> Result<bool, UiError> {
    let target = observe_self_target(hwnd, expected_pid, approved)?;
    Ok(target.authorizes_target_access())
}

#[cfg(feature = "windows-ui-write")]
fn ensure_self_target(
    hwnd: HWND,
    expected_pid: u32,
    approved: &ApprovedSend,
) -> Result<(), UiError> {
    if verify_self_target(hwnd, expected_pid, approved)? {
        Ok(())
    } else {
        Err(UiError::new(
            UiErrorKind::TargetNotSelf,
            "windows_mutation_target_unverified",
        ))
    }
}

#[cfg(feature = "windows-ui-write")]
struct MutationComposer {
    hwnd: HWND,
    fingerprint: String,
    enabled: bool,
    writable: bool,
    focused: bool,
    element: IUIAutomationElement,
    value_pattern: IUIAutomationValuePattern,
}

#[cfg(feature = "windows-ui-write")]
enum MutationComposerDiscovery {
    Absent,
    Unique(MutationComposer),
    Ambiguous(usize),
}

#[cfg(feature = "windows-ui-write")]
fn open_mutation_composer(
    hwnd: HWND,
    pid: u32,
    fingerprints: FingerprintKey,
    profile: &UiProfile,
) -> Result<MutationComposerDiscovery, UiError> {
    // SAFETY: COM is initialized MTA on this worker and every returned
    // interface remains in the same scoped thread/apartment.
    let automation: IUIAutomation =
        unsafe { CoCreateInstance(&CUIAutomation8, None, CLSCTX_INPROC_SERVER) }
            .map_err(|error| map_windows_error(error, "windows_mutation_uia_create"))?;
    let class_value = VARIANT::from(profile.composer_class);
    let automation_id_value = VARIANT::from(profile.composer_automation_id);
    let control_type_value = VARIANT::from(profile.composer_control_type);
    let class_condition =
        unsafe { automation.CreatePropertyCondition(UIA_ClassNamePropertyId, &class_value) }
            .map_err(|error| map_windows_error(error, "windows_mutation_uia_class_condition"))?;
    let id_condition = unsafe {
        automation.CreatePropertyCondition(UIA_AutomationIdPropertyId, &automation_id_value)
    }
    .map_err(|error| map_windows_error(error, "windows_mutation_uia_id_condition"))?;
    let type_condition = unsafe {
        automation.CreatePropertyCondition(UIA_ControlTypePropertyId, &control_type_value)
    }
    .map_err(|error| map_windows_error(error, "windows_mutation_uia_type_condition"))?;
    let class_and_id = unsafe { automation.CreateAndCondition(&class_condition, &id_condition) }
        .map_err(|error| map_windows_error(error, "windows_mutation_uia_selector"))?;
    let selector = unsafe { automation.CreateAndCondition(&class_and_id, &type_condition) }
        .map_err(|error| map_windows_error(error, "windows_mutation_uia_selector"))?;

    // SAFETY: exact HWND bridge and server-side condition return only matching
    // descendants; no raw tree, Name, or Value property is requested here.
    let root = unsafe { automation.ElementFromHandle(hwnd) }
        .map_err(|error| map_windows_error(error, "windows_mutation_uia_window"))?;
    let elements = unsafe { root.FindAll(TreeScope_Descendants, &selector) }
        .map_err(|error| map_windows_error(error, "windows_mutation_uia_find_composer"))?;
    let raw_count = unsafe { elements.Length() }
        .map_err(|error| map_windows_error(error, "windows_mutation_uia_composer_count"))?;
    let count = usize::try_from(raw_count).map_err(|_| {
        UiError::new(
            UiErrorKind::UnsupportedCapability,
            "windows_mutation_uia_composer_count",
        )
    })?;
    if count == 0 {
        return Ok(MutationComposerDiscovery::Absent);
    }
    if count > 1 {
        return Ok(MutationComposerDiscovery::Ambiguous(count));
    }
    let element = unsafe { elements.GetElement(0) }
        .map_err(|error| map_windows_error(error, "windows_mutation_uia_composer"))?;

    let element_pid = unsafe { element.CurrentProcessId() }
        .map_err(|error| map_windows_error(error, "windows_mutation_composer_process"))?;
    let element_pid = u32::try_from(element_pid).map_err(|_| {
        UiError::new(
            UiErrorKind::StaleSnapshot,
            "windows_mutation_composer_process",
        )
    })?;
    let composer_hwnd = unsafe { element.CurrentNativeWindowHandle() }
        .map_err(|error| map_windows_error(error, "windows_mutation_composer_handle"))?;
    if element_pid != pid || composer_hwnd.0.is_null() {
        return Err(UiError::new(
            UiErrorKind::StaleSnapshot,
            "windows_mutation_composer_identity",
        ));
    }
    let identity = NativeMutationIdentity {
        hwnd,
        composer_hwnd,
        pid,
        creation_time_100ns: 0,
        executable_fingerprint: String::new(),
        session_id: 0,
    };
    validate_mutation_composer_element(&element, &identity, profile)?;
    let enabled = unsafe { element.CurrentIsEnabled() }
        .map_err(|error| map_windows_error(error, "windows_mutation_composer_enabled"))?
        .as_bool();
    let focused = unsafe { element.CurrentHasKeyboardFocus() }
        .map_err(|error| map_windows_error(error, "windows_mutation_composer_focus"))?
        .as_bool();
    let value_pattern =
        unsafe { element.GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId) }
            .map_err(|error| map_windows_error(error, "windows_mutation_value_pattern"))?;
    let writable = !unsafe { value_pattern.CurrentIsReadOnly() }
        .map_err(|error| map_windows_error(error, "windows_mutation_composer_read_only"))?
        .as_bool();

    Ok(MutationComposerDiscovery::Unique(MutationComposer {
        hwnd: composer_hwnd,
        fingerprint: fingerprints.composer(composer_hwnd.0 as usize, pid),
        enabled,
        writable,
        focused,
        element,
        value_pattern,
    }))
}

#[cfg(feature = "windows-ui-write")]
fn validate_mutation_composer_element(
    element: &IUIAutomationElement,
    identity: &NativeMutationIdentity,
    profile: &UiProfile,
) -> Result<(), UiError> {
    let class_name = unsafe { element.CurrentClassName() }
        .map_err(|error| map_windows_error(error, "windows_mutation_composer_class"))?;
    let automation_id = unsafe { element.CurrentAutomationId() }
        .map_err(|error| map_windows_error(error, "windows_mutation_composer_id"))?;
    let control_type = unsafe { element.CurrentControlType() }
        .map_err(|error| map_windows_error(error, "windows_mutation_composer_type"))?;
    let element_pid = unsafe { element.CurrentProcessId() }
        .map_err(|error| map_windows_error(error, "windows_mutation_composer_process"))?;
    let element_hwnd = unsafe { element.CurrentNativeWindowHandle() }
        .map_err(|error| map_windows_error(error, "windows_mutation_composer_handle"))?;
    if !profile.matches_selector(
        &class_name.to_string(),
        &automation_id.to_string(),
        control_type.0,
    ) || control_type != UIA_DocumentControlTypeId
        || u32::try_from(element_pid).ok() != Some(identity.pid)
        || element_hwnd != identity.composer_hwnd
    {
        return Err(UiError::new(
            UiErrorKind::StaleSnapshot,
            "windows_mutation_composer_identity",
        ));
    }
    Ok(())
}

#[cfg(feature = "windows-ui-write")]
fn classify_current_value(
    pattern: &IUIAutomationValuePattern,
    composer_hwnd: HWND,
    expected_message_utf16: &[u16],
    profile: &UiProfile,
) -> Result<DraftState, UiError> {
    if composer_native_text_empty(composer_hwnd)? {
        return Ok(DraftState::Empty);
    }
    // SAFETY: read occurs only after live self-target verification. The BSTR is
    // immediately wrapped, never formatted/decoded/serialized, compared as
    // UTF-16 only, and scrubbed in place before SysFreeString runs.
    let current = ScrubbedBstr::new(
        unsafe { pattern.CurrentValue() }
            .map_err(|error| map_windows_error(error, "windows_mutation_current_value"))?,
    );
    Ok(
        if profile.matches_staged_value(current.units(), expected_message_utf16) {
            DraftState::ExactMessage
        } else if profile.matches_empty_placeholder(current.units()) {
            DraftState::Empty
        } else {
            DraftState::Different
        },
    )
}

struct ScrubbedBstr(BSTR);

impl ScrubbedBstr {
    fn new(value: BSTR) -> Self {
        Self(value)
    }

    #[cfg(feature = "windows-ui-write")]
    fn from_wide(value: &[u16]) -> Self {
        // Callers encode secrets directly into a Zeroizing UTF-16 Vec. This
        // avoids BSTR::from(&str), whose internal temporary is not scrubbed.
        Self(BSTR::from_wide(value))
    }

    fn units(&self) -> &[u16] {
        &self.0
    }

    #[cfg(feature = "windows-ui-write")]
    fn as_bstr(&self) -> &BSTR {
        &self.0
    }
}

impl Drop for ScrubbedBstr {
    fn drop(&mut self) {
        let len = self.0.len();
        if len == 0 {
            return;
        }
        // SAFETY: BSTR uniquely owns a writable SysAllocStringLen allocation;
        // its dereferenced length excludes the terminator. The mutable slice is
        // used only during Drop, before the field's BSTR Drop frees it, and no
        // alias is retained. Zeroing the allocation prevents draft/message data
        // from remaining in the COM task allocator after free.
        unsafe {
            std::slice::from_raw_parts_mut(self.0.as_ptr().cast_mut(), len).zeroize();
        }
    }
}

fn map_windows_error(error: WindowsError, operation: &'static str) -> UiError {
    let code = error.code().0 as u32;
    let kind = if error.code() == E_ACCESSDENIED {
        UiErrorKind::PermissionDenied
    } else if code == UIA_E_ELEMENTNOTAVAILABLE {
        UiErrorKind::StaleSnapshot
    } else if code == UIA_E_TIMEOUT {
        UiErrorKind::Timeout
    } else {
        UiErrorKind::UnsupportedCapability
    };
    UiError::new(kind, operation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approved_window_selection_requires_one_exact_match_among_helpers() {
        assert_eq!(
            select_unique_matching_candidate([(1_u8, false), (2, true), (3, false)]),
            Some(2)
        );
        assert_eq!(
            select_unique_matching_candidate([(1_u8, false), (2, false)]),
            None
        );
        assert_eq!(
            select_unique_matching_candidate([(1_u8, true), (2, true)]),
            None
        );
    }

    #[test]
    fn native_composer_length_query_is_content_free_bounded_and_fail_closed() {
        let hwnd = HWND::default();
        let empty = composer_native_text_empty_with(
            hwnd,
            |actual_hwnd, message, wparam, lparam, flags, timeout_ms, result| {
                assert_eq!(actual_hwnd, hwnd);
                assert_eq!(message, WM_GETTEXTLENGTH);
                assert_eq!(wparam.0, 0);
                assert_eq!(lparam.0, 0);
                assert_eq!(flags, SMTO_ABORTIFHUNG | SMTO_BLOCK | SMTO_ERRORONEXIT);
                assert_eq!(timeout_ms, 1_000);
                assert_eq!(*result, 0);
                true
            },
        )
        .expect("a delivered zero-length query must classify empty");
        assert!(empty);

        let nonempty = composer_native_text_empty_with(hwnd, |_, _, _, _, _, _, result| {
            *result = 7;
            true
        })
        .expect("a delivered nonzero-length query must classify nonempty");
        assert!(!nonempty);

        let error = composer_native_text_empty_with(hwnd, |_, _, _, _, _, _, _| false)
            .expect_err("a failed or timed-out query must fail closed");
        assert_eq!(error.kind, UiErrorKind::Timeout);
        assert_eq!(error.operation, "windows_draft_native_length");
        assert!(error.retry_safe);
    }

    #[cfg(feature = "windows-ui-write")]
    #[test]
    fn composer_enter_dispatch_is_exact_single_call_and_fail_closed() {
        let hwnd = HWND::default();
        let result = submit_profile_bound_composer_enter_with(
            hwnd,
            |actual_hwnd, message, wparam, lparam, flags, timeout_ms, result| {
                assert_eq!(actual_hwnd, hwnd);
                assert_eq!(message, WM_KEYDOWN);
                assert_eq!(wparam.0, 0x0D);
                assert_eq!(lparam.0, 1 | (0x1C << 16));
                assert_eq!(flags, SMTO_ABORTIFHUNG | SMTO_BLOCK | SMTO_ERRORONEXIT);
                assert_eq!(timeout_ms, 1_000);
                assert_eq!(*result, 0);
                *result = 7;
                true
            },
        );
        assert!(result.is_ok());

        let error = submit_profile_bound_composer_enter_with(hwnd, |_, _, _, _, _, _, _| false)
            .expect_err("a failed or timed-out dispatch must remain uncertain");
        assert_eq!(error.kind, UiErrorKind::SubmissionUncertain);
        assert_eq!(error.operation, "windows_commit_enter_message_uncertain");
        assert!(!error.retry_safe);
    }

    #[test]
    fn cancellation_classifier_accepts_only_completed_or_already_cancelled_calls() {
        assert!(cancellation_error_is_terminal(RPC_E_CALL_COMPLETE));
        assert!(cancellation_error_is_terminal(RPC_E_CALL_CANCELED));
        assert!(!cancellation_error_is_terminal(E_ACCESSDENIED));
        assert!(!cancellation_error_is_terminal(HRESULT(0)));
    }

    #[test]
    fn read_only_enumeration_ignores_hidden_windows_without_weakening_raw_scope() {
        for (exact_class, visible, expected_read_only, expected_raw) in [
            (false, false, false, false),
            (false, true, false, false),
            (true, false, false, true),
            (true, true, true, true),
        ] {
            assert_eq!(
                window_matches_enumeration_scope(
                    WindowEnumerationScope::ReadOnlyVisible,
                    exact_class,
                    visible,
                ),
                expected_read_only
            );
            assert_eq!(
                window_matches_enumeration_scope(
                    WindowEnumerationScope::RawExactClass,
                    exact_class,
                    visible,
                ),
                expected_raw
            );
        }
    }

    #[test]
    fn file_version_profile_is_exact() {
        let profile = profile_for(Some(FileVersion::KNOWN))
            .expect("the reviewed version must select one exact profile");
        assert_eq!(profile.composer_control_type, UIA_DocumentControlTypeId.0);
        assert!(profile_for(Some(FileVersion {
            major: 26,
            minor: 7,
            patch: 0,
            build: 5256,
        }))
        .is_none());
        assert!(profile_for(None).is_none());
    }

    #[test]
    fn executable_name_verification_is_exact() {
        let valid = Path::new(r"C:\Synthetic\KakaoTalk.exe");
        let wrong_case = Path::new(r"C:\Synthetic\kakaotalk.exe");
        assert_eq!(valid.file_name(), Some(OsStr::new("KakaoTalk.exe")));
        assert_ne!(wrong_case.file_name(), Some(OsStr::new("KakaoTalk.exe")));
    }

    #[test]
    fn secret_utf16_encoding_never_reallocates() {
        for message in [
            "ASCII synthetic canary".to_string(),
            "BMP \u{ac00}\u{b098}\u{b2e4}".to_string(),
            "non-BMP \u{1f642}\u{1f680}".to_string(),
            "\u{1f642}".repeat(1_000),
        ] {
            let encoded = encode_secret_utf16(&message);
            assert_eq!(
                encoded.as_slice(),
                message.encode_utf16().collect::<Vec<_>>()
            );
            assert!(encoded.capacity() >= message.len());
        }
    }

    #[test]
    fn same_process_foreground_popup_is_user_activity() {
        assert!(!classify_foreground_activity(10, 0, None, 42));
        assert!(classify_foreground_activity(10, 10, None, 42));
        assert!(classify_foreground_activity(10, 11, Some(42), 42));
        assert!(!classify_foreground_activity(10, 11, Some(99), 42));
    }

    #[test]
    fn only_visible_owned_popups_in_the_selected_owner_group_block() {
        let selected = WindowOwnerGroup {
            hwnd: 10,
            pid: 42,
            root_owner: 10,
        };
        let classify = |candidate_hwnd, candidate_pid, visible, owner, root_owner| {
            owned_popup_blocks_selected(
                selected,
                OwnedPopupObservation {
                    hwnd: candidate_hwnd,
                    pid: candidate_pid,
                    visible,
                    owner,
                    root_owner,
                },
            )
        };

        assert_eq!(classify(10, 42, true, Some(10), Some(10)), Ok(false));
        assert_eq!(classify(11, 99, true, Some(10), Some(10)), Ok(false));
        assert_eq!(classify(11, 42, false, Some(10), Some(10)), Ok(false));
        assert_eq!(classify(11, 42, true, None, Some(11)), Ok(false));
        assert_eq!(classify(11, 42, true, Some(0), Some(11)), Ok(false));
        assert_eq!(classify(11, 42, true, Some(10), Some(20)), Ok(false));
        assert_eq!(classify(11, 42, true, Some(10), Some(10)), Ok(true));
        assert_eq!(classify(11, 42, true, Some(10), None), Err(()));
        assert_eq!(classify(11, 42, true, Some(10), Some(0)), Err(()));
        assert_eq!(
            owned_popup_blocks_selected(
                WindowOwnerGroup {
                    hwnd: 0,
                    ..selected
                },
                OwnedPopupObservation {
                    hwnd: 11,
                    pid: 42,
                    visible: true,
                    owner: Some(10),
                    root_owner: Some(10),
                }
            ),
            Err(())
        );
        for invalid in [
            WindowOwnerGroup { pid: 0, ..selected },
            WindowOwnerGroup {
                root_owner: 0,
                ..selected
            },
        ] {
            assert_eq!(
                owned_popup_blocks_selected(
                    invalid,
                    OwnedPopupObservation {
                        hwnd: 11,
                        pid: 42,
                        visible: true,
                        owner: Some(10),
                        root_owner: Some(10),
                    }
                ),
                Err(())
            );
        }
    }

    #[test]
    fn target_evidence_requires_ephemeral_binding_and_exact_unique_selection() {
        let expected: Vec<u16> = "SYNTHETIC_SELF_TARGET".encode_utf16().collect();

        let absent = target_evidence_from_observation(ObservedTargetSelection::Absent, |_| {
            panic!("binding verifier must not run without an exact unique observation")
        });
        assert!(!absent.self_chat_verified);
        assert!(!absent.target_binding_verified);
        assert!(!absent.exact);
        assert!(!absent.unique);
        assert!(!absent.authorizes_target_access());

        let exact = target_evidence_from_observation(
            ObservedTargetSelection::ExactUnique(&expected),
            |candidate| candidate == expected,
        );
        assert!(exact.self_chat_verified);
        assert!(exact.target_binding_verified);
        assert!(exact.exact);
        assert!(exact.unique);
        assert!(exact.authorizes_target_access());

        let inexact =
            target_evidence_from_observation(ObservedTargetSelection::UniqueInexact, |_| {
                panic!("binding verifier must not run for an inexact observation")
            });
        assert!(!inexact.self_chat_verified);
        assert!(!inexact.target_binding_verified);
        assert!(!inexact.exact);
        assert!(inexact.unique);
        assert!(!inexact.authorizes_target_access());

        let wrong: Vec<u16> = "SYNTHETIC_OTHER_TARGET".encode_utf16().collect();
        let mismatched = target_evidence_from_observation(
            ObservedTargetSelection::ExactUnique(&wrong),
            |candidate| candidate == expected,
        );
        assert!(!mismatched.self_chat_verified);
        assert!(!mismatched.target_binding_verified);
        assert!(!mismatched.authorizes_target_access());

        let ambiguous =
            target_evidence_from_observation(ObservedTargetSelection::AmbiguousExact, |_| {
                panic!("binding verifier must not run for an ambiguous observation")
            });
        assert!(!ambiguous.self_chat_verified);
        assert!(!ambiguous.target_binding_verified);
        assert!(ambiguous.exact);
        assert!(!ambiguous.unique);
        assert!(!ambiguous.authorizes_target_access());

        let ambiguous_inexact =
            target_evidence_from_observation(ObservedTargetSelection::AmbiguousInexact, |_| {
                panic!("binding verifier must not run for an ambiguous inexact observation")
            });
        assert!(!ambiguous_inexact.self_chat_verified);
        assert!(!ambiguous_inexact.target_binding_verified);
        assert!(!ambiguous_inexact.exact);
        assert!(!ambiguous_inexact.unique);
        assert!(!ambiguous_inexact.authorizes_target_access());
    }

    #[test]
    fn mutex_wait_uncertainty_is_never_retryable() {
        assert!(mutation_mutex_wait_error(MutationMutexWait::Acquired).is_none());
        for outcome in [
            MutationMutexWait::Contended,
            MutationMutexWait::Abandoned,
            MutationMutexWait::Failed,
        ] {
            let error = mutation_mutex_wait_error(outcome)
                .expect("every non-acquired wait result must fail closed");
            assert_eq!(error.kind, UiErrorKind::SubmissionUncertain);
            assert!(!error.retry_safe);
        }
    }

    #[test]
    fn mutation_time_refuses_when_either_clock_reaches_expiry() {
        assert!(!mutation_time_expired(false, 1_999, 2_000));
        assert!(mutation_time_expired(true, 1_999, 2_000));
        assert!(mutation_time_expired(false, 2_000, 2_000));
        assert!(mutation_time_expired(false, 2_001, 2_000));
    }
}
