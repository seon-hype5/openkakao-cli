//! Small native Windows boundary for process, window, and UIA data.
//!
//! Inspection never reads UIA Value or mutates UI state. Production Value and
//! Invoke calls exist only with the `windows-ui-write` build feature and behind
//! the transaction state machine. No function sends a window message, changes
//! focus/Z-order, synthesizes input, or touches the clipboard. COM objects stay
//! on the dedicated MTA thread that created them.

use std::ffi::{c_void, OsStr, OsString};
use std::mem::{align_of, size_of};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::ptr;

#[cfg(feature = "windows-ui-write")]
use windows::core::BSTR;
use windows::core::{w, Error as WindowsError, BOOL, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, SetLastError, ERROR_SUCCESS, E_ACCESSDENIED, FILETIME, HANDLE, HWND,
    LPARAM,
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
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
#[cfg(feature = "windows-ui-write")]
use windows::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, OpenProcess, OpenProcessToken,
    QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::System::Variant::VARIANT;
use windows::Win32::UI::Accessibility::{
    CUIAutomation8, IUIAutomation, IUIAutomationValuePattern, TreeScope_Descendants,
    UIA_AutomationIdPropertyId, UIA_ClassNamePropertyId, UIA_ControlTypePropertyId,
    UIA_EditControlTypeId, UIA_ValuePatternId, UIA_E_ELEMENTNOTAVAILABLE, UIA_E_TIMEOUT,
};
#[cfg(feature = "windows-ui-write")]
use windows::Win32::UI::Accessibility::{IUIAutomationElement, IUIAutomationInvokePattern};
#[cfg(feature = "windows-ui-write")]
use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClassNameW, GetWindowLongPtrW, GetWindowThreadProcessId, IsWindowVisible,
    GWL_STYLE, WS_DISABLED,
};

#[cfg(feature = "windows-ui-write")]
use zeroize::Zeroize;
#[cfg(any(feature = "windows-ui-write", test))]
use zeroize::Zeroizing;

#[cfg(feature = "windows-ui-write")]
use super::{
    ledger::{LedgerRecord, MutationLedger, RecordCorrelation, UnavailableLedger},
    transaction::{self, CommitSelectorState, DraftState, ExpectedState, FreshState, MutationPort},
    unix_now_ms, KNOWN_PROFILE,
};
use super::{
    profile_for, select_read_only_window, ComposerDiscovery, FileVersion, FingerprintKey,
    NativeComposer, NativeInspection, NativeProcess, NativeWindow, UiProfile, WindowDiscovery,
    TOP_LEVEL_CLASS,
};
#[cfg(feature = "windows-ui-write")]
use crate::platform::{ApprovedSend, SendOutcome};
use crate::platform::{UiError, UiErrorKind};

const CLASS_BUFFER_UNITS: usize = 256;
const PROCESS_PATH_BUFFER_UNITS: usize = 32_768;
const FIXED_FILE_INFO_SIGNATURE: u32 = 0xFEEF_04BD;
const MAX_READ_ONLY_WINDOW_CANDIDATES: usize = 8;

pub(super) fn inspect(fingerprints: FingerprintKey) -> Result<NativeInspection, UiError> {
    // The caller creates a fresh, windowless worker thread for every probe.
    // Every successful S_OK/S_FALSE initialization is balanced by this guard,
    // and no COM interface leaves the scope guarded by `_apartment`.
    let _apartment = ComApartment::initialize_mta()?;
    let windows = enumerate_top_level_windows()?;

    let window = match windows.len() {
        0 => WindowDiscovery::Absent,
        count if count > MAX_READ_ONLY_WINDOW_CANDIDATES => WindowDiscovery::Ambiguous(count),
        _ => {
            let mut inspected = Vec::with_capacity(windows.len());
            for hwnd in windows {
                inspected.push(inspect_unique_window(hwnd, fingerprints)?);
            }
            select_read_only_window(inspected)
        }
    };

    Ok(NativeInspection { window })
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
}

fn enumerate_top_level_windows() -> Result<Vec<HWND>, UiError> {
    let mut context = EnumContext {
        handles: Vec::new(),
        callback_panicked: false,
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
        if window_has_exact_class(hwnd) {
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
    let executable_verified =
        image.path.is_absolute() && image.path.file_name() == Some(OsStr::new("KakaoTalk.exe"));
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

    let profile = executable_verified.then(|| profile_for(version)).flatten();
    let composer = if let Some(profile) = profile {
        if visible && enabled && interactive_session_match && integrity_compatible {
            discover_composer(hwnd, pid, fingerprints, profile)?
        } else {
            ComposerDiscovery::NotInspected
        }
    } else {
        ComposerDiscovery::NotInspected
    };

    revalidate_window(hwnd, pid)?;

    Ok(NativeWindow {
        fingerprint: fingerprints.window(hwnd.0 as usize, pid),
        visible,
        enabled,
        process: NativeProcess {
            pid,
            executable_fingerprint,
            #[cfg(feature = "windows-ui-write")]
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
        return Ok(ComposerDiscovery::Absent);
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
    ) || control_type != UIA_EditControlTypeId
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

    // GetCurrentPatternAs and CurrentIsReadOnly inspect metadata only. We never
    // call CurrentValue or SetValue. Any pattern uncertainty becomes unwritable.
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

#[cfg(feature = "windows-ui-write")]
pub(super) fn stage(
    fingerprints: FingerprintKey,
    approved: &ApprovedSend,
    expected: &ExpectedState<'_>,
) -> Result<SendOutcome, UiError> {
    let _apartment = ComApartment::initialize_mta()?;
    let _mutex = NamedMutationMutex::acquire()?;
    let correlation = RecordCorrelation::from_policy(approved.take_transaction_correlation()?)?;
    let message_utf16 = encode_secret_utf16(approved.message());
    let mut port = NativeMutationPort::new(fingerprints, expected, &message_utf16, correlation);
    transaction::run_stage(expected, &message_utf16, approved, &mut port)
}

#[cfg(feature = "windows-ui-write")]
pub(super) fn commit(
    fingerprints: FingerprintKey,
    approved: &ApprovedSend,
    expected: &ExpectedState<'_>,
) -> Result<SendOutcome, UiError> {
    let _apartment = ComApartment::initialize_mta()?;
    let _mutex = NamedMutationMutex::acquire()?;
    let correlation = RecordCorrelation::from_policy(approved.take_transaction_correlation()?)?;
    let message_utf16 = encode_secret_utf16(approved.message());
    let mut port = NativeMutationPort::new(fingerprints, expected, &message_utf16, correlation);
    transaction::run_commit(expected, &message_utf16, approved, &mut port)
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
struct NativeMutationPort<'message> {
    ledger: UnavailableLedger,
    fingerprints: FingerprintKey,
    expires_at_unix_ms: u64,
    message_utf16: &'message [u16],
    identity: Option<NativeMutationIdentity>,
    composer_element: Option<IUIAutomationElement>,
    value_pattern: Option<IUIAutomationValuePattern>,
    invoke_pattern: Option<IUIAutomationInvokePattern>,
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
impl<'message> NativeMutationPort<'message> {
    fn new(
        fingerprints: FingerprintKey,
        expected: &ExpectedState<'_>,
        message_utf16: &'message [u16],
        correlation: RecordCorrelation,
    ) -> Self {
        Self {
            ledger: UnavailableLedger::new(correlation),
            fingerprints,
            expires_at_unix_ms: expected.expires_at_unix_ms,
            message_utf16,
            identity: None,
            composer_element: None,
            value_pattern: None,
            invoke_pattern: None,
            prepared: PreparedMutation::None,
        }
    }

    fn revalidate_before_mutation(&self, required_draft: DraftState) -> Result<(), UiError> {
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

        let windows = enumerate_top_level_windows()?;
        if windows.len() != 1 || windows[0] != identity.hwnd {
            return Err(stale_window_error());
        }
        revalidate_window(identity.hwnd, identity.pid)?;
        if !unsafe { IsWindowVisible(identity.hwnd).as_bool() } || !window_enabled(identity.hwnd)? {
            return Err(UiError::new(
                UiErrorKind::TargetNotFound,
                "windows_mutation_window_state",
            ));
        }
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
        if unix_now_ms() >= self.expires_at_unix_ms {
            return Err(UiError::new(
                UiErrorKind::StaleSnapshot,
                "windows_mutation_staleness",
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

        // Current profile has no independently verified non-content self-chat
        // selector. Refuse before CurrentValue so an arbitrary room's draft is
        // never read, even when a public caller forges approval booleans.
        if !verify_self_target(identity.hwnd)? {
            return Err(UiError::new(
                UiErrorKind::TargetNotSelf,
                "windows_mutation_target_unverified",
            ));
        }
        let draft = classify_current_value(pattern, self.message_utf16)?;
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
impl MutationLedger for NativeMutationPort<'_> {
    fn ensure_clear(&mut self) -> Result<(), UiError> {
        self.ledger.ensure_clear()
    }

    fn begin_stage(&mut self) -> Result<LedgerRecord, UiError> {
        self.ledger.begin_stage()
    }

    fn mark_commit(&mut self, stage: LedgerRecord) -> Result<LedgerRecord, UiError> {
        self.ledger.mark_commit(stage)
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
        self.prepared = PreparedMutation::None;

        let now_unix_ms = unix_now_ms();
        let windows = enumerate_top_level_windows()?;
        let mut fresh = FreshState::unavailable(now_unix_ms, windows.len());
        if windows.len() != 1 {
            return Ok(fresh);
        }

        let hwnd = windows[0];
        let NativeWindow {
            fingerprint,
            visible,
            enabled,
            process,
            composer,
        } = inspect_unique_window(hwnd, self.fingerprints)?;
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
        fresh.modal_present = !enabled;
        fresh.window_fingerprint = Some(fingerprint);
        fresh.user_active = foreground_indicates_user_activity(hwnd, process.pid)?;
        fresh.selector_profile_id = profile.map(|profile| profile.id.to_string());

        match composer {
            ComposerDiscovery::NotInspected | ComposerDiscovery::Absent => return Ok(fresh),
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

        // These claims are intentionally independent of the approval snapshot.
        // No measured self-chat selector exists for this profile, so the native
        // observer cannot assert any target identity and must not read Value.
        let target = observe_self_target(hwnd)?;
        fresh.self_chat_verified = target.self_chat_verified;
        fresh.exact_target = target.exact;
        fresh.unique_target = target.unique;
        fresh.draft = if target.self_chat_verified && target.exact && target.unique {
            classify_current_value(&opened.value_pattern, self.message_utf16)?
        } else {
            DraftState::Unobserved
        };

        // No send-button selector has completed the required measured profile
        // validation, so an InvokePattern is never acquired or guessed.
        fresh.commit_selector = CommitSelectorState::Unconfigured;
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
        let required_preparation = if value_utf16.is_empty() {
            PreparedMutation::Clear
        } else if value_utf16 == self.message_utf16 {
            PreparedMutation::SetMessage
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
        let pattern = self.value_pattern.as_ref().ok_or_else(|| {
            UiError::new(
                UiErrorKind::PermissionDenied,
                "windows_mutation_value_pattern_missing",
            )
        })?;
        let value = ScrubbedBstr::from_wide(value_utf16);
        // SAFETY: the exact writable ValuePattern was freshly revalidated in
        // this MTA apartment while the named mutex is held. The BSTR remains
        // alive through the synchronous call and is scrubbed before free.
        unsafe { pattern.SetValue(value.as_bstr()) }
            .map_err(|error| map_windows_error(error, "windows_mutation_set_value"))
    }

    fn prepare_invoke(&mut self) -> Result<(), UiError> {
        self.prepared = PreparedMutation::None;
        if self.invoke_pattern.is_none() {
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
        let pattern = self.invoke_pattern.as_ref().ok_or_else(|| {
            UiError::new(
                UiErrorKind::UnsupportedCapability,
                "windows_commit_selector_unconfigured",
            )
        })?;
        // SAFETY: this interface can only be stored after an exact, unique,
        // profile-bound send selector and InvokePattern are verified. The
        // current profile stores none, so production cannot reach this call.
        unsafe { pattern.Invoke() }
            .map_err(|error| map_windows_error(error, "windows_commit_invoke"))
    }
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

#[cfg(feature = "windows-ui-write")]
struct TargetEvidence {
    self_chat_verified: bool,
    exact: bool,
    unique: bool,
}

#[cfg(feature = "windows-ui-write")]
fn observe_self_target(_hwnd: HWND) -> Result<TargetEvidence, UiError> {
    // Profile 26.7.0.5255 has no privacy-safe, measured self-chat identity
    // selector. Do not inspect Name/title text or substitute process identity.
    Ok(TargetEvidence {
        self_chat_verified: false,
        exact: false,
        unique: false,
    })
}

#[cfg(feature = "windows-ui-write")]
fn verify_self_target(hwnd: HWND) -> Result<bool, UiError> {
    let target = observe_self_target(hwnd)?;
    Ok(target.self_chat_verified && target.exact && target.unique)
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
    ) || control_type != UIA_EditControlTypeId
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
    expected_message_utf16: &[u16],
) -> Result<DraftState, UiError> {
    // SAFETY: read occurs only after live self-target verification. The BSTR is
    // immediately wrapped, never formatted/decoded/serialized, compared as
    // UTF-16 only, and scrubbed in place before SysFreeString runs.
    let current = ScrubbedBstr::new(
        unsafe { pattern.CurrentValue() }
            .map_err(|error| map_windows_error(error, "windows_mutation_current_value"))?,
    );
    Ok(if current.units().is_empty() {
        DraftState::Empty
    } else if current.units() == expected_message_utf16 {
        DraftState::ExactMessage
    } else {
        DraftState::Different
    })
}

#[cfg(feature = "windows-ui-write")]
struct ScrubbedBstr(BSTR);

#[cfg(feature = "windows-ui-write")]
impl ScrubbedBstr {
    fn new(value: BSTR) -> Self {
        Self(value)
    }

    fn from_wide(value: &[u16]) -> Self {
        // Callers encode secrets directly into a Zeroizing UTF-16 Vec. This
        // avoids BSTR::from(&str), whose internal temporary is not scrubbed.
        Self(BSTR::from_wide(value))
    }

    fn units(&self) -> &[u16] {
        &self.0
    }

    fn as_bstr(&self) -> &BSTR {
        &self.0
    }
}

#[cfg(feature = "windows-ui-write")]
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
    fn file_version_profile_is_exact() {
        assert!(profile_for(Some(FileVersion::KNOWN)).is_some());
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
}
