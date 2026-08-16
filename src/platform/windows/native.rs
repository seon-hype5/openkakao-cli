//! Small native Windows boundary for read-only process, window, and UIA data.
//!
//! No function in this module sends a window message, changes focus/Z-order,
//! invokes a UIA pattern, or reads a UIA Value. COM objects are created and
//! destroyed on the dedicated MTA thread established by [`inspect`].

use std::ffi::{c_void, OsStr, OsString};
use std::mem::{align_of, size_of};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::ptr;

use windows::core::{w, Error as WindowsError, BOOL, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, SetLastError, ERROR_SUCCESS, E_ACCESSDENIED, HANDLE, HWND, LPARAM,
};
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
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, OpenProcess, OpenProcessToken,
    QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::System::Variant::VARIANT;
use windows::Win32::UI::Accessibility::{
    CUIAutomation8, IUIAutomation, IUIAutomationValuePattern, TreeScope_Descendants,
    UIA_AutomationIdPropertyId, UIA_ClassNamePropertyId, UIA_ControlTypePropertyId,
    UIA_EditControlTypeId, UIA_ValuePatternId, UIA_E_ELEMENTNOTAVAILABLE, UIA_E_TIMEOUT,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClassNameW, GetWindowLongPtrW, GetWindowThreadProcessId, IsWindowVisible,
    GWL_STYLE, WS_DISABLED,
};

use super::{
    profile_for, ComposerDiscovery, FileVersion, FingerprintKey, NativeComposer, NativeInspection,
    NativeProcess, NativeWindow, UiProfile, WindowDiscovery, TOP_LEVEL_CLASS,
};
use crate::platform::{UiError, UiErrorKind};

const CLASS_BUFFER_UNITS: usize = 256;
const PROCESS_PATH_BUFFER_UNITS: usize = 32_768;
const FIXED_FILE_INFO_SIGNATURE: u32 = 0xFEEF_04BD;

pub(super) fn inspect(fingerprints: FingerprintKey) -> Result<NativeInspection, UiError> {
    // The caller creates a fresh, windowless worker thread for every probe.
    // Every successful S_OK/S_FALSE initialization is balanced by this guard,
    // and no COM interface leaves the scope guarded by `_apartment`.
    let _apartment = ComApartment::initialize_mta()?;
    let windows = enumerate_top_level_windows()?;

    let window = match windows.len() {
        0 => WindowDiscovery::Absent,
        1 => WindowDiscovery::Unique(inspect_unique_window(windows[0], fingerprints)?),
        count => WindowDiscovery::Ambiguous(count),
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
    let executable_verified =
        image.path.is_absolute() && image.path.file_name() == Some(OsStr::new("KakaoTalk.exe"));
    let executable_fingerprint = fingerprints.executable(&image.utf16);
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
        fingerprint: fingerprints.composer(hwnd.0 as usize, pid),
        enabled,
        value_pattern_present,
        writable,
        focused,
    }))
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
}
