//! Disconnected current-user LocalAppData locator for the durable ledger.
//!
//! The native adapter is compiled behind `windows-ui-write`, but production
//! does not call it. Tests exercise the orchestration with content-free fakes;
//! they never resolve or write the real LocalAppData directory.

#![allow(dead_code)]

use std::ffi::{c_void, OsString};
use std::fmt;
use std::mem::size_of_val;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Component, Path, PathBuf};
use std::ptr;

use windows::core::{GUID, HRESULT, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FileAttributeTagInfo, GetDriveTypeW, GetFileInformationByHandleEx, GetFileType,
    GetFinalPathNameByHandleW, GetVolumePathNameW, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK,
    GETFINALPATHNAMEBYHANDLE_FLAGS, OPEN_EXISTING, VOLUME_NAME_GUID,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::UI::Shell::{FOLDERID_LocalAppData, KF_FLAG_DEFAULT};

use super::ledger::LedgerStoreError;

const PRODUCTION_DIRECTORY_NAME: &str = "openkakao-cli";
const MAX_PATH_UNITS: usize = 32_760;
const MAX_VOLUME_ROOT_UNITS: usize = 128;
const DRIVE_FIXED_VALUE: u32 = 3;

// The generated windows-rs wrapper discards a non-null output pointer when
// HRESULT is failure. This narrow declaration keeps ownership visible so the
// Shell allocation can be freed on every status path.
#[link(name = "shell32")]
extern "system" {
    #[link_name = "SHGetKnownFolderPath"]
    fn sh_get_known_folder_path_raw(
        rfid: *const GUID,
        flags: u32,
        token: HANDLE,
        path: *mut PWSTR,
    ) -> HRESULT;
}

pub(super) struct ValidatedLedgerLocation {
    directory: PathBuf,
    guard: LocationGuard,
}

impl ValidatedLedgerLocation {
    pub(super) fn directory(&self) -> &Path {
        &self.directory
    }

    pub(super) fn revalidate(&self) -> Result<(), LedgerStoreError> {
        match &self.guard {
            LocationGuard::Native {
                handle,
                canonical_base,
            } => {
                if !inspect_directory_handle(handle)?
                    || canonical_path_from_handle(handle)?.as_path() != canonical_base.as_path()
                {
                    return Err(LedgerStoreError::IoUncertain);
                }
                Ok(())
            }
            #[cfg(test)]
            LocationGuard::Synthetic => Ok(()),
        }
    }

    #[cfg(test)]
    pub(super) fn for_synthetic_parent(parent: &Path) -> Result<Self, LedgerStoreError> {
        validate_basic_path(parent)?;
        let directory = append_application_directory(parent)?;
        Ok(Self {
            directory,
            guard: LocationGuard::Synthetic,
        })
    }

    #[cfg(test)]
    pub(super) fn directory_for_test(&self) -> &Path {
        &self.directory
    }
}

enum LocationGuard {
    Native {
        handle: OwnedDirectoryHandle,
        canonical_base: PathBuf,
    },
    #[cfg(test)]
    Synthetic,
}

impl fmt::Debug for ValidatedLedgerLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedLedgerLocation")
            .field("directory", &"<redacted-validated>")
            .finish()
    }
}

trait NativeLedgerLocationApi {
    type BaseState;

    fn open_current_user_local_app_data(&mut self) -> Result<Self::BaseState, LedgerStoreError>;

    fn canonical_path(&mut self, state: &Self::BaseState) -> Result<PathBuf, LedgerStoreError>;

    fn is_fixed_local_volume(&mut self, path: &Path) -> Result<bool, LedgerStoreError>;

    fn source_and_canonical_chains_are_reparse_free(
        &mut self,
        state: &Self::BaseState,
        canonical_path: &Path,
    ) -> Result<bool, LedgerStoreError>;

    fn revalidate_canonical_path(
        &mut self,
        state: &Self::BaseState,
        expected: &Path,
    ) -> Result<bool, LedgerStoreError>;

    fn retain_state(
        &mut self,
        state: Self::BaseState,
        canonical_base: &Path,
    ) -> Result<LocationGuard, LedgerStoreError>;
}

pub(super) fn resolve_production_ledger_location(
) -> Result<ValidatedLedgerLocation, LedgerStoreError> {
    resolve_with(&mut WindowsLedgerLocationApi)
}

fn resolve_with<A: NativeLedgerLocationApi>(
    api: &mut A,
) -> Result<ValidatedLedgerLocation, LedgerStoreError> {
    let state = guarded(|| api.open_current_user_local_app_data())?;
    let canonical = guarded(|| api.canonical_path(&state))?;
    validate_canonical_volume_path(&canonical)?;

    if !guarded(|| api.is_fixed_local_volume(&canonical))? {
        return Err(LedgerStoreError::AccessDenied);
    }
    if !guarded(|| api.source_and_canonical_chains_are_reparse_free(&state, &canonical))? {
        return Err(LedgerStoreError::AccessDenied);
    }
    if !guarded(|| api.revalidate_canonical_path(&state, &canonical))? {
        return Err(LedgerStoreError::IoUncertain);
    }

    let directory = append_application_directory(&canonical)?;
    let guard = guarded(|| api.retain_state(state, &canonical))?;
    let location = ValidatedLedgerLocation { directory, guard };
    location.revalidate()?;
    Ok(location)
}

fn guarded<T>(
    operation: impl FnOnce() -> Result<T, LedgerStoreError>,
) -> Result<T, LedgerStoreError> {
    catch_unwind(AssertUnwindSafe(operation)).map_err(|_| LedgerStoreError::IoUncertain)?
}

struct WindowsLedgerLocationApi;

struct KnownFolderState {
    handle: OwnedDirectoryHandle,
    source_path: PathBuf,
}

impl NativeLedgerLocationApi for WindowsLedgerLocationApi {
    type BaseState = KnownFolderState;

    fn open_current_user_local_app_data(&mut self) -> Result<Self::BaseState, LedgerStoreError> {
        let mut raw_path = PWSTR::null();
        // SAFETY: the GUID and out pointer are valid for the synchronous call;
        // a null token requests the current user's known folder. Any non-null
        // output is wrapped before the HRESULT is interpreted.
        let status = unsafe {
            sh_get_known_folder_path_raw(
                ptr::from_ref(&FOLDERID_LocalAppData),
                KF_FLAG_DEFAULT.0 as u32,
                HANDLE::default(),
                ptr::from_mut(&mut raw_path),
            )
        };
        let owned_path = if raw_path.0.is_null() {
            None
        } else {
            Some(OwnedKnownFolderPath(raw_path))
        };
        if status.is_err() {
            return Err(LedgerStoreError::IoUncertain);
        }
        let path = owned_path
            .as_ref()
            .ok_or(LedgerStoreError::IoUncertain)?
            .to_path_buf()?;
        validate_basic_path(&path)?;
        let handle = open_directory_no_follow(&path)?;
        if !inspect_directory_handle(&handle)? {
            return Err(LedgerStoreError::AccessDenied);
        }
        Ok(KnownFolderState {
            handle,
            source_path: path,
        })
    }

    fn canonical_path(&mut self, state: &Self::BaseState) -> Result<PathBuf, LedgerStoreError> {
        canonical_path_from_handle(&state.handle)
    }

    fn is_fixed_local_volume(&mut self, path: &Path) -> Result<bool, LedgerStoreError> {
        fixed_local_volume(path)
    }

    fn source_and_canonical_chains_are_reparse_free(
        &mut self,
        state: &Self::BaseState,
        canonical_path: &Path,
    ) -> Result<bool, LedgerStoreError> {
        Ok(path_chain_is_reparse_free(&state.source_path)?
            && path_chain_is_reparse_free(canonical_path)?)
    }

    fn revalidate_canonical_path(
        &mut self,
        state: &Self::BaseState,
        expected: &Path,
    ) -> Result<bool, LedgerStoreError> {
        if !inspect_directory_handle(&state.handle)? {
            return Ok(false);
        }
        Ok(canonical_path_from_handle(&state.handle)? == expected)
    }

    fn retain_state(
        &mut self,
        state: Self::BaseState,
        canonical_base: &Path,
    ) -> Result<LocationGuard, LedgerStoreError> {
        Ok(LocationGuard::Native {
            handle: state.handle,
            canonical_base: canonical_base.to_path_buf(),
        })
    }
}

struct OwnedKnownFolderPath(PWSTR);

impl OwnedKnownFolderPath {
    fn to_path_buf(&self) -> Result<PathBuf, LedgerStoreError> {
        if self.0 .0.is_null() {
            return Err(LedgerStoreError::IoUncertain);
        }
        let mut len = 0_usize;
        // SAFETY: SHGetKnownFolderPath documents a caller-owned,
        // NUL-terminated UTF-16 allocation on non-null output. The explicit
        // cap prevents accepting an oversized path; the OS allocation contract
        // is the basis for reading until its terminator.
        unsafe {
            while len < MAX_PATH_UNITS && *self.0 .0.add(len) != 0 {
                len += 1;
            }
        }
        if len == 0 || len == MAX_PATH_UNITS {
            return Err(LedgerStoreError::AccessDenied);
        }
        // SAFETY: the preceding scan established `len` initialized units in
        // the live Shell allocation, excluding the terminator.
        let units = unsafe { std::slice::from_raw_parts(self.0 .0, len) };
        Ok(PathBuf::from(OsString::from_wide(units)))
    }
}

impl Drop for OwnedKnownFolderPath {
    fn drop(&mut self) {
        if !self.0 .0.is_null() {
            // SAFETY: SHGetKnownFolderPath transfers this allocation to the
            // caller and requires CoTaskMemFree exactly once.
            unsafe { CoTaskMemFree(Some(self.0 .0.cast_const().cast::<c_void>())) };
            self.0 = PWSTR::null();
        }
    }
}

struct OwnedDirectoryHandle(HANDLE);

impl Drop for OwnedDirectoryHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: this wrapper owns one CreateFileW handle.
            let _ = unsafe { CloseHandle(self.0) };
            self.0 = HANDLE::default();
        }
    }
}

fn open_directory_no_follow(path: &Path) -> Result<OwnedDirectoryHandle, LedgerStoreError> {
    let wide = wide_path(path)?;
    // SAFETY: the path is bounded, absolute, and NUL terminated. The returned
    // handle is immediately owned, and OPEN_REPARSE_POINT prevents following
    // the final component.
    unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            share_all(),
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map(OwnedDirectoryHandle)
    .map_err(|_| LedgerStoreError::IoUncertain)
}

fn inspect_directory_handle(handle: &OwnedDirectoryHandle) -> Result<bool, LedgerStoreError> {
    // SAFETY: the wrapper owns a live handle for both synchronous queries.
    if unsafe { GetFileType(handle.0) } != FILE_TYPE_DISK {
        return Ok(false);
    }
    let mut tags = FILE_ATTRIBUTE_TAG_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            handle.0,
            FileAttributeTagInfo,
            ptr::from_mut(&mut tags).cast(),
            u32::try_from(size_of_val(&tags)).map_err(|_| LedgerStoreError::Unavailable)?,
        )
    }
    .map_err(|_| LedgerStoreError::IoUncertain)?;
    Ok(tags.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
        && tags.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0)
}

fn path_chain_is_reparse_free(path: &Path) -> Result<bool, LedgerStoreError> {
    let ancestors: Vec<&Path> = path
        .ancestors()
        .filter(|value| !value.as_os_str().is_empty())
        .collect();
    for ancestor in ancestors.into_iter().rev() {
        let handle = open_directory_no_follow(ancestor)?;
        if !inspect_directory_handle(&handle)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn canonical_path_from_handle(handle: &OwnedDirectoryHandle) -> Result<PathBuf, LedgerStoreError> {
    let flags = GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_GUID.0);
    // SAFETY: a zero-length output performs the documented size query against
    // the live directory handle.
    let required = unsafe { GetFinalPathNameByHandleW(handle.0, &mut [], flags) };
    let required = usize::try_from(required).map_err(|_| LedgerStoreError::IoUncertain)?;
    if required == 0 || required >= MAX_PATH_UNITS {
        return Err(LedgerStoreError::IoUncertain);
    }
    let mut buffer = vec![0_u16; required];
    // SAFETY: `buffer` is initialized and uniquely borrowed for the
    // synchronous call; its exact capacity came from the bounded size query.
    let written = unsafe { GetFinalPathNameByHandleW(handle.0, &mut buffer, flags) };
    let written = usize::try_from(written).map_err(|_| LedgerStoreError::IoUncertain)?;
    if written == 0 || written >= buffer.len() || buffer[written] != 0 {
        return Err(LedgerStoreError::IoUncertain);
    }
    buffer.truncate(written);
    if buffer.contains(&0) || !is_volume_guid_path(&buffer) {
        return Err(LedgerStoreError::AccessDenied);
    }
    let path = PathBuf::from(OsString::from_wide(&buffer));
    validate_basic_path(&path)?;
    Ok(path)
}

fn fixed_local_volume(path: &Path) -> Result<bool, LedgerStoreError> {
    let path_wide = wide_path(path)?;
    let expected_root = volume_guid_root(&path_wide[..path_wide.len() - 1])
        .ok_or(LedgerStoreError::AccessDenied)?;
    let mut root = vec![0_u16; MAX_VOLUME_ROOT_UNITS];
    // SAFETY: input and output are bounded NUL-terminated/initialized buffers.
    unsafe { GetVolumePathNameW(PCWSTR(path_wide.as_ptr()), &mut root) }
        .map_err(|_| LedgerStoreError::IoUncertain)?;
    let root_len = root
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(LedgerStoreError::IoUncertain)?;
    if root_len == 0 || !ascii_units_equal(&root[..root_len], expected_root) {
        return Ok(false);
    }
    // SAFETY: `root` is NUL terminated within the live allocation.
    Ok(unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) } == DRIVE_FIXED_VALUE)
}

fn append_application_directory(base: &Path) -> Result<PathBuf, LedgerStoreError> {
    if PRODUCTION_DIRECTORY_NAME.is_empty()
        || !PRODUCTION_DIRECTORY_NAME.is_ascii()
        || PRODUCTION_DIRECTORY_NAME
            .bytes()
            .any(|byte| matches!(byte, 0 | b'/' | b'\\' | b':'))
    {
        return Err(LedgerStoreError::Unavailable);
    }
    let directory = base.join(PRODUCTION_DIRECTORY_NAME);
    validate_basic_path(&directory)?;
    if directory.file_name() != Some(PRODUCTION_DIRECTORY_NAME.as_ref()) {
        return Err(LedgerStoreError::AccessDenied);
    }
    Ok(directory)
}

fn validate_canonical_volume_path(path: &Path) -> Result<(), LedgerStoreError> {
    validate_basic_path(path)?;
    let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if !is_volume_guid_path(&wide) {
        return Err(LedgerStoreError::AccessDenied);
    }
    Ok(())
}

fn validate_basic_path(path: &Path) -> Result<(), LedgerStoreError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(LedgerStoreError::AccessDenied);
    }
    let _ = wide_path(path)?;
    Ok(())
}

fn wide_path(path: &Path) -> Result<Vec<u16>, LedgerStoreError> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.is_empty() || wide.len() >= MAX_PATH_UNITS || wide.contains(&0) {
        return Err(LedgerStoreError::AccessDenied);
    }
    wide.push(0);
    Ok(wide)
}

fn is_volume_guid_path(units: &[u16]) -> bool {
    volume_guid_root(units).is_some()
}

fn volume_guid_root(units: &[u16]) -> Option<&[u16]> {
    let prefix: Vec<u16> = r"\\?\Volume{".encode_utf16().collect();
    if units.len() < prefix.len() + 38 || !ascii_units_equal(&units[..prefix.len()], &prefix) {
        return None;
    }
    let guid = &units[prefix.len()..prefix.len() + 36];
    for (index, unit) in guid.iter().copied().enumerate() {
        let valid = if matches!(index, 8 | 13 | 18 | 23) {
            unit == u16::from(b'-')
        } else {
            ascii_hex(unit)
        };
        if !valid {
            return None;
        }
    }
    let suffix = prefix.len() + 36;
    if units[suffix] != u16::from(b'}') || units[suffix + 1] != u16::from(b'\\') {
        return None;
    }
    Some(&units[..suffix + 2])
}

fn ascii_hex(unit: u16) -> bool {
    matches!(unit, 0x30..=0x39 | 0x41..=0x46 | 0x61..=0x66)
}

fn ascii_units_equal(left: &[u16], right: &[u16]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| ascii_lower(*left) == ascii_lower(*right))
}

fn ascii_lower(unit: u16) -> u16 {
    if (u16::from(b'A')..=u16::from(b'Z')).contains(&unit) {
        unit + u16::from(b'a' - b'A')
    } else {
        unit
    }
}

const fn share_all() -> FILE_SHARE_MODE {
    FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Step {
        Open,
        Canonical,
        Volume,
        Components,
        Revalidate,
        Retain,
    }

    struct FakeApi {
        canonical: PathBuf,
        volume_fixed: bool,
        components_safe: bool,
        revalidated: bool,
        error_at: Option<Step>,
        panic_at: Option<Step>,
        calls: Vec<Step>,
    }

    impl NativeLedgerLocationApi for FakeApi {
        type BaseState = u64;

        fn open_current_user_local_app_data(
            &mut self,
        ) -> Result<Self::BaseState, LedgerStoreError> {
            self.record(Step::Open)?;
            Ok(7)
        }

        fn canonical_path(&mut self, state: &Self::BaseState) -> Result<PathBuf, LedgerStoreError> {
            assert_eq!(*state, 7);
            self.record(Step::Canonical)?;
            Ok(self.canonical.clone())
        }

        fn is_fixed_local_volume(&mut self, _path: &Path) -> Result<bool, LedgerStoreError> {
            self.record(Step::Volume)?;
            Ok(self.volume_fixed)
        }

        fn source_and_canonical_chains_are_reparse_free(
            &mut self,
            state: &Self::BaseState,
            _canonical_path: &Path,
        ) -> Result<bool, LedgerStoreError> {
            assert_eq!(*state, 7);
            self.record(Step::Components)?;
            Ok(self.components_safe)
        }

        fn revalidate_canonical_path(
            &mut self,
            state: &Self::BaseState,
            _expected: &Path,
        ) -> Result<bool, LedgerStoreError> {
            assert_eq!(*state, 7);
            self.record(Step::Revalidate)?;
            Ok(self.revalidated)
        }

        fn retain_state(
            &mut self,
            state: Self::BaseState,
            _canonical_base: &Path,
        ) -> Result<LocationGuard, LedgerStoreError> {
            assert_eq!(state, 7);
            self.record(Step::Retain)?;
            Ok(LocationGuard::Synthetic)
        }
    }

    impl FakeApi {
        fn record(&mut self, step: Step) -> Result<(), LedgerStoreError> {
            self.calls.push(step);
            if self.panic_at == Some(step) {
                panic!("synthetic fixed panic");
            }
            if self.error_at == Some(step) {
                Err(LedgerStoreError::IoUncertain)
            } else {
                Ok(())
            }
        }
    }

    fn canonical() -> PathBuf {
        PathBuf::from(
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\Users\synthetic\AppData\Local",
        )
    }

    fn fake() -> FakeApi {
        FakeApi {
            canonical: canonical(),
            volume_fixed: true,
            components_safe: true,
            revalidated: true,
            error_at: None,
            panic_at: None,
            calls: Vec::new(),
        }
    }

    #[test]
    fn exact_location_requires_every_gate_in_order() {
        let mut api = fake();
        let location = resolve_with(&mut api).unwrap();
        assert_eq!(
            api.calls,
            [
                Step::Open,
                Step::Canonical,
                Step::Volume,
                Step::Components,
                Step::Revalidate,
                Step::Retain,
            ]
        );
        assert_eq!(
            location.directory.file_name(),
            Some(PRODUCTION_DIRECTORY_NAME.as_ref())
        );
    }

    #[test]
    fn native_errors_and_panics_are_content_free_uncertainty() {
        for step in [
            Step::Open,
            Step::Canonical,
            Step::Volume,
            Step::Components,
            Step::Revalidate,
            Step::Retain,
        ] {
            let mut error = fake();
            error.error_at = Some(step);
            assert_eq!(
                resolve_with(&mut error).unwrap_err(),
                LedgerStoreError::IoUncertain
            );

            let mut panic = fake();
            panic.panic_at = Some(step);
            assert_eq!(
                resolve_with(&mut panic).unwrap_err(),
                LedgerStoreError::IoUncertain
            );
        }
    }

    #[test]
    fn nonlocal_reparse_or_revalidation_uncertainty_stops_immediately() {
        let mut nonlocal = fake();
        nonlocal.volume_fixed = false;
        assert_eq!(
            resolve_with(&mut nonlocal).unwrap_err(),
            LedgerStoreError::AccessDenied
        );
        assert_eq!(nonlocal.calls, [Step::Open, Step::Canonical, Step::Volume]);

        let mut reparse = fake();
        reparse.components_safe = false;
        assert_eq!(
            resolve_with(&mut reparse).unwrap_err(),
            LedgerStoreError::AccessDenied
        );
        assert_eq!(
            reparse.calls,
            [Step::Open, Step::Canonical, Step::Volume, Step::Components]
        );

        let mut changed = fake();
        changed.revalidated = false;
        assert_eq!(
            resolve_with(&mut changed).unwrap_err(),
            LedgerStoreError::IoUncertain
        );
    }

    #[test]
    fn canonical_shape_is_volume_guid_absolute_and_parent_free() {
        for path in [
            PathBuf::from(r"C:\Users\synthetic\AppData\Local"),
            PathBuf::from(r"relative\Local"),
            PathBuf::from(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdeg}\Users\synthetic"),
            PathBuf::from(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}"),
            PathBuf::from(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\Users\..\Local"),
        ] {
            let mut api = fake();
            api.canonical = path;
            assert_eq!(
                resolve_with(&mut api).unwrap_err(),
                LedgerStoreError::AccessDenied
            );
            assert_eq!(api.calls, [Step::Open, Step::Canonical]);
        }
    }

    #[test]
    fn volume_guid_parser_and_root_comparison_are_exact() {
        let mixed = r"\\?\vOlUmE{01234567-89AB-cdef-0123-456789abcdef}\Users";
        let units: Vec<u16> = mixed.encode_utf16().collect();
        let root = volume_guid_root(&units).unwrap();
        let expected: Vec<u16> = r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\"
            .encode_utf16()
            .collect();
        assert!(ascii_units_equal(root, &expected));
        assert!(!is_volume_guid_path(
            &r"\\?\UNC\server\share".encode_utf16().collect::<Vec<_>>()
        ));
    }

    #[test]
    fn debug_and_failure_vocabulary_never_expose_a_path() {
        let canary = "PRIVATE_LOCALAPPDATA_CANARY";
        let location = ValidatedLedgerLocation {
            directory: PathBuf::from(format!(r"C:\{canary}")),
            guard: LocationGuard::Synthetic,
        };
        let rendered = format!("{location:?} {:?}", LedgerStoreError::IoUncertain);
        assert!(!rendered.contains(canary));
        assert!(rendered.contains("<redacted-validated>"));
    }

    #[test]
    fn retained_native_guard_revalidates_only_a_synthetic_directory_handle() {
        let parent = tempfile::tempdir().unwrap();
        let handle = open_directory_no_follow(parent.path()).unwrap();
        assert!(inspect_directory_handle(&handle).unwrap());
        let canonical_base = canonical_path_from_handle(&handle).unwrap();
        validate_canonical_volume_path(&canonical_base).unwrap();
        let directory = append_application_directory(&canonical_base).unwrap();
        let location = ValidatedLedgerLocation {
            directory,
            guard: LocationGuard::Native {
                handle,
                canonical_base,
            },
        };
        location.revalidate().unwrap();

        let handle = open_directory_no_follow(parent.path()).unwrap();
        let location = ValidatedLedgerLocation {
            directory: append_application_directory(parent.path()).unwrap(),
            guard: LocationGuard::Native {
                handle,
                canonical_base: PathBuf::from(
                    r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\changed",
                ),
            },
        };
        assert_eq!(
            location.revalidate().unwrap_err(),
            LedgerStoreError::IoUncertain
        );
    }

    #[test]
    fn fixed_application_component_and_bounds_are_closed() {
        assert_eq!(PRODUCTION_DIRECTORY_NAME, "openkakao-cli");
        assert!(PRODUCTION_DIRECTORY_NAME.is_ascii());
        assert_eq!(DRIVE_FIXED_VALUE, 3);
        let overlong = format!(r"C:\{}", "a".repeat(MAX_PATH_UNITS));
        assert_eq!(
            ValidatedLedgerLocation::for_synthetic_parent(Path::new(&overlong)).unwrap_err(),
            LedgerStoreError::AccessDenied
        );
    }
}
