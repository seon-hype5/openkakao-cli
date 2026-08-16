//! Windows DPAPI/ACL storage implementation for the durable mutation ledger.
//!
//! A disconnected constructor can now consume the separately validated
//! current-user LocalAppData location. Production deliberately never calls it;
//! tests create the same store shape only below an explicit synthetic parent.
//! This keeps native ownership and durability compiled without touching a user
//! application, the real LocalAppData directory, or the mutation path.

#![cfg_attr(not(test), allow(dead_code))]

use std::ffi::{c_void, OsStr, OsString};
use std::mem::{size_of, size_of_val};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};
use std::ptr;

use rand::{rngs::OsRng, RngCore};
use windows::core::{BOOL, PCWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND,
    ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_FILES, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
    GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL,
};
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use windows::Win32::Security::{
    AclSizeInformation, AddAccessAllowedAceEx, CopySid, EqualSid, GetAce, GetAclInformation,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorLength,
    GetSecurityDescriptorOwner, GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor,
    IsValidAcl, IsValidSecurityDescriptor, IsValidSid, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, TokenUser, ACCESS_ALLOWED_ACE, ACL,
    ACL_REVISION, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
    OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SE_DACL_PROTECTED, SE_SELF_RELATIVE, TOKEN_QUERY,
    TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, DeleteFileW, FileAttributeTagInfo, FindClose, FindExInfoBasic,
    FindExSearchNameMatch, FindFirstFileExW, FindNextFileW, FlushFileBuffers, GetFileAttributesW,
    GetFileInformationByHandleEx, GetFileSizeEx, GetFileType, MoveFileExW, ReadFile, WriteFile,
    CREATE_NEW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, FIND_FIRST_EX_FLAGS,
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, OPEN_EXISTING, READ_CONTROL,
    WIN32_FIND_DATAW,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use zeroize::{Zeroize, Zeroizing};

use super::ledger::{
    decode_record, encode_record, DurableLedgerStore, LedgerRecord, LedgerStoreError,
    ENCODED_RECORD_LEN,
};
use super::ledger_location::{resolve_production_ledger_location, ValidatedLedgerLocation};

const LEDGER_FILE_NAME: &str = "mutation-ledger.v1";
const SYNTHETIC_DIRECTORY_NAME: &str = "openkakao-ledger-synthetic";
const TEMP_PREFIX: &str = "mutation-ledger.tmp.";
const TOMBSTONE_PREFIX: &str = "mutation-ledger.tomb.";
const MAX_PATH_UNITS: usize = 32_760;
const MAX_PROTECTED_RECORD_LEN: usize = 64 * 1024;
const MAX_SECURITY_DESCRIPTOR_LEN: usize = 64 * 1024;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const ACCESS_ALLOWED_ACE_TYPE_VALUE: u8 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FaultPoint {
    BeforeTempCreate,
    AfterTempCreate,
    AfterTempWrite,
    AfterTempFlush,
    AfterTempVerify,
    AfterInstallRename,
    AfterInstallVerify,
    AfterTombstoneRename,
    AfterTombstoneDelete,
}

pub(super) struct WindowsLedgerStore {
    directory: PathBuf,
    owner: OwnedSid,
    location: Option<ValidatedLedgerLocation>,
    #[cfg(test)]
    fault: Option<FaultPoint>,
}

impl WindowsLedgerStore {
    /// Deliberately disconnected from `NativeMutationPort`. Merely compiling
    /// this constructor does not resolve or create the real LocalAppData path.
    #[allow(dead_code)]
    fn open_disconnected_production() -> Result<Self, LedgerStoreError> {
        Self::open_validated(resolve_production_ledger_location()?)
    }

    fn open_validated(location: ValidatedLedgerLocation) -> Result<Self, LedgerStoreError> {
        location.revalidate()?;
        let directory = location.directory().to_path_buf();
        validate_absolute_path(&directory)?;
        let owner = OwnedSid::current_user()?;
        create_secure_directory_if_absent(&directory, &owner)?;
        location.revalidate()?;
        let store = Self {
            directory,
            owner,
            location: Some(location),
            #[cfg(test)]
            fault: None,
        };
        store.verify_directory()?;
        store.ensure_known_directory_entries()?;
        Ok(store)
    }

    #[cfg(test)]
    fn create_synthetic(parent: &Path) -> Result<Self, LedgerStoreError> {
        let directory = parent.join(SYNTHETIC_DIRECTORY_NAME);
        validate_absolute_path(&directory)?;
        let owner = OwnedSid::current_user()?;
        create_secure_directory(&directory, &owner)?;
        let store = Self {
            directory,
            owner,
            location: None,
            #[cfg(test)]
            fault: None,
        };
        store.verify_directory()?;
        store.ensure_known_directory_entries()?;
        Ok(store)
    }

    #[cfg(test)]
    fn reopen_synthetic(directory: PathBuf) -> Result<Self, LedgerStoreError> {
        validate_absolute_path(&directory)?;
        if directory.file_name() != Some(OsStr::new(SYNTHETIC_DIRECTORY_NAME)) {
            return Err(LedgerStoreError::AccessDenied);
        }
        let owner = OwnedSid::current_user()?;
        let store = Self {
            directory,
            owner,
            location: None,
            fault: None,
        };
        store.verify_directory()?;
        Ok(store)
    }

    #[cfg(test)]
    fn inject_once(&mut self, point: FaultPoint) {
        self.fault = Some(point);
    }

    fn injected_failure(&mut self, point: FaultPoint) -> Result<(), LedgerStoreError> {
        #[cfg(test)]
        if self.fault == Some(point) {
            self.fault = None;
            return Err(LedgerStoreError::IoUncertain);
        }
        let _ = point;
        Ok(())
    }

    fn ledger_path(&self) -> PathBuf {
        self.directory.join(LEDGER_FILE_NAME)
    }

    fn verify_directory(&self) -> Result<(), LedgerStoreError> {
        if let Some(location) = &self.location {
            location.revalidate()?;
        }
        let handle = open_existing(&self.directory, true, directory_access(), share_all())?;
        verify_handle(&handle, true, &self.owner, directory_ace_flags())?;
        if let Some(location) = &self.location {
            location.revalidate()?;
        }
        Ok(())
    }

    fn ensure_known_directory_entries(&self) -> Result<bool, LedgerStoreError> {
        self.verify_directory()?;
        let pattern = self.directory.join("*");
        let pattern_wide = wide_path(&pattern)?;
        let mut data = WIN32_FIND_DATAW::default();
        // SAFETY: the pattern is a bounded, NUL-terminated absolute path;
        // `data` is a valid out buffer for the synchronous call.
        let handle = unsafe {
            FindFirstFileExW(
                PCWSTR(pattern_wide.as_ptr()),
                FindExInfoBasic,
                ptr::from_mut(&mut data).cast(),
                FindExSearchNameMatch,
                None,
                FIND_FIRST_EX_FLAGS(0),
            )
        }
        .map_err(|_| LedgerStoreError::IoUncertain)?;
        let find = OwnedFindHandle(handle);
        let mut ledger_present = false;
        loop {
            let name = bounded_find_name(&data)?;
            if name != OsStr::new(".") && name != OsStr::new("..") {
                if name == OsStr::new(LEDGER_FILE_NAME) && !ledger_present {
                    ledger_present = true;
                } else {
                    return Err(LedgerStoreError::IoUncertain);
                }
            }

            // SAFETY: `find` owns a live enumeration handle and `data` remains
            // a valid out buffer for the duration of the call.
            match unsafe { FindNextFileW(find.0, ptr::from_mut(&mut data)) } {
                Ok(()) => {}
                Err(_) if unsafe { GetLastError() } == ERROR_NO_MORE_FILES => break,
                Err(_) => return Err(LedgerStoreError::IoUncertain),
            }
        }
        Ok(ledger_present)
    }

    fn read_record_path(&self, path: &Path) -> Result<LedgerRecord, LedgerStoreError> {
        let handle = open_existing(path, false, file_read_access(), FILE_SHARE_MODE(0))?;
        verify_handle(&handle, false, &self.owner, 0)?;

        let mut file_len = 0_i64;
        // SAFETY: `handle` is a live disk-file handle and the out pointer is
        // valid for this synchronous call.
        unsafe { GetFileSizeEx(handle.0, ptr::from_mut(&mut file_len)) }
            .map_err(|_| LedgerStoreError::IoUncertain)?;
        let file_len = usize::try_from(file_len).map_err(|_| LedgerStoreError::InvalidRecord)?;
        if file_len == 0 || file_len > MAX_PROTECTED_RECORD_LEN {
            return Err(LedgerStoreError::InvalidRecord);
        }

        let mut protected = Zeroizing::new(vec![0_u8; file_len]);
        let mut read = 0_u32;
        // SAFETY: the buffer is initialized and uniquely borrowed; the handle
        // is synchronous and exclusive, and the byte-count out pointer lives
        // through the call.
        unsafe {
            ReadFile(
                handle.0,
                Some(protected.as_mut_slice()),
                Some(ptr::from_mut(&mut read)),
                None,
            )
        }
        .map_err(|_| LedgerStoreError::IoUncertain)?;
        if usize::try_from(read).ok() != Some(file_len) {
            return Err(LedgerStoreError::IoUncertain);
        }

        let mut trailing = [0_u8; 1];
        let mut trailing_read = 0_u32;
        // SAFETY: this bounded read proves the exclusive file did not contain
        // bytes beyond the size observed before allocation.
        unsafe {
            ReadFile(
                handle.0,
                Some(&mut trailing),
                Some(ptr::from_mut(&mut trailing_read)),
                None,
            )
        }
        .map_err(|_| LedgerStoreError::IoUncertain)?;
        if trailing_read != 0 {
            return Err(LedgerStoreError::InvalidRecord);
        }
        dpapi_unprotect_and_decode(&protected)
    }

    fn write_temp(&mut self, path: &Path, next: LedgerRecord) -> Result<(), LedgerStoreError> {
        let mut descriptor = OwnedSecurityDescriptor::new(&self.owner, 0)?;
        let attributes = descriptor.attributes();
        let path_wide = wide_path(path)?;
        // SAFETY: path and security descriptor storage outlive this synchronous
        // call. CREATE_NEW plus no sharing gives unique ownership.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path_wide.as_ptr()),
                file_write_access(),
                FILE_SHARE_MODE(0),
                Some(ptr::from_ref(&attributes)),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
                None,
            )
        }
        .map(OwnedHandle)
        .map_err(|_| LedgerStoreError::IoUncertain)?;
        verify_handle(&handle, false, &self.owner, 0)?;
        self.injected_failure(FaultPoint::AfterTempCreate)?;

        let mut encoded = encode_record(next)?;
        let protected = dpapi_protect(&encoded);
        encoded.zeroize();
        let protected = protected?;
        if protected.is_empty() || protected.len() > MAX_PROTECTED_RECORD_LEN {
            return Err(LedgerStoreError::IoUncertain);
        }
        let mut written = 0_u32;
        // SAFETY: the protected buffer and byte-count pointer remain valid;
        // the file handle is synchronous and exclusively owned.
        unsafe {
            WriteFile(
                handle.0,
                Some(protected.as_slice()),
                Some(ptr::from_mut(&mut written)),
                None,
            )
        }
        .map_err(|_| LedgerStoreError::IoUncertain)?;
        if usize::try_from(written).ok() != Some(protected.len()) {
            return Err(LedgerStoreError::IoUncertain);
        }
        self.injected_failure(FaultPoint::AfterTempWrite)?;
        // SAFETY: the handle was opened with write access and write-through;
        // this call completes before the handle is closed.
        unsafe { FlushFileBuffers(handle.0) }.map_err(|_| LedgerStoreError::IoUncertain)?;
        self.injected_failure(FaultPoint::AfterTempFlush)?;
        drop(handle);
        if self.read_record_path(path)? != next {
            return Err(LedgerStoreError::IoUncertain);
        }
        Ok(())
    }

    fn random_artifact_path(&self, prefix: &str) -> Result<PathBuf, LedgerStoreError> {
        let mut random = [0_u8; 16];
        OsRng.fill_bytes(&mut random);
        if random == [0; 16] {
            return Err(LedgerStoreError::Unavailable);
        }
        Ok(self
            .directory
            .join(format!("{prefix}{}", hex::encode(random))))
    }
}

impl DurableLedgerStore for WindowsLedgerStore {
    fn load(&mut self) -> Result<Option<LedgerRecord>, LedgerStoreError> {
        if !self.ensure_known_directory_entries()? {
            return Ok(None);
        }
        self.read_record_path(&self.ledger_path()).map(Some)
    }

    fn durable_replace(
        &mut self,
        expected: Option<LedgerRecord>,
        next: LedgerRecord,
    ) -> Result<(), LedgerStoreError> {
        if self.load()? != expected {
            return Err(LedgerStoreError::IoUncertain);
        }
        self.injected_failure(FaultPoint::BeforeTempCreate)?;
        let temporary = self.random_artifact_path(TEMP_PREFIX)?;
        self.write_temp(&temporary, next)?;
        self.injected_failure(FaultPoint::AfterTempVerify)?;
        let temporary_wide = wide_path(&temporary)?;
        let ledger = self.ledger_path();
        let ledger_wide = wide_path(&ledger)?;
        // SAFETY: both paths are bounded and NUL-terminated, reside in the
        // same verified directory, and MOVEFILE_COPY_ALLOWED is absent.
        unsafe {
            MoveFileExW(
                PCWSTR(temporary_wide.as_ptr()),
                PCWSTR(ledger_wide.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
        .map_err(|_| LedgerStoreError::IoUncertain)?;
        self.injected_failure(FaultPoint::AfterInstallRename)?;
        if self.read_record_path(&ledger)? != next {
            return Err(LedgerStoreError::IoUncertain);
        }
        self.injected_failure(FaultPoint::AfterInstallVerify)?;
        Ok(())
    }

    fn durable_remove(&mut self, expected: LedgerRecord) -> Result<(), LedgerStoreError> {
        if self.load()? != Some(expected) {
            return Err(LedgerStoreError::IoUncertain);
        }
        let ledger = self.ledger_path();
        let tombstone = self.random_artifact_path(TOMBSTONE_PREFIX)?;
        let ledger_wide = wide_path(&ledger)?;
        let tombstone_wide = wide_path(&tombstone)?;
        // SAFETY: both paths are bounded and in the same verified directory;
        // the random destination must not already exist and copying is absent.
        unsafe {
            MoveFileExW(
                PCWSTR(ledger_wide.as_ptr()),
                PCWSTR(tombstone_wide.as_ptr()),
                MOVEFILE_WRITE_THROUGH,
            )
        }
        .map_err(|_| LedgerStoreError::IoUncertain)?;
        self.injected_failure(FaultPoint::AfterTombstoneRename)?;
        if path_exists(&ledger)? {
            return Err(LedgerStoreError::IoUncertain);
        }
        // SAFETY: this exact tombstone was produced by the successful rename;
        // it contains only a protected content-free record.
        unsafe { DeleteFileW(PCWSTR(tombstone_wide.as_ptr())) }
            .map_err(|_| LedgerStoreError::IoUncertain)?;
        self.injected_failure(FaultPoint::AfterTombstoneDelete)?;
        if path_exists(&tombstone)? || self.ensure_known_directory_entries()? {
            return Err(LedgerStoreError::IoUncertain);
        }
        Ok(())
    }
}

fn create_secure_directory(path: &Path, owner: &OwnedSid) -> Result<(), LedgerStoreError> {
    let mut descriptor = OwnedSecurityDescriptor::new(owner, directory_ace_flags())?;
    let attributes = descriptor.attributes();
    let path_wide = wide_path(path)?;
    // SAFETY: path and descriptor pointers remain valid for this synchronous
    // call; the synthetic parent is unique, so an existing child is refusal.
    unsafe { CreateDirectoryW(PCWSTR(path_wide.as_ptr()), Some(ptr::from_ref(&attributes))) }
        .map_err(|_| LedgerStoreError::IoUncertain)
}

fn create_secure_directory_if_absent(
    path: &Path,
    owner: &OwnedSid,
) -> Result<(), LedgerStoreError> {
    let mut descriptor = OwnedSecurityDescriptor::new(owner, directory_ace_flags())?;
    let attributes = descriptor.attributes();
    let path_wide = wide_path(path)?;
    // SAFETY: path and descriptor pointers remain valid for the synchronous
    // call. An already-existing entry is accepted only provisionally; the
    // caller immediately reopens it without following reparse points and
    // proves its type, owner, and exact protected DACL.
    match unsafe { CreateDirectoryW(PCWSTR(path_wide.as_ptr()), Some(ptr::from_ref(&attributes))) }
    {
        Ok(()) => Ok(()),
        Err(_) if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS => Ok(()),
        Err(_) => Err(LedgerStoreError::IoUncertain),
    }
}

fn open_existing(
    path: &Path,
    directory: bool,
    access: u32,
    share: FILE_SHARE_MODE,
) -> Result<OwnedHandle, LedgerStoreError> {
    let path_wide = wide_path(path)?;
    let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
    if directory {
        flags |= FILE_FLAG_BACKUP_SEMANTICS;
    } else {
        flags |= FILE_ATTRIBUTE_NORMAL;
    }
    // SAFETY: path is a bounded NUL-terminated absolute path. No security
    // descriptor is needed for OPEN_EXISTING and the returned handle is owned.
    unsafe {
        CreateFileW(
            PCWSTR(path_wide.as_ptr()),
            access,
            share,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    }
    .map(OwnedHandle)
    .map_err(|_| LedgerStoreError::IoUncertain)
}

fn verify_handle(
    handle: &OwnedHandle,
    directory: bool,
    owner: &OwnedSid,
    expected_ace_flags: u8,
) -> Result<(), LedgerStoreError> {
    // SAFETY: the owned handle is live for each synchronous metadata query.
    if unsafe { GetFileType(handle.0) } != FILE_TYPE_DISK {
        return Err(LedgerStoreError::AccessDenied);
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
    let is_directory = tags.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
    let is_reparse = tags.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0;
    if is_reparse || is_directory != directory {
        return Err(LedgerStoreError::AccessDenied);
    }
    verify_handle_security(handle.0, owner, expected_ace_flags)
}

fn verify_handle_security(
    handle: HANDLE,
    expected_owner: &OwnedSid,
    expected_ace_flags: u8,
) -> Result<(), LedgerStoreError> {
    let mut owner = PSID::default();
    let mut dacl = ptr::null_mut::<ACL>();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: all out pointers are writable. On success, owner and DACL borrow
    // the returned descriptor allocation, which is immediately wrapped.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(ptr::from_mut(&mut owner)),
            None,
            Some(ptr::from_mut(&mut dacl)),
            None,
            Some(ptr::from_mut(&mut descriptor)),
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_invalid() {
        return Err(LedgerStoreError::AccessDenied);
    }
    let descriptor = OwnedLocalDescriptor(descriptor);
    // SAFETY: GetSecurityInfo returned this descriptor and the wrapper keeps it
    // alive until all borrowed pointer validation has completed.
    if !unsafe { IsValidSecurityDescriptor(descriptor.0) }.as_bool() {
        return Err(LedgerStoreError::AccessDenied);
    }
    let descriptor_len = usize::try_from(unsafe { GetSecurityDescriptorLength(descriptor.0) })
        .map_err(|_| LedgerStoreError::AccessDenied)?;
    if descriptor_len < size_of::<SECURITY_DESCRIPTOR>()
        || descriptor_len > MAX_SECURITY_DESCRIPTOR_LEN
    {
        return Err(LedgerStoreError::AccessDenied);
    }
    let base = descriptor.0 .0.cast_const().cast::<u8>();

    let mut control = 0_u16;
    let mut revision = 0_u32;
    unsafe {
        GetSecurityDescriptorControl(
            descriptor.0,
            ptr::from_mut(&mut control),
            ptr::from_mut(&mut revision),
        )
    }
    .map_err(|_| LedgerStoreError::AccessDenied)?;
    if revision != SECURITY_DESCRIPTOR_REVISION
        || control & SE_SELF_RELATIVE.0 == 0
        || control & SE_DACL_PROTECTED.0 == 0
    {
        return Err(LedgerStoreError::AccessDenied);
    }

    let mut queried_owner = PSID::default();
    let mut owner_defaulted = BOOL::default();
    unsafe {
        GetSecurityDescriptorOwner(
            descriptor.0,
            ptr::from_mut(&mut queried_owner),
            ptr::from_mut(&mut owner_defaulted),
        )
    }
    .map_err(|_| LedgerStoreError::AccessDenied)?;
    if owner_defaulted.as_bool()
        || queried_owner != owner
        || validated_sid_len(base, descriptor_len, queried_owner)? != expected_owner.len
        || unsafe { EqualSid(queried_owner, expected_owner.as_psid()) }.is_err()
    {
        return Err(LedgerStoreError::AccessDenied);
    }

    let mut dacl_present = BOOL::default();
    let mut queried_dacl = ptr::null_mut::<ACL>();
    let mut dacl_defaulted = BOOL::default();
    unsafe {
        GetSecurityDescriptorDacl(
            descriptor.0,
            ptr::from_mut(&mut dacl_present),
            ptr::from_mut(&mut queried_dacl),
            ptr::from_mut(&mut dacl_defaulted),
        )
    }
    .map_err(|_| LedgerStoreError::AccessDenied)?;
    if !dacl_present.as_bool()
        || dacl_defaulted.as_bool()
        || queried_dacl.is_null()
        || queried_dacl != dacl
    {
        return Err(LedgerStoreError::AccessDenied);
    }
    validate_exact_dacl(
        base,
        descriptor_len,
        queried_dacl,
        expected_owner,
        expected_ace_flags,
    )
}

fn validate_exact_dacl(
    descriptor_base: *const u8,
    descriptor_len: usize,
    dacl: *mut ACL,
    owner: &OwnedSid,
    expected_flags: u8,
) -> Result<(), LedgerStoreError> {
    if !range_contains(
        descriptor_base,
        descriptor_len,
        dacl.cast_const().cast(),
        size_of::<ACL>(),
    ) {
        return Err(LedgerStoreError::AccessDenied);
    }
    // SAFETY: the fixed ACL header lies within the returned descriptor.
    let acl_header = unsafe { ptr::read_unaligned(dacl) };
    let acl_len = usize::from(acl_header.AclSize);
    if acl_len < size_of::<ACL>()
        || !range_contains(
            descriptor_base,
            descriptor_len,
            dacl.cast_const().cast(),
            acl_len,
        )
        || !unsafe { IsValidAcl(dacl) }.as_bool()
    {
        return Err(LedgerStoreError::AccessDenied);
    }
    let mut info = ACL_SIZE_INFORMATION::default();
    unsafe {
        GetAclInformation(
            dacl,
            ptr::from_mut(&mut info).cast(),
            u32::try_from(size_of_val(&info)).map_err(|_| LedgerStoreError::Unavailable)?,
            AclSizeInformation,
        )
    }
    .map_err(|_| LedgerStoreError::AccessDenied)?;
    if info.AceCount != 1 {
        return Err(LedgerStoreError::AccessDenied);
    }
    let mut ace_ptr = ptr::null_mut::<c_void>();
    unsafe { GetAce(dacl, 0, ptr::from_mut(&mut ace_ptr)) }
        .map_err(|_| LedgerStoreError::AccessDenied)?;
    if !range_contains(
        descriptor_base,
        descriptor_len,
        ace_ptr.cast_const().cast(),
        size_of::<ACCESS_ALLOWED_ACE>(),
    ) {
        return Err(LedgerStoreError::AccessDenied);
    }
    // SAFETY: the minimum ACCESS_ALLOWED_ACE lies in the validated descriptor.
    let ace = unsafe { ptr::read_unaligned(ace_ptr.cast::<ACCESS_ALLOWED_ACE>()) };
    if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE_VALUE
        || ace.Header.AceFlags != expected_flags
        || ace.Mask != FILE_ALL_ACCESS.0
    {
        return Err(LedgerStoreError::AccessDenied);
    }
    let ace_len = usize::from(ace.Header.AceSize);
    let sid_offset = size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>();
    if ace_len < sid_offset
        || !range_contains(
            descriptor_base,
            descriptor_len,
            ace_ptr.cast_const().cast(),
            ace_len,
        )
    {
        return Err(LedgerStoreError::AccessDenied);
    }
    // SAFETY: the ACE and SID offset were bounded above.
    let sid = PSID(unsafe { ace_ptr.cast::<u8>().add(sid_offset) }.cast());
    let sid_len = validated_sid_len(descriptor_base, descriptor_len, sid)?;
    let expected_ace_len = sid_offset
        .checked_add(sid_len)
        .ok_or(LedgerStoreError::AccessDenied)?;
    if ace_len != expected_ace_len
        || sid_len != owner.len
        || unsafe { EqualSid(sid, owner.as_psid()) }.is_err()
    {
        return Err(LedgerStoreError::AccessDenied);
    }
    Ok(())
}

struct OwnedSid {
    storage: AlignedBuffer,
    len: usize,
}

impl OwnedSid {
    fn current_user() -> Result<Self, LedgerStoreError> {
        let mut token = HANDLE::default();
        // SAFETY: the current-process pseudo-handle is valid and `token` is a
        // writable out parameter. The returned real token handle is owned.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, ptr::from_mut(&mut token)) }
            .map_err(|_| LedgerStoreError::AccessDenied)?;
        let token = OwnedHandle(token);

        let mut required = 0_u32;
        // SAFETY: the zero-length probe has a null data pointer and a valid
        // required-length out parameter.
        let probe = unsafe {
            GetTokenInformation(token.0, TokenUser, None, 0, ptr::from_mut(&mut required))
        };
        if probe.is_ok()
            || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
            || usize::try_from(required)
                .ok()
                .filter(|v| *v >= size_of::<TOKEN_USER>())
                .filter(|v| *v <= MAX_SECURITY_DESCRIPTOR_LEN)
                .is_none()
        {
            return Err(LedgerStoreError::AccessDenied);
        }
        let required_usize =
            usize::try_from(required).map_err(|_| LedgerStoreError::Unavailable)?;
        let mut token_info = AlignedBuffer::zeroed(required_usize)?;
        let mut returned = required;
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                Some(token_info.as_mut_void()),
                required,
                ptr::from_mut(&mut returned),
            )
        }
        .map_err(|_| LedgerStoreError::AccessDenied)?;
        if returned == 0 || returned > required {
            return Err(LedgerStoreError::AccessDenied);
        }
        let returned = usize::try_from(returned).map_err(|_| LedgerStoreError::Unavailable)?;
        // SAFETY: storage is usize-aligned and contains at least TOKEN_USER.
        let token_user = unsafe { ptr::read(token_info.as_ptr().cast::<TOKEN_USER>()) };
        let sid_len = validated_sid_len(token_info.as_ptr(), returned, token_user.User.Sid)?;
        let mut storage = AlignedBuffer::zeroed(sid_len)?;
        let destination = PSID(storage.as_mut_void());
        unsafe {
            CopySid(
                u32::try_from(sid_len).map_err(|_| LedgerStoreError::Unavailable)?,
                destination,
                token_user.User.Sid,
            )
        }
        .map_err(|_| LedgerStoreError::AccessDenied)?;
        if !unsafe { IsValidSid(destination) }.as_bool() {
            return Err(LedgerStoreError::AccessDenied);
        }
        Ok(Self {
            storage,
            len: sid_len,
        })
    }

    fn as_psid(&self) -> PSID {
        PSID(self.storage.as_ptr().cast_mut().cast())
    }
}

struct OwnedSecurityDescriptor {
    descriptor: SECURITY_DESCRIPTOR,
    acl: AlignedBuffer,
}

impl OwnedSecurityDescriptor {
    fn new(owner: &OwnedSid, ace_flags: u8) -> Result<Self, LedgerStoreError> {
        let sid_offset = size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>();
        let ace_len = sid_offset
            .checked_add(owner.len)
            .ok_or(LedgerStoreError::Unavailable)?;
        let acl_len = size_of::<ACL>()
            .checked_add(ace_len)
            .ok_or(LedgerStoreError::Unavailable)?;
        let mut value = Self {
            descriptor: SECURITY_DESCRIPTOR::default(),
            acl: AlignedBuffer::zeroed(acl_len)?,
        };
        let descriptor =
            PSECURITY_DESCRIPTOR(ptr::from_mut(&mut value.descriptor).cast::<c_void>());
        let acl = value.acl.as_mut_ptr().cast::<ACL>();
        unsafe { InitializeSecurityDescriptor(descriptor, SECURITY_DESCRIPTOR_REVISION) }
            .map_err(|_| LedgerStoreError::Unavailable)?;
        unsafe {
            InitializeAcl(
                acl,
                u32::try_from(acl_len).map_err(|_| LedgerStoreError::Unavailable)?,
                ACL_REVISION,
            )
        }
        .map_err(|_| LedgerStoreError::Unavailable)?;
        unsafe {
            AddAccessAllowedAceEx(
                acl,
                ACL_REVISION,
                windows::Win32::Security::ACE_FLAGS(u32::from(ace_flags)),
                FILE_ALL_ACCESS.0,
                owner.as_psid(),
            )
        }
        .map_err(|_| LedgerStoreError::Unavailable)?;
        unsafe { SetSecurityDescriptorOwner(descriptor, Some(owner.as_psid()), false) }
            .map_err(|_| LedgerStoreError::Unavailable)?;
        unsafe { SetSecurityDescriptorDacl(descriptor, true, Some(acl), false) }
            .map_err(|_| LedgerStoreError::Unavailable)?;
        unsafe { SetSecurityDescriptorControl(descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED) }
            .map_err(|_| LedgerStoreError::Unavailable)?;
        Ok(value)
    }

    fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
                .expect("SECURITY_ATTRIBUTES size fits u32"),
            lpSecurityDescriptor: ptr::from_mut(&mut self.descriptor).cast(),
            bInheritHandle: false.into(),
        }
    }
}

struct AlignedBuffer {
    words: Vec<usize>,
    len: usize,
}

impl AlignedBuffer {
    fn zeroed(len: usize) -> Result<Self, LedgerStoreError> {
        if len == 0 || len > MAX_SECURITY_DESCRIPTOR_LEN {
            return Err(LedgerStoreError::Unavailable);
        }
        let word = size_of::<usize>();
        let count = len
            .checked_add(word - 1)
            .ok_or(LedgerStoreError::Unavailable)?
            / word;
        Ok(Self {
            words: vec![0; count],
            len,
        })
    }

    fn as_ptr(&self) -> *const u8 {
        self.words.as_ptr().cast()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.words.as_mut_ptr().cast()
    }

    fn as_mut_void(&mut self) -> *mut c_void {
        self.as_mut_ptr().cast()
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        self.words.zeroize();
        self.len = 0;
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the wrapper is created only from an owned CreateFile or
        // OpenProcessToken result and therefore closes exactly once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

struct OwnedFindHandle(HANDLE);

impl Drop for OwnedFindHandle {
    fn drop(&mut self) {
        // SAFETY: FindFirstFileExW returned this enumeration handle; FindClose
        // is the required (and only) release operation.
        unsafe {
            let _ = FindClose(self.0);
        }
    }
}

struct OwnedLocalDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for OwnedLocalDescriptor {
    fn drop(&mut self) {
        // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc.
        unsafe {
            let _ = windows::Win32::Foundation::LocalFree(Some(HLOCAL(self.0 .0)));
        }
    }
}

struct OwnedDpapiBuffer {
    pointer: *mut u8,
    len: usize,
}

impl OwnedDpapiBuffer {
    fn from_blob(blob: CRYPT_INTEGER_BLOB) -> Result<Self, LedgerStoreError> {
        let len = usize::try_from(blob.cbData).map_err(|_| LedgerStoreError::InvalidRecord)?;
        if blob.pbData.is_null() || len == 0 || len > MAX_PROTECTED_RECORD_LEN {
            if !blob.pbData.is_null() {
                // SAFETY: this constructor is called only after DPAPI success,
                // so its non-null pointer owns `cbData` initialized bytes even
                // when the application bound rejects that length.
                unsafe {
                    ptr::write_bytes(blob.pbData, 0, len);
                    let _ = windows::Win32::Foundation::LocalFree(Some(HLOCAL(blob.pbData.cast())));
                }
            }
            return Err(LedgerStoreError::InvalidRecord);
        }
        Ok(Self {
            pointer: blob.pbData,
            len,
        })
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: DPAPI returned a non-null allocation of the validated length,
        // retained by this wrapper.
        unsafe { std::slice::from_raw_parts(self.pointer, self.len) }
    }
}

impl Drop for OwnedDpapiBuffer {
    fn drop(&mut self) {
        // SAFETY: the wrapper uniquely owns `len` initialized bytes returned by
        // DPAPI. Zero them before releasing the LocalAlloc allocation once.
        unsafe {
            ptr::write_bytes(self.pointer, 0, self.len);
            let _ = windows::Win32::Foundation::LocalFree(Some(HLOCAL(self.pointer.cast())));
        }
        self.pointer = ptr::null_mut();
        self.len = 0;
    }
}

fn dpapi_protect(plain: &[u8]) -> Result<Zeroizing<Vec<u8>>, LedgerStoreError> {
    if plain.len() != ENCODED_RECORD_LEN {
        return Err(LedgerStoreError::InvalidRecord);
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(plain.len()).map_err(|_| LedgerStoreError::InvalidRecord)?,
        pbData: plain.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input is an initialized fixed-size slice; output is writable.
    // UI, machine scope, prompts, descriptions, and entropy are all absent.
    unsafe {
        CryptProtectData(
            ptr::from_ref(&input),
            PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ptr::from_mut(&mut output),
        )
    }
    .map_err(|_| LedgerStoreError::AccessDenied)?;
    let output = OwnedDpapiBuffer::from_blob(output)?;
    Ok(Zeroizing::new(output.as_slice().to_vec()))
}

fn dpapi_unprotect_and_decode(protected: &[u8]) -> Result<LedgerRecord, LedgerStoreError> {
    if protected.is_empty() || protected.len() > MAX_PROTECTED_RECORD_LEN {
        return Err(LedgerStoreError::InvalidRecord);
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(protected.len()).map_err(|_| LedgerStoreError::InvalidRecord)?,
        pbData: protected.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input is a bounded initialized ciphertext slice; output is
    // writable. A null description avoids another returned allocation.
    unsafe {
        CryptUnprotectData(
            ptr::from_ref(&input),
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ptr::from_mut(&mut output),
        )
    }
    .map_err(|_| LedgerStoreError::InvalidRecord)?;
    let output = OwnedDpapiBuffer::from_blob(output)?;
    if output.len != ENCODED_RECORD_LEN {
        return Err(LedgerStoreError::InvalidRecord);
    }
    let mut plain = [0_u8; ENCODED_RECORD_LEN];
    plain.copy_from_slice(output.as_slice());
    let decoded = decode_record(&plain);
    plain.zeroize();
    decoded
}

fn validated_sid_len(
    allocation_base: *const u8,
    allocation_len: usize,
    sid: PSID,
) -> Result<usize, LedgerStoreError> {
    const SID_HEADER_LEN: usize = 8;
    if sid.is_invalid()
        || !range_contains(
            allocation_base,
            allocation_len,
            sid.0.cast_const().cast(),
            SID_HEADER_LEN,
        )
    {
        return Err(LedgerStoreError::AccessDenied);
    }
    // SAFETY: the fixed SID header is inside the containing allocation; byte 1
    // is SubAuthorityCount.
    let sub_authority_count = usize::from(unsafe { *sid.0.cast::<u8>().add(1) });
    let computed = SID_HEADER_LEN
        .checked_add(
            sub_authority_count
                .checked_mul(size_of::<u32>())
                .ok_or(LedgerStoreError::AccessDenied)?,
        )
        .ok_or(LedgerStoreError::AccessDenied)?;
    if !range_contains(
        allocation_base,
        allocation_len,
        sid.0.cast_const().cast(),
        computed,
    ) || !unsafe { IsValidSid(sid) }.as_bool()
    {
        return Err(LedgerStoreError::AccessDenied);
    }
    Ok(computed)
}

fn range_contains(base: *const u8, len: usize, pointer: *const u8, size: usize) -> bool {
    let start = base as usize;
    let end = match start.checked_add(len) {
        Some(end) => end,
        None => return false,
    };
    let pointer = pointer as usize;
    match pointer.checked_add(size) {
        Some(pointer_end) => pointer >= start && pointer_end <= end,
        None => false,
    }
}

fn bounded_find_name(data: &WIN32_FIND_DATAW) -> Result<OsString, LedgerStoreError> {
    let length = data
        .cFileName
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(LedgerStoreError::IoUncertain)?;
    if length == 0 {
        return Err(LedgerStoreError::IoUncertain);
    }
    Ok(OsString::from_wide(&data.cFileName[..length]))
}

fn validate_absolute_path(path: &Path) -> Result<(), LedgerStoreError> {
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
    if !path.is_absolute() {
        return Err(LedgerStoreError::AccessDenied);
    }
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.is_empty() || wide.len() >= MAX_PATH_UNITS || wide.contains(&0) {
        return Err(LedgerStoreError::AccessDenied);
    }
    wide.push(0);
    Ok(wide)
}

fn path_exists(path: &Path) -> Result<bool, LedgerStoreError> {
    let wide = wide_path(path)?;
    // SAFETY: `wide` is a valid bounded NUL-terminated absolute path.
    let attributes = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
    if attributes != u32::MAX {
        return Ok(true);
    }
    match unsafe { GetLastError() } {
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(false),
        _ => Err(LedgerStoreError::IoUncertain),
    }
}

const fn directory_access() -> u32 {
    FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0
}

const fn file_read_access() -> u32 {
    GENERIC_READ.0 | FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0
}

const fn file_write_access() -> u32 {
    GENERIC_READ.0 | GENERIC_WRITE.0 | FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0
}

const fn share_all() -> FILE_SHARE_MODE {
    FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
}

const fn directory_ace_flags() -> u8 {
    (CONTAINER_INHERIT_ACE.0 | OBJECT_INHERIT_ACE.0) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::windows::ledger::{LedgerController, MutationLedger, RecordCorrelation};

    fn correlation(value: u8) -> RecordCorrelation {
        RecordCorrelation::from_bytes([value; 16]).unwrap()
    }

    #[test]
    fn synthetic_secure_store_round_trips_and_exact_stage_removal_clears() {
        let parent = tempfile::tempdir().unwrap();
        let store = WindowsLedgerStore::create_synthetic(parent.path()).unwrap();
        let mut controller = LedgerController::new(store, correlation(1));
        controller.ensure_clear().unwrap();
        let stage = controller.begin_stage().unwrap();
        controller.resolve_restored_stage(stage).unwrap();
        controller.ensure_clear().unwrap();
    }

    #[test]
    fn validated_location_creates_and_reopens_only_the_fixed_secure_directory() {
        let parent = tempfile::tempdir().unwrap();
        let location = ValidatedLedgerLocation::for_synthetic_parent(parent.path()).unwrap();
        let directory = location.directory_for_test().to_path_buf();
        let mut store = WindowsLedgerStore::open_validated(location).unwrap();
        assert_eq!(store.load().unwrap(), None);
        drop(store);

        let location = ValidatedLedgerLocation::for_synthetic_parent(parent.path()).unwrap();
        let mut reopened = WindowsLedgerStore::open_validated(location).unwrap();
        assert_eq!(reopened.load().unwrap(), None);
        drop(reopened);

        std::fs::write(directory.join("unexpected.production"), b"x").unwrap();
        let location = ValidatedLedgerLocation::for_synthetic_parent(parent.path()).unwrap();
        match WindowsLedgerStore::open_validated(location) {
            Err(error) => assert_eq!(error, LedgerStoreError::IoUncertain),
            Ok(_) => panic!("unexpected directory entry must refuse"),
        }
    }

    #[test]
    fn restart_with_present_record_refuses_and_does_not_age_out() {
        let parent = tempfile::tempdir().unwrap();
        let store = WindowsLedgerStore::create_synthetic(parent.path()).unwrap();
        let directory = store.directory.clone();
        let mut first = LedgerController::new(store, correlation(2));
        first.begin_stage().unwrap();
        drop(first);

        let reopened = WindowsLedgerStore::reopen_synthetic(directory).unwrap();
        let mut restarted = LedgerController::new(reopened, correlation(3));
        let error = restarted.ensure_clear().unwrap_err();
        assert_eq!(error.operation, "windows_ledger_existing");
        assert!(!error.retry_safe);
    }

    #[test]
    fn inherited_file_acl_and_unexpected_artifact_fail_closed() {
        let parent = tempfile::tempdir().unwrap();
        let mut store = WindowsLedgerStore::create_synthetic(parent.path()).unwrap();
        std::fs::write(store.ledger_path(), b"synthetic-corrupt").unwrap();
        assert_eq!(store.load(), Err(LedgerStoreError::AccessDenied));

        std::fs::remove_file(store.ledger_path()).unwrap();
        std::fs::write(store.directory.join("unexpected.synthetic"), b"x").unwrap();
        assert_eq!(store.load(), Err(LedgerStoreError::IoUncertain));
    }

    #[test]
    fn corrupt_ciphertext_with_valid_acl_fails_closed() {
        let parent = tempfile::tempdir().unwrap();
        let store = WindowsLedgerStore::create_synthetic(parent.path()).unwrap();
        let directory = store.directory.clone();
        let ledger = store.ledger_path();
        let mut controller = LedgerController::new(store, correlation(4));
        controller.begin_stage().unwrap();
        drop(controller);

        // Opening/truncating the existing file preserves its reviewed ACL, so
        // the refusal below exercises ciphertext/DPAPI validation rather than
        // the independent inherited-ACL gate.
        std::fs::write(ledger, b"synthetic-corrupt").unwrap();
        let mut reopened = WindowsLedgerStore::reopen_synthetic(directory).unwrap();
        assert_eq!(reopened.load(), Err(LedgerStoreError::InvalidRecord));
    }

    #[test]
    fn bounds_reparse_classification_and_dpapi_flags_are_fixed() {
        assert_eq!(CRYPTPROTECT_UI_FORBIDDEN, 1);
        assert_eq!(ENCODED_RECORD_LEN, 48);
        assert!(!range_contains(
            usize::MAX as *const u8,
            2,
            usize::MAX as *const u8,
            2
        ));
        let reparse = FILE_ATTRIBUTE_TAG_INFO {
            FileAttributes: FILE_ATTRIBUTE_REPARSE_POINT.0,
            ReparseTag: 1,
        };
        assert_ne!(reparse.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0, 0);
    }

    #[test]
    fn injected_replace_failures_are_restart_safe() {
        let cases = [
            (FaultPoint::BeforeTempCreate, true),
            (FaultPoint::AfterTempCreate, false),
            (FaultPoint::AfterTempWrite, false),
            (FaultPoint::AfterTempFlush, false),
            (FaultPoint::AfterTempVerify, false),
            (FaultPoint::AfterInstallRename, false),
            (FaultPoint::AfterInstallVerify, false),
        ];
        for (index, (fault, restart_is_clear)) in cases.into_iter().enumerate() {
            let parent = tempfile::tempdir().unwrap();
            let mut store = WindowsLedgerStore::create_synthetic(parent.path()).unwrap();
            let directory = store.directory.clone();
            store.inject_once(fault);
            let mut controller = LedgerController::new(store, correlation(index as u8 + 10));
            let error = controller.begin_stage().unwrap_err();
            assert_eq!(error.operation, "windows_ledger_state_uncertain");
            assert!(!error.retry_safe);
            drop(controller);

            let reopened = WindowsLedgerStore::reopen_synthetic(directory).unwrap();
            let mut restarted = LedgerController::new(reopened, correlation(index as u8 + 30));
            if restart_is_clear {
                restarted.ensure_clear().unwrap();
            } else {
                let error = restarted.ensure_clear().unwrap_err();
                assert!(!error.retry_safe);
            }
        }
    }

    #[test]
    fn injected_remove_failures_never_turn_uncertainty_into_success() {
        for (index, fault) in [
            FaultPoint::AfterTombstoneRename,
            FaultPoint::AfterTombstoneDelete,
        ]
        .into_iter()
        .enumerate()
        {
            let parent = tempfile::tempdir().unwrap();
            let mut store = WindowsLedgerStore::create_synthetic(parent.path()).unwrap();
            let directory = store.directory.clone();
            store.inject_once(fault);
            let mut controller = LedgerController::new(store, correlation(index as u8 + 50));
            let stage = controller.begin_stage().unwrap();
            let error = controller.resolve_restored_stage(stage).unwrap_err();
            assert_eq!(error.operation, "windows_ledger_state_uncertain");
            assert!(!error.retry_safe);
            drop(controller);

            let reopened = WindowsLedgerStore::reopen_synthetic(directory).unwrap();
            let mut restarted = LedgerController::new(reopened, correlation(index as u8 + 60));
            if fault == FaultPoint::AfterTombstoneDelete {
                restarted.ensure_clear().unwrap();
            } else {
                let error = restarted.ensure_clear().unwrap_err();
                assert!(!error.retry_safe);
            }
        }
    }
}
