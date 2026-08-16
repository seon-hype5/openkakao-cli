//! Fakeable orchestration and disconnected native Windows executable trust.
//!
//! The orchestration freezes the exact offline WinTrust policy plus
//! VERIFY/extract/CLOSE lifetime. A native adapter now implements the process,
//! file-identity, known-folder-relative root, provider-chain, and SPKI
//! boundary, but no production path constructs the full process-bound adapter
//! and automated tests never call it. Reviewed signer/root values remain
//! mandatory before wiring. The stable WinTrust state is revalidated after
//! VERIFY, including exact provider pointer linkage and the primary
//! verified-signature index.

#![cfg_attr(not(test), allow(dead_code))]

use std::ffi::{c_void, OsString};
use std::fmt;
use std::mem::{align_of, size_of, size_of_val};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Component, Path, PathBuf};
use std::ptr;

use sha2::{Digest, Sha256};
use windows::core::{w, GUID, HRESULT, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, FILETIME, GENERIC_READ, HANDLE, HWND,
    INVALID_HANDLE_VALUE,
};
#[cfg(test)]
use windows::Win32::Security::Cryptography::{
    CertCreateCertificateContext, CertFreeCertificateContext,
};
use windows::Win32::Security::Cryptography::{
    CryptEncodeObjectEx, CERT_CONTEXT, CERT_INFO, CRYPT_ENCODE_OBJECT_FLAGS, X509_ASN_ENCODING,
    X509_PUBLIC_KEY_INFO,
};
use windows::Win32::Security::WinTrust::{
    WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    WinVerifyTrust, CRYPT_PROVIDER_CERT, CRYPT_PROVIDER_DATA, CRYPT_PROVIDER_SGNR,
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_DATA_PROVIDER_FLAGS, WINTRUST_DATA_REVOCATION_CHECKS, WINTRUST_DATA_STATE_ACTION,
    WINTRUST_DATA_UICHOICE, WINTRUST_DATA_UICONTEXT, WINTRUST_DATA_UNION_CHOICE,
    WINTRUST_FILE_INFO, WINTRUST_SIGNATURE_SETTINGS, WINTRUST_SIGNATURE_SETTINGS_FLAGS,
    WSS_GET_SECONDARY_SIG_COUNT, WSS_INPUT_FLAG_MASK, WSS_OUTPUT_FLAG_MASK,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4,
    WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UICONTEXT_EXECUTE, WTD_UI_NONE,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FileAttributeTagInfo, FileIdInfo, GetDriveTypeW, GetFileInformationByHandleEx,
    GetFileType, GetFileVersionInfoSizeW, GetFileVersionInfoW, GetFinalPathNameByHandleW,
    GetVolumePathNameW, VerQueryValueW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_ID_INFO, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_MODE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, GETFINALPATHNAMEBYHANDLE_FLAGS,
    OPEN_EXISTING, VOLUME_NAME_GUID, VS_FIXEDFILEINFO,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessId, GetProcessTimes, QueryFullProcessImageNameW,
    PROCESS_NAME_WIN32,
};
use windows::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_ProgramFilesX64, FOLDERID_ProgramFilesX86, KF_FLAG_DEFAULT,
};
use windows::Win32::UI::WindowsAndMessaging::{GetWindowThreadProcessId, IsWindow};
use zeroize::Zeroizing;

use crate::platform::{UiError, UiErrorKind};

use super::executable_trust::{
    observed_install_root_digest, verify_executable_trust, AuthenticodeStatus,
    ExecutableTrustBoundary, ExecutableTrustEvidence, ExecutableTrustProfile, FileIdentity,
    FinalPathSource, InstallRootKind, ReparseState, TrustDigest, VolumeKind,
    MAX_INSTALL_ROOT_COMPONENTS, MAX_INSTALL_ROOT_COMPONENT_BYTES, MAX_INSTALL_ROOT_RELATION_BYTES,
};
#[cfg(test)]
use super::executable_trust::{InstallRootDigest, ReviewedSignerDigest};
use super::FileVersion;

#[derive(Clone, Copy, PartialEq, Eq)]
struct WinTrustCallPolicy {
    action: GUID,
    noninteractive_hwnd: bool,
    ui_choice: WINTRUST_DATA_UICHOICE,
    revocation_checks: WINTRUST_DATA_REVOCATION_CHECKS,
    union_choice: WINTRUST_DATA_UNION_CHOICE,
    verify_action: WINTRUST_DATA_STATE_ACTION,
    close_action: WINTRUST_DATA_STATE_ACTION,
    provider_flags: WINTRUST_DATA_PROVIDER_FLAGS,
    ui_context: WINTRUST_DATA_UICONTEXT,
    signature_flags: WINTRUST_SIGNATURE_SETTINGS_FLAGS,
}

impl WinTrustCallPolicy {
    fn offline_embedded() -> Self {
        Self {
            action: WINTRUST_ACTION_GENERIC_VERIFY_V2,
            noninteractive_hwnd: true,
            ui_choice: WTD_UI_NONE,
            revocation_checks: WTD_REVOKE_WHOLECHAIN,
            union_choice: WTD_CHOICE_FILE,
            verify_action: WTD_STATEACTION_VERIFY,
            close_action: WTD_STATEACTION_CLOSE,
            provider_flags: WTD_CACHE_ONLY_URL_RETRIEVAL
                | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
                | WTD_DISABLE_MD2_MD4,
            ui_context: WTD_UICONTEXT_EXECUTE,
            signature_flags: WSS_GET_SECONDARY_SIG_COUNT,
        }
    }

    fn is_exact(self) -> bool {
        self.action == WINTRUST_ACTION_GENERIC_VERIFY_V2
            && self.noninteractive_hwnd
            && self.ui_choice == WTD_UI_NONE
            && self.revocation_checks == WTD_REVOKE_WHOLECHAIN
            && self.union_choice == WTD_CHOICE_FILE
            && self.verify_action == WTD_STATEACTION_VERIFY
            && self.close_action == WTD_STATEACTION_CLOSE
            && self.provider_flags
                == (WTD_CACHE_ONLY_URL_RETRIEVAL
                    | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
                    | WTD_DISABLE_MD2_MD4)
            && self.ui_context == WTD_UICONTEXT_EXECUTE
            && self.signature_flags == WSS_GET_SECONDARY_SIG_COUNT
    }
}

impl fmt::Debug for WinTrustCallPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WinTrustCallPolicy")
            .field("action", &"generic_verify_v2")
            .field("window", &"noninteractive")
            .field("ui", &"none")
            .field("subject", &"embedded_file")
            .field("network", &"cache_only")
            .field("revocation", &"whole_chain_excluding_root")
            .field("weak_hashes", &"disabled")
            .field("secondary_signature_count", &"required")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeTrustFailure {
    PathObservation,
    ReopenedIdentity,
    VerifyBegin,
    ProviderExtraction,
    StateClose,
    Panicked,
}

impl NativeTrustFailure {
    fn into_ui_error(self) -> UiError {
        let operation = match self {
            Self::PathObservation => "windows_executable_path_trust",
            Self::ReopenedIdentity => "windows_executable_file_identity",
            Self::VerifyBegin | Self::ProviderExtraction | Self::StateClose | Self::Panicked => {
                "windows_executable_signature_trust"
            }
        };
        let kind = if matches!(self, Self::ReopenedIdentity) {
            UiErrorKind::StaleSnapshot
        } else {
            UiErrorKind::PermissionDenied
        };
        UiError::new(kind, operation)
    }
}

#[derive(Clone, Copy)]
struct NativePathObservation {
    final_path_source: FinalPathSource,
    path_is_absolute_and_normalized: bool,
    volume_kind: VolumeKind,
    reparse_state: ReparseState,
    process_image_handle_bound: bool,
    process_creation_time_bound: bool,
    process_file_identity: Option<FileIdentity>,
    verified_file_identity: Option<FileIdentity>,
    version: Option<FileVersion>,
    install_root_digest: Option<TrustDigest>,
}

impl fmt::Debug for NativePathObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativePathObservation")
            .field("final_path_source", &self.final_path_source)
            .field("normalized", &self.path_is_absolute_and_normalized)
            .field("volume_kind", &self.volume_kind)
            .field("reparse_state", &self.reparse_state)
            .field("process_handle_bound", &self.process_image_handle_bound)
            .field("creation_bound", &self.process_creation_time_bound)
            .field("process_identity", &presence(self.process_file_identity))
            .field("verified_identity", &presence(self.verified_file_identity))
            .field("version_observed", &self.version.is_some())
            .field("root_digest", &presence(self.install_root_digest))
            .finish()
    }
}

#[derive(Clone, Copy)]
struct NativeAuthenticodeObservation {
    winverifytrust_status: i32,
    catalog_choice_used: bool,
    primary_signer_count: usize,
    secondary_signature_count: usize,
    signer_digest: Option<TrustDigest>,
}

impl fmt::Debug for NativeAuthenticodeObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeAuthenticodeObservation")
            .field(
                "trust_status",
                &if self.winverifytrust_status == 0 {
                    "zero"
                } else {
                    "nonzero"
                },
            )
            .field("catalog_choice_used", &self.catalog_choice_used)
            .field("primary_signers", &bounded_count(self.primary_signer_count))
            .field(
                "secondary_signatures",
                &bounded_count(self.secondary_signature_count),
            )
            .field("signer_digest", &presence(self.signer_digest))
            .finish()
    }
}

fn presence<T>(value: Option<T>) -> &'static str {
    if value.is_some() {
        "<redacted-present>"
    } else {
        "<absent>"
    }
}

fn bounded_count(value: usize) -> &'static str {
    match value {
        0 => "zero",
        1 => "one",
        _ => "multiple",
    }
}

trait NativeExecutableTrustApi {
    /// Opaque state that keeps the original process-image handle and canonical
    /// path binding alive until verification closes and the path is reopened.
    type PathState;
    type TrustState;

    fn observe_path(
        &mut self,
        install_root_kind: InstallRootKind,
    ) -> Result<(Self::PathState, NativePathObservation), NativeTrustFailure>;

    fn begin_authenticode(
        &mut self,
        path: &Self::PathState,
        policy: WinTrustCallPolicy,
    ) -> Result<Self::TrustState, NativeTrustFailure>;

    fn extract_authenticode(
        &mut self,
        state: &Self::TrustState,
    ) -> Result<NativeAuthenticodeObservation, NativeTrustFailure>;

    fn close_authenticode(
        &mut self,
        state: Self::TrustState,
        policy: WinTrustCallPolicy,
    ) -> Result<(), NativeTrustFailure>;

    /// Reopens the canonical path after WinTrust state has been closed. The
    /// original path state remains alive so the adapter can compare both file
    /// identities without materializing either identifier outside this seam.
    fn reopen_file_identity(
        &mut self,
        path: &Self::PathState,
    ) -> Result<Option<FileIdentity>, NativeTrustFailure>;
}

struct NativeExecutableTrustObserver<A> {
    profile: ExecutableTrustProfile,
    api: A,
}

impl<A> NativeExecutableTrustObserver<A> {
    fn new(profile: ExecutableTrustProfile, api: A) -> Self {
        Self { profile, api }
    }

    #[cfg(test)]
    fn into_api(self) -> A {
        self.api
    }
}

impl<A: NativeExecutableTrustApi> ExecutableTrustBoundary for NativeExecutableTrustObserver<A> {
    fn verify_executable_trust(&mut self) -> Result<(), UiError> {
        observe_and_verify(&self.profile, &mut self.api)
    }
}

fn observe_and_verify<A: NativeExecutableTrustApi>(
    profile: &ExecutableTrustProfile,
    api: &mut A,
) -> Result<(), UiError> {
    let install_root_kind = profile.install_root_kind();
    let (path_state, path) = catch_unwind(AssertUnwindSafe(|| api.observe_path(install_root_kind)))
        .map_err(|_| NativeTrustFailure::PathObservation.into_ui_error())?
        .map_err(NativeTrustFailure::into_ui_error)?;

    let policy = WinTrustCallPolicy::offline_embedded();
    if !policy.is_exact() {
        return Err(NativeTrustFailure::VerifyBegin.into_ui_error());
    }
    let state = catch_unwind(AssertUnwindSafe(|| {
        api.begin_authenticode(&path_state, policy)
    }))
    .map_err(|_| NativeTrustFailure::Panicked.into_ui_error())?
    .map_err(NativeTrustFailure::into_ui_error)?;

    let extracted = catch_unwind(AssertUnwindSafe(|| api.extract_authenticode(&state)));
    // CLOSE is attempted exactly once for every successfully created state,
    // even when provider extraction returned an error or unwound.
    let close = catch_unwind(AssertUnwindSafe(|| api.close_authenticode(state, policy)));
    match close {
        Ok(Ok(())) => {}
        Ok(Err(_)) | Err(_) => return Err(NativeTrustFailure::StateClose.into_ui_error()),
    }
    let authenticode = extracted
        .map_err(|_| NativeTrustFailure::Panicked.into_ui_error())?
        .map_err(NativeTrustFailure::into_ui_error)?;
    // The third identity is intentionally observed only after WinTrust state
    // is closed. This catches path replacement during verification while the
    // original process-image handle/path state is still alive for comparison.
    let reopened_file_identity =
        catch_unwind(AssertUnwindSafe(|| api.reopen_file_identity(&path_state)))
            .map_err(|_| NativeTrustFailure::ReopenedIdentity.into_ui_error())?
            .map_err(NativeTrustFailure::into_ui_error)?;

    let signer_count = authenticode
        .primary_signer_count
        .saturating_add(authenticode.secondary_signature_count);
    let evidence = ExecutableTrustEvidence {
        final_path_source: path.final_path_source,
        path_is_absolute_and_normalized: path.path_is_absolute_and_normalized,
        volume_kind: path.volume_kind,
        reparse_state: path.reparse_state,
        process_image_handle_bound: path.process_image_handle_bound,
        process_creation_time_bound: path.process_creation_time_bound,
        process_file_identity: path.process_file_identity,
        verified_file_identity: path.verified_file_identity,
        reopened_file_identity,
        version: path.version,
        authenticode_status: if authenticode.winverifytrust_status == 0 {
            AuthenticodeStatus::Trusted
        } else {
            AuthenticodeStatus::Untrusted
        },
        trust_ui_forbidden: policy.noninteractive_hwnd && policy.ui_choice == WTD_UI_NONE,
        cache_only_url_retrieval: policy.provider_flags.contains(WTD_CACHE_ONLY_URL_RETRIEVAL),
        catalog_ambiguous: authenticode.catalog_choice_used
            || authenticode.secondary_signature_count != 0,
        signer_count,
        signer_digest: authenticode.signer_digest,
        install_root_digest: path.install_root_digest,
    };
    verify_executable_trust(profile, &evidence).map(|_| ())
}

const MAX_NATIVE_PATH_UNITS: usize = 32_760;
const MAX_PATH_ANCESTORS: usize = 64;
const MAX_VOLUME_ROOT_UNITS: usize = 64;
const MAX_CERTIFICATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_SPKI_DER_BYTES: usize = 64 * 1024;
const DRIVE_FIXED_VALUE: u32 = 3;
const FIXED_FILE_INFO_SIGNATURE: u32 = 0xFEEF_04BD;
const FILE_ID_DOMAIN: &[u8] = b"openkakao.windows.executable-file-id.v1\0";

// The generated windows-rs wrapper discards a non-null output pointer when
// HRESULT is failure. This narrow declaration preserves ownership so every
// Shell allocation can be released on both success and failure paths.
#[link(name = "shell32")]
extern "system" {
    #[link_name = "SHGetKnownFolderPath"]
    fn sh_get_known_folder_path_for_trust(
        rfid: *const GUID,
        flags: u32,
        token: HANDLE,
        path: *mut PWSTR,
    ) -> HRESULT;
}

/// Owned Win32 handle used only by the disconnected executable-trust adapter.
/// It is intentionally separate from the mutation backend's handle wrapper so
/// no production path can construct this adapter accidentally.
struct OwnedNativeHandle(HANDLE);

impl OwnedNativeHandle {
    fn duplicate(handle: HANDLE) -> Result<Self, NativeTrustFailure> {
        if handle.is_invalid() {
            return Err(NativeTrustFailure::PathObservation);
        }
        let mut duplicated = HANDLE::default();
        // SAFETY: both process handles are the current-process pseudo handle,
        // `handle` is validated by DuplicateHandle, and the out parameter is
        // writable. The returned handle is immediately owned by this wrapper.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                handle,
                GetCurrentProcess(),
                ptr::from_mut(&mut duplicated),
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )
        }
        .map_err(|_| NativeTrustFailure::PathObservation)?;
        if duplicated.is_invalid() {
            Err(NativeTrustFailure::PathObservation)
        } else {
            Ok(Self(duplicated))
        }
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedNativeHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: this wrapper owns exactly one non-pseudo kernel handle.
            let _ = unsafe { CloseHandle(self.0) };
            self.0 = HANDLE::default();
        }
    }
}

struct WindowsPathState {
    process_image_file: OwnedNativeHandle,
    verification_file: OwnedNativeHandle,
    /// Keeps every canonical parent directory open without write/delete
    /// sharing until VERIFY, CLOSE, and the final identity reopen complete.
    /// This closes path-component rename/reparse ABA races around the
    /// path-only version API.
    _canonical_parent_guards: Vec<OwnedNativeHandle>,
    /// Retains the separately resolved known-folder root and its canonical
    /// ancestors with write/delete sharing excluded for the same lifetime.
    known_folder_root: OwnedNativeHandle,
    _known_folder_parent_guards: Vec<OwnedNativeHandle>,
    canonical_path: Zeroizing<Vec<u16>>,
    canonical_known_folder: Zeroizing<Vec<u16>>,
    identity: FileIdentity,
}

/// Native implementation of the already-frozen adapter seam. The constructor
/// duplicates the caller's process handle; no raw handle or path escapes this
/// module. It remains disconnected from `NativeMutationPort` until signer and
/// installation-root provenance are independently reviewed.
struct WindowsNativeExecutableTrustApi {
    hwnd: HWND,
    pid: u32,
    expected_creation_time_100ns: u64,
    process: OwnedNativeHandle,
}

impl WindowsNativeExecutableTrustApi {
    #[allow(dead_code)] // Deliberately disconnected until reviewed provenance is available.
    fn from_bound_process(
        hwnd: HWND,
        pid: u32,
        expected_creation_time_100ns: u64,
        process: HANDLE,
    ) -> Result<Self, NativeTrustFailure> {
        if pid == 0 || expected_creation_time_100ns == 0 {
            return Err(NativeTrustFailure::PathObservation);
        }
        Ok(Self {
            hwnd,
            pid,
            expected_creation_time_100ns,
            process: OwnedNativeHandle::duplicate(process)?,
        })
    }

    fn validate_process_binding(&self) -> Result<(), NativeTrustFailure> {
        if !unsafe { IsWindow(Some(self.hwnd)).as_bool() }
            || unsafe { GetProcessId(self.process.raw()) } != self.pid
        {
            return Err(NativeTrustFailure::PathObservation);
        }
        let mut owner_pid = 0_u32;
        // SAFETY: `owner_pid` is a live writable out parameter and HWND is
        // validated immediately above. A zero thread result is a refusal.
        let thread_id =
            unsafe { GetWindowThreadProcessId(self.hwnd, Some(ptr::from_mut(&mut owner_pid))) };
        if thread_id == 0 || owner_pid != self.pid {
            return Err(NativeTrustFailure::PathObservation);
        }
        if query_creation_time(self.process.raw())? != self.expected_creation_time_100ns {
            return Err(NativeTrustFailure::PathObservation);
        }
        Ok(())
    }
}

impl NativeExecutableTrustApi for WindowsNativeExecutableTrustApi {
    type PathState = WindowsPathState;
    type TrustState = WindowsTrustState;

    fn observe_path(
        &mut self,
        install_root_kind: InstallRootKind,
    ) -> Result<(Self::PathState, NativePathObservation), NativeTrustFailure> {
        self.validate_process_binding()?;
        let source_path = query_process_image_path(self.process.raw())?;
        validate_absolute_path(&source_path)?;
        // The source-path guards remain live until the canonical handle and
        // its independently guarded parent chain have both been established.
        let _source_parent_guards = open_reparse_free_parent_chain(&source_path)?;

        let process_image_file = open_regular_file_no_follow(&source_path)?;
        validate_regular_file_handle(&process_image_file)?;
        let canonical_path = canonical_file_path(&process_image_file)?;
        if !is_fixed_local_volume(&canonical_path)? {
            return Err(NativeTrustFailure::PathObservation);
        }
        let canonical_parent_guards = open_reparse_free_parent_chain(&canonical_path)?;

        // Unlike the initial discovery handle, this handle deliberately omits
        // FILE_SHARE_WRITE and FILE_SHARE_DELETE. It either excludes writers
        // and renames for the full verification lifetime or fails closed when
        // an incompatible handle already exists.
        let verification_file = open_guarded_regular_file_no_follow(&canonical_path)?;
        validate_regular_file_handle(&verification_file)?;
        if canonical_file_path(&verification_file)? != canonical_path {
            return Err(NativeTrustFailure::PathObservation);
        }

        let known_folder_source = resolve_known_folder_path(install_root_kind)?;
        let _known_folder_source_parent_guards =
            open_reparse_free_parent_chain(&known_folder_source)?;
        let known_folder_source_handle = open_directory_no_follow(&known_folder_source)?;
        validate_directory_handle(&known_folder_source_handle)?;
        let canonical_known_folder = canonical_file_path(&known_folder_source_handle)?;
        if !is_fixed_local_volume(&canonical_known_folder)? {
            return Err(NativeTrustFailure::PathObservation);
        }
        let known_folder_parent_guards = open_reparse_free_parent_chain(&canonical_known_folder)?;
        let known_folder_root = open_directory_no_follow(&canonical_known_folder)?;
        validate_directory_handle(&known_folder_root)?;
        if canonical_file_path(&known_folder_root)? != canonical_known_folder {
            return Err(NativeTrustFailure::PathObservation);
        }
        let install_root_digest = derive_install_root_digest(
            install_root_kind,
            &canonical_known_folder,
            &canonical_path,
        )?;

        let process_identity =
            file_identity(&process_image_file, self.expected_creation_time_100ns)?;
        let verified_identity =
            file_identity(&verification_file, self.expected_creation_time_100ns)?;
        if process_identity != verified_identity {
            return Err(NativeTrustFailure::PathObservation);
        }
        let version = query_file_version(&canonical_path);
        // The version API is path-based. Reopen immediately after it and bind
        // the result back to the held verification handle so a replacement
        // cannot silently supply version bytes for a different file.
        let after_version = open_regular_file_no_follow(&canonical_path)?;
        validate_regular_file_handle(&after_version)?;
        if canonical_file_path(&after_version)? != canonical_path
            || file_identity(&after_version, self.expected_creation_time_100ns)?
                != verified_identity
        {
            return Err(NativeTrustFailure::PathObservation);
        }
        self.validate_process_binding()?;

        let canonical_path = wide_path(&canonical_path)?;
        let state = WindowsPathState {
            process_image_file,
            verification_file,
            _canonical_parent_guards: canonical_parent_guards,
            known_folder_root,
            _known_folder_parent_guards: known_folder_parent_guards,
            canonical_path: Zeroizing::new(canonical_path),
            canonical_known_folder: Zeroizing::new(wide_path(&canonical_known_folder)?),
            identity: verified_identity,
        };
        let observation = NativePathObservation {
            final_path_source: FinalPathSource::OpenedProcessImageHandle,
            path_is_absolute_and_normalized: true,
            volume_kind: VolumeKind::FixedLocal,
            reparse_state: ReparseState::Absent,
            process_image_handle_bound: true,
            process_creation_time_bound: true,
            process_file_identity: Some(process_identity),
            verified_file_identity: Some(verified_identity),
            version,
            install_root_digest: Some(install_root_digest),
        };
        Ok((state, observation))
    }

    fn begin_authenticode(
        &mut self,
        path: &Self::PathState,
        policy: WinTrustCallPolicy,
    ) -> Result<Self::TrustState, NativeTrustFailure> {
        if !policy.is_exact() {
            return Err(NativeTrustFailure::VerifyBegin);
        }
        self.validate_process_binding()?;
        validate_regular_file_handle(&path.process_image_file)?;
        validate_regular_file_handle(&path.verification_file)?;
        validate_known_folder_binding(path)?;
        if file_identity(&path.verification_file, self.expected_creation_time_100ns)?
            != path.identity
        {
            return Err(NativeTrustFailure::ReopenedIdentity);
        }

        let mut state = WindowsTrustState::new(path, policy)?;
        state.verify(policy);
        Ok(state)
    }

    fn extract_authenticode(
        &mut self,
        state: &Self::TrustState,
    ) -> Result<NativeAuthenticodeObservation, NativeTrustFailure> {
        extract_windows_authenticode(state)
    }

    fn close_authenticode(
        &mut self,
        mut state: Self::TrustState,
        policy: WinTrustCallPolicy,
    ) -> Result<(), NativeTrustFailure> {
        state.close_once(policy)
    }

    fn reopen_file_identity(
        &mut self,
        path: &Self::PathState,
    ) -> Result<Option<FileIdentity>, NativeTrustFailure> {
        self.validate_process_binding()
            .map_err(|_| NativeTrustFailure::ReopenedIdentity)?;
        validate_known_folder_binding(path).map_err(|_| NativeTrustFailure::ReopenedIdentity)?;
        let reopened = open_regular_file_no_follow_wide(&path.canonical_path)
            .map_err(|_| NativeTrustFailure::ReopenedIdentity)?;
        validate_regular_file_handle(&reopened)
            .map_err(|_| NativeTrustFailure::ReopenedIdentity)?;
        let reopened_path =
            canonical_file_path(&reopened).map_err(|_| NativeTrustFailure::ReopenedIdentity)?;
        let expected_path = path_from_wide(&path.canonical_path)
            .map_err(|_| NativeTrustFailure::ReopenedIdentity)?;
        if reopened_path != expected_path {
            return Err(NativeTrustFailure::ReopenedIdentity);
        }
        let identity = file_identity(&reopened, self.expected_creation_time_100ns)
            .map_err(|_| NativeTrustFailure::ReopenedIdentity)?;
        self.validate_process_binding()
            .map_err(|_| NativeTrustFailure::ReopenedIdentity)?;
        Ok(Some(identity))
    }
}

fn validate_known_folder_binding(path: &WindowsPathState) -> Result<(), NativeTrustFailure> {
    validate_directory_handle(&path.known_folder_root)?;
    let expected = path_from_wide(&path.canonical_known_folder)?;
    if canonical_file_path(&path.known_folder_root)? != expected {
        return Err(NativeTrustFailure::PathObservation);
    }
    Ok(())
}

fn known_folder_id(kind: InstallRootKind) -> &'static GUID {
    match kind {
        InstallRootKind::ProgramFilesX86 => &FOLDERID_ProgramFilesX86,
        InstallRootKind::ProgramFiles64 => &FOLDERID_ProgramFilesX64,
        InstallRootKind::CurrentUserLocalAppData => &FOLDERID_LocalAppData,
    }
}

fn resolve_known_folder_path(kind: InstallRootKind) -> Result<PathBuf, NativeTrustFailure> {
    let mut raw_path = PWSTR::null();
    // SAFETY: the selected source-static GUID and writable output pointer live
    // through the synchronous call; a null token selects the current user.
    // Any non-null output is owned before the HRESULT is interpreted.
    let status = unsafe {
        sh_get_known_folder_path_for_trust(
            ptr::from_ref(known_folder_id(kind)),
            KF_FLAG_DEFAULT.0 as u32,
            HANDLE::default(),
            ptr::from_mut(&mut raw_path),
        )
    };
    // SAFETY: every non-null pointer is the exact Shell allocation from the
    // call above and CoTaskMemFree is its matching release. On success, Shell
    // guarantees a NUL-terminated UTF-16 path.
    unsafe { resolve_known_folder_result(status, raw_path, release_known_folder_path) }
}

type KnownFolderPathRelease = unsafe fn(*const c_void);

/// Owns and decodes one raw known-folder result.
///
/// # Safety
///
/// Every non-null `raw_path` must be owned by `release`. When `status` is
/// successful, it must also point to a readable NUL-terminated UTF-16 string
/// within `MAX_NATIVE_PATH_UNITS` units.
unsafe fn resolve_known_folder_result(
    status: HRESULT,
    raw_path: PWSTR,
    release: KnownFolderPathRelease,
) -> Result<PathBuf, NativeTrustFailure> {
    // Take ownership before interpreting HRESULT. Shell is permitted to
    // return a non-null allocation on failure and that allocation must not be
    // lost through an early return.
    // SAFETY: the caller upholds the allocation, release, and successful-string
    // invariants documented above.
    let owned_path = unsafe { OwnedTrustKnownFolderPath::new(raw_path, release) };
    if status.is_err() {
        return Err(NativeTrustFailure::PathObservation);
    }
    let path = owned_path
        .as_ref()
        .ok_or(NativeTrustFailure::PathObservation)?
        .to_path_buf()?;
    validate_absolute_path(&path)?;
    Ok(path)
}

unsafe fn release_known_folder_path(raw_path: *const c_void) {
    // SAFETY: callers supply only the exact non-null allocation returned by
    // SHGetKnownFolderPath; OwnedTrustKnownFolderPath invokes this once.
    debug_assert!(!raw_path.is_null());
    unsafe { CoTaskMemFree(Some(raw_path)) };
}

struct OwnedTrustKnownFolderPath {
    raw_path: PWSTR,
    release: KnownFolderPathRelease,
}

impl OwnedTrustKnownFolderPath {
    /// # Safety
    ///
    /// A non-null `raw_path` must satisfy the allocation, matching-release,
    /// and successful-string invariants of `resolve_known_folder_result`.
    unsafe fn new(raw_path: PWSTR, release: KnownFolderPathRelease) -> Option<Self> {
        if raw_path.0.is_null() {
            None
        } else {
            Some(Self { raw_path, release })
        }
    }

    fn to_path_buf(&self) -> Result<PathBuf, NativeTrustFailure> {
        if self.raw_path.0.is_null() {
            return Err(NativeTrustFailure::PathObservation);
        }
        let mut length = 0_usize;
        // SAFETY: SHGetKnownFolderPath returns a caller-owned NUL-terminated
        // UTF-16 allocation. The explicit cap bounds the terminator scan.
        unsafe {
            while length < MAX_NATIVE_PATH_UNITS && *self.raw_path.0.add(length) != 0 {
                length += 1;
            }
        }
        if length == 0 || length == MAX_NATIVE_PATH_UNITS {
            return Err(NativeTrustFailure::PathObservation);
        }
        // SAFETY: the bounded scan established this initialized live span.
        let units = unsafe { std::slice::from_raw_parts(self.raw_path.0, length) };
        Ok(PathBuf::from(OsString::from_wide(units)))
    }
}

impl Drop for OwnedTrustKnownFolderPath {
    fn drop(&mut self) {
        if !self.raw_path.0.is_null() {
            // This is the exact Shell allocation returned by
            // SHGetKnownFolderPath. Clear ownership before the private release
            // function performs the matching deallocation exactly once.
            let raw_path = self.raw_path.0.cast_const().cast::<c_void>();
            self.raw_path = PWSTR::null();
            // SAFETY: construction requires this exact non-null allocation and
            // matching release pair, and ownership was just consumed.
            unsafe { (self.release)(raw_path) };
        }
    }
}

fn derive_install_root_digest(
    kind: InstallRootKind,
    known_folder: &Path,
    executable: &Path,
) -> Result<TrustDigest, NativeTrustFailure> {
    validate_absolute_path(known_folder)?;
    validate_absolute_path(executable)?;
    let mut known_units = Zeroizing::new(wide_path(known_folder)?);
    let mut executable_units = Zeroizing::new(wide_path(executable)?);
    if known_units.pop() != Some(0) || executable_units.pop() != Some(0) {
        return Err(NativeTrustFailure::PathObservation);
    }

    let known_volume = volume_guid_root(&known_units).ok_or(NativeTrustFailure::PathObservation)?;
    let executable_volume =
        volume_guid_root(&executable_units).ok_or(NativeTrustFailure::PathObservation)?;
    if !ascii_units_equal(known_volume, executable_volume)
        || known_units.len() <= known_volume.len()
        || known_units.last() == Some(&u16::from(b'\\'))
        || executable_units.len() <= known_units.len()
        || !ascii_units_equal(&executable_units[..known_units.len()], &known_units)
        || executable_units.get(known_units.len()) != Some(&u16::from(b'\\'))
    {
        return Err(NativeTrustFailure::PathObservation);
    }

    let relative = &executable_units[known_units.len() + 1..];
    let mut relation_bytes = 0_usize;
    let mut components: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    for units in relative.split(|unit| *unit == u16::from(b'\\')) {
        if units.is_empty()
            || units.len() > MAX_INSTALL_ROOT_COMPONENT_BYTES
            || components.len() == MAX_INSTALL_ROOT_COMPONENTS
        {
            return Err(NativeTrustFailure::PathObservation);
        }
        relation_bytes = relation_bytes
            .checked_add(units.len())
            .ok_or(NativeTrustFailure::PathObservation)?;
        if relation_bytes > MAX_INSTALL_ROOT_RELATION_BYTES {
            return Err(NativeTrustFailure::PathObservation);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(units.len()));
        for unit in units {
            if *unit > 0x7f {
                return Err(NativeTrustFailure::PathObservation);
            }
            bytes.push(*unit as u8);
        }
        components.push(bytes);
    }
    let component_refs: Vec<&[u8]> = components
        .iter()
        .map(|component| component.as_slice())
        .collect();
    observed_install_root_digest(kind, &component_refs)
        .map_err(|_| NativeTrustFailure::PathObservation)
}

struct WindowsTrustState {
    action: Box<GUID>,
    file_path: Zeroizing<Vec<u16>>,
    file_handle: OwnedNativeHandle,
    file_info: Box<WINTRUST_FILE_INFO>,
    signature_settings: Box<WINTRUST_SIGNATURE_SETTINGS>,
    data: Box<WINTRUST_DATA>,
    verify_status: i32,
    verify_attempted: bool,
    close_attempted: bool,
}

impl WindowsTrustState {
    fn new(
        path: &WindowsPathState,
        policy: WinTrustCallPolicy,
    ) -> Result<Self, NativeTrustFailure> {
        if !policy.is_exact() || path.canonical_path.last() != Some(&0) {
            return Err(NativeTrustFailure::VerifyBegin);
        }
        let file_handle = OwnedNativeHandle::duplicate(path.verification_file.raw())
            .map_err(|_| NativeTrustFailure::VerifyBegin)?;
        let file_path = Zeroizing::new(path.canonical_path.to_vec());
        let mut file_info = Box::new(WINTRUST_FILE_INFO {
            cbStruct: checked_struct_size::<WINTRUST_FILE_INFO>()?,
            pcwszFilePath: PCWSTR(file_path.as_ptr()),
            hFile: file_handle.raw(),
            pgKnownSubject: ptr::null_mut(),
        });
        let mut signature_settings = Box::new(WINTRUST_SIGNATURE_SETTINGS {
            cbStruct: checked_struct_size::<WINTRUST_SIGNATURE_SETTINGS>()?,
            dwIndex: 0,
            dwFlags: policy.signature_flags,
            cSecondarySigs: 0,
            dwVerifiedSigIndex: 0,
            pCryptoPolicy: ptr::null_mut(),
        });
        let data = Box::new(WINTRUST_DATA {
            cbStruct: checked_struct_size::<WINTRUST_DATA>()?,
            pPolicyCallbackData: ptr::null_mut(),
            pSIPClientData: ptr::null_mut(),
            dwUIChoice: policy.ui_choice,
            fdwRevocationChecks: policy.revocation_checks,
            dwUnionChoice: policy.union_choice,
            Anonymous: WINTRUST_DATA_0 {
                pFile: ptr::from_mut(&mut *file_info),
            },
            dwStateAction: policy.verify_action,
            hWVTStateData: HANDLE::default(),
            pwszURLReference: PWSTR::null(),
            dwProvFlags: policy.provider_flags,
            dwUIContext: policy.ui_context,
            pSignatureSettings: ptr::from_mut(&mut *signature_settings),
        });
        Ok(Self {
            action: Box::new(policy.action),
            file_path,
            file_handle,
            file_info,
            signature_settings,
            data,
            verify_status: i32::MIN,
            verify_attempted: false,
            close_attempted: false,
        })
    }

    fn verify(&mut self, policy: WinTrustCallPolicy) {
        debug_assert!(policy.is_exact());
        self.verify_attempted = true;
        self.data.dwStateAction = policy.verify_action;
        // SAFETY: all referenced allocations are boxed or fixed-capacity and
        // remain live in `self` through CLOSE. INVALID_HANDLE_VALUE and
        // WTD_UI_NONE jointly forbid provider UI. The integer status is kept
        // verbatim because WinVerifyTrust returns LONG, not HRESULT.
        self.verify_status = unsafe {
            WinVerifyTrust(
                noninteractive_hwnd(),
                ptr::from_mut(&mut *self.action),
                ptr::from_mut(&mut *self.data).cast(),
            )
        };
    }

    fn close_once(&mut self, policy: WinTrustCallPolicy) -> Result<(), NativeTrustFailure> {
        if !self.verify_attempted || self.close_attempted || !policy.is_exact() {
            return Err(NativeTrustFailure::StateClose);
        }
        // Mark before entry so a panic or exceptional return can never cause a
        // second CLOSE attempt from Drop.
        self.close_attempted = true;
        self.data.dwStateAction = policy.close_action;
        // SAFETY: this is the same stable action/data/file/settings state used
        // by VERIFY. Exactly one CLOSE attempt is made for this state.
        let status = unsafe {
            WinVerifyTrust(
                noninteractive_hwnd(),
                ptr::from_mut(&mut *self.action),
                ptr::from_mut(&mut *self.data).cast(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(NativeTrustFailure::StateClose)
        }
    }

    fn debug_invariants(&self) -> bool {
        // SAFETY: dwUnionChoice is fixed to WTD_CHOICE_FILE before this union
        // member is read, and the pointer is compared only, never dereferenced.
        let subject = unsafe { self.data.Anonymous.pFile };
        let policy = WinTrustCallPolicy::offline_embedded();
        *self.action == policy.action
            && self.data.cbStruct as usize == size_of::<WINTRUST_DATA>()
            && self.data.pPolicyCallbackData.is_null()
            && self.data.pSIPClientData.is_null()
            && self.data.dwUIChoice == policy.ui_choice
            && self.data.fdwRevocationChecks == policy.revocation_checks
            && self.data.dwUnionChoice == policy.union_choice
            && subject == ptr::from_ref(&*self.file_info).cast_mut()
            && self.data.dwStateAction == policy.verify_action
            && self.data.pwszURLReference.is_null()
            && self.data.dwProvFlags == policy.provider_flags
            && self.data.dwUIContext == policy.ui_context
            && self.data.pSignatureSettings == ptr::from_ref(&*self.signature_settings).cast_mut()
            && self.file_path.last() == Some(&0)
            && self.file_info.cbStruct as usize == size_of::<WINTRUST_FILE_INFO>()
            && self.file_info.pcwszFilePath.0 == self.file_path.as_ptr()
            && self.file_info.hFile == self.file_handle.raw()
            && self.file_info.pgKnownSubject.is_null()
            && self.signature_settings.cbStruct as usize == size_of::<WINTRUST_SIGNATURE_SETTINGS>()
            && self.signature_settings.dwIndex == 0
            && signature_settings_flags_are_exact(
                self.signature_settings.dwFlags,
                policy.signature_flags,
            )
            && self.signature_settings.pCryptoPolicy.is_null()
    }
}

fn signature_settings_flags_are_exact(
    observed: WINTRUST_SIGNATURE_SETTINGS_FLAGS,
    expected_input: WINTRUST_SIGNATURE_SETTINGS_FLAGS,
) -> bool {
    // WinTrust preserves the input mask and may add only the documented
    // WSS_OUT_* result bits to this in/out field. Unknown or changed input
    // bits still fail closed.
    observed.0 & WSS_INPUT_FLAG_MASK == expected_input.0
        && observed.0 & !(WSS_INPUT_FLAG_MASK | WSS_OUTPUT_FLAG_MASK) == 0
}

impl Drop for WindowsTrustState {
    fn drop(&mut self) {
        if self.verify_attempted && !self.close_attempted {
            let _ = self.close_once(WinTrustCallPolicy::offline_embedded());
        }
    }
}

fn noninteractive_hwnd() -> HWND {
    HWND(INVALID_HANDLE_VALUE.0)
}

fn extract_windows_authenticode(
    state: &WindowsTrustState,
) -> Result<NativeAuthenticodeObservation, NativeTrustFailure> {
    if !state.verify_attempted || state.close_attempted || !state.debug_invariants() {
        return Err(NativeTrustFailure::ProviderExtraction);
    }
    let secondary_signature_count = usize::try_from(state.signature_settings.cSecondarySigs)
        .map_err(|_| NativeTrustFailure::ProviderExtraction)?;
    if secondary_signature_count == 0 && state.signature_settings.dwVerifiedSigIndex != 0 {
        return Err(NativeTrustFailure::ProviderExtraction);
    }
    let catalog_choice_used = state.data.dwUnionChoice != WTD_CHOICE_FILE;
    let base = NativeAuthenticodeObservation {
        winverifytrust_status: state.verify_status,
        catalog_choice_used,
        primary_signer_count: 0,
        secondary_signature_count,
        signer_digest: None,
    };

    // Provider state is not assumed to be materialized on a trust failure.
    // The nonzero LONG is sufficient for the pure verifier to refuse.
    if state.verify_status != 0 || catalog_choice_used || secondary_signature_count != 0 {
        return Ok(base);
    }
    if state.data.hWVTStateData.is_invalid() {
        return Err(NativeTrustFailure::ProviderExtraction);
    }

    // SAFETY: the state handle belongs to the live VERIFY state and is used
    // only before CLOSE. Returned pointers are borrowed from that state.
    let provider_pointer = unsafe { WTHelperProvDataFromStateData(state.data.hWVTStateData) };
    // SAFETY: WinTrust returned `provider_pointer` for this exact live state;
    // the helper below additionally validates alignment and cbStruct.
    let provider = unsafe { checked_provider(state, provider_pointer) }?;
    if provider.pWintrustData != ptr::from_ref(&*state.data).cast_mut()
        || provider.pgActionID != ptr::from_ref(&*state.action).cast_mut()
        || provider.pSigSettings != ptr::from_ref(&*state.signature_settings).cast_mut()
    {
        return Err(NativeTrustFailure::ProviderExtraction);
    }
    let primary_signer_count =
        usize::try_from(provider.csSigners).map_err(|_| NativeTrustFailure::ProviderExtraction)?;
    if primary_signer_count != 1 {
        return Ok(NativeAuthenticodeObservation {
            primary_signer_count,
            ..base
        });
    }

    // SAFETY: provider is validated and remains borrowed from the live state;
    // only signer index zero is requested after exact cardinality one.
    if provider.pasSigners.is_null()
        || !(provider.pasSigners as usize).is_multiple_of(align_of::<CRYPT_PROVIDER_SGNR>())
    {
        return Err(NativeTrustFailure::ProviderExtraction);
    }
    let signer_pointer = unsafe { WTHelperGetProvSignerFromChain(provider_pointer, 0, false, 0) };
    if signer_pointer != provider.pasSigners {
        return Err(NativeTrustFailure::ProviderExtraction);
    }
    // SAFETY: the helper returned index zero from the validated one-signer
    // provider state, and pointer identity is checked above.
    let signer = unsafe { checked_signer(state, signer_pointer) }?;
    if signer.csCertChain == 0
        || signer.csCertChain > 64
        || signer.pasCertChain.is_null()
        || !(signer.pasCertChain as usize).is_multiple_of(align_of::<CRYPT_PROVIDER_CERT>())
    {
        return Err(NativeTrustFailure::ProviderExtraction);
    }
    // SAFETY: signer is a validated live provider pointer and its certificate
    // chain has at least one entry. The returned certificate remains borrowed.
    let certificate_pointer = unsafe { WTHelperGetProvCertFromChain(signer_pointer, 0) };
    if certificate_pointer != signer.pasCertChain {
        return Err(NativeTrustFailure::ProviderExtraction);
    }
    // SAFETY: certificate index zero is borrowed from the validated signer and
    // remains live until CLOSE; all nested pointers are shape-checked below.
    let certificate = unsafe { checked_provider_certificate(state, certificate_pointer) }?;
    let context = unsafe { checked_certificate_context(state, certificate.pCert) }?;
    let info = unsafe { checked_certificate_info(state, context.pCertInfo) }?;
    let signer_digest = Some(spki_digest(info)?);

    Ok(NativeAuthenticodeObservation {
        primary_signer_count,
        signer_digest,
        ..base
    })
}

unsafe fn checked_provider(
    state: &WindowsTrustState,
    value: *mut CRYPT_PROVIDER_DATA,
) -> Result<&CRYPT_PROVIDER_DATA, NativeTrustFailure> {
    unsafe { checked_native_struct(state, value) }
}

unsafe fn checked_signer(
    state: &WindowsTrustState,
    value: *mut CRYPT_PROVIDER_SGNR,
) -> Result<&CRYPT_PROVIDER_SGNR, NativeTrustFailure> {
    unsafe { checked_native_struct(state, value) }
}

unsafe fn checked_provider_certificate(
    state: &WindowsTrustState,
    value: *mut CRYPT_PROVIDER_CERT,
) -> Result<&CRYPT_PROVIDER_CERT, NativeTrustFailure> {
    unsafe { checked_native_struct(state, value) }
}

unsafe fn checked_native_struct<T>(
    _state: &WindowsTrustState,
    value: *mut T,
) -> Result<&T, NativeTrustFailure> {
    if value.is_null() || !(value as usize).is_multiple_of(align_of::<T>()) {
        return Err(NativeTrustFailure::ProviderExtraction);
    }
    // SAFETY: every provider structure begins with cbStruct. Read only those
    // four bytes before accepting the complete structure contract.
    let observed_size = unsafe { ptr::read(value.cast::<u32>()) };
    if usize::try_from(observed_size).ok() != Some(size_of::<T>()) {
        return Err(NativeTrustFailure::ProviderExtraction);
    }
    // SAFETY: the helper returned a correctly aligned pointer borrowed from
    // `_state`; exact cbStruct now establishes the complete structure shape.
    Ok(unsafe { &*value })
}

unsafe fn checked_certificate_context(
    _state: &WindowsTrustState,
    value: *const CERT_CONTEXT,
) -> Result<&CERT_CONTEXT, NativeTrustFailure> {
    if value.is_null() || !(value as usize).is_multiple_of(align_of::<CERT_CONTEXT>()) {
        return Err(NativeTrustFailure::ProviderExtraction);
    }
    // SAFETY: pointer is borrowed from the validated provider certificate and
    // remains live until CLOSE.
    let value = unsafe { &*value };
    let encoded_len =
        usize::try_from(value.cbCertEncoded).map_err(|_| NativeTrustFailure::ProviderExtraction)?;
    if encoded_len == 0
        || encoded_len > MAX_CERTIFICATE_BYTES
        || value.pbCertEncoded.is_null()
        || value.dwCertEncodingType.0 & X509_ASN_ENCODING.0 == 0
    {
        return Err(NativeTrustFailure::ProviderExtraction);
    }
    Ok(value)
}

unsafe fn checked_certificate_info(
    _state: &WindowsTrustState,
    value: *mut CERT_INFO,
) -> Result<&CERT_INFO, NativeTrustFailure> {
    if value.is_null() || !(value as usize).is_multiple_of(align_of::<CERT_INFO>()) {
        return Err(NativeTrustFailure::ProviderExtraction);
    }
    // SAFETY: pCertInfo belongs to the validated live certificate context.
    Ok(unsafe { &*value })
}

fn spki_digest(info: &CERT_INFO) -> Result<TrustDigest, NativeTrustFailure> {
    let mut encoded_len = 0_u32;
    // SAFETY: SubjectPublicKeyInfo is embedded in the live CERT_INFO. A null
    // output performs the documented size query and no pointer escapes.
    unsafe {
        CryptEncodeObjectEx(
            X509_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO,
            ptr::from_ref(&info.SubjectPublicKeyInfo).cast(),
            CRYPT_ENCODE_OBJECT_FLAGS(0),
            None,
            None,
            ptr::from_mut(&mut encoded_len),
        )
    }
    .map_err(|_| NativeTrustFailure::ProviderExtraction)?;
    let capacity = validate_spki_lengths(encoded_len, encoded_len)?;
    let mut encoded = Zeroizing::new(vec![0_u8; capacity]);
    let mut written = encoded_len;
    // SAFETY: the initialized output allocation is exactly the bounded size
    // returned by the first call and remains exclusively borrowed.
    unsafe {
        CryptEncodeObjectEx(
            X509_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO,
            ptr::from_ref(&info.SubjectPublicKeyInfo).cast(),
            CRYPT_ENCODE_OBJECT_FLAGS(0),
            None,
            Some(encoded.as_mut_ptr().cast()),
            ptr::from_mut(&mut written),
        )
    }
    .map_err(|_| NativeTrustFailure::ProviderExtraction)?;
    let written = validate_spki_lengths(encoded_len, written)?;
    let digest: [u8; 32] = Sha256::digest(&encoded[..written]).into();
    TrustDigest::from_bytes(digest).map_err(|_| NativeTrustFailure::ProviderExtraction)
}

fn validate_spki_lengths(required: u32, written: u32) -> Result<usize, NativeTrustFailure> {
    let required = usize::try_from(required).map_err(|_| NativeTrustFailure::ProviderExtraction)?;
    let written = usize::try_from(written).map_err(|_| NativeTrustFailure::ProviderExtraction)?;
    if required == 0 || required > MAX_SPKI_DER_BYTES || written == 0 || written > required {
        return Err(NativeTrustFailure::ProviderExtraction);
    }
    Ok(written)
}

fn checked_struct_size<T>() -> Result<u32, NativeTrustFailure> {
    u32::try_from(size_of::<T>()).map_err(|_| NativeTrustFailure::VerifyBegin)
}

fn query_creation_time(process: HANDLE) -> Result<u64, NativeTrustFailure> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all FILETIME out parameters are initialized and writable; the
    // duplicated process handle remains live for the entire call.
    unsafe {
        GetProcessTimes(
            process,
            ptr::from_mut(&mut creation),
            ptr::from_mut(&mut exit),
            ptr::from_mut(&mut kernel),
            ptr::from_mut(&mut user),
        )
    }
    .map_err(|_| NativeTrustFailure::PathObservation)?;
    let value = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    if value == 0 {
        Err(NativeTrustFailure::PathObservation)
    } else {
        Ok(value)
    }
}

fn query_process_image_path(process: HANDLE) -> Result<PathBuf, NativeTrustFailure> {
    let mut buffer = Zeroizing::new(vec![0_u16; MAX_NATIVE_PATH_UNITS]);
    let mut length =
        u32::try_from(buffer.len()).map_err(|_| NativeTrustFailure::PathObservation)?;
    // SAFETY: the initialized buffer and in/out count remain live; the process
    // handle has already been duplicated and process-bound by the adapter.
    unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            ptr::from_mut(&mut length),
        )
    }
    .map_err(|_| NativeTrustFailure::PathObservation)?;
    let length = usize::try_from(length).map_err(|_| NativeTrustFailure::PathObservation)?;
    if length == 0 || length >= buffer.len() || buffer[..length].contains(&0) {
        return Err(NativeTrustFailure::PathObservation);
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..length])))
}

fn validate_absolute_path(path: &Path) -> Result<(), NativeTrustFailure> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(NativeTrustFailure::PathObservation);
    }
    let _ = wide_path(path)?;
    Ok(())
}

fn wide_path(path: &Path) -> Result<Vec<u16>, NativeTrustFailure> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.is_empty() || wide.len() >= MAX_NATIVE_PATH_UNITS || wide.contains(&0) {
        return Err(NativeTrustFailure::PathObservation);
    }
    wide.push(0);
    Ok(wide)
}

fn path_from_wide(wide: &[u16]) -> Result<PathBuf, NativeTrustFailure> {
    let Some((&0, value)) = wide.split_last() else {
        return Err(NativeTrustFailure::PathObservation);
    };
    if value.is_empty() || value.contains(&0) {
        return Err(NativeTrustFailure::PathObservation);
    }
    let path = PathBuf::from(OsString::from_wide(value));
    validate_absolute_path(&path)?;
    Ok(path)
}

fn share_all() -> FILE_SHARE_MODE {
    FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
}

fn verification_share() -> FILE_SHARE_MODE {
    // Read sharing is needed by WinTrust/version providers. Omitting write and
    // delete sharing prevents in-place writes, replacement, and rename for as
    // long as the verification and ancestor guard handles remain open.
    FILE_SHARE_MODE(FILE_SHARE_READ.0)
}

fn open_regular_file_no_follow(path: &Path) -> Result<OwnedNativeHandle, NativeTrustFailure> {
    let wide = wide_path(path)?;
    open_regular_file_no_follow_wide(&wide)
}

fn open_regular_file_no_follow_wide(wide: &[u16]) -> Result<OwnedNativeHandle, NativeTrustFailure> {
    open_regular_file_no_follow_with_share(wide, share_all())
}

fn open_guarded_regular_file_no_follow(
    path: &Path,
) -> Result<OwnedNativeHandle, NativeTrustFailure> {
    let wide = wide_path(path)?;
    open_regular_file_no_follow_with_share(&wide, verification_share())
}

fn open_regular_file_no_follow_with_share(
    wide: &[u16],
    share: FILE_SHARE_MODE,
) -> Result<OwnedNativeHandle, NativeTrustFailure> {
    if wide.len() < 2 || wide.len() > MAX_NATIVE_PATH_UNITS || wide.last() != Some(&0) {
        return Err(NativeTrustFailure::PathObservation);
    }
    // SAFETY: the path is a bounded NUL-terminated allocation. OPEN_REPARSE_POINT
    // prevents following the final component; all sharing modes avoid
    // disturbing the running executable.
    unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_READ.0 | FILE_READ_ATTRIBUTES.0,
            share,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map(OwnedNativeHandle)
    .map_err(|_| NativeTrustFailure::PathObservation)
}

fn open_directory_no_follow(path: &Path) -> Result<OwnedNativeHandle, NativeTrustFailure> {
    let wide = wide_path(path)?;
    // SAFETY: the absolute bounded path is NUL terminated. BACKUP_SEMANTICS
    // permits directory handles and OPEN_REPARSE_POINT inspects, never follows,
    // the final component.
    unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            verification_share(),
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map(OwnedNativeHandle)
    .map_err(|_| NativeTrustFailure::PathObservation)
}

fn file_attribute_tags(
    handle: &OwnedNativeHandle,
) -> Result<FILE_ATTRIBUTE_TAG_INFO, NativeTrustFailure> {
    if unsafe { GetFileType(handle.raw()) } != FILE_TYPE_DISK {
        return Err(NativeTrustFailure::PathObservation);
    }
    let mut tags = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: `tags` is initialized and writable and the owned handle remains
    // live for the synchronous query.
    unsafe {
        GetFileInformationByHandleEx(
            handle.raw(),
            FileAttributeTagInfo,
            ptr::from_mut(&mut tags).cast(),
            u32::try_from(size_of_val(&tags)).map_err(|_| NativeTrustFailure::PathObservation)?,
        )
    }
    .map_err(|_| NativeTrustFailure::PathObservation)?;
    Ok(tags)
}

fn validate_regular_file_handle(handle: &OwnedNativeHandle) -> Result<(), NativeTrustFailure> {
    let tags = file_attribute_tags(handle)?;
    if tags.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
        || tags.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
    {
        return Err(NativeTrustFailure::PathObservation);
    }
    Ok(())
}

fn validate_directory_handle(handle: &OwnedNativeHandle) -> Result<(), NativeTrustFailure> {
    let tags = file_attribute_tags(handle)?;
    if tags.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
        || tags.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
    {
        return Err(NativeTrustFailure::PathObservation);
    }
    Ok(())
}

fn open_reparse_free_parent_chain(
    path: &Path,
) -> Result<Vec<OwnedNativeHandle>, NativeTrustFailure> {
    let parent = path.parent().ok_or(NativeTrustFailure::PathObservation)?;
    let ancestors: Vec<&Path> = parent
        .ancestors()
        .filter(|value| !value.as_os_str().is_empty())
        .collect();
    if ancestors.is_empty() || ancestors.len() > MAX_PATH_ANCESTORS {
        return Err(NativeTrustFailure::PathObservation);
    }
    let mut guards = Vec::with_capacity(ancestors.len());
    for ancestor in ancestors.into_iter().rev() {
        let handle = open_directory_no_follow(ancestor)?;
        validate_directory_handle(&handle)?;
        guards.push(handle);
    }
    Ok(guards)
}

fn canonical_file_path(handle: &OwnedNativeHandle) -> Result<PathBuf, NativeTrustFailure> {
    let flags = GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_GUID.0);
    // SAFETY: a zero-length output requests the exact path buffer size for the
    // live file handle.
    let required = unsafe { GetFinalPathNameByHandleW(handle.raw(), &mut [], flags) };
    let required = usize::try_from(required).map_err(|_| NativeTrustFailure::PathObservation)?;
    if required == 0 || required >= MAX_NATIVE_PATH_UNITS {
        return Err(NativeTrustFailure::PathObservation);
    }
    let mut buffer = Zeroizing::new(vec![0_u16; required]);
    // SAFETY: the initialized buffer has the exact bounded size requested and
    // is uniquely borrowed for the call.
    let written = unsafe { GetFinalPathNameByHandleW(handle.raw(), &mut buffer, flags) };
    let written = usize::try_from(written).map_err(|_| NativeTrustFailure::PathObservation)?;
    if written == 0 || written >= buffer.len() || buffer[written] != 0 {
        return Err(NativeTrustFailure::PathObservation);
    }
    buffer.truncate(written);
    if buffer.contains(&0) || volume_guid_root(&buffer).is_none() {
        return Err(NativeTrustFailure::PathObservation);
    }
    let path = PathBuf::from(OsString::from_wide(&buffer));
    validate_absolute_path(&path)?;
    Ok(path)
}

fn is_fixed_local_volume(path: &Path) -> Result<bool, NativeTrustFailure> {
    let path_wide = wide_path(path)?;
    let expected_root = volume_guid_root(&path_wide[..path_wide.len() - 1])
        .ok_or(NativeTrustFailure::PathObservation)?;
    let mut root = [0_u16; MAX_VOLUME_ROOT_UNITS];
    // SAFETY: both buffers are bounded, initialized, and NUL terminated within
    // their live allocations.
    unsafe { GetVolumePathNameW(PCWSTR(path_wide.as_ptr()), &mut root) }
        .map_err(|_| NativeTrustFailure::PathObservation)?;
    let root_len = root
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(NativeTrustFailure::PathObservation)?;
    if root_len == 0 || !ascii_units_equal(&root[..root_len], expected_root) {
        return Ok(false);
    }
    Ok(unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) } == DRIVE_FIXED_VALUE)
}

fn volume_guid_root(units: &[u16]) -> Option<&[u16]> {
    const GUID_CHARS: usize = 36;
    let prefix: Vec<u16> = r"\\?\Volume{".encode_utf16().collect();
    if units.len() < prefix.len() + GUID_CHARS + 2
        || !ascii_units_equal(&units[..prefix.len()], &prefix)
    {
        return None;
    }
    let guid = &units[prefix.len()..prefix.len() + GUID_CHARS];
    for (index, unit) in guid.iter().copied().enumerate() {
        let valid = if matches!(index, 8 | 13 | 18 | 23) {
            unit == u16::from(b'-')
        } else {
            matches!(unit, 0x30..=0x39 | 0x41..=0x46 | 0x61..=0x66)
        };
        if !valid {
            return None;
        }
    }
    let suffix = prefix.len() + GUID_CHARS;
    if units[suffix] != u16::from(b'}') || units[suffix + 1] != u16::from(b'\\') {
        return None;
    }
    Some(&units[..suffix + 2])
}

fn ascii_units_equal(left: &[u16], right: &[u16]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| ascii_lower(*left) == ascii_lower(*right))
}

fn ascii_lower(value: u16) -> u16 {
    if (u16::from(b'A')..=u16::from(b'Z')).contains(&value) {
        value + u16::from(b'a' - b'A')
    } else {
        value
    }
}

fn file_identity(
    handle: &OwnedNativeHandle,
    process_creation_time_100ns: u64,
) -> Result<FileIdentity, NativeTrustFailure> {
    let mut native = FILE_ID_INFO::default();
    // SAFETY: the initialized fixed-size output remains writable and the file
    // handle is owned for the entire synchronous query.
    unsafe {
        GetFileInformationByHandleEx(
            handle.raw(),
            FileIdInfo,
            ptr::from_mut(&mut native).cast(),
            u32::try_from(size_of_val(&native)).map_err(|_| NativeTrustFailure::PathObservation)?,
        )
    }
    .map_err(|_| NativeTrustFailure::PathObservation)?;
    if native.VolumeSerialNumber == 0 || native.FileId.Identifier == [0; 16] {
        return Err(NativeTrustFailure::PathObservation);
    }
    let digest = file_identity_digest(
        native.VolumeSerialNumber,
        &native.FileId.Identifier,
        process_creation_time_100ns,
    );
    FileIdentity::from_bytes(digest).map_err(|_| NativeTrustFailure::PathObservation)
}

fn file_identity_digest(
    volume_serial: u64,
    file_id: &[u8; 16],
    process_creation_time_100ns: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FILE_ID_DOMAIN);
    hasher.update(volume_serial.to_le_bytes());
    hasher.update(file_id);
    hasher.update(process_creation_time_100ns.to_le_bytes());
    hasher.finalize().into()
}

fn query_file_version(path: &Path) -> Option<FileVersion> {
    let path = Zeroizing::new(wide_path(path).ok()?);
    let pointer = PCWSTR(path.as_ptr());
    // SAFETY: the NUL-terminated path remains live through all version calls.
    let size = unsafe { GetFileVersionInfoSizeW(pointer, None) };
    if size == 0 || usize::try_from(size).ok()? > MAX_CERTIFICATE_BYTES {
        return None;
    }
    let mut data = Zeroizing::new(vec![0_u8; usize::try_from(size).ok()?]);
    // SAFETY: data is initialized and writable for exactly `size` bytes.
    unsafe { GetFileVersionInfoW(pointer, None, size, data.as_mut_ptr().cast()) }.ok()?;
    let mut fixed = ptr::null_mut::<c_void>();
    let mut fixed_len = 0_u32;
    // SAFETY: the version allocation remains live and the output pointers are
    // checked against that exact allocation before being copied.
    let found = unsafe {
        VerQueryValueW(
            data.as_ptr().cast(),
            w!("\\"),
            ptr::from_mut(&mut fixed),
            ptr::from_mut(&mut fixed_len),
        )
        .as_bool()
    };
    if !found || fixed.is_null() || fixed_len < size_of::<VS_FIXEDFILEINFO>() as u32 {
        return None;
    }
    let allocation_start = data.as_ptr() as usize;
    let allocation_end = allocation_start.checked_add(data.len())?;
    let fixed_start = fixed as usize;
    let fixed_end = fixed_start.checked_add(size_of::<VS_FIXEDFILEINFO>())?;
    if fixed_start < allocation_start || fixed_end > allocation_end {
        return None;
    }
    // SAFETY: the entire structure lies in the live version allocation;
    // read_unaligned avoids relying on resource alignment.
    let fixed = unsafe { ptr::read_unaligned(fixed.cast::<VS_FIXEDFILEINFO>()) };
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use windows::Win32::Foundation::E_FAIL;
    use windows::Win32::System::Com::CoTaskMemAlloc;

    use super::*;

    const SIGNED_FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/windows-authenticode/fixture.exe"
    ));
    const FIXTURE_CERTIFICATE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/windows-authenticode/signer.cer"
    ));
    const FIXTURE_MANIFEST: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/windows-authenticode/build-manifest.toml"
    ));
    const FIXTURE_SHA256_FILE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/windows-authenticode/fixture.exe.sha256"
    ));
    const FIXTURE_SOURCE_C: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/windows-authenticode/source/fixture.c"
    ));
    const FIXTURE_SOURCE_RC: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/windows-authenticode/source/fixture.rc"
    ));
    const FIXTURE_BUILD_SCRIPT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/build-windows-authenticode-fixture.ps1"
    ));
    const SIGNED_FIXTURE_SHA256: [u8; 32] = [
        0xc3, 0x57, 0x08, 0x40, 0xec, 0xb6, 0xa9, 0x47, 0x5a, 0x85, 0xcc, 0x89, 0x1a, 0xb3, 0x9a,
        0xa9, 0x5d, 0x1f, 0xe2, 0x63, 0xc0, 0xbc, 0xcc, 0xd4, 0x2e, 0x2d, 0x09, 0x25, 0x60, 0x79,
        0x38, 0x7f,
    ];
    const FIXTURE_CERTIFICATE_SHA256: [u8; 32] = [
        0x90, 0x66, 0xc5, 0x35, 0x3f, 0xad, 0x59, 0x14, 0x29, 0x65, 0xc5, 0x50, 0xa8, 0xc5, 0x5d,
        0xb7, 0xd3, 0xbe, 0xab, 0x0d, 0x16, 0xec, 0xa0, 0xb7, 0x55, 0x05, 0x44, 0xcd, 0xd4, 0x3e,
        0xba, 0xae,
    ];
    const FIXTURE_SPKI_SHA256: [u8; 32] = [
        0x1e, 0x21, 0xb2, 0x53, 0x43, 0xc9, 0x0c, 0xfc, 0x99, 0x24, 0x4c, 0x16, 0x20, 0x08, 0xb2,
        0xe6, 0xb5, 0x7e, 0xba, 0xd6, 0x31, 0xcd, 0x39, 0xc3, 0x16, 0x94, 0x6f, 0x60, 0x79, 0x90,
        0xb1, 0x90,
    ];
    static SYNTHETIC_KNOWN_FOLDER_RELEASES: AtomicUsize = AtomicUsize::new(0);

    fn allocate_synthetic_known_folder_path(path: &Path) -> PWSTR {
        let wide = wide_path(path).unwrap();
        let allocation_bytes = wide
            .len()
            .checked_mul(size_of::<u16>())
            .expect("synthetic allocation length must fit");
        // SAFETY: the exact nonzero allocation length is checked above and a
        // null result is rejected before the initialized UTF-16 copy.
        let allocation = unsafe { CoTaskMemAlloc(allocation_bytes) };
        assert!(!allocation.is_null());
        // SAFETY: the destination has exactly allocation_bytes writable bytes
        // and the source contains wide.len() initialized u16 values.
        unsafe {
            ptr::copy_nonoverlapping(wide.as_ptr(), allocation.cast::<u16>(), wide.len());
        }
        PWSTR(allocation.cast::<u16>())
    }

    unsafe fn release_synthetic_known_folder_path(raw_path: *const c_void) {
        assert!(!raw_path.is_null());
        SYNTHETIC_KNOWN_FOLDER_RELEASES.fetch_add(1, Ordering::SeqCst);
        // SAFETY: tests pass only allocations returned by CoTaskMemAlloc and
        // ownership moves into exactly one OwnedTrustKnownFolderPath.
        unsafe { CoTaskMemFree(Some(raw_path)) };
    }

    fn resolve_synthetic_known_folder_result(
        status: HRESULT,
        raw_path: PWSTR,
    ) -> Result<PathBuf, NativeTrustFailure> {
        // SAFETY: every non-null pointer is returned by the synthetic
        // CoTaskMem allocator above, is NUL terminated, and uses its matching
        // counting CoTaskMem release. NULL has no allocation invariant.
        unsafe {
            resolve_known_folder_result(status, raw_path, release_synthetic_known_folder_path)
        }
    }

    fn fixture_u16(offset: usize) -> u16 {
        let bytes: [u8; 2] = fixture_slice(offset, 2).try_into().unwrap();
        u16::from_le_bytes(bytes)
    }

    fn fixture_u32(offset: usize) -> u32 {
        let bytes: [u8; 4] = fixture_slice(offset, 4).try_into().unwrap();
        u32::from_le_bytes(bytes)
    }

    fn fixture_slice(offset: usize, length: usize) -> &'static [u8] {
        let end = offset
            .checked_add(length)
            .expect("fixture range must not overflow");
        SIGNED_FIXTURE
            .get(offset..end)
            .expect("fixture range must be in bounds")
    }

    struct OwnedFixtureCertificateContext(*mut CERT_CONTEXT);

    impl Drop for OwnedFixtureCertificateContext {
        fn drop(&mut self) {
            // SAFETY: this pointer came from CertCreateCertificateContext and
            // ownership is released exactly once by this guard.
            let released = unsafe { CertFreeCertificateContext(Some(self.0)) };
            debug_assert!(released.as_bool());
        }
    }

    #[test]
    fn repository_fixture_is_exact_bounded_signed_pe_without_execution() {
        const PE32_PLUS_MAGIC: u16 = 0x020b;
        const OPTIONAL_HEADER_DATA_DIRECTORIES: usize = 112;
        const NUMBER_OF_RVA_AND_SIZES: usize = 108;
        const SECURITY_DIRECTORY_INDEX: usize = 4;
        const WIN_CERT_REVISION_2_0: u16 = 0x0200;
        const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

        let fixture_digest: [u8; 32] = Sha256::digest(SIGNED_FIXTURE).into();
        let certificate_digest: [u8; 32] = Sha256::digest(FIXTURE_CERTIFICATE).into();
        assert_eq!(fixture_digest, SIGNED_FIXTURE_SHA256);
        assert_eq!(certificate_digest, FIXTURE_CERTIFICATE_SHA256);

        let manifest: toml::Value = toml::from_str(FIXTURE_MANIFEST).unwrap();
        let manifest_string = |key: &str| {
            manifest
                .get(key)
                .and_then(toml::Value::as_str)
                .expect("fixture manifest string must exist")
        };
        assert_eq!(
            manifest
                .get("schema_version")
                .and_then(toml::Value::as_integer),
            Some(1)
        );
        assert_eq!(
            manifest
                .get("signature_count")
                .and_then(toml::Value::as_integer),
            Some(1)
        );
        assert_eq!(
            manifest.get("timestamped").and_then(toml::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            manifest_string("private_key_retention"),
            "not_retained_after_signing"
        );
        assert_eq!(
            manifest_string("fixture_sha256"),
            hex::encode(fixture_digest)
        );
        assert_eq!(
            manifest_string("certificate_sha256"),
            hex::encode(certificate_digest)
        );
        assert_eq!(
            manifest_string("leaf_spki_sha256"),
            hex::encode(FIXTURE_SPKI_SHA256)
        );
        assert_eq!(
            manifest_string("source_c_sha256"),
            hex::encode(Sha256::digest(FIXTURE_SOURCE_C))
        );
        assert_eq!(
            manifest_string("source_rc_sha256"),
            hex::encode(Sha256::digest(FIXTURE_SOURCE_RC))
        );
        assert_eq!(
            manifest_string("build_script_sha256"),
            hex::encode(Sha256::digest(FIXTURE_BUILD_SCRIPT))
        );
        assert_eq!(
            FIXTURE_SHA256_FILE,
            format!("{}  fixture.exe\n", hex::encode(fixture_digest))
        );

        assert_eq!(fixture_slice(0, 2), b"MZ");
        let pe_offset = usize::try_from(fixture_u32(0x3c)).unwrap();
        assert_eq!(fixture_slice(pe_offset, 4), b"PE\0\0");

        let optional_header_offset = pe_offset.checked_add(24).unwrap();
        let optional_header_size = usize::from(fixture_u16(pe_offset.checked_add(20).unwrap()));
        let optional_header_end = optional_header_offset
            .checked_add(optional_header_size)
            .unwrap();
        fixture_slice(optional_header_offset, optional_header_size);
        assert_eq!(fixture_u16(optional_header_offset), PE32_PLUS_MAGIC);
        assert!(fixture_u32(optional_header_offset + NUMBER_OF_RVA_AND_SIZES) > 4);

        let security_directory_offset = optional_header_offset
            .checked_add(OPTIONAL_HEADER_DATA_DIRECTORIES)
            .and_then(|offset| offset.checked_add(SECURITY_DIRECTORY_INDEX * 8))
            .unwrap();
        assert!(security_directory_offset + 8 <= optional_header_end);
        let certificate_table_offset =
            usize::try_from(fixture_u32(security_directory_offset)).unwrap();
        let certificate_table_size =
            usize::try_from(fixture_u32(security_directory_offset + 4)).unwrap();
        assert_ne!(certificate_table_size, 0);
        assert_eq!(certificate_table_offset % 8, 0);
        let certificate_table = fixture_slice(certificate_table_offset, certificate_table_size);
        assert_eq!(
            certificate_table_offset + certificate_table_size,
            SIGNED_FIXTURE.len()
        );

        let certificate_length = usize::try_from(fixture_u32(certificate_table_offset)).unwrap();
        assert!((8..=certificate_table.len()).contains(&certificate_length));
        assert_eq!(
            fixture_u16(certificate_table_offset + 4),
            WIN_CERT_REVISION_2_0
        );
        assert_eq!(
            fixture_u16(certificate_table_offset + 6),
            WIN_CERT_TYPE_PKCS_SIGNED_DATA
        );
        let aligned_certificate_length = certificate_length.checked_add(7).unwrap() & !7;
        assert_eq!(aligned_certificate_length, certificate_table.len());
        assert!(certificate_table[certificate_length..]
            .iter()
            .all(|byte| *byte == 0));

        // SAFETY: the committed DER allocation remains live for the call; the
        // returned independent context is checked and immediately owned.
        let certificate_context =
            unsafe { CertCreateCertificateContext(X509_ASN_ENCODING, FIXTURE_CERTIFICATE) };
        assert!(!certificate_context.is_null());
        let certificate_context = OwnedFixtureCertificateContext(certificate_context);
        // SAFETY: the owning guard keeps the context live and the API promises
        // a valid CERT_CONTEXT with a valid pCertInfo on success.
        let certificate_info = unsafe { (*certificate_context.0).pCertInfo.as_ref() }
            .expect("fixture certificate info must exist");
        let observed_spki = spki_digest(certificate_info).unwrap();
        let expected_spki = TrustDigest::from_bytes(FIXTURE_SPKI_SHA256).unwrap();
        assert_eq!(observed_spki, expected_spki);
    }

    #[test]
    fn repository_fixture_wintrust_state_is_offline_and_closed_once() {
        let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("windows-authenticode")
            .join("fixture.exe");
        validate_absolute_path(&fixture_path).unwrap();

        let _source_parent_guards = open_reparse_free_parent_chain(&fixture_path).unwrap();
        let process_image_file = open_regular_file_no_follow(&fixture_path).unwrap();
        validate_regular_file_handle(&process_image_file).unwrap();
        let canonical_path = canonical_file_path(&process_image_file).unwrap();
        assert!(is_fixed_local_volume(&canonical_path).unwrap());
        let canonical_parent_guards = open_reparse_free_parent_chain(&canonical_path).unwrap();
        let verification_file = open_guarded_regular_file_no_follow(&canonical_path).unwrap();
        validate_regular_file_handle(&verification_file).unwrap();
        assert_eq!(
            canonical_file_path(&verification_file).unwrap(),
            canonical_path
        );
        let runtime_fixture = std::fs::read(&canonical_path).unwrap();
        let runtime_digest: [u8; 32] = Sha256::digest(&runtime_fixture).into();
        assert_eq!(runtime_digest, SIGNED_FIXTURE_SHA256);

        let identity = file_identity(&verification_file, 1).unwrap();
        assert_eq!(file_identity(&process_image_file, 1).unwrap(), identity);
        let fixture_parent = canonical_path.parent().unwrap();
        let known_folder_parent_guards = open_reparse_free_parent_chain(fixture_parent).unwrap();
        let known_folder_root = open_directory_no_follow(fixture_parent).unwrap();
        validate_directory_handle(&known_folder_root).unwrap();
        let canonical_known_folder = canonical_file_path(&known_folder_root).unwrap();
        let path_state = WindowsPathState {
            process_image_file,
            verification_file,
            _canonical_parent_guards: canonical_parent_guards,
            known_folder_root,
            _known_folder_parent_guards: known_folder_parent_guards,
            canonical_path: Zeroizing::new(wide_path(&canonical_path).unwrap()),
            canonical_known_folder: Zeroizing::new(wide_path(&canonical_known_folder).unwrap()),
            identity,
        };
        validate_known_folder_binding(&path_state).unwrap();

        let policy = WinTrustCallPolicy::offline_embedded();
        assert!(policy.is_exact());
        let mut trust_state = WindowsTrustState::new(&path_state, policy).unwrap();
        assert!(trust_state.debug_invariants());
        trust_state.verify(policy);
        assert!(trust_state.verify_attempted);
        assert!(!trust_state.close_attempted);
        assert_ne!(trust_state.verify_status, i32::MIN);
        assert!(trust_state.debug_invariants());

        let observation = extract_windows_authenticode(&trust_state).unwrap();
        assert!(!observation.catalog_choice_used);
        assert_eq!(observation.secondary_signature_count, 0);
        if observation.winverifytrust_status == 0 {
            assert_eq!(observation.primary_signer_count, 1);
            assert_eq!(
                observation.signer_digest,
                Some(TrustDigest::from_bytes(FIXTURE_SPKI_SHA256).unwrap())
            );
        } else {
            assert_eq!(observation.primary_signer_count, 0);
            assert_eq!(observation.signer_digest, None);
        }

        trust_state.close_once(policy).unwrap();
        assert!(trust_state.close_attempted);
        assert_eq!(
            trust_state.close_once(policy),
            Err(NativeTrustFailure::StateClose)
        );
    }

    static SYNTHETIC_SIGNER_BYTES: [u8; 32] = [1; 32];
    static SYNTHETIC_ROOT_RELATION: &[&str] = &["SyntheticVendor", "SyntheticApp", "Synthetic.exe"];

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum PanicAt {
        Observe,
        Begin,
        Extract,
        Close,
        Reopen,
    }

    struct FakeApi {
        path: Result<NativePathObservation, NativeTrustFailure>,
        authenticode: Result<NativeAuthenticodeObservation, NativeTrustFailure>,
        begin_error: Option<NativeTrustFailure>,
        close_error: Option<NativeTrustFailure>,
        reopen_error: Option<NativeTrustFailure>,
        reopened_identity: Option<FileIdentity>,
        panic_at: Option<PanicAt>,
        calls: Vec<&'static str>,
        policy: Option<WinTrustCallPolicy>,
        root_kind: Option<InstallRootKind>,
        closes: usize,
    }

    impl NativeExecutableTrustApi for FakeApi {
        type PathState = u64;
        type TrustState = u64;

        fn observe_path(
            &mut self,
            install_root_kind: InstallRootKind,
        ) -> Result<(Self::PathState, NativePathObservation), NativeTrustFailure> {
            self.calls.push("observe");
            self.root_kind = Some(install_root_kind);
            if self.panic_at == Some(PanicAt::Observe) {
                panic!("synthetic observe panic");
            }
            self.path.map(|observation| (11, observation))
        }

        fn begin_authenticode(
            &mut self,
            path: &Self::PathState,
            policy: WinTrustCallPolicy,
        ) -> Result<Self::TrustState, NativeTrustFailure> {
            self.calls.push("begin");
            assert_eq!(*path, 11);
            self.policy = Some(policy);
            if self.panic_at == Some(PanicAt::Begin) {
                panic!("synthetic begin panic");
            }
            if let Some(error) = self.begin_error {
                Err(error)
            } else {
                Ok(7)
            }
        }

        fn extract_authenticode(
            &mut self,
            state: &Self::TrustState,
        ) -> Result<NativeAuthenticodeObservation, NativeTrustFailure> {
            self.calls.push("extract");
            assert_eq!(*state, 7);
            if self.panic_at == Some(PanicAt::Extract) {
                panic!("synthetic extract panic");
            }
            self.authenticode
        }

        fn close_authenticode(
            &mut self,
            state: Self::TrustState,
            policy: WinTrustCallPolicy,
        ) -> Result<(), NativeTrustFailure> {
            self.calls.push("close");
            self.closes += 1;
            assert_eq!(state, 7);
            assert!(policy.is_exact());
            if self.panic_at == Some(PanicAt::Close) {
                panic!("synthetic close panic");
            }
            self.close_error.map_or(Ok(()), Err)
        }

        fn reopen_file_identity(
            &mut self,
            path: &Self::PathState,
        ) -> Result<Option<FileIdentity>, NativeTrustFailure> {
            self.calls.push("reopen");
            assert_eq!(*path, 11);
            if self.panic_at == Some(PanicAt::Reopen) {
                panic!("synthetic reopen panic");
            }
            self.reopen_error.map_or(Ok(self.reopened_identity), Err)
        }
    }

    fn digest(value: u8) -> TrustDigest {
        TrustDigest::from_bytes([value; 32]).unwrap()
    }

    fn identity(value: u8) -> FileIdentity {
        FileIdentity::from_bytes([value; 32]).unwrap()
    }

    fn profile() -> ExecutableTrustProfile {
        ExecutableTrustProfile::new(FileVersion::KNOWN, reviewed_signer(), root_digest()).unwrap()
    }

    fn reviewed_signer() -> ReviewedSignerDigest {
        ReviewedSignerDigest::from_static_reviewed_bytes(&SYNTHETIC_SIGNER_BYTES).unwrap()
    }

    fn root_digest() -> InstallRootDigest {
        InstallRootDigest::from_static_reviewed_relation(
            InstallRootKind::ProgramFilesX86,
            SYNTHETIC_ROOT_RELATION,
        )
        .unwrap()
    }

    fn path() -> NativePathObservation {
        NativePathObservation {
            final_path_source: FinalPathSource::OpenedProcessImageHandle,
            path_is_absolute_and_normalized: true,
            volume_kind: VolumeKind::FixedLocal,
            reparse_state: ReparseState::Absent,
            process_image_handle_bound: true,
            process_creation_time_bound: true,
            process_file_identity: Some(identity(3)),
            verified_file_identity: Some(identity(3)),
            version: Some(FileVersion::KNOWN),
            install_root_digest: Some(root_digest().trust_digest()),
        }
    }

    fn authenticode() -> NativeAuthenticodeObservation {
        NativeAuthenticodeObservation {
            winverifytrust_status: 0,
            catalog_choice_used: false,
            primary_signer_count: 1,
            secondary_signature_count: 0,
            signer_digest: Some(digest(1)),
        }
    }

    fn api() -> FakeApi {
        FakeApi {
            path: Ok(path()),
            authenticode: Ok(authenticode()),
            begin_error: None,
            close_error: None,
            reopen_error: None,
            reopened_identity: Some(identity(3)),
            panic_at: None,
            calls: Vec::new(),
            policy: None,
            root_kind: None,
            closes: 0,
        }
    }

    fn run(api: FakeApi) -> (Result<(), UiError>, FakeApi) {
        let mut observer = NativeExecutableTrustObserver::new(profile(), api);
        let result = observer.verify_executable_trust();
        (result, observer.into_api())
    }

    fn inert_windows_state() -> WindowsTrustState {
        let file_path = Zeroizing::new(vec![b'C' as u16, b':' as u16, b'\\' as u16, 0]);
        let file_handle = OwnedNativeHandle(HANDLE::default());
        let mut file_info = Box::new(WINTRUST_FILE_INFO::default());
        file_info.cbStruct = size_of::<WINTRUST_FILE_INFO>() as u32;
        file_info.pcwszFilePath = PCWSTR(file_path.as_ptr());
        file_info.hFile = file_handle.raw();
        let mut signature_settings = Box::new(WINTRUST_SIGNATURE_SETTINGS::default());
        signature_settings.cbStruct = size_of::<WINTRUST_SIGNATURE_SETTINGS>() as u32;
        signature_settings.dwFlags = WSS_GET_SECONDARY_SIG_COUNT;
        let mut data = Box::new(WINTRUST_DATA::default());
        data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous = WINTRUST_DATA_0 {
            pFile: ptr::from_mut(&mut *file_info),
        };
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL
            | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
            | WTD_DISABLE_MD2_MD4;
        data.dwUIContext = WTD_UICONTEXT_EXECUTE;
        data.pSignatureSettings = ptr::from_mut(&mut *signature_settings);
        WindowsTrustState {
            action: Box::new(WINTRUST_ACTION_GENERIC_VERIFY_V2),
            file_path,
            file_handle,
            file_info,
            signature_settings,
            data,
            verify_status: i32::MIN,
            verify_attempted: false,
            close_attempted: false,
        }
    }

    #[test]
    fn exact_evidence_uses_fixed_policy_and_closes_state_once() {
        let (result, api) = run(api());
        result.unwrap();
        assert_eq!(
            api.calls,
            ["observe", "begin", "extract", "close", "reopen"]
        );
        assert_eq!(api.closes, 1);
        assert!(api.policy.unwrap().is_exact());
        assert_eq!(api.root_kind, Some(InstallRootKind::ProgramFilesX86));
    }

    #[test]
    fn path_or_begin_failure_never_invents_a_state_to_close() {
        let mut path_error = api();
        path_error.path = Err(NativeTrustFailure::PathObservation);
        let (result, path_error) = run(path_error);
        assert_eq!(
            result.unwrap_err().operation,
            "windows_executable_path_trust"
        );
        assert_eq!(path_error.calls, ["observe"]);
        assert_eq!(path_error.closes, 0);

        let mut begin_error = api();
        begin_error.begin_error = Some(NativeTrustFailure::VerifyBegin);
        let (result, begin_error) = run(begin_error);
        assert_eq!(
            result.unwrap_err().operation,
            "windows_executable_signature_trust"
        );
        assert_eq!(begin_error.calls, ["observe", "begin"]);
        assert_eq!(begin_error.closes, 0);
    }

    #[test]
    fn extraction_error_or_panic_always_closes_once() {
        let mut extraction_error = api();
        extraction_error.authenticode = Err(NativeTrustFailure::ProviderExtraction);
        let (result, extraction_error) = run(extraction_error);
        assert_eq!(
            result.unwrap_err().operation,
            "windows_executable_signature_trust"
        );
        assert_eq!(extraction_error.closes, 1);
        assert_eq!(
            extraction_error.calls,
            ["observe", "begin", "extract", "close"]
        );

        let mut extraction_panic = api();
        extraction_panic.panic_at = Some(PanicAt::Extract);
        let (result, extraction_panic) = run(extraction_panic);
        assert_eq!(
            result.unwrap_err().operation,
            "windows_executable_signature_trust"
        );
        assert_eq!(extraction_panic.closes, 1);
    }

    #[test]
    fn close_error_or_panic_overrides_apparent_success() {
        let mut close_error = api();
        close_error.close_error = Some(NativeTrustFailure::StateClose);
        let (result, close_error) = run(close_error);
        assert_eq!(
            result.unwrap_err().operation,
            "windows_executable_signature_trust"
        );
        assert_eq!(close_error.closes, 1);

        let mut close_panic = api();
        close_panic.panic_at = Some(PanicAt::Close);
        let (result, close_panic) = run(close_panic);
        assert_eq!(
            result.unwrap_err().operation,
            "windows_executable_signature_trust"
        );
        assert_eq!(close_panic.closes, 1);
    }

    #[test]
    fn observe_or_begin_panic_is_sanitized_without_close() {
        for panic_at in [PanicAt::Observe, PanicAt::Begin] {
            let mut fake = api();
            fake.panic_at = Some(panic_at);
            let (result, fake) = run(fake);
            let expected = if panic_at == PanicAt::Observe {
                "windows_executable_path_trust"
            } else {
                "windows_executable_signature_trust"
            };
            assert_eq!(result.unwrap_err().operation, expected);
            assert_eq!(fake.closes, 0);
        }
    }

    #[test]
    fn reopened_identity_error_or_panic_refuses_after_close() {
        let mut reopen_error = api();
        reopen_error.reopen_error = Some(NativeTrustFailure::ReopenedIdentity);
        let (result, reopen_error) = run(reopen_error);
        let error = result.unwrap_err();
        assert_eq!(error.kind, UiErrorKind::StaleSnapshot);
        assert_eq!(error.operation, "windows_executable_file_identity");
        assert_eq!(reopen_error.closes, 1);
        assert_eq!(
            reopen_error.calls,
            ["observe", "begin", "extract", "close", "reopen"]
        );

        let mut reopen_panic = api();
        reopen_panic.panic_at = Some(PanicAt::Reopen);
        let (result, reopen_panic) = run(reopen_panic);
        let error = result.unwrap_err();
        assert_eq!(error.kind, UiErrorKind::StaleSnapshot);
        assert_eq!(error.operation, "windows_executable_file_identity");
        assert_eq!(reopen_panic.closes, 1);
    }

    #[test]
    fn nonzero_status_catalog_or_secondary_signature_refuses_after_close() {
        let mut cases = Vec::new();
        let mut nonzero = authenticode();
        nonzero.winverifytrust_status = 1;
        cases.push(nonzero);
        let mut catalog = authenticode();
        catalog.catalog_choice_used = true;
        cases.push(catalog);
        let mut secondary = authenticode();
        secondary.secondary_signature_count = 1;
        cases.push(secondary);

        for observation in cases {
            let mut fake = api();
            fake.authenticode = Ok(observation);
            let (result, fake) = run(fake);
            assert_eq!(
                result.unwrap_err().operation,
                "windows_executable_signature_trust"
            );
            assert_eq!(fake.closes, 1);
        }
    }

    #[test]
    fn signer_cardinality_digest_and_path_replacement_are_exact() {
        let mut no_signer = api();
        no_signer
            .authenticode
            .as_mut()
            .unwrap()
            .primary_signer_count = 0;
        let (result, fake) = run(no_signer);
        assert_eq!(result.unwrap_err().operation, "windows_executable_signer");
        assert_eq!(fake.closes, 1);

        let mut wrong_signer = api();
        wrong_signer.authenticode.as_mut().unwrap().signer_digest = Some(digest(9));
        let (result, fake) = run(wrong_signer);
        assert_eq!(result.unwrap_err().operation, "windows_executable_signer");
        assert_eq!(fake.closes, 1);

        let mut replaced = api();
        replaced.reopened_identity = Some(identity(8));
        let (result, fake) = run(replaced);
        assert_eq!(
            result.unwrap_err().operation,
            "windows_executable_file_identity"
        );
        assert_eq!(fake.closes, 1);
    }

    #[test]
    fn all_debug_surfaces_are_content_free_and_redacted() {
        let canary = "PRIVATE_PATH_SIGNER_CANARY";
        let rendered = format!(
            "{:?} {:?} {:?}",
            WinTrustCallPolicy::offline_embedded(),
            path(),
            authenticode()
        );
        assert!(!rendered.contains(canary));
        assert!(!rendered.contains(&hex::encode([1_u8; 32])));
        assert!(!rendered.contains(&hex::encode([2_u8; 32])));
        assert!(!rendered.contains(&hex::encode([3_u8; 32])));
    }

    #[test]
    fn native_adapter_is_type_checked_without_calling_windows_or_opening_a_file() {
        fn assert_adapter<T: NativeExecutableTrustApi>() {}
        assert_adapter::<WindowsNativeExecutableTrustApi>();
        assert_eq!(noninteractive_hwnd().0, INVALID_HANDLE_VALUE.0);
        assert!(WinTrustCallPolicy::offline_embedded().is_exact());
    }

    #[test]
    fn native_provider_pointer_shapes_fail_closed_without_calling_wintrust() {
        let state = inert_windows_state();
        assert!(state.debug_invariants());
        let mut provider = Box::new(CRYPT_PROVIDER_DATA::default());
        provider.cbStruct = size_of::<CRYPT_PROVIDER_DATA>() as u32;
        // SAFETY: the boxed synthetic provider has the exact native layout and
        // remains live for the returned borrow.
        assert!(unsafe { checked_provider(&state, ptr::from_mut(&mut *provider)) }.is_ok());

        provider.cbStruct -= 1;
        // SAFETY: the allocation is still live; the deliberately wrong size is
        // rejected before any later field is consumed.
        assert!(unsafe { checked_provider(&state, ptr::from_mut(&mut *provider)) }.is_err());
        // SAFETY: null and deliberately misaligned pointers are rejected before
        // dereference by the validation helper.
        assert!(unsafe { checked_provider(&state, ptr::null_mut()) }.is_err());
        let mut unaligned =
            vec![0_u8; size_of::<CRYPT_PROVIDER_DATA>() + align_of::<CRYPT_PROVIDER_DATA>()];
        let unaligned_pointer =
            unsafe { unaligned.as_mut_ptr().add(1).cast::<CRYPT_PROVIDER_DATA>() };
        assert!(unsafe { checked_provider(&state, unaligned_pointer) }.is_err());
        assert!(unsafe { checked_certificate_context(&state, ptr::null()) }.is_err());
        assert!(unsafe { checked_certificate_info(&state, ptr::null_mut()) }.is_err());
    }

    #[test]
    fn stable_wintrust_state_rejects_every_mutable_policy_or_pointer_drift() {
        let mut state = inert_windows_state();
        assert!(state.debug_invariants());

        state.data.pSignatureSettings = ptr::null_mut();
        assert!(!state.debug_invariants());

        let mut state = inert_windows_state();
        state.file_info.cbStruct -= 1;
        assert!(!state.debug_invariants());

        let mut state = inert_windows_state();
        state.signature_settings.dwIndex = 1;
        assert!(!state.debug_invariants());

        let mut state = inert_windows_state();
        state.signature_settings.dwFlags = WINTRUST_SIGNATURE_SETTINGS_FLAGS(0);
        assert!(!state.debug_invariants());

        let mut state = inert_windows_state();
        state.signature_settings.dwFlags =
            WINTRUST_SIGNATURE_SETTINGS_FLAGS(WSS_GET_SECONDARY_SIG_COUNT.0 | WSS_OUTPUT_FLAG_MASK);
        assert!(state.debug_invariants());

        let mut state = inert_windows_state();
        state.signature_settings.dwFlags =
            WINTRUST_SIGNATURE_SETTINGS_FLAGS(WSS_GET_SECONDARY_SIG_COUNT.0 | 0x0000_0001);
        assert!(!state.debug_invariants());

        let mut state = inert_windows_state();
        state.signature_settings.dwFlags =
            WINTRUST_SIGNATURE_SETTINGS_FLAGS(WSS_GET_SECONDARY_SIG_COUNT.0 | 0x0000_0008);
        assert!(!state.debug_invariants());

        let mut state = inert_windows_state();
        state.data.dwProvFlags = WINTRUST_DATA_PROVIDER_FLAGS(0);
        assert!(!state.debug_invariants());

        let mut state = inert_windows_state();
        state.data.dwStateAction = WTD_STATEACTION_CLOSE;
        assert!(!state.debug_invariants());
    }

    #[test]
    fn zero_secondary_signatures_require_primary_verified_index_zero() {
        let mut state = inert_windows_state();
        state.verify_attempted = true;
        state.verify_status = 0;
        state.signature_settings.cSecondarySigs = 0;
        state.signature_settings.dwVerifiedSigIndex = 1;

        assert!(matches!(
            extract_windows_authenticode(&state),
            Err(NativeTrustFailure::ProviderExtraction)
        ));
    }

    #[test]
    fn verification_share_mode_excludes_write_delete_and_rename() {
        assert_eq!(verification_share().0, FILE_SHARE_READ.0);
        assert_eq!(
            share_all().0,
            FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0
        );
        assert_eq!(verification_share().0 & FILE_SHARE_WRITE.0, 0);
        assert_eq!(verification_share().0 & FILE_SHARE_DELETE.0, 0);
    }

    #[test]
    fn canonical_volume_guid_parser_is_exact_and_case_insensitive_only_for_ascii() {
        let canonical = r"\\?\Volume{01234567-89ab-CDEF-0123-456789abcdef}\folder\file.exe";
        let wide: Vec<u16> = canonical.encode_utf16().collect();
        let root = volume_guid_root(&wide).expect("exact volume GUID root");
        assert_eq!(
            OsString::from_wide(root),
            OsString::from(r"\\?\Volume{01234567-89ab-CDEF-0123-456789abcdef}\")
        );

        for malformed in [
            r"\\?\UNC\server\share\file.exe",
            r"\\?\Volume{01234567-89ab-CDEF-0123-456789abcdeg}\file.exe",
            r"\\?\Volume{0123456789ab-CDEF-0123-456789abcdef}\file.exe",
            r"\\?\Volume{01234567-89ab-CDEF-0123-456789abcdef}/file.exe",
        ] {
            assert!(volume_guid_root(&malformed.encode_utf16().collect::<Vec<_>>()).is_none());
        }
    }

    #[test]
    fn reviewed_root_kind_maps_only_to_exact_known_folder_ids() {
        assert_eq!(
            *known_folder_id(InstallRootKind::ProgramFilesX86),
            FOLDERID_ProgramFilesX86
        );
        assert_eq!(
            *known_folder_id(InstallRootKind::ProgramFiles64),
            FOLDERID_ProgramFilesX64
        );
        assert_eq!(
            *known_folder_id(InstallRootKind::CurrentUserLocalAppData),
            FOLDERID_LocalAppData
        );
    }

    #[test]
    fn shell_known_folder_allocation_is_released_on_every_result_path() {
        let releases_before = SYNTHETIC_KNOWN_FOLDER_RELEASES.load(Ordering::SeqCst);
        let expected = PathBuf::from(r"C:\synthetic\known-folder");

        let success_path = allocate_synthetic_known_folder_path(&expected);
        assert_eq!(
            resolve_synthetic_known_folder_result(HRESULT(0), success_path).unwrap(),
            expected
        );
        assert_eq!(
            SYNTHETIC_KNOWN_FOLDER_RELEASES.load(Ordering::SeqCst),
            releases_before + 1
        );

        let failure_path = allocate_synthetic_known_folder_path(&expected);
        assert_eq!(
            resolve_synthetic_known_folder_result(E_FAIL, failure_path),
            Err(NativeTrustFailure::PathObservation)
        );
        assert_eq!(
            SYNTHETIC_KNOWN_FOLDER_RELEASES.load(Ordering::SeqCst),
            releases_before + 2
        );

        let relative_path = allocate_synthetic_known_folder_path(Path::new(r"relative\folder"));
        assert_eq!(
            resolve_synthetic_known_folder_result(HRESULT(0), relative_path),
            Err(NativeTrustFailure::PathObservation)
        );
        assert_eq!(
            SYNTHETIC_KNOWN_FOLDER_RELEASES.load(Ordering::SeqCst),
            releases_before + 3
        );

        for status in [HRESULT(0), E_FAIL] {
            assert_eq!(
                resolve_synthetic_known_folder_result(status, PWSTR::null()),
                Err(NativeTrustFailure::PathObservation)
            );
        }
        assert_eq!(
            SYNTHETIC_KNOWN_FOLDER_RELEASES.load(Ordering::SeqCst),
            releases_before + 3
        );
    }

    #[test]
    fn canonical_relative_root_matches_the_reviewed_digest_without_observed_promotion() {
        let known_folder =
            PathBuf::from(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\PROGRAM FILES (X86)");
        let executable = PathBuf::from(
            r"\\?\Volume{01234567-89ab-CDEF-0123-456789abcdef}\Program Files (x86)\SyntheticVendor\SyntheticApp\Synthetic.exe",
        );
        let observed = derive_install_root_digest(
            InstallRootKind::ProgramFilesX86,
            &known_folder,
            &executable,
        )
        .unwrap();
        assert_eq!(observed, root_digest().trust_digest());
        assert_ne!(
            observed,
            derive_install_root_digest(
                InstallRootKind::ProgramFiles64,
                &known_folder,
                &executable,
            )
            .unwrap()
        );
    }

    #[test]
    fn canonical_relative_root_rejects_escape_ambiguity_and_nonportable_components() {
        let root =
            PathBuf::from(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\Program Files (x86)");
        let invalid = [
            PathBuf::from(
                r"\\?\Volume{11234567-89ab-cdef-0123-456789abcdef}\Program Files (x86)\Vendor\App.exe",
            ),
            PathBuf::from(
                r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\Program Files (x86)-other\Vendor\App.exe",
            ),
            root.clone(),
            root.join(r"Vendor\bad:name\App.exe"),
            root.join(r"Vendor\CON\App.exe"),
            root.join(r"Vendor\비공개\App.exe"),
            root.join("x".repeat(MAX_INSTALL_ROOT_COMPONENT_BYTES + 1)),
            root.join(r"a\b\c\d\e\f\g\h\i"),
        ];
        for executable in invalid {
            assert_eq!(
                derive_install_root_digest(InstallRootKind::ProgramFilesX86, &root, &executable,),
                Err(NativeTrustFailure::PathObservation)
            );
        }

        let trailing_root =
            PathBuf::from(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\Program Files (x86)\");
        assert_eq!(
            derive_install_root_digest(
                InstallRootKind::ProgramFilesX86,
                &trailing_root,
                &root.join(r"Vendor\App.exe"),
            ),
            Err(NativeTrustFailure::PathObservation)
        );
    }

    #[test]
    fn file_identity_digest_binds_volume_file_and_process_instance() {
        let base = file_identity_digest(7, &[9; 16], 11);
        assert_ne!(base, [0; 32]);
        assert_ne!(base, file_identity_digest(8, &[9; 16], 11));
        assert_ne!(base, file_identity_digest(7, &[8; 16], 11));
        assert_ne!(base, file_identity_digest(7, &[9; 16], 12));
        assert_eq!(base, file_identity_digest(7, &[9; 16], 11));
    }

    #[test]
    fn spki_der_lengths_are_strictly_bounded() {
        assert_eq!(validate_spki_lengths(1, 1).unwrap(), 1);
        assert_eq!(
            validate_spki_lengths(MAX_SPKI_DER_BYTES as u32, MAX_SPKI_DER_BYTES as u32).unwrap(),
            MAX_SPKI_DER_BYTES
        );
        for (required, written) in [(0, 0), (1, 0), (1, 2), (MAX_SPKI_DER_BYTES as u32 + 1, 1)] {
            assert_eq!(
                validate_spki_lengths(required, written),
                Err(NativeTrustFailure::ProviderExtraction)
            );
        }
    }

    #[test]
    fn wide_path_round_trip_is_bounded_without_file_access() {
        let source = PathBuf::from(r"C:\synthetic\PRIVATE_PATH_CANARY.exe");
        let wide = wide_path(&source).unwrap();
        assert_eq!(path_from_wide(&wide).unwrap(), source);

        let mut embedded_nul: Vec<u16> = r"C:\synthetic".encode_utf16().collect();
        embedded_nul.extend([0, b'x' as u16, 0]);
        assert_eq!(
            path_from_wide(&embedded_nul),
            Err(NativeTrustFailure::PathObservation)
        );
    }
}
