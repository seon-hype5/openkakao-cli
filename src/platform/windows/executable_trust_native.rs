//! Fakeable orchestration for the future Windows executable-trust observer.
//!
//! This module makes no native call and opens no file. It freezes the exact
//! offline WinTrust policy plus VERIFY/extract/CLOSE lifetime so a later
//! adapter cannot skip state cleanup or weaken flags without changing tests.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};

use windows::core::GUID;
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA_PROVIDER_FLAGS,
    WINTRUST_DATA_REVOCATION_CHECKS, WINTRUST_DATA_STATE_ACTION, WINTRUST_DATA_UICHOICE,
    WINTRUST_DATA_UICONTEXT, WINTRUST_DATA_UNION_CHOICE, WINTRUST_SIGNATURE_SETTINGS_FLAGS,
    WSS_GET_SECONDARY_SIG_COUNT, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE,
    WTD_DISABLE_MD2_MD4, WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UICONTEXT_EXECUTE, WTD_UI_NONE,
};

use crate::platform::{UiError, UiErrorKind};

use super::executable_trust::{
    verify_executable_trust, AuthenticodeStatus, ExecutableTrustBoundary, ExecutableTrustEvidence,
    ExecutableTrustProfile, FileIdentity, FinalPathSource, ReparseState, TrustDigest, VolumeKind,
};
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
    let (path_state, path) = catch_unwind(AssertUnwindSafe(|| api.observe_path()))
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

#[cfg(test)]
mod tests {
    use super::*;

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
        closes: usize,
    }

    impl NativeExecutableTrustApi for FakeApi {
        type PathState = u64;
        type TrustState = u64;

        fn observe_path(
            &mut self,
        ) -> Result<(Self::PathState, NativePathObservation), NativeTrustFailure> {
            self.calls.push("observe");
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
        ExecutableTrustProfile::new(FileVersion::KNOWN, digest(1), digest(2)).unwrap()
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
            install_root_digest: Some(digest(2)),
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
            closes: 0,
        }
    }

    fn run(api: FakeApi) -> (Result<(), UiError>, FakeApi) {
        let mut observer = NativeExecutableTrustObserver::new(profile(), api);
        let result = observer.verify_executable_trust();
        (result, observer.into_api())
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
}
