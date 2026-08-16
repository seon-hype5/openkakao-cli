//! Pure executable-trust decision seam for guarded Windows mutations.
//!
//! Native path, file-handle, and Authenticode APIs are intentionally absent
//! here. A future native observer must reduce those results to this fixed,
//! content-free evidence shape. Production remains wired to
//! [`UnavailableExecutableTrust`] until reviewed signer and installation-root
//! digests plus the native verifier are available.

#![cfg_attr(
    not(test),
    allow(dead_code),
    doc = "The pure verifier remains compiled while production uses the fail-closed placeholder."
)]

use std::fmt;

use crate::platform::{UiError, UiErrorKind};

use super::FileVersion;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct TrustDigest([u8; 32]);

impl TrustDigest {
    pub(super) fn from_bytes(bytes: [u8; 32]) -> Result<Self, UiError> {
        if bytes == [0; 32] {
            Err(UiError::new(
                UiErrorKind::InvalidInput,
                "windows_executable_trust_profile",
            ))
        } else {
            Ok(Self(bytes))
        }
    }
}

impl fmt::Debug for TrustDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrustDigest(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct FileIdentity([u8; 32]);

impl FileIdentity {
    pub(super) fn from_bytes(bytes: [u8; 32]) -> Result<Self, UiError> {
        if bytes == [0; 32] {
            Err(UiError::new(
                UiErrorKind::InvalidInput,
                "windows_executable_file_identity",
            ))
        } else {
            Ok(Self(bytes))
        }
    }
}

impl fmt::Debug for FileIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FileIdentity(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FinalPathSource {
    OpenedProcessImageHandle,
    TextOnly,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum VolumeKind {
    FixedLocal,
    Network,
    Removable,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReparseState {
    Absent,
    Present,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AuthenticodeStatus {
    Trusted,
    Untrusted,
    Unknown,
}

pub(super) struct ExecutableTrustProfile {
    version: FileVersion,
    signer_digest: TrustDigest,
    install_root_digest: TrustDigest,
}

impl ExecutableTrustProfile {
    pub(super) fn new(
        version: FileVersion,
        signer_digest: TrustDigest,
        install_root_digest: TrustDigest,
    ) -> Result<Self, UiError> {
        if version != FileVersion::KNOWN || signer_digest == install_root_digest {
            return Err(UiError::new(
                UiErrorKind::InvalidInput,
                "windows_executable_trust_profile",
            ));
        }
        Ok(Self {
            version,
            signer_digest,
            install_root_digest,
        })
    }
}

impl fmt::Debug for ExecutableTrustProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutableTrustProfile")
            .field("version", &self.version.to_string())
            .field("signer_digest", &"<redacted>")
            .field("install_root_digest", &"<redacted>")
            .finish()
    }
}

pub(super) struct ExecutableTrustEvidence {
    pub final_path_source: FinalPathSource,
    pub path_is_absolute_and_normalized: bool,
    pub volume_kind: VolumeKind,
    pub reparse_state: ReparseState,
    pub process_image_handle_bound: bool,
    pub process_creation_time_bound: bool,
    pub process_file_identity: Option<FileIdentity>,
    pub verified_file_identity: Option<FileIdentity>,
    pub reopened_file_identity: Option<FileIdentity>,
    pub version: Option<FileVersion>,
    pub authenticode_status: AuthenticodeStatus,
    pub trust_ui_forbidden: bool,
    pub cache_only_url_retrieval: bool,
    pub catalog_ambiguous: bool,
    pub signer_count: usize,
    pub signer_digest: Option<TrustDigest>,
    pub install_root_digest: Option<TrustDigest>,
}

impl fmt::Debug for ExecutableTrustEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutableTrustEvidence")
            .field("final_path_source", &self.final_path_source)
            .field(
                "path_is_absolute_and_normalized",
                &self.path_is_absolute_and_normalized,
            )
            .field("volume_kind", &self.volume_kind)
            .field("reparse_state", &self.reparse_state)
            .field(
                "process_image_handle_bound",
                &self.process_image_handle_bound,
            )
            .field(
                "process_creation_time_bound",
                &self.process_creation_time_bound,
            )
            .field(
                "process_file_identity",
                &redacted_option(self.process_file_identity),
            )
            .field(
                "verified_file_identity",
                &redacted_option(self.verified_file_identity),
            )
            .field(
                "reopened_file_identity",
                &redacted_option(self.reopened_file_identity),
            )
            .field("version_observed", &self.version.is_some())
            .field("authenticode_status", &self.authenticode_status)
            .field("trust_ui_forbidden", &self.trust_ui_forbidden)
            .field("cache_only_url_retrieval", &self.cache_only_url_retrieval)
            .field("catalog_ambiguous", &self.catalog_ambiguous)
            .field("signer_count", &bounded_count(self.signer_count))
            .field("signer_digest", &redacted_option(self.signer_digest))
            .field(
                "install_root_digest",
                &redacted_option(self.install_root_digest),
            )
            .finish()
    }
}

fn redacted_option<T>(value: Option<T>) -> &'static str {
    if value.is_some() {
        "<redacted-present>"
    } else {
        "<absent>"
    }
}

fn bounded_count(count: usize) -> &'static str {
    match count {
        0 => "zero",
        1 => "one",
        _ => "multiple",
    }
}

#[derive(Debug)]
pub(super) struct VerifiedExecutableTrust(());

pub(super) fn verify_executable_trust(
    profile: &ExecutableTrustProfile,
    evidence: &ExecutableTrustEvidence,
) -> Result<VerifiedExecutableTrust, UiError> {
    if evidence.final_path_source != FinalPathSource::OpenedProcessImageHandle
        || !evidence.path_is_absolute_and_normalized
        || evidence.volume_kind != VolumeKind::FixedLocal
        || evidence.reparse_state != ReparseState::Absent
    {
        return Err(UiError::new(
            UiErrorKind::PermissionDenied,
            "windows_executable_path_trust",
        ));
    }

    if !evidence.process_image_handle_bound || !evidence.process_creation_time_bound {
        return Err(UiError::new(
            UiErrorKind::StaleSnapshot,
            "windows_executable_process_binding",
        ));
    }

    let process_identity = evidence.process_file_identity.ok_or_else(|| {
        UiError::new(
            UiErrorKind::StaleSnapshot,
            "windows_executable_file_identity",
        )
    })?;
    if evidence.verified_file_identity != Some(process_identity)
        || evidence.reopened_file_identity != Some(process_identity)
    {
        return Err(UiError::new(
            UiErrorKind::StaleSnapshot,
            "windows_executable_file_identity",
        ));
    }

    if evidence.version != Some(profile.version) {
        return Err(UiError::new(
            UiErrorKind::UnknownUiProfile,
            "windows_executable_trust_version",
        ));
    }

    if evidence.authenticode_status != AuthenticodeStatus::Trusted
        || !evidence.trust_ui_forbidden
        || !evidence.cache_only_url_retrieval
        || evidence.catalog_ambiguous
    {
        return Err(UiError::new(
            UiErrorKind::PermissionDenied,
            "windows_executable_signature_trust",
        ));
    }

    if evidence.signer_count != 1 || evidence.signer_digest != Some(profile.signer_digest) {
        return Err(UiError::new(
            UiErrorKind::PermissionDenied,
            "windows_executable_signer",
        ));
    }

    if evidence.install_root_digest != Some(profile.install_root_digest) {
        return Err(UiError::new(
            UiErrorKind::PermissionDenied,
            "windows_executable_install_root",
        ));
    }

    Ok(VerifiedExecutableTrust(()))
}

pub(super) trait ExecutableTrustBoundary {
    fn verify_executable_trust(&mut self) -> Result<(), UiError>;
}

pub(super) struct UnavailableExecutableTrust;

impl ExecutableTrustBoundary for UnavailableExecutableTrust {
    fn verify_executable_trust(&mut self) -> Result<(), UiError> {
        Err(UiError::new(
            UiErrorKind::UnsupportedCapability,
            "windows_executable_trust_unavailable",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: u8) -> TrustDigest {
        TrustDigest::from_bytes([value; 32]).unwrap()
    }

    fn identity(value: u8) -> FileIdentity {
        FileIdentity::from_bytes([value; 32]).unwrap()
    }

    fn profile() -> ExecutableTrustProfile {
        ExecutableTrustProfile::new(FileVersion::KNOWN, digest(1), digest(2)).unwrap()
    }

    fn evidence() -> ExecutableTrustEvidence {
        ExecutableTrustEvidence {
            final_path_source: FinalPathSource::OpenedProcessImageHandle,
            path_is_absolute_and_normalized: true,
            volume_kind: VolumeKind::FixedLocal,
            reparse_state: ReparseState::Absent,
            process_image_handle_bound: true,
            process_creation_time_bound: true,
            process_file_identity: Some(identity(3)),
            verified_file_identity: Some(identity(3)),
            reopened_file_identity: Some(identity(3)),
            version: Some(FileVersion::KNOWN),
            authenticode_status: AuthenticodeStatus::Trusted,
            trust_ui_forbidden: true,
            cache_only_url_retrieval: true,
            catalog_ambiguous: false,
            signer_count: 1,
            signer_digest: Some(digest(1)),
            install_root_digest: Some(digest(2)),
        }
    }

    fn assert_refusal(evidence: ExecutableTrustEvidence, operation: &'static str) {
        let error = verify_executable_trust(&profile(), &evidence).unwrap_err();
        assert_eq!(error.operation, operation);
        assert!(!matches!(error.kind, UiErrorKind::SubmissionUncertain));
    }

    #[test]
    fn exact_synthetic_trust_evidence_is_accepted() {
        assert!(verify_executable_trust(&profile(), &evidence()).is_ok());
    }

    #[test]
    fn path_source_volume_reparse_and_normalization_fail_closed() {
        for mutation in [
            "text_path",
            "unknown_path",
            "relative_path",
            "network",
            "removable",
            "unknown_volume",
            "reparse",
            "unknown_reparse",
        ] {
            let mut observed = evidence();
            match mutation {
                "text_path" => observed.final_path_source = FinalPathSource::TextOnly,
                "unknown_path" => observed.final_path_source = FinalPathSource::Unknown,
                "relative_path" => observed.path_is_absolute_and_normalized = false,
                "network" => observed.volume_kind = VolumeKind::Network,
                "removable" => observed.volume_kind = VolumeKind::Removable,
                "unknown_volume" => observed.volume_kind = VolumeKind::Unknown,
                "reparse" => observed.reparse_state = ReparseState::Present,
                "unknown_reparse" => observed.reparse_state = ReparseState::Unknown,
                _ => unreachable!(),
            }
            assert_refusal(observed, "windows_executable_path_trust");
        }
    }

    #[test]
    fn process_replacement_and_file_identity_disagreement_fail_closed() {
        for mutation in [
            "handle_unbound",
            "creation_unbound",
            "process_absent",
            "verified_absent",
            "reopened_absent",
            "verified_changed",
            "reopened_changed",
        ] {
            let mut observed = evidence();
            match mutation {
                "handle_unbound" => observed.process_image_handle_bound = false,
                "creation_unbound" => observed.process_creation_time_bound = false,
                "process_absent" => observed.process_file_identity = None,
                "verified_absent" => observed.verified_file_identity = None,
                "reopened_absent" => observed.reopened_file_identity = None,
                "verified_changed" => observed.verified_file_identity = Some(identity(4)),
                "reopened_changed" => observed.reopened_file_identity = Some(identity(4)),
                _ => unreachable!(),
            }
            let operation = if matches!(mutation, "handle_unbound" | "creation_unbound") {
                "windows_executable_process_binding"
            } else {
                "windows_executable_file_identity"
            };
            assert_refusal(observed, operation);
        }
    }

    #[test]
    fn signature_must_be_offline_no_ui_unambiguous_and_trusted() {
        for mutation in [
            "untrusted",
            "unknown",
            "ui_allowed",
            "network_allowed",
            "catalog_ambiguous",
        ] {
            let mut observed = evidence();
            match mutation {
                "untrusted" => observed.authenticode_status = AuthenticodeStatus::Untrusted,
                "unknown" => observed.authenticode_status = AuthenticodeStatus::Unknown,
                "ui_allowed" => observed.trust_ui_forbidden = false,
                "network_allowed" => observed.cache_only_url_retrieval = false,
                "catalog_ambiguous" => observed.catalog_ambiguous = true,
                _ => unreachable!(),
            }
            assert_refusal(observed, "windows_executable_signature_trust");
        }
    }

    #[test]
    fn signer_root_and_version_are_exact_without_fallback() {
        let mut version = evidence();
        version.version = None;
        assert_refusal(version, "windows_executable_trust_version");

        for mutation in ["zero_signers", "multiple_signers", "wrong_signer"] {
            let mut observed = evidence();
            match mutation {
                "zero_signers" => observed.signer_count = 0,
                "multiple_signers" => observed.signer_count = 2,
                "wrong_signer" => observed.signer_digest = Some(digest(9)),
                _ => unreachable!(),
            }
            assert_refusal(observed, "windows_executable_signer");
        }

        let mut wrong_root = evidence();
        wrong_root.install_root_digest = Some(digest(9));
        assert_refusal(wrong_root, "windows_executable_install_root");
    }

    #[test]
    fn evidence_and_profile_debug_never_emit_opaque_identifiers() {
        let rendered = format!("{:?} {:?}", profile(), evidence());
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("01010101"));
        assert!(!rendered.contains("02020202"));
        assert!(!rendered.contains("03030303"));
        assert!(!rendered.contains("OPENKAKAO_TRUST_CANARY"));
    }

    #[test]
    fn invalid_or_colliding_profile_digests_are_refused() {
        assert!(TrustDigest::from_bytes([0; 32]).is_err());
        assert!(FileIdentity::from_bytes([0; 32]).is_err());
        assert!(ExecutableTrustProfile::new(FileVersion::KNOWN, digest(1), digest(1)).is_err());
        assert!(ExecutableTrustProfile::new(
            FileVersion {
                major: 99,
                minor: 0,
                patch: 0,
                build: 1,
            },
            digest(1),
            digest(2),
        )
        .is_err());
    }

    #[test]
    fn unavailable_production_boundary_refuses_before_native_observation() {
        let mut boundary = UnavailableExecutableTrust;
        let error = boundary.verify_executable_trust().unwrap_err();
        assert_eq!(error.kind, UiErrorKind::UnsupportedCapability);
        assert_eq!(error.operation, "windows_executable_trust_unavailable");
    }
}
