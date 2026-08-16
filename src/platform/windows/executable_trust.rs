//! Pure executable-trust decision seam for guarded Windows mutations.
//!
//! Native path, file-handle, and Authenticode APIs are intentionally absent
//! here. The disconnected native observer reduces its results to this fixed,
//! path-free and redacted evidence shape. Installation-root pins can be
//! constructed only from the versioned reviewed root-relation codec below,
//! never an observed absolute path. The reviewed executable-byte digest is
//! source-static and cannot be promoted from runtime evidence. Production
//! remains wired to [`UnavailableExecutableTrust`] until complete target,
//! signer, root, and activation-qualification evidence is available.

#![cfg_attr(
    not(test),
    allow(dead_code),
    doc = "The pure verifier remains compiled while production uses the fail-closed placeholder."
)]

use std::fmt;

use sha2::{Digest, Sha256};

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
pub(super) struct ReviewedSignerDigest(TrustDigest);

impl ReviewedSignerDigest {
    /// Production profile bytes must be source-embedded and independently
    /// reviewed. Runtime certificate observations produce `TrustDigest`
    /// directly and cannot satisfy this constructor by accident.
    pub(super) fn from_static_reviewed_bytes(bytes: &'static [u8; 32]) -> Result<Self, UiError> {
        TrustDigest::from_bytes(*bytes).map(Self)
    }

    fn trust_digest(self) -> TrustDigest {
        self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ReviewedExecutableDigest(TrustDigest);

impl ReviewedExecutableDigest {
    /// This is the SHA-256 of the complete reviewed target executable, not the
    /// installer and not a runtime-promoted observation. Production bytes must
    /// come from an independently reviewed, source-embedded provenance bundle.
    pub(super) fn from_static_reviewed_bytes(bytes: &'static [u8; 32]) -> Result<Self, UiError> {
        TrustDigest::from_bytes(*bytes).map(Self)
    }

    fn trust_digest(self) -> TrustDigest {
        self.0
    }
}

impl fmt::Debug for ReviewedExecutableDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReviewedExecutableDigest(<redacted>)")
    }
}

impl fmt::Debug for ReviewedSignerDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReviewedSignerDigest(<redacted>)")
    }
}

const INSTALL_ROOT_RELATION_DOMAIN: &[u8] = b"openkakao.windows.install-root-relation.v1\0";
pub(super) const MAX_INSTALL_ROOT_COMPONENTS: usize = 8;
pub(super) const MAX_INSTALL_ROOT_COMPONENT_BYTES: usize = 64;
pub(super) const MAX_INSTALL_ROOT_RELATION_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InstallRootKind {
    ProgramFilesX86,
    ProgramFiles64,
    CurrentUserLocalAppData,
}

impl InstallRootKind {
    fn domain_tag(self) -> u8 {
        match self {
            Self::ProgramFilesX86 => 1,
            Self::ProgramFiles64 => 2,
            Self::CurrentUserLocalAppData => 3,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct InstallRootDigest {
    kind: InstallRootKind,
    digest: TrustDigest,
}

impl InstallRootDigest {
    /// Reduces a reviewed root kind and exact relative path to a stable,
    /// content-free digest. Version 1 deliberately accepts only portable
    /// printable ASCII components so Windows Unicode/case normalization can
    /// never be guessed during activation.
    pub(super) fn from_static_reviewed_relation(
        kind: InstallRootKind,
        components: &'static [&'static str],
    ) -> Result<Self, UiError> {
        Self::from_relation_components(kind, components)
    }

    fn from_relation_components(
        kind: InstallRootKind,
        components: &[&str],
    ) -> Result<Self, UiError> {
        let component_bytes: Vec<&[u8]> = components
            .iter()
            .map(|component| component.as_bytes())
            .collect();
        install_root_relation_digest(kind, &component_bytes).map(|digest| Self { kind, digest })
    }

    pub(super) fn trust_digest(self) -> TrustDigest {
        self.digest
    }

    fn kind(self) -> InstallRootKind {
        self.kind
    }
}

pub(super) fn observed_install_root_digest(
    kind: InstallRootKind,
    components: &[&[u8]],
) -> Result<TrustDigest, UiError> {
    install_root_relation_digest(kind, components)
}

fn install_root_relation_digest(
    kind: InstallRootKind,
    components: &[&[u8]],
) -> Result<TrustDigest, UiError> {
    if components.is_empty() || components.len() > MAX_INSTALL_ROOT_COMPONENTS {
        return Err(invalid_trust_profile());
    }

    let mut relation_len = 0_usize;
    let mut hasher = Sha256::new();
    hasher.update(INSTALL_ROOT_RELATION_DOMAIN);
    hasher.update([kind.domain_tag()]);
    hasher.update([components.len() as u8]);
    for bytes in components {
        if !valid_install_root_component(bytes) {
            return Err(invalid_trust_profile());
        }
        relation_len = relation_len
            .checked_add(bytes.len())
            .ok_or_else(invalid_trust_profile)?;
        if relation_len > MAX_INSTALL_ROOT_RELATION_BYTES {
            return Err(invalid_trust_profile());
        }
        hasher.update((bytes.len() as u16).to_le_bytes());
        for byte in *bytes {
            hasher.update([byte.to_ascii_lowercase()]);
        }
    }
    let digest: [u8; 32] = hasher.finalize().into();
    TrustDigest::from_bytes(digest)
}

impl fmt::Debug for InstallRootDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InstallRootDigest(<redacted>)")
    }
}

fn valid_install_root_component(component: &[u8]) -> bool {
    if component.is_empty()
        || component.len() > MAX_INSTALL_ROOT_COMPONENT_BYTES
        || component
            .first()
            .is_some_and(|value| matches!(value, b' ' | b'.'))
        || component
            .last()
            .is_some_and(|value| matches!(value, b' ' | b'.'))
        || component == b"."
        || component == b".."
        || is_reserved_dos_device_name(component)
    {
        return false;
    }
    component.iter().all(|value| {
        matches!(value, 0x20..=0x7e)
            && !matches!(
                value,
                b'/' | b'\\' | b':' | b'*' | b'?' | b'"' | b'<' | b'>' | b'|'
            )
    })
}

fn is_reserved_dos_device_name(component: &[u8]) -> bool {
    let stem = component
        .split(|value| *value == b'.')
        .next()
        .unwrap_or_default();
    if [b"con".as_slice(), b"prn", b"aux", b"nul"]
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
    {
        return true;
    }
    stem.len() == 4
        && (stem[..3].eq_ignore_ascii_case(b"com") || stem[..3].eq_ignore_ascii_case(b"lpt"))
        && matches!(stem[3], b'1'..=b'9')
}

fn invalid_trust_profile() -> UiError {
    UiError::new(
        UiErrorKind::InvalidInput,
        "windows_executable_trust_profile",
    )
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
    RequeriedProcessImagePathGuarded,
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
pub(super) enum FileSystemKind {
    Ntfs,
    Other,
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
    executable_digest: TrustDigest,
    signer_digest: TrustDigest,
    install_root_kind: InstallRootKind,
    install_root_digest: TrustDigest,
}

impl ExecutableTrustProfile {
    pub(super) fn new(
        version: FileVersion,
        executable_digest: ReviewedExecutableDigest,
        signer_digest: ReviewedSignerDigest,
        install_root_digest: InstallRootDigest,
    ) -> Result<Self, UiError> {
        let executable_digest = executable_digest.trust_digest();
        let signer_digest = signer_digest.trust_digest();
        let install_root_kind = install_root_digest.kind();
        let install_root_digest = install_root_digest.trust_digest();
        if version != FileVersion::KNOWN
            || executable_digest == signer_digest
            || executable_digest == install_root_digest
            || signer_digest == install_root_digest
        {
            return Err(invalid_trust_profile());
        }
        Ok(Self {
            version,
            executable_digest,
            signer_digest,
            install_root_kind,
            install_root_digest,
        })
    }

    pub(super) fn install_root_kind(&self) -> InstallRootKind {
        self.install_root_kind
    }
}

impl fmt::Debug for ExecutableTrustProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutableTrustProfile")
            .field("version", &self.version.to_string())
            .field("executable_digest", &"<redacted>")
            .field("signer_digest", &"<redacted>")
            .field("install_root_digest", &"<redacted>")
            .finish()
    }
}

pub(super) struct ExecutableTrustEvidence {
    pub final_path_source: FinalPathSource,
    pub path_is_absolute_and_normalized: bool,
    pub volume_kind: VolumeKind,
    pub file_system_kind: FileSystemKind,
    pub reparse_state: ReparseState,
    pub process_image_path_requeried_and_guarded: bool,
    pub process_creation_time_bound: bool,
    pub process_file_identity: Option<FileIdentity>,
    pub verified_file_identity: Option<FileIdentity>,
    pub reopened_file_identity: Option<FileIdentity>,
    pub version: Option<FileVersion>,
    pub executable_digest: Option<TrustDigest>,
    pub authenticode_status: AuthenticodeStatus,
    pub trust_ui_forbidden: bool,
    pub cache_only_url_retrieval: bool,
    pub sha2_strong_signature_policy: bool,
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
            .field("file_system_kind", &self.file_system_kind)
            .field("reparse_state", &self.reparse_state)
            .field(
                "process_image_path_requeried_and_guarded",
                &self.process_image_path_requeried_and_guarded,
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
            .field(
                "executable_digest",
                &redacted_option(self.executable_digest),
            )
            .field("authenticode_status", &self.authenticode_status)
            .field("trust_ui_forbidden", &self.trust_ui_forbidden)
            .field("cache_only_url_retrieval", &self.cache_only_url_retrieval)
            .field(
                "sha2_strong_signature_policy",
                &self.sha2_strong_signature_policy,
            )
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
    if evidence.final_path_source != FinalPathSource::RequeriedProcessImagePathGuarded
        || !evidence.path_is_absolute_and_normalized
        || evidence.volume_kind != VolumeKind::FixedLocal
        || evidence.file_system_kind != FileSystemKind::Ntfs
        || evidence.reparse_state != ReparseState::Absent
    {
        return Err(UiError::new(
            UiErrorKind::PermissionDenied,
            "windows_executable_path_trust",
        ));
    }

    if !evidence.process_image_path_requeried_and_guarded || !evidence.process_creation_time_bound {
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

    if evidence.executable_digest != Some(profile.executable_digest) {
        return Err(UiError::new(
            UiErrorKind::UnknownUiProfile,
            "windows_executable_content_digest",
        ));
    }

    if evidence.authenticode_status != AuthenticodeStatus::Trusted
        || !evidence.trust_ui_forbidden
        || !evidence.cache_only_url_retrieval
        || !evidence.sha2_strong_signature_policy
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

    static SYNTHETIC_SIGNER_BYTES: [u8; 32] = [1; 32];
    static SYNTHETIC_EXECUTABLE_BYTES: [u8; 32] = [2; 32];
    static ZERO_SIGNER_BYTES: [u8; 32] = [0; 32];
    static ZERO_EXECUTABLE_BYTES: [u8; 32] = [0; 32];
    static SYNTHETIC_ROOT_RELATION: &[&str] = &["SyntheticVendor", "SyntheticApp", "Synthetic.exe"];

    fn digest(value: u8) -> TrustDigest {
        TrustDigest::from_bytes([value; 32]).unwrap()
    }

    fn identity(value: u8) -> FileIdentity {
        FileIdentity::from_bytes([value; 32]).unwrap()
    }

    fn profile() -> ExecutableTrustProfile {
        ExecutableTrustProfile::new(
            FileVersion::KNOWN,
            reviewed_executable(),
            reviewed_signer(),
            root_digest(),
        )
        .unwrap()
    }

    fn reviewed_executable() -> ReviewedExecutableDigest {
        ReviewedExecutableDigest::from_static_reviewed_bytes(&SYNTHETIC_EXECUTABLE_BYTES).unwrap()
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

    fn evidence() -> ExecutableTrustEvidence {
        ExecutableTrustEvidence {
            final_path_source: FinalPathSource::RequeriedProcessImagePathGuarded,
            path_is_absolute_and_normalized: true,
            volume_kind: VolumeKind::FixedLocal,
            file_system_kind: FileSystemKind::Ntfs,
            reparse_state: ReparseState::Absent,
            process_image_path_requeried_and_guarded: true,
            process_creation_time_bound: true,
            process_file_identity: Some(identity(3)),
            verified_file_identity: Some(identity(3)),
            reopened_file_identity: Some(identity(3)),
            version: Some(FileVersion::KNOWN),
            executable_digest: Some(digest(2)),
            authenticode_status: AuthenticodeStatus::Trusted,
            trust_ui_forbidden: true,
            cache_only_url_retrieval: true,
            sha2_strong_signature_policy: true,
            catalog_ambiguous: false,
            signer_count: 1,
            signer_digest: Some(digest(1)),
            install_root_digest: Some(root_digest().trust_digest()),
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
            "other_file_system",
            "unknown_file_system",
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
                "other_file_system" => observed.file_system_kind = FileSystemKind::Other,
                "unknown_file_system" => observed.file_system_kind = FileSystemKind::Unknown,
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
            "path_guard_unbound",
            "creation_unbound",
            "process_absent",
            "verified_absent",
            "reopened_absent",
            "verified_changed",
            "reopened_changed",
        ] {
            let mut observed = evidence();
            match mutation {
                "path_guard_unbound" => observed.process_image_path_requeried_and_guarded = false,
                "creation_unbound" => observed.process_creation_time_bound = false,
                "process_absent" => observed.process_file_identity = None,
                "verified_absent" => observed.verified_file_identity = None,
                "reopened_absent" => observed.reopened_file_identity = None,
                "verified_changed" => observed.verified_file_identity = Some(identity(4)),
                "reopened_changed" => observed.reopened_file_identity = Some(identity(4)),
                _ => unreachable!(),
            }
            let operation = if matches!(mutation, "path_guard_unbound" | "creation_unbound") {
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
            "weak_signature_policy",
            "catalog_ambiguous",
        ] {
            let mut observed = evidence();
            match mutation {
                "untrusted" => observed.authenticode_status = AuthenticodeStatus::Untrusted,
                "unknown" => observed.authenticode_status = AuthenticodeStatus::Unknown,
                "ui_allowed" => observed.trust_ui_forbidden = false,
                "network_allowed" => observed.cache_only_url_retrieval = false,
                "weak_signature_policy" => observed.sha2_strong_signature_policy = false,
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

        for value in [None, Some(digest(9))] {
            let mut observed = evidence();
            observed.executable_digest = value;
            assert_refusal(observed, "windows_executable_content_digest");
        }

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
        assert!(!rendered.contains("03030303"));
        assert!(!rendered.contains("OPENKAKAO_TRUST_CANARY"));
    }

    #[test]
    fn invalid_or_colliding_profile_digests_are_refused() {
        assert!(TrustDigest::from_bytes([0; 32]).is_err());
        assert!(ReviewedSignerDigest::from_static_reviewed_bytes(&ZERO_SIGNER_BYTES).is_err());
        assert!(
            ReviewedExecutableDigest::from_static_reviewed_bytes(&ZERO_EXECUTABLE_BYTES).is_err()
        );
        assert!(FileIdentity::from_bytes([0; 32]).is_err());
        assert!(ExecutableTrustProfile::new(
            FileVersion::KNOWN,
            ReviewedExecutableDigest(root_digest().trust_digest()),
            ReviewedSignerDigest(root_digest().trust_digest()),
            root_digest()
        )
        .is_err());
        assert!(ExecutableTrustProfile::new(
            FileVersion {
                major: 99,
                minor: 0,
                patch: 0,
                build: 1,
            },
            reviewed_executable(),
            reviewed_signer(),
            root_digest(),
        )
        .is_err());
    }

    #[test]
    fn install_root_relation_is_domain_separated_bounded_and_ascii_case_folded() {
        let x86 = InstallRootDigest::from_relation_components(
            InstallRootKind::ProgramFilesX86,
            &["Vendor", "Product", "Product.exe"],
        )
        .unwrap();
        let case_only = InstallRootDigest::from_relation_components(
            InstallRootKind::ProgramFilesX86,
            &["VENDOR", "product", "PRODUCT.EXE"],
        )
        .unwrap();
        assert_eq!(x86, case_only);

        for distinct in [
            InstallRootDigest::from_relation_components(
                InstallRootKind::ProgramFiles64,
                &["Vendor", "Product", "Product.exe"],
            )
            .unwrap(),
            InstallRootDigest::from_relation_components(
                InstallRootKind::CurrentUserLocalAppData,
                &["Vendor", "Product", "Product.exe"],
            )
            .unwrap(),
            InstallRootDigest::from_relation_components(
                InstallRootKind::ProgramFilesX86,
                &["Vendor", "Other", "Product.exe"],
            )
            .unwrap(),
        ] {
            assert_ne!(x86, distinct);
        }
        assert_eq!(format!("{x86:?}"), "InstallRootDigest(<redacted>)");
        assert_eq!(
            format!("{:?}", reviewed_signer()),
            "ReviewedSignerDigest(<redacted>)"
        );
    }

    #[test]
    fn install_root_relation_rejects_ambiguous_or_nonportable_components() {
        let long = "x".repeat(MAX_INSTALL_ROOT_COMPONENT_BYTES + 1);
        for components in [
            Vec::<&str>::new(),
            vec!["."],
            vec![".."],
            vec![" leading"],
            vec!["trailing."],
            vec!["contains\\separator"],
            vec!["contains:stream"],
            vec!["CON"],
            vec!["nul.txt"],
            vec!["Com1"],
            vec!["lpt9.log"],
            vec!["nonascii-한글"],
            vec![long.as_str()],
        ] {
            assert!(InstallRootDigest::from_relation_components(
                InstallRootKind::ProgramFilesX86,
                &components
            )
            .is_err());
        }
        let too_many = vec!["x"; MAX_INSTALL_ROOT_COMPONENTS + 1];
        assert!(InstallRootDigest::from_relation_components(
            InstallRootKind::ProgramFilesX86,
            &too_many
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
