use std::fmt;

use serde::Serialize;
use zeroize::Zeroize;

use crate::safety::ApprovalToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UiPlatform {
    Macos,
    Windows,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct UiCapabilities {
    pub inspect: bool,
    pub send_open_chat: bool,
    pub open_chat_by_name: bool,
    pub read_visible: bool,
    pub watch_unread: bool,
}

impl UiCapabilities {
    pub const fn windows_read_only() -> Self {
        Self {
            inspect: true,
            send_open_chat: false,
            open_chat_by_name: false,
            read_visible: false,
            watch_unread: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessFingerprint {
    pub pid: u32,
    /// An execution-scoped digest; never the raw executable path.
    pub executable: String,
    pub session_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppSnapshot {
    pub platform: UiPlatform,
    pub app_running: bool,
    pub process: Option<ProcessFingerprint>,
    pub app_version: Option<String>,
    pub interactive_session_match: bool,
    pub integrity_compatible: bool,
    pub known_ui_profile: bool,
    pub top_level_window_count: usize,
    pub modal_present: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    SelfChat,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChatTargetSnapshot {
    pub kind: TargetKind,
    pub self_chat_verified: bool,
    pub exact_match: bool,
    pub unique_match: bool,
    /// An execution-scoped digest; never a raw room title or HWND.
    pub window: Option<String>,
    /// An execution-scoped digest; never a raw UI Automation runtime ID.
    pub composer: Option<String>,
    pub observed_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InputSnapshot {
    pub present: bool,
    pub unique: bool,
    pub enabled: bool,
    pub writable: bool,
    pub draft_empty: bool,
    pub focused: bool,
    pub selector_profile_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UiSnapshot {
    pub app: AppSnapshot,
    pub target: ChatTargetSnapshot,
    pub input: InputSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InspectRequest {
    pub target: TargetKind,
}

/// A message value that cannot leak through `Debug`, `Display`, or serde.
pub struct SecretMessage(String);

impl SecretMessage {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len_chars(&self) -> usize {
        self.0.chars().count()
    }

    #[allow(dead_code)] // Consumed by the guarded backend beginning in Wave 2.
    pub(crate) fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretMessage(<redacted>)")
    }
}

impl fmt::Display for SecretMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl Drop for SecretMessage {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SendMode {
    DryRun,
    StageOnly,
    Commit,
}

pub struct SendIntent {
    pub target: TargetKind,
    pub message: SecretMessage,
    pub mode: SendMode,
    pub explicit_yes: bool,
    pub nonce: String,
}

impl fmt::Debug for SendIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SendIntent")
            .field("target", &self.target)
            .field("message", &"<redacted>")
            .field("mode", &self.mode)
            .field("explicit_yes", &self.explicit_yes)
            .field("nonce", &"<redacted>")
            .finish()
    }
}

impl SendIntent {
    pub fn new(
        target: TargetKind,
        message: SecretMessage,
        mode: SendMode,
        explicit_yes: bool,
        nonce: impl Into<String>,
    ) -> Self {
        Self {
            target,
            message,
            mode,
            explicit_yes,
            nonce: nonce.into(),
        }
    }
}

/// A safety-policy capability. Its fields are private and construction also
/// requires the unforgeable token owned by `crate::safety`.
pub struct ApprovedSend {
    intent: SendIntent,
    snapshot: UiSnapshot,
    approved_at_unix_ms: u64,
}

impl ApprovedSend {
    #[allow(dead_code)] // Consumed by the safety policy beginning in Wave 1.
    pub(crate) fn from_policy(
        intent: SendIntent,
        snapshot: UiSnapshot,
        approved_at_unix_ms: u64,
        _token: ApprovalToken,
    ) -> Self {
        Self {
            intent,
            snapshot,
            approved_at_unix_ms,
        }
    }

    pub fn target(&self) -> TargetKind {
        self.intent.target
    }

    pub fn mode(&self) -> SendMode {
        self.intent.mode
    }

    pub fn nonce(&self) -> &str {
        &self.intent.nonce
    }

    pub fn message_len_chars(&self) -> usize {
        self.intent.message.len_chars()
    }

    pub fn snapshot(&self) -> &UiSnapshot {
        &self.snapshot
    }

    pub fn approved_at_unix_ms(&self) -> u64 {
        self.approved_at_unix_ms
    }

    #[allow(dead_code)] // Consumed by the guarded backend beginning in Wave 2.
    pub(crate) fn message(&self) -> &str {
        self.intent.message.expose_secret()
    }
}

impl fmt::Debug for ApprovedSend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedSend")
            .field("target", &self.target())
            .field("mode", &self.mode())
            .field("message", &"<redacted>")
            .field("nonce", &"<redacted>")
            .field("snapshot", &self.snapshot)
            .field("approved_at_unix_ms", &self.approved_at_unix_ms)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SendOutcome {
    DryRun,
    StagedAndRestored,
    CommitIssued,
    EchoConfirmed,
    SubmittedUnverified,
    NotSubmitted,
    Indeterminate,
}

impl SendOutcome {
    pub const fn attempted(self) -> bool {
        matches!(
            self,
            Self::CommitIssued
                | Self::EchoConfirmed
                | Self::SubmittedUnverified
                | Self::Indeterminate
        )
    }

    pub const fn retry_safe(self) -> bool {
        !matches!(
            self,
            Self::CommitIssued | Self::SubmittedUnverified | Self::Indeterminate
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UiErrorKind {
    ProcessNotFound,
    SessionMismatch,
    IntegrityMismatch,
    UnknownUiProfile,
    TargetNotFound,
    AmbiguousTarget,
    TargetNotSelf,
    ComposerNotFound,
    AmbiguousComposer,
    ExistingDraft,
    UserActive,
    ModalPresent,
    StaleSnapshot,
    PermissionDenied,
    Timeout,
    SubmissionUncertain,
    UnsupportedCapability,
    InvalidInput,
}

impl UiErrorKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ProcessNotFound => "process_not_found",
            Self::SessionMismatch => "session_mismatch",
            Self::IntegrityMismatch => "integrity_mismatch",
            Self::UnknownUiProfile => "unknown_ui_profile",
            Self::TargetNotFound => "target_not_found",
            Self::AmbiguousTarget => "ambiguous_target",
            Self::TargetNotSelf => "target_not_self",
            Self::ComposerNotFound => "composer_not_found",
            Self::AmbiguousComposer => "ambiguous_composer",
            Self::ExistingDraft => "existing_draft",
            Self::UserActive => "user_active",
            Self::ModalPresent => "modal_present",
            Self::StaleSnapshot => "stale_snapshot",
            Self::PermissionDenied => "permission_denied",
            Self::Timeout => "timeout",
            Self::SubmissionUncertain => "submission_uncertain",
            Self::UnsupportedCapability => "unsupported_capability",
            Self::InvalidInput => "invalid_input",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiError {
    pub kind: UiErrorKind,
    pub operation: &'static str,
    pub retry_safe: bool,
}

impl UiError {
    pub const fn new(kind: UiErrorKind, operation: &'static str) -> Self {
        Self {
            kind,
            operation,
            retry_safe: !matches!(kind, UiErrorKind::SubmissionUncertain),
        }
    }
}

impl fmt::Display for UiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.operation, self.kind.code())
    }
}

impl std::error::Error for UiError {}

pub trait PlatformProbe {
    fn capabilities(&self) -> UiCapabilities;
    fn inspect(&self, request: &InspectRequest) -> Result<UiSnapshot, UiError>;
}

pub trait MessageSender {
    fn stage(&self, approved: &ApprovedSend) -> Result<SendOutcome, UiError>;
    fn commit(&self, approved: &ApprovedSend) -> Result<SendOutcome, UiError>;
}

/// The dry-run seam accepts only the read-only trait, so mutation methods are
/// not available anywhere in its call graph.
pub fn inspect_dry_run<P: PlatformProbe>(
    probe: &P,
    request: &InspectRequest,
) -> Result<UiSnapshot, UiError> {
    probe.inspect(request)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    MacosAx,
    WindowsUia,
    Fake,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActionReport {
    pub schema_version: u8,
    pub action: String,
    pub platform: UiPlatform,
    pub backend: BackendKind,
    pub ui_profile: Option<String>,
    pub target: TargetKind,
    pub attempted: bool,
    pub outcome: SendOutcome,
    pub evidence: Vec<String>,
    pub retry_safe: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    Success = 0,
    Usage = 2,
    CapabilityUnavailable = 10,
    TargetRefused = 11,
    InputStateRefused = 12,
    EnvironmentRefused = 13,
    BackendFailure = 20,
    SubmissionIndeterminate = 21,
}

impl ExitCode {
    pub const fn for_error(kind: UiErrorKind) -> Self {
        match kind {
            UiErrorKind::InvalidInput => Self::Usage,
            UiErrorKind::ProcessNotFound | UiErrorKind::UnsupportedCapability => {
                Self::CapabilityUnavailable
            }
            UiErrorKind::TargetNotFound
            | UiErrorKind::AmbiguousTarget
            | UiErrorKind::TargetNotSelf => Self::TargetRefused,
            UiErrorKind::ComposerNotFound
            | UiErrorKind::AmbiguousComposer
            | UiErrorKind::ExistingDraft
            | UiErrorKind::UserActive
            | UiErrorKind::ModalPresent
            | UiErrorKind::StaleSnapshot => Self::InputStateRefused,
            UiErrorKind::SessionMismatch
            | UiErrorKind::IntegrityMismatch
            | UiErrorKind::UnknownUiProfile
            | UiErrorKind::PermissionDenied => Self::EnvironmentRefused,
            UiErrorKind::SubmissionUncertain => Self::SubmissionIndeterminate,
            UiErrorKind::Timeout => Self::BackendFailure,
        }
    }

    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_message_never_formats_as_plaintext() {
        let secret = SecretMessage::new("OPENKAKAO_CANARY");
        assert_eq!(format!("{secret}"), "<redacted>");
        assert_eq!(format!("{secret:?}"), "SecretMessage(<redacted>)");
    }

    #[test]
    fn send_intent_debug_redacts_message_and_nonce() {
        let intent = SendIntent::new(
            TargetKind::SelfChat,
            SecretMessage::new("OPENKAKAO_MESSAGE_CANARY"),
            SendMode::DryRun,
            false,
            "OPENKAKAO_NONCE_CANARY",
        );
        let rendered = format!("{intent:?}");
        assert!(!rendered.contains("OPENKAKAO_MESSAGE_CANARY"));
        assert!(!rendered.contains("OPENKAKAO_NONCE_CANARY"));
    }

    #[test]
    fn uncertain_outcomes_are_never_retry_safe() {
        for outcome in [
            SendOutcome::CommitIssued,
            SendOutcome::SubmittedUnverified,
            SendOutcome::Indeterminate,
        ] {
            assert!(!outcome.retry_safe());
        }
    }

    #[test]
    fn action_report_serialization_has_no_message_field() {
        let report = ActionReport {
            schema_version: 1,
            action: "local_send".to_string(),
            platform: UiPlatform::Windows,
            backend: BackendKind::Fake,
            ui_profile: Some("synthetic".to_string()),
            target: TargetKind::SelfChat,
            attempted: false,
            outcome: SendOutcome::DryRun,
            evidence: vec!["target_exact_unique".to_string()],
            retry_safe: true,
        };
        let json = serde_json::to_string(&report).expect("report should serialize");
        assert!(!json.contains("message"));
        assert!(!json.contains("chat_name"));
    }
}
