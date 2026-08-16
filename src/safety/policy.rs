//! Deny-by-default policy for the Windows self-chat MVP.
//!
//! The policy accepts only the supported Windows UI profile, a byte-exact and
//! unique configured self-chat label, a fresh read-only snapshot, and a
//! conservative message. Dry-run returns a redacted plan and cannot mint an
//! [`ApprovedSend`]. Write modes require explicit confirmation and return an
//! in-process lease that keeps all other approvals serialized until dropped.

use std::collections::HashSet;
use std::fmt;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::ApprovalToken;
use crate::platform::{
    exact_unique_match, ApprovedSend, ExactMatch, InspectRequest, PlatformProbe, SendIntent,
    SendMode, SendOutcome, TargetKind, UiCapabilities, UiError, UiErrorKind, UiPlatform,
    UiSnapshot,
};

/// The only KakaoTalk version accepted by the frozen Windows MVP profile.
pub const SUPPORTED_APP_VERSION: &str = "26.7.0.5255";

/// Conservative maximum message length, counted as Unicode scalar values.
pub const MAX_MESSAGE_SCALARS: usize = 1_000;

/// Aligned UTF-8 input ceiling: four bytes for each permitted scalar value.
pub const MAX_MESSAGE_UTF8_BYTES: usize = MAX_MESSAGE_SCALARS * 4;

/// Maximum caller nonce size. Nonces are opaque ASCII identifiers.
pub const MAX_NONCE_BYTES: usize = 128;

/// Maximum lifetime accepted for one inspection snapshot.
pub const MAX_SNAPSHOT_TTL_MS: u64 = 5_000;

const REDACTED_NONCE: &str = "<redacted>";

const OP_ALLOWLIST_CONFIG: &str = "policy_allowlist_config";
const OP_ALLOWLIST_MATCH: &str = "policy_allowlist_match";
const OP_VALIDATE_MODE: &str = "policy_validate_mode";
const OP_VALIDATE_CONFIRMATION: &str = "policy_validate_confirmation";
const OP_VALIDATE_MESSAGE: &str = "policy_validate_message";
const OP_VALIDATE_NONCE: &str = "policy_validate_nonce";
const OP_NONCE_REPLAY: &str = "policy_nonce_replay";
const OP_APPROVAL_MUTEX: &str = "policy_approval_mutex";
const OP_INSPECT_CAPABILITY: &str = "policy_inspect_capability";
const OP_SEND_CAPABILITY: &str = "policy_send_capability";
const OP_APP_SNAPSHOT: &str = "policy_app_snapshot";
const OP_SNAPSHOT_TIME: &str = "policy_snapshot_time";
const OP_TARGET_SNAPSHOT: &str = "policy_target_snapshot";
const OP_INPUT_SNAPSHOT: &str = "policy_input_snapshot";
const OP_CURRENT_TIME: &str = "policy_current_time";

/// Configuration kept at the safety boundary until root wires the legacy
/// flat configuration module into the Windows CLI.
pub struct WindowsPolicyConfig {
    allowed_self_chat_labels: Vec<String>,
}

impl WindowsPolicyConfig {
    /// Build an exact allowlist. Empty lists, empty/control-bearing entries,
    /// and byte-for-byte duplicate entries are rejected.
    pub fn new<I, S>(labels: I) -> Result<Self, UiError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let allowed_self_chat_labels: Vec<String> = labels.into_iter().map(Into::into).collect();

        if allowed_self_chat_labels.is_empty()
            || allowed_self_chat_labels
                .iter()
                .any(|label| label.is_empty() || label.chars().any(char::is_control))
        {
            return Err(policy_error(UiErrorKind::InvalidInput, OP_ALLOWLIST_CONFIG));
        }

        let mut unique = HashSet::with_capacity(allowed_self_chat_labels.len());
        if allowed_self_chat_labels
            .iter()
            .any(|label| !unique.insert(label.as_str()))
        {
            return Err(policy_error(
                UiErrorKind::AmbiguousTarget,
                OP_ALLOWLIST_CONFIG,
            ));
        }

        Ok(Self {
            allowed_self_chat_labels,
        })
    }

    pub fn allowed_label_count(&self) -> usize {
        self.allowed_self_chat_labels.len()
    }

    fn require_exact_unique(&self, requested_label: &str) -> Result<(), UiError> {
        match exact_unique_match(
            self.allowed_self_chat_labels
                .iter()
                .map(|label| Some(label.as_str())),
            requested_label,
        ) {
            ExactMatch::Found(_) => Ok(()),
            ExactMatch::NotFound => Err(policy_error(
                UiErrorKind::TargetNotFound,
                OP_ALLOWLIST_MATCH,
            )),
            ExactMatch::Ambiguous(_) => Err(policy_error(
                UiErrorKind::AmbiguousTarget,
                OP_ALLOWLIST_MATCH,
            )),
        }
    }
}

impl fmt::Debug for WindowsPolicyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsPolicyConfig")
            .field("allowed_self_chat_labels", &"<redacted>")
            .field("allowed_label_count", &self.allowed_label_count())
            .finish()
    }
}

/// Clock seam used to keep expiration checks deterministic in tests.
pub trait PolicyClock: Send + Sync {
    fn now_unix_ms(&self) -> Result<u64, UiError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemPolicyClock;

impl PolicyClock for SystemPolicyClock {
    fn now_unix_ms(&self) -> Result<u64, UiError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| policy_error(UiErrorKind::StaleSnapshot, OP_CURRENT_TIME))?;
        u64::try_from(elapsed.as_millis())
            .map_err(|_| policy_error(UiErrorKind::StaleSnapshot, OP_CURRENT_TIME))
    }
}

#[derive(Default)]
struct ApprovalState {
    used_nonces: HashSet<[u8; 32]>,
}

/// Windows self-chat policy. The mutex is deliberately process-local in Wave
/// 1: it has no OS-wide name or side effects and is fully testable with fakes.
pub struct WindowsSafetyPolicy<C = SystemPolicyClock> {
    config: WindowsPolicyConfig,
    clock: C,
    approval_state: Mutex<ApprovalState>,
}

impl WindowsSafetyPolicy<SystemPolicyClock> {
    pub fn new(config: WindowsPolicyConfig) -> Self {
        Self::with_clock(config, SystemPolicyClock)
    }
}

impl<C> WindowsSafetyPolicy<C>
where
    C: PolicyClock,
{
    pub fn with_clock(config: WindowsPolicyConfig, clock: C) -> Self {
        Self {
            config,
            clock,
            approval_state: Mutex::new(ApprovalState::default()),
        }
    }

    /// Validate a read-only dry-run. This method's generic bound exposes only
    /// [`PlatformProbe`], so stage/commit methods cannot occur in its call
    /// graph. It does not acquire the write lease or consume the nonce.
    pub fn dry_run<P>(
        &self,
        probe: &P,
        requested_label: &str,
        intent: &SendIntent,
    ) -> Result<DryRunPlan, UiError>
    where
        P: PlatformProbe + ?Sized,
    {
        validate_common_intent(&self.config, requested_label, intent)?;
        if intent.mode != SendMode::DryRun {
            return Err(policy_error(UiErrorKind::InvalidInput, OP_VALIDATE_MODE));
        }

        validate_inspect_capability(probe.capabilities())?;
        let snapshot = probe.inspect(&InspectRequest {
            target: TargetKind::SelfChat,
        })?;
        let now_unix_ms = self.clock.now_unix_ms()?;
        validate_snapshot(&snapshot, intent.target, now_unix_ms)?;

        Ok(DryRunPlan {
            schema_version: 1,
            target: TargetKind::SelfChat,
            mode: SendMode::DryRun,
            attempted: false,
            outcome: SendOutcome::DryRun,
            approval_issued: false,
            message_scalar_count: intent.message.len_chars(),
            snapshot_observed_at_unix_ms: snapshot.target.observed_at_unix_ms,
            snapshot_expires_at_unix_ms: snapshot.target.expires_at_unix_ms,
            retry_safe: true,
            snapshot,
        })
    }

    /// Validate and mint a one-shot approval for stage-only or commit mode.
    /// The returned lease keeps the process-local approval mutex held until it
    /// is dropped. A successfully approved nonce is permanently consumed.
    pub fn authorize<'policy, P>(
        &'policy self,
        probe: &P,
        requested_label: &str,
        intent: SendIntent,
    ) -> Result<ApprovedOperation<'policy>, UiError>
    where
        P: PlatformProbe + ?Sized,
    {
        validate_common_intent(&self.config, requested_label, &intent)?;
        match intent.mode {
            SendMode::DryRun => {
                return Err(policy_error(UiErrorKind::InvalidInput, OP_VALIDATE_MODE));
            }
            SendMode::StageOnly | SendMode::Commit if !intent.explicit_yes => {
                return Err(policy_error(
                    UiErrorKind::InvalidInput,
                    OP_VALIDATE_CONFIRMATION,
                ));
            }
            SendMode::StageOnly | SendMode::Commit => {}
        }

        let capabilities = probe.capabilities();
        validate_inspect_capability(capabilities)?;
        validate_send_capability(capabilities)?;
        let nonce_key = nonce_digest(&intent.nonce);
        let mut lease = self
            .approval_state
            .lock()
            .map_err(|_| policy_error(UiErrorKind::UnsupportedCapability, OP_APPROVAL_MUTEX))?;

        if lease.used_nonces.contains(&nonce_key) {
            return Err(policy_error(UiErrorKind::InvalidInput, OP_NONCE_REPLAY));
        }

        let snapshot = probe.inspect(&InspectRequest {
            target: TargetKind::SelfChat,
        })?;
        let now_unix_ms = self.clock.now_unix_ms()?;
        validate_snapshot(&snapshot, intent.target, now_unix_ms)?;

        lease.used_nonces.insert(nonce_key);
        let approved_intent = redact_intent_nonce(intent);
        let approved = ApprovedSend::from_policy(
            approved_intent,
            snapshot,
            now_unix_ms,
            ApprovalToken::issue(),
        );

        Ok(ApprovedOperation {
            approved,
            _lease: lease,
        })
    }
}

impl<C> fmt::Debug for WindowsSafetyPolicy<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsSafetyPolicy")
            .field("config", &self.config)
            .field("approval_state", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// A redacted, non-approved dry-run result.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct DryRunPlan {
    pub schema_version: u8,
    pub target: TargetKind,
    pub mode: SendMode,
    pub attempted: bool,
    pub outcome: SendOutcome,
    pub approval_issued: bool,
    pub message_scalar_count: usize,
    pub snapshot_observed_at_unix_ms: u64,
    pub snapshot_expires_at_unix_ms: u64,
    pub retry_safe: bool,
    #[serde(skip)]
    snapshot: UiSnapshot,
}

impl DryRunPlan {
    /// The exact redacted snapshot validated by this plan. Keeping this value
    /// avoids a second live probe and its associated state race.
    pub fn snapshot(&self) -> &UiSnapshot {
        &self.snapshot
    }
}

impl fmt::Debug for DryRunPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DryRunPlan")
            .field("schema_version", &self.schema_version)
            .field("target", &self.target)
            .field("mode", &self.mode)
            .field("attempted", &self.attempted)
            .field("outcome", &self.outcome)
            .field("approval_issued", &self.approval_issued)
            .field("message_scalar_count", &self.message_scalar_count)
            .field(
                "snapshot_observed_at_unix_ms",
                &self.snapshot_observed_at_unix_ms,
            )
            .field(
                "snapshot_expires_at_unix_ms",
                &self.snapshot_expires_at_unix_ms,
            )
            .field("retry_safe", &self.retry_safe)
            .field("snapshot", &"<redacted>")
            .finish()
    }
}

/// One in-process approval lease. The private [`MutexGuard`] makes the value
/// non-`Send`, and `approved()` lends rather than transfers the capability.
pub struct ApprovedOperation<'policy> {
    approved: ApprovedSend,
    _lease: MutexGuard<'policy, ApprovalState>,
}

impl ApprovedOperation<'_> {
    pub fn approved(&self) -> &ApprovedSend {
        &self.approved
    }
}

impl fmt::Debug for ApprovedOperation<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedOperation")
            .field("target", &self.approved.target())
            .field("mode", &self.approved.mode())
            .field("message", &"<redacted>")
            .field("nonce", &"<redacted>")
            .field("approved_at_unix_ms", &self.approved.approved_at_unix_ms())
            .finish()
    }
}

fn validate_common_intent(
    config: &WindowsPolicyConfig,
    requested_label: &str,
    intent: &SendIntent,
) -> Result<(), UiError> {
    if intent.target != TargetKind::SelfChat {
        return Err(policy_error(UiErrorKind::TargetNotSelf, OP_TARGET_SNAPSHOT));
    }

    config.require_exact_unique(requested_label)?;
    validate_message(&intent.message)?;
    validate_nonce(&intent.nonce)
}

fn validate_message(message: &crate::platform::SecretMessage) -> Result<(), UiError> {
    let value = message.expose_secret();
    let scalar_count = value.chars().count();
    if scalar_count == 0
        || scalar_count > MAX_MESSAGE_SCALARS
        || value.len() > MAX_MESSAGE_UTF8_BYTES
    {
        return Err(policy_error(UiErrorKind::InvalidInput, OP_VALIDATE_MESSAGE));
    }
    if value.chars().any(char::is_control) {
        return Err(policy_error(UiErrorKind::InvalidInput, OP_VALIDATE_MESSAGE));
    }
    Ok(())
}

fn validate_nonce(nonce: &str) -> Result<(), UiError> {
    let valid = !nonce.is_empty()
        && nonce.len() <= MAX_NONCE_BYTES
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'));
    if valid {
        Ok(())
    } else {
        Err(policy_error(UiErrorKind::InvalidInput, OP_VALIDATE_NONCE))
    }
}

fn validate_inspect_capability(capabilities: UiCapabilities) -> Result<(), UiError> {
    if capabilities.inspect {
        Ok(())
    } else {
        Err(policy_error(
            UiErrorKind::UnsupportedCapability,
            OP_INSPECT_CAPABILITY,
        ))
    }
}

fn validate_send_capability(capabilities: UiCapabilities) -> Result<(), UiError> {
    if capabilities.send_open_chat {
        Ok(())
    } else {
        Err(policy_error(
            UiErrorKind::UnsupportedCapability,
            OP_SEND_CAPABILITY,
        ))
    }
}

fn validate_snapshot(
    snapshot: &UiSnapshot,
    requested_target: TargetKind,
    now_unix_ms: u64,
) -> Result<(), UiError> {
    validate_app_snapshot(snapshot)?;
    validate_snapshot_time(snapshot, now_unix_ms)?;
    validate_target_snapshot(snapshot, requested_target)?;
    validate_input_snapshot(snapshot)
}

fn validate_app_snapshot(snapshot: &UiSnapshot) -> Result<(), UiError> {
    let app = &snapshot.app;
    if app.platform != UiPlatform::Windows {
        return Err(policy_error(
            UiErrorKind::UnsupportedCapability,
            OP_APP_SNAPSHOT,
        ));
    }
    if app.top_level_window_count > 1 {
        return Err(policy_error(UiErrorKind::AmbiguousTarget, OP_APP_SNAPSHOT));
    }
    if !app.app_running {
        return Err(policy_error(UiErrorKind::ProcessNotFound, OP_APP_SNAPSHOT));
    }
    let process = app
        .process
        .as_ref()
        .ok_or_else(|| policy_error(UiErrorKind::ProcessNotFound, OP_APP_SNAPSHOT))?;
    if process.pid == 0 || app.top_level_window_count == 0 {
        return Err(policy_error(UiErrorKind::ProcessNotFound, OP_APP_SNAPSHOT));
    }
    if process.session_id.is_none() || !app.interactive_session_match {
        return Err(policy_error(UiErrorKind::SessionMismatch, OP_APP_SNAPSHOT));
    }
    if !app.integrity_compatible {
        return Err(policy_error(
            UiErrorKind::IntegrityMismatch,
            OP_APP_SNAPSHOT,
        ));
    }
    if process.executable.is_empty()
        || !app.known_ui_profile
        || app.app_version.as_deref() != Some(SUPPORTED_APP_VERSION)
    {
        return Err(policy_error(UiErrorKind::UnknownUiProfile, OP_APP_SNAPSHOT));
    }
    if app.modal_present {
        return Err(policy_error(UiErrorKind::ModalPresent, OP_APP_SNAPSHOT));
    }
    Ok(())
}

fn validate_snapshot_time(snapshot: &UiSnapshot, now_unix_ms: u64) -> Result<(), UiError> {
    let observed = snapshot.target.observed_at_unix_ms;
    let expires = snapshot.target.expires_at_unix_ms;
    let ttl = expires
        .checked_sub(observed)
        .ok_or_else(|| policy_error(UiErrorKind::StaleSnapshot, OP_SNAPSHOT_TIME))?;

    if ttl == 0 || ttl > MAX_SNAPSHOT_TTL_MS || now_unix_ms < observed || now_unix_ms >= expires {
        return Err(policy_error(UiErrorKind::StaleSnapshot, OP_SNAPSHOT_TIME));
    }
    Ok(())
}

fn validate_target_snapshot(
    snapshot: &UiSnapshot,
    requested_target: TargetKind,
) -> Result<(), UiError> {
    let target = &snapshot.target;
    if requested_target != TargetKind::SelfChat
        || target.kind != TargetKind::SelfChat
        || !target.self_chat_verified
    {
        return Err(policy_error(UiErrorKind::TargetNotSelf, OP_TARGET_SNAPSHOT));
    }
    if !target.exact_match {
        return Err(policy_error(
            UiErrorKind::TargetNotFound,
            OP_TARGET_SNAPSHOT,
        ));
    }
    if !target.unique_match {
        return Err(policy_error(
            UiErrorKind::AmbiguousTarget,
            OP_TARGET_SNAPSHOT,
        ));
    }
    if target.window.as_deref().is_none_or(str::is_empty) {
        return Err(policy_error(
            UiErrorKind::TargetNotFound,
            OP_TARGET_SNAPSHOT,
        ));
    }
    if target.composer.as_deref().is_none_or(str::is_empty) {
        return Err(policy_error(
            UiErrorKind::ComposerNotFound,
            OP_TARGET_SNAPSHOT,
        ));
    }
    Ok(())
}

fn validate_input_snapshot(snapshot: &UiSnapshot) -> Result<(), UiError> {
    let input = &snapshot.input;
    if !input.present {
        return Err(policy_error(
            UiErrorKind::ComposerNotFound,
            OP_INPUT_SNAPSHOT,
        ));
    }
    if !input.unique {
        return Err(policy_error(
            UiErrorKind::AmbiguousComposer,
            OP_INPUT_SNAPSHOT,
        ));
    }
    if !input.enabled || !input.writable {
        return Err(policy_error(
            UiErrorKind::PermissionDenied,
            OP_INPUT_SNAPSHOT,
        ));
    }
    if !input.draft_empty {
        return Err(policy_error(UiErrorKind::ExistingDraft, OP_INPUT_SNAPSHOT));
    }
    if input.focused {
        return Err(policy_error(UiErrorKind::UserActive, OP_INPUT_SNAPSHOT));
    }
    if input
        .selector_profile_id
        .as_deref()
        .is_none_or(str::is_empty)
    {
        return Err(policy_error(
            UiErrorKind::UnknownUiProfile,
            OP_INPUT_SNAPSHOT,
        ));
    }
    Ok(())
}

fn nonce_digest(nonce: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"openkakao.windows.policy.nonce.v1\0");
    hasher.update(nonce.as_bytes());
    hasher.finalize().into()
}

fn redact_intent_nonce(intent: SendIntent) -> SendIntent {
    SendIntent {
        target: intent.target,
        message: intent.message,
        mode: intent.mode,
        explicit_yes: intent.explicit_yes,
        nonce: REDACTED_NONCE.to_string(),
    }
}

const fn policy_error(kind: UiErrorKind, operation: &'static str) -> UiError {
    UiError::new(kind, operation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{AppSnapshot, InputSnapshot, ProcessFingerprint, SecretMessage};

    fn snapshot() -> UiSnapshot {
        UiSnapshot {
            app: AppSnapshot {
                platform: UiPlatform::Windows,
                app_running: true,
                process: Some(ProcessFingerprint {
                    pid: 7,
                    executable: "process-fingerprint".to_string(),
                    session_id: Some(1),
                }),
                app_version: Some(SUPPORTED_APP_VERSION.to_string()),
                interactive_session_match: true,
                integrity_compatible: true,
                known_ui_profile: true,
                top_level_window_count: 1,
                modal_present: false,
            },
            target: crate::platform::ChatTargetSnapshot {
                kind: TargetKind::SelfChat,
                self_chat_verified: true,
                exact_match: true,
                unique_match: true,
                window: Some("window-fingerprint".to_string()),
                composer: Some("composer-fingerprint".to_string()),
                observed_at_unix_ms: 1_000,
                expires_at_unix_ms: 2_000,
            },
            input: InputSnapshot {
                present: true,
                unique: true,
                enabled: true,
                writable: true,
                draft_empty: true,
                focused: false,
                selector_profile_id: Some("known-selector".to_string()),
            },
        }
    }

    #[test]
    fn scalar_limit_counts_unicode_scalars_not_bytes() {
        let accepted = SecretMessage::new("\u{1f642}".repeat(MAX_MESSAGE_SCALARS));
        let refused = SecretMessage::new("\u{1f642}".repeat(MAX_MESSAGE_SCALARS + 1));
        assert!(validate_message(&accepted).is_ok());
        assert_eq!(
            validate_message(&refused)
                .expect_err("over limit must fail")
                .kind,
            UiErrorKind::InvalidInput
        );
    }

    #[test]
    fn ttl_is_observed_inclusive_and_expiry_exclusive() {
        let state = snapshot();
        assert!(validate_snapshot_time(&state, 1_000).is_ok());
        assert_eq!(
            validate_snapshot_time(&state, 2_000)
                .expect_err("expiry boundary must be stale")
                .kind,
            UiErrorKind::StaleSnapshot
        );
    }

    #[test]
    fn nonce_digest_is_deterministic_and_domain_separated() {
        let first = nonce_digest("nonce-1");
        assert_eq!(first, nonce_digest("nonce-1"));
        assert_ne!(first, nonce_digest("nonce-2"));
        assert_ne!(first.as_slice(), "nonce-1".as_bytes());
    }
}
