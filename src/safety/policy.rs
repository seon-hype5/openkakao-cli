//! Deny-by-default policy for the Windows self-chat MVP.
//!
//! The policy accepts only the supported Windows UI profile, a byte-exact and
//! unique configured self-chat label, a fresh read-only snapshot, and a
//! conservative message. Dry-run returns a redacted plan and cannot mint an
//! [`ApprovedSend`]. Write modes require explicit confirmation and return an
//! in-process lease that keeps all other approvals serialized until dropped.

use std::collections::HashSet;
use std::fmt;
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::ApprovalToken;
use crate::platform::contract::{TargetBindingPermit, MAX_TARGET_LABEL_UTF16_UNITS};
use crate::platform::{
    exact_unique_match, ApprovedSend, ExactMatch, InspectRequest, MessageSender, PlatformProbe,
    SendIntent, SendMode, SendOutcome, TargetKind, UiCapabilities, UiError, UiErrorKind,
    UiPlatform, UiSnapshot,
};

/// The only KakaoTalk version accepted by the frozen Windows MVP profile.
pub const SUPPORTED_APP_VERSION: &str = "26.7.0.5255";

/// The only selector profile accepted by the frozen Windows MVP policy.
pub const SUPPORTED_SELECTOR_PROFILE_ID: &str = "kakaotalk-windows-x64-stable-26.7.0.5255-v2";

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
const OP_DRY_RUN_INSPECT: &str = "policy_dry_run_inspect";
const OP_AUTHORIZE_INSPECT: &str = "policy_authorize_inspect";
const OP_EXECUTE_MODE: &str = "policy_execute_mode";
const OP_EXECUTE_OUTCOME: &str = "policy_execute_outcome";
const OP_APP_SNAPSHOT: &str = "policy_app_snapshot";
const OP_SNAPSHOT_TIME: &str = "policy_snapshot_time";
const OP_TARGET_SNAPSHOT: &str = "policy_target_snapshot";
const OP_INPUT_SNAPSHOT: &str = "policy_input_snapshot";
const OP_CURRENT_TIME: &str = "policy_current_time";
const OP_CORRELATION_RNG: &str = "policy_correlation_rng";
const OP_TARGET_BINDING_RNG: &str = "policy_target_binding_rng";
const OP_TARGET_BINDING: &str = "policy_target_binding";

/// Configuration kept at the safety boundary until root wires the legacy
/// flat configuration module into the Windows CLI.
pub struct WindowsPolicyConfig {
    allowed_self_chat_labels: Vec<String>,
}

impl WindowsPolicyConfig {
    /// Build an exact allowlist. Empty lists, empty/control-bearing or
    /// over-bound entries, and byte-for-byte duplicate entries are rejected.
    pub fn new<I, S>(labels: I) -> Result<Self, UiError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut allowed_self_chat_labels: Vec<String> =
            labels.into_iter().map(Into::into).collect();

        if allowed_self_chat_labels.is_empty()
            || allowed_self_chat_labels.iter().any(|label| {
                label.is_empty()
                    || label.chars().all(char::is_whitespace)
                    || label.chars().any(char::is_control)
                    || label.encode_utf16().count() > MAX_TARGET_LABEL_UTF16_UNITS
            })
        {
            allowed_self_chat_labels.zeroize();
            return Err(policy_error(UiErrorKind::InvalidInput, OP_ALLOWLIST_CONFIG));
        }

        let has_duplicate = {
            let mut unique = HashSet::with_capacity(allowed_self_chat_labels.len());
            allowed_self_chat_labels
                .iter()
                .any(|label| !unique.insert(label.as_str()))
        };
        if has_duplicate {
            allowed_self_chat_labels.zeroize();
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

    /// Validates a sensitive requested label without formatting or returning
    /// it. Callers may use this before acquiring message bytes or UI state;
    /// authorization repeats the same validation at the policy boundary.
    pub fn validate_requested_label(&self, requested_label: &str) -> Result<(), UiError> {
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

impl Drop for WindowsPolicyConfig {
    fn drop(&mut self) {
        self.allowed_self_chat_labels.zeroize();
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
        let (snapshot, target_binding) =
            inspect_for_policy(probe, requested_label, OP_DRY_RUN_INSPECT)?;
        let now_unix_ms = policy_now(&self.clock)?;
        validate_snapshot(
            &snapshot,
            intent.target,
            now_unix_ms,
            &target_binding,
            false,
        )?;

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
        let mut lease = match self.approval_state.try_lock() {
            Ok(lease) => lease,
            Err(TryLockError::WouldBlock | TryLockError::Poisoned(_)) => {
                return Err(policy_error(
                    UiErrorKind::UnsupportedCapability,
                    OP_APPROVAL_MUTEX,
                ));
            }
        };

        if lease.used_nonces.contains(&nonce_key) {
            return Err(policy_error(UiErrorKind::InvalidInput, OP_NONCE_REPLAY));
        }

        let (snapshot, target_binding) =
            inspect_for_policy(probe, requested_label, OP_AUTHORIZE_INSPECT)?;
        let approved_at_monotonic = Instant::now();
        let now_unix_ms = policy_now(&self.clock)?;
        let allow_indeterminate_stage_recovery =
            intent.mode == SendMode::Commit && capabilities.recover_indeterminate_stage;
        validate_snapshot(
            &snapshot,
            intent.target,
            now_unix_ms,
            &target_binding,
            allow_indeterminate_stage_recovery,
        )?;
        let approval_deadline = approval_deadline(&snapshot, now_unix_ms, approved_at_monotonic)?;

        let transaction_correlation = generate_transaction_correlation()?;
        let approved_intent = redact_intent_nonce(intent);
        let approved = ApprovedSend::from_policy(
            approved_intent,
            snapshot,
            target_binding,
            now_unix_ms,
            approval_deadline,
            transaction_correlation,
            ApprovalToken::issue(),
        )?;
        lease.used_nonces.insert(nonce_key);

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
/// non-`Send`, and [`execute`](Self::execute) consumes the capability.
pub struct ApprovedOperation<'policy> {
    approved: ApprovedSend,
    _lease: MutexGuard<'policy, ApprovalState>,
}

impl ApprovedOperation<'_> {
    pub fn target(&self) -> TargetKind {
        self.approved.target()
    }

    pub fn mode(&self) -> SendMode {
        self.approved.mode()
    }

    pub fn snapshot(&self) -> &UiSnapshot {
        self.approved.snapshot()
    }

    pub fn approved_at_unix_ms(&self) -> u64 {
        self.approved.approved_at_unix_ms()
    }

    /// Dispatches exactly once according to the approved mode while retaining
    /// the policy lease for the entire backend transaction.
    ///
    /// The operation is consumed regardless of success or failure. No public
    /// API lends the underlying [`ApprovedSend`], so a caller cannot invoke a
    /// sender twice with the same approval.
    pub fn execute<S>(self, sender: &S) -> Result<SendOutcome, UiError>
    where
        S: MessageSender + ?Sized,
    {
        self.execute_at(sender, Instant::now())
    }

    fn execute_at<S>(self, sender: &S, now_monotonic: Instant) -> Result<SendOutcome, UiError>
    where
        S: MessageSender + ?Sized,
    {
        if self.approved.monotonic_deadline_reached_at(now_monotonic) {
            return Err(policy_error(UiErrorKind::StaleSnapshot, OP_SNAPSHOT_TIME));
        }

        let mode = self.approved.mode();
        let outcome = match mode {
            SendMode::StageOnly => sender.stage(&self.approved),
            SendMode::Commit => sender.commit(&self.approved),
            SendMode::DryRun => Err(policy_error(UiErrorKind::InvalidInput, OP_EXECUTE_MODE)),
        }?;

        validate_execute_outcome(mode, outcome)
    }
}

/// Refuses a sender result that is incompatible with the operation that was
/// dispatched. Once a mutation method has returned, the policy cannot prove
/// that no write or submission occurred, so a mismatch is always uncertain
/// and never retry-safe.
fn validate_execute_outcome(mode: SendMode, outcome: SendOutcome) -> Result<SendOutcome, UiError> {
    let compatible = match mode {
        SendMode::StageOnly => matches!(outcome, SendOutcome::StagedAndRestored),
        SendMode::Commit => matches!(
            outcome,
            SendOutcome::CommitIssued
                | SendOutcome::EchoConfirmed
                | SendOutcome::SubmittedUnverified
                | SendOutcome::Indeterminate
        ),
        SendMode::DryRun => false,
    };

    if compatible {
        Ok(outcome)
    } else {
        Err(policy_error(
            UiErrorKind::SubmissionUncertain,
            OP_EXECUTE_OUTCOME,
        ))
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

    config.validate_requested_label(requested_label)?;
    validate_message(&intent.message)?;
    validate_nonce(&intent.nonce)
}

fn validate_message(message: &crate::platform::SecretMessage) -> Result<(), UiError> {
    let value = message.expose_secret();
    let scalar_count = value.chars().count();
    if scalar_count == 0
        || scalar_count > MAX_MESSAGE_SCALARS
        || value.len() > MAX_MESSAGE_UTF8_BYTES
        || value.chars().all(char::is_whitespace)
    {
        return Err(policy_error(UiErrorKind::InvalidInput, OP_VALIDATE_MESSAGE));
    }
    if value.chars().any(is_disallowed_message_scalar) {
        return Err(policy_error(UiErrorKind::InvalidInput, OP_VALIDATE_MESSAGE));
    }
    Ok(())
}

fn is_disallowed_message_scalar(value: char) -> bool {
    value.is_control() || matches!(value, '\u{2028}' | '\u{2029}')
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

fn inspect_for_policy<P>(
    probe: &P,
    requested_label: &str,
    operation: &'static str,
) -> Result<(UiSnapshot, TargetBindingPermit), UiError>
where
    P: PlatformProbe + ?Sized,
{
    let binding_key = generate_target_binding_key()?;
    let (request, permit) = InspectRequest::bound_self_chat(requested_label, binding_key);
    let snapshot = probe
        .inspect(&request)
        .map_err(|error| sanitize_external_error(error, operation))?;
    Ok((snapshot, permit))
}

fn policy_now<C>(clock: &C) -> Result<u64, UiError>
where
    C: PolicyClock,
{
    clock
        .now_unix_ms()
        .map_err(|_| policy_error(UiErrorKind::StaleSnapshot, OP_CURRENT_TIME))
}

fn sanitize_external_error(error: UiError, operation: &'static str) -> UiError {
    let mut sanitized = policy_error(error.kind, operation);
    sanitized.retry_safe &= error.retry_safe;
    sanitized
}

fn validate_snapshot(
    snapshot: &UiSnapshot,
    requested_target: TargetKind,
    now_unix_ms: u64,
    target_binding: &TargetBindingPermit,
    allow_indeterminate_stage_recovery: bool,
) -> Result<(), UiError> {
    validate_app_snapshot(snapshot)?;
    validate_snapshot_time(snapshot, now_unix_ms)?;
    validate_target_snapshot(snapshot, requested_target, target_binding)?;
    validate_input_snapshot(snapshot, allow_indeterminate_stage_recovery)
}

fn validate_app_snapshot(snapshot: &UiSnapshot) -> Result<(), UiError> {
    let app = &snapshot.app;
    if app.platform != UiPlatform::Windows {
        return Err(policy_error(
            UiErrorKind::UnsupportedCapability,
            OP_APP_SNAPSHOT,
        ));
    }
    if app.read_only_window_ambiguity.is_some() || app.top_level_window_count > 1 {
        return Err(policy_error(UiErrorKind::AmbiguousTarget, OP_APP_SNAPSHOT));
    }
    if app.read_only_composer_selector_evidence.is_some() {
        return Err(policy_error(
            UiErrorKind::ComposerNotFound,
            OP_INPUT_SNAPSHOT,
        ));
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
    if !is_redacted_fingerprint(&process.executable)
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

fn approval_deadline(
    snapshot: &UiSnapshot,
    approved_at_unix_ms: u64,
    approved_at_monotonic: Instant,
) -> Result<Instant, UiError> {
    let remaining_ms = snapshot
        .target
        .expires_at_unix_ms
        .checked_sub(approved_at_unix_ms)
        .filter(|remaining| *remaining > 0 && *remaining <= MAX_SNAPSHOT_TTL_MS)
        .ok_or_else(|| policy_error(UiErrorKind::StaleSnapshot, OP_SNAPSHOT_TIME))?;

    approved_at_monotonic
        .checked_add(Duration::from_millis(remaining_ms))
        .ok_or_else(|| policy_error(UiErrorKind::StaleSnapshot, OP_SNAPSHOT_TIME))
}

fn validate_target_snapshot(
    snapshot: &UiSnapshot,
    requested_target: TargetKind,
    target_binding: &TargetBindingPermit,
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
    let window = target
        .window
        .as_deref()
        .filter(|value| is_redacted_fingerprint(value))
        .ok_or_else(|| policy_error(UiErrorKind::TargetNotFound, OP_TARGET_SNAPSHOT))?;
    let composer = target
        .composer
        .as_deref()
        .filter(|value| is_redacted_fingerprint(value))
        .ok_or_else(|| policy_error(UiErrorKind::ComposerNotFound, OP_TARGET_SNAPSHOT))?;
    if window == composer {
        return Err(policy_error(
            UiErrorKind::UnknownUiProfile,
            OP_TARGET_SNAPSHOT,
        ));
    }
    if !target_binding.verifies_snapshot(snapshot) {
        return Err(policy_error(UiErrorKind::TargetNotSelf, OP_TARGET_BINDING));
    }
    Ok(())
}

fn validate_input_snapshot(
    snapshot: &UiSnapshot,
    allow_indeterminate_stage_recovery: bool,
) -> Result<(), UiError> {
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
    if input.focused {
        return Err(policy_error(UiErrorKind::UserActive, OP_INPUT_SNAPSHOT));
    }
    if !input.draft_empty && !allow_indeterminate_stage_recovery {
        return Err(policy_error(UiErrorKind::ExistingDraft, OP_INPUT_SNAPSHOT));
    }
    if input.selector_profile_id.as_deref() != Some(SUPPORTED_SELECTOR_PROFILE_ID) {
        return Err(policy_error(
            UiErrorKind::UnknownUiProfile,
            OP_INPUT_SNAPSHOT,
        ));
    }
    Ok(())
}

fn is_redacted_fingerprint(value: &str) -> bool {
    value.strip_prefix("run:").is_some_and(|digest| {
        digest.len() == 32
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn nonce_digest(nonce: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"openkakao.windows.policy.nonce.v1\0");
    hasher.update(nonce.as_bytes());
    hasher.finalize().into()
}

fn generate_transaction_correlation() -> Result<[u8; 16], UiError> {
    let mut correlation = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut correlation)
        .map_err(|_| policy_error(UiErrorKind::UnsupportedCapability, OP_CORRELATION_RNG))?;
    if correlation == [0; 16] {
        return Err(policy_error(
            UiErrorKind::UnsupportedCapability,
            OP_CORRELATION_RNG,
        ));
    }
    Ok(correlation)
}

fn generate_target_binding_key() -> Result<[u8; 32], UiError> {
    let mut key = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut key)
        .map_err(|_| policy_error(UiErrorKind::UnsupportedCapability, OP_TARGET_BINDING_RNG))?;
    if key == [0; 32] {
        key.zeroize();
        return Err(policy_error(
            UiErrorKind::UnsupportedCapability,
            OP_TARGET_BINDING_RNG,
        ));
    }
    Ok(key)
}

fn redact_intent_nonce(mut intent: SendIntent) -> SendIntent {
    intent.nonce.zeroize();
    intent.nonce.push_str(REDACTED_NONCE);
    intent
}

const fn policy_error(kind: UiErrorKind, operation: &'static str) -> UiError {
    UiError::new(kind, operation)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::platform::{
        AppSnapshot, InputSnapshot, ProcessFingerprint, ReadOnlyComposerSelectorEvidence,
        SecretMessage,
    };

    fn snapshot() -> UiSnapshot {
        UiSnapshot {
            app: AppSnapshot {
                platform: UiPlatform::Windows,
                app_running: true,
                process: Some(ProcessFingerprint {
                    pid: 7,
                    executable: "run:11111111111111111111111111111111".to_string(),
                    session_id: Some(1),
                }),
                app_version: Some(SUPPORTED_APP_VERSION.to_string()),
                interactive_session_match: true,
                integrity_compatible: true,
                known_ui_profile: true,
                top_level_window_count: 1,
                read_only_window_ambiguity: None,
                read_only_composer_selector_evidence: None,
                modal_present: false,
            },
            target: crate::platform::ChatTargetSnapshot {
                kind: TargetKind::SelfChat,
                self_chat_verified: true,
                exact_match: true,
                unique_match: true,
                window: Some("run:22222222222222222222222222222222".to_string()),
                composer: Some("run:33333333333333333333333333333333".to_string()),
                observed_at_unix_ms: 1_000,
                expires_at_unix_ms: 2_000,
                target_binding: None,
            },
            input: InputSnapshot {
                present: true,
                unique: true,
                enabled: true,
                writable: true,
                draft_empty: true,
                focused: false,
                selector_profile_id: Some(SUPPORTED_SELECTOR_PROFILE_ID.to_string()),
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
    fn composer_selector_diagnostic_is_always_a_policy_refusal() {
        let mut state = snapshot();
        state.app.read_only_composer_selector_evidence = Some(
            ReadOnlyComposerSelectorEvidence::from_near_matches(true, true, true),
        );

        let error = validate_app_snapshot(&state)
            .expect_err("diagnostic evidence must never become mutation authority");
        assert_eq!(error.kind, UiErrorKind::ComposerNotFound);
        assert_eq!(error.operation, OP_INPUT_SNAPSHOT);
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

        let anchor = Instant::now();
        let deadline = approval_deadline(&state, 1_500, anchor)
            .expect("synthetic remaining lifetime must form a deadline");
        assert_eq!(
            deadline.checked_duration_since(anchor),
            Some(Duration::from_millis(500))
        );
        let exact_expiry = approval_deadline(&state, 2_000, anchor)
            .expect_err("zero remaining lifetime must fail closed");
        assert_eq!(exact_expiry.kind, UiErrorKind::StaleSnapshot);
        assert_eq!(exact_expiry.operation, OP_SNAPSHOT_TIME);
    }

    #[test]
    fn existing_draft_recovery_requires_commit_mode_and_the_sealed_capability() {
        let mut state = snapshot();
        state.input.draft_empty = false;
        let policy = WindowsSafetyPolicy::with_clock(
            WindowsPolicyConfig::new(["SYNTHETIC_SELF_CHAT"]).unwrap(),
            FixedClock,
        );

        let unsupported = policy
            .authorize(
                &StaticProbe(state.clone()),
                "SYNTHETIC_SELF_CHAT",
                SendIntent::new(
                    TargetKind::SelfChat,
                    SecretMessage::new("SYNTHETIC_BODY"),
                    SendMode::Commit,
                    true,
                    "synthetic-recovery-unsupported",
                ),
            )
            .unwrap_err();
        assert_eq!(unsupported.kind, UiErrorKind::ExistingDraft);

        let wrong_mode = policy
            .authorize(
                &RecoveryProbe(state.clone()),
                "SYNTHETIC_SELF_CHAT",
                SendIntent::new(
                    TargetKind::SelfChat,
                    SecretMessage::new("SYNTHETIC_BODY"),
                    SendMode::StageOnly,
                    true,
                    "synthetic-recovery-stage",
                ),
            )
            .unwrap_err();
        assert_eq!(wrong_mode.kind, UiErrorKind::ExistingDraft);

        state.input.focused = true;
        let focused = policy
            .authorize(
                &RecoveryProbe(state.clone()),
                "SYNTHETIC_SELF_CHAT",
                SendIntent::new(
                    TargetKind::SelfChat,
                    SecretMessage::new("SYNTHETIC_BODY"),
                    SendMode::Commit,
                    true,
                    "synthetic-recovery-focused",
                ),
            )
            .unwrap_err();
        assert_eq!(focused.kind, UiErrorKind::UserActive);

        state.input.focused = false;
        let approval = policy
            .authorize(
                &RecoveryProbe(state),
                "SYNTHETIC_SELF_CHAT",
                SendIntent::new(
                    TargetKind::SelfChat,
                    SecretMessage::new("SYNTHETIC_BODY"),
                    SendMode::Commit,
                    true,
                    "synthetic-recovery-authorized",
                ),
            )
            .expect("the capability may mint only a recovery-marked commit approval");
        assert!(approval.approved.recover_indeterminate_stage());
    }

    #[test]
    fn expired_monotonic_approval_refuses_before_sender_dispatch() {
        let policy = WindowsSafetyPolicy::with_clock(
            WindowsPolicyConfig::new(["SYNTHETIC_SELF_CHAT"]).unwrap(),
            FixedClock,
        );
        let approval = policy
            .authorize(
                &StaticProbe(snapshot()),
                "SYNTHETIC_SELF_CHAT",
                SendIntent::new(
                    TargetKind::SelfChat,
                    SecretMessage::new("SYNTHETIC_BODY"),
                    SendMode::StageOnly,
                    true,
                    "synthetic-expired-monotonic",
                ),
            )
            .expect("synthetic state should authorize");
        let sender = MismatchedOutcomeSender {
            outcome: SendOutcome::StagedAndRestored,
            stage_calls: Cell::new(0),
            commit_calls: Cell::new(0),
        };
        let after_maximum_ttl = Instant::now()
            .checked_add(Duration::from_millis(MAX_SNAPSHOT_TTL_MS + 1))
            .expect("synthetic future instant must be representable");

        let error = approval
            .execute_at(&sender, after_maximum_ttl)
            .expect_err("expired monotonic approval must fail closed");

        assert_eq!(error.kind, UiErrorKind::StaleSnapshot);
        assert_eq!(error.operation, OP_SNAPSHOT_TIME);
        assert_eq!(sender.stage_calls.get(), 0);
        assert_eq!(sender.commit_calls.get(), 0);
    }

    #[test]
    fn nonce_digest_is_deterministic_and_domain_separated() {
        let first = nonce_digest("nonce-1");
        assert_eq!(first, nonce_digest("nonce-1"));
        assert_ne!(first, nonce_digest("nonce-2"));
        assert_ne!(first.as_slice(), "nonce-1".as_bytes());
    }

    #[test]
    fn execute_outcomes_are_compatible_with_the_dispatched_mode() {
        assert_eq!(
            validate_execute_outcome(SendMode::StageOnly, SendOutcome::StagedAndRestored),
            Ok(SendOutcome::StagedAndRestored)
        );

        for outcome in [
            SendOutcome::CommitIssued,
            SendOutcome::EchoConfirmed,
            SendOutcome::SubmittedUnverified,
            SendOutcome::Indeterminate,
        ] {
            assert_eq!(
                validate_execute_outcome(SendMode::Commit, outcome),
                Ok(outcome)
            );
        }
    }

    #[test]
    fn incompatible_execute_outcomes_are_submission_uncertain() {
        for (mode, outcome) in [
            (SendMode::StageOnly, SendOutcome::DryRun),
            (SendMode::StageOnly, SendOutcome::CommitIssued),
            (SendMode::StageOnly, SendOutcome::NotSubmitted),
            (SendMode::Commit, SendOutcome::DryRun),
            (SendMode::Commit, SendOutcome::StagedAndRestored),
            (SendMode::Commit, SendOutcome::NotSubmitted),
            (SendMode::DryRun, SendOutcome::DryRun),
        ] {
            let error = validate_execute_outcome(mode, outcome)
                .expect_err("a mode/outcome mismatch must fail closed");
            assert_eq!(error.kind, UiErrorKind::SubmissionUncertain);
            assert_eq!(error.operation, OP_EXECUTE_OUTCOME);
            assert!(!error.retry_safe);
        }
    }

    #[derive(Clone)]
    struct FixedClock;

    impl PolicyClock for FixedClock {
        fn now_unix_ms(&self) -> Result<u64, UiError> {
            Ok(1_500)
        }
    }

    struct StaticProbe(UiSnapshot);

    impl PlatformProbe for StaticProbe {
        fn capabilities(&self) -> UiCapabilities {
            UiCapabilities {
                inspect: true,
                send_open_chat: true,
                recover_indeterminate_stage: false,
                open_chat_by_name: false,
                read_visible: false,
                watch_unread: false,
            }
        }

        fn inspect(&self, request: &InspectRequest) -> Result<UiSnapshot, UiError> {
            let mut snapshot = self.0.clone();
            let observed_utf16: Vec<u16> = "SYNTHETIC_SELF_CHAT".encode_utf16().collect();
            snapshot.target.target_binding =
                request.bind_observed_target_utf16(&observed_utf16, &snapshot);
            Ok(snapshot)
        }
    }

    struct RecoveryProbe(UiSnapshot);

    impl PlatformProbe for RecoveryProbe {
        fn capabilities(&self) -> UiCapabilities {
            UiCapabilities::windows_guarded_write()
        }

        fn inspect(&self, request: &InspectRequest) -> Result<UiSnapshot, UiError> {
            let mut snapshot = self.0.clone();
            let observed_utf16: Vec<u16> = "SYNTHETIC_SELF_CHAT".encode_utf16().collect();
            snapshot.target.target_binding =
                request.bind_observed_target_utf16(&observed_utf16, &snapshot);
            Ok(snapshot)
        }
    }

    struct MismatchedOutcomeSender {
        outcome: SendOutcome,
        stage_calls: Cell<usize>,
        commit_calls: Cell<usize>,
    }

    impl crate::platform::contract::message_sender_seal::Sealed for MismatchedOutcomeSender {}

    impl MessageSender for MismatchedOutcomeSender {
        fn stage(&self, _approved: &ApprovedSend) -> Result<SendOutcome, UiError> {
            self.stage_calls.set(self.stage_calls.get() + 1);
            Ok(self.outcome)
        }

        fn commit(&self, _approved: &ApprovedSend) -> Result<SendOutcome, UiError> {
            self.commit_calls.set(self.commit_calls.get() + 1);
            Ok(self.outcome)
        }
    }

    struct CorrelationInspectingSender {
        stage_calls: Cell<usize>,
    }

    impl crate::platform::contract::message_sender_seal::Sealed for CorrelationInspectingSender {}

    impl MessageSender for CorrelationInspectingSender {
        fn stage(&self, approved: &ApprovedSend) -> Result<SendOutcome, UiError> {
            self.stage_calls.set(self.stage_calls.get() + 1);
            let correlation = approved.take_transaction_correlation()?;
            assert_eq!(
                format!("{correlation:?}"),
                "TransactionCorrelation(<redacted>)"
            );
            assert_ne!(correlation.into_bytes(), [0; 16]);

            let replay = approved.take_transaction_correlation().unwrap_err();
            assert_eq!(replay.kind, UiErrorKind::InvalidInput);
            assert_eq!(replay.operation, "approved_send_correlation_consumed");
            Ok(SendOutcome::StagedAndRestored)
        }

        fn commit(&self, _approved: &ApprovedSend) -> Result<SendOutcome, UiError> {
            panic!("synthetic stage approval must not dispatch commit")
        }
    }

    #[test]
    fn policy_correlation_is_nonzero_one_shot_and_redacted() {
        let policy = WindowsSafetyPolicy::with_clock(
            WindowsPolicyConfig::new(["SYNTHETIC_SELF_CHAT"]).unwrap(),
            FixedClock,
        );
        let approval = policy
            .authorize(
                &StaticProbe(snapshot()),
                "SYNTHETIC_SELF_CHAT",
                SendIntent::new(
                    TargetKind::SelfChat,
                    SecretMessage::new("SYNTHETIC_BODY"),
                    SendMode::StageOnly,
                    true,
                    "synthetic-correlation",
                ),
            )
            .unwrap();
        assert!(approval.approved.target_binding_verified());
        let exact_label: Vec<u16> = "SYNTHETIC_SELF_CHAT".encode_utf16().collect();
        let wrong_label: Vec<u16> = "SYNTHETIC_OTHER_CHAT".encode_utf16().collect();
        assert!(approval
            .approved
            .target_binding_matches_observed_utf16(&exact_label));
        assert!(!approval
            .approved
            .target_binding_matches_observed_utf16(&wrong_label));
        let debug = format!("{approval:?}");
        assert!(!debug.contains("synthetic-correlation"));
        assert!(!debug.contains("approval_deadline"));
        assert!(!format!("{:?}", approval.approved).contains("approval_deadline"));
        assert!(debug.contains("<redacted>"));

        let sender = CorrelationInspectingSender {
            stage_calls: Cell::new(0),
        };
        assert_eq!(
            approval.execute(&sender).unwrap(),
            SendOutcome::StagedAndRestored
        );
        assert_eq!(sender.stage_calls.get(), 1);
    }

    #[test]
    fn consuming_execute_normalizes_sender_mismatch_after_one_dispatch() {
        for (mode, outcome, expected_stage_calls, expected_commit_calls) in [
            (SendMode::StageOnly, SendOutcome::CommitIssued, 1, 0),
            (SendMode::Commit, SendOutcome::StagedAndRestored, 0, 1),
        ] {
            let probe = StaticProbe(snapshot());
            let policy = WindowsSafetyPolicy::with_clock(
                WindowsPolicyConfig::new(["SYNTHETIC_SELF_CHAT"])
                    .expect("synthetic allowlist should be valid"),
                FixedClock,
            );
            let approval = policy
                .authorize(
                    &probe,
                    "SYNTHETIC_SELF_CHAT",
                    SendIntent::new(
                        TargetKind::SelfChat,
                        SecretMessage::new("SYNTHETIC_BODY"),
                        mode,
                        true,
                        format!("synthetic-{mode:?}"),
                    ),
                )
                .expect("synthetic state should authorize");
            let sender = MismatchedOutcomeSender {
                outcome,
                stage_calls: Cell::new(0),
                commit_calls: Cell::new(0),
            };

            let error = approval
                .execute(&sender)
                .expect_err("a sender mismatch must normalize to uncertainty");

            assert_eq!(error.kind, UiErrorKind::SubmissionUncertain);
            assert_eq!(error.operation, OP_EXECUTE_OUTCOME);
            assert!(!error.retry_safe);
            assert_eq!(sender.stage_calls.get(), expected_stage_calls);
            assert_eq!(sender.commit_calls.get(), expected_commit_calls);
        }
    }
}
