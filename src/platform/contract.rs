use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;

use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::safety::ApprovalToken;

/// Shared privacy bound for configured and observed Windows target labels.
/// Measured UIA Name values above this UTF-16 unit count fail closed.
pub(crate) const MAX_TARGET_LABEL_UTF16_UNITS: usize = 512;

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

/// Content-free reason why read-only Windows discovery could not select one
/// diagnostic window. The value is internal snapshot state: public reports
/// map it to a fixed allowlisted evidence code, while serde omits it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOnlyWindowAmbiguity {
    CandidateLimit,
    DuplicateComposer,
    ComposerAmbiguous,
    CandidateNotInspected(ReadOnlyCandidateBlockers),
    NoComposer,
}

/// Fixed aggregate reasons that prevented one or more visible read-only
/// candidates from reaching composer inspection. The private bitset can only
/// be constructed by crate-owned observation code; public reports expose
/// individual booleans solely through allowlisted evidence codes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReadOnlyCandidateBlockers(u8);

impl fmt::Debug for ReadOnlyCandidateBlockers {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReadOnlyCandidateBlockers(<fixed>)")
    }
}

// These constructors and accessors are consumed only by the Windows backend
// and renderer; the binding accessor remains active on every platform.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
impl ReadOnlyCandidateBlockers {
    const EXECUTABLE_UNVERIFIED: u8 = 1 << 0;
    const UI_PROFILE_UNKNOWN: u8 = 1 << 1;
    const WINDOW_NOT_VISIBLE: u8 = 1 << 2;
    const WINDOW_DISABLED: u8 = 1 << 3;
    const MODAL_PRESENT: u8 = 1 << 4;
    const SESSION_MISMATCH: u8 = 1 << 5;
    const INTEGRITY_INCOMPATIBLE: u8 = 1 << 6;

    pub(crate) const fn from_observation(
        executable_verified: bool,
        known_ui_profile: bool,
        visible: bool,
        enabled: bool,
        modal_present: bool,
        interactive_session_match: bool,
        integrity_compatible: bool,
    ) -> Self {
        let mut bits = 0_u8;
        if !executable_verified {
            bits |= Self::EXECUTABLE_UNVERIFIED;
        } else if !known_ui_profile {
            bits |= Self::UI_PROFILE_UNKNOWN;
        }
        if !visible {
            bits |= Self::WINDOW_NOT_VISIBLE;
        }
        if !enabled {
            bits |= Self::WINDOW_DISABLED;
        }
        if modal_present {
            bits |= Self::MODAL_PRESENT;
        }
        if !interactive_session_match {
            bits |= Self::SESSION_MISMATCH;
        }
        if !integrity_compatible {
            bits |= Self::INTEGRITY_INCOMPATIBLE;
        }
        Self(bits)
    }

    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub(crate) const fn binding_bits(self) -> u8 {
        self.0
    }

    pub(crate) const fn executable_unverified(self) -> bool {
        self.0 & Self::EXECUTABLE_UNVERIFIED != 0
    }

    pub(crate) const fn ui_profile_unknown(self) -> bool {
        self.0 & Self::UI_PROFILE_UNKNOWN != 0
    }

    pub(crate) const fn window_not_visible(self) -> bool {
        self.0 & Self::WINDOW_NOT_VISIBLE != 0
    }

    pub(crate) const fn window_disabled(self) -> bool {
        self.0 & Self::WINDOW_DISABLED != 0
    }

    pub(crate) const fn modal_present(self) -> bool {
        self.0 & Self::MODAL_PRESENT != 0
    }

    pub(crate) const fn session_mismatch(self) -> bool {
        self.0 & Self::SESSION_MISMATCH != 0
    }

    pub(crate) const fn integrity_incompatible(self) -> bool {
        self.0 & Self::INTEGRITY_INCOMPATIBLE != 0
    }
}

/// Bounded, content-free evidence collected only after the exact reviewed
/// composer selector returned no match. Each private bit means that at least
/// one descendant matched one exact pair of the three reviewed non-content
/// properties. It retains no count, element association, or observed value.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReadOnlyComposerSelectorEvidence(u8);

impl fmt::Debug for ReadOnlyComposerSelectorEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReadOnlyComposerSelectorEvidence(<fixed>)")
    }
}

// Construction and reporting are Windows-only; target binding consumes the
// opaque bits on every platform so forged diagnostic state stays detectable.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
impl ReadOnlyComposerSelectorEvidence {
    const CLASS_AND_AUTOMATION_ID: u8 = 1 << 0;
    const CLASS_AND_CONTROL_TYPE: u8 = 1 << 1;
    const AUTOMATION_ID_AND_CONTROL_TYPE: u8 = 1 << 2;

    pub(crate) const fn from_near_matches(
        class_and_automation_id: bool,
        class_and_control_type: bool,
        automation_id_and_control_type: bool,
    ) -> Self {
        let mut bits = 0_u8;
        if class_and_automation_id {
            bits |= Self::CLASS_AND_AUTOMATION_ID;
        }
        if class_and_control_type {
            bits |= Self::CLASS_AND_CONTROL_TYPE;
        }
        if automation_id_and_control_type {
            bits |= Self::AUTOMATION_ID_AND_CONTROL_TYPE;
        }
        Self(bits)
    }

    pub(crate) const fn binding_bits(self) -> u8 {
        self.0
    }

    pub(crate) const fn near_match_without_class_name(self) -> bool {
        self.0 & Self::AUTOMATION_ID_AND_CONTROL_TYPE != 0
    }

    pub(crate) const fn near_match_without_automation_id(self) -> bool {
        self.0 & Self::CLASS_AND_CONTROL_TYPE != 0
    }

    pub(crate) const fn near_match_without_control_type(self) -> bool {
        self.0 & Self::CLASS_AND_AUTOMATION_ID != 0
    }

    pub(crate) const fn no_two_property_near_match(self) -> bool {
        self.0 == 0
    }
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
    /// Exact top-level candidates remaining after platform-specific,
    /// non-content selector narrowing: zero is absent, one is unique, and
    /// more than one is ambiguous.
    pub top_level_window_count: usize,
    /// Fixed, content-free diagnostic for a read-only ambiguous result. It is
    /// excluded from snapshot serialization and cannot authorize mutation.
    #[serde(skip)]
    pub read_only_window_ambiguity: Option<ReadOnlyWindowAmbiguity>,
    /// Fixed near-match evidence for an absent known-profile composer. It is
    /// excluded from serialization and can never authorize mutation.
    #[serde(skip)]
    pub read_only_composer_selector_evidence: Option<ReadOnlyComposerSelectorEvidence>,
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
    /// Request-scoped proof that an ephemeral observed UTF-16 label matched
    /// the configured target exactly. It is never serialized or formatted.
    #[serde(skip)]
    pub target_binding: Option<TargetBindingEvidence>,
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

/// A read-only inspection request. Target-binding material, when present, is
/// opaque and redacted; callers cannot obtain the configured target label.
pub struct InspectRequest {
    pub target: TargetKind,
    target_binding: Option<TargetBindingRequest>,
}

impl InspectRequest {
    pub const fn new(target: TargetKind) -> Self {
        Self {
            target,
            target_binding: None,
        }
    }

    pub const fn self_chat() -> Self {
        Self::new(TargetKind::SelfChat)
    }

    /// Returns whether this request requires an exact observed-label binding.
    /// No key, digest, or label bytes are exposed.
    pub fn requires_target_binding(&self) -> bool {
        self.target_binding.is_some()
    }

    /// Creates an owned copy for the bounded Windows inspection worker.
    ///
    /// The copy shares only the opaque request-scoped binding secret. It does
    /// not expose the requested label and remains unable to serialize or format
    /// that secret. This avoids moving a raw label into a second allocation
    /// merely to satisfy the worker thread's `'static` lifetime.
    pub(crate) fn clone_for_worker(&self) -> Self {
        Self {
            target: self.target,
            target_binding: self
                .target_binding
                .as_ref()
                .map(|binding| TargetBindingRequest {
                    secret: Arc::clone(&binding.secret),
                }),
        }
    }

    /// Produces opaque evidence only when `observed_label_utf16` is an exact
    /// code-unit match for the policy-configured target. The caller must keep
    /// the observed buffer ephemeral and zeroize it after this call.
    ///
    /// The proof commits to the complete redacted snapshot, so moving it to a
    /// different process/window/composer/time/input state cannot validate.
    pub fn bind_observed_target_utf16(
        &self,
        observed_label_utf16: &[u16],
        snapshot: &UiSnapshot,
    ) -> Option<TargetBindingEvidence> {
        if self.target != snapshot.target.kind {
            return None;
        }
        self.target_binding
            .as_ref()?
            .bind_observed_target_utf16(observed_label_utf16, snapshot)
    }

    pub(crate) fn bound_self_chat(
        requested_label: &str,
        key: [u8; 32],
    ) -> (Self, TargetBindingPermit) {
        let secret = Arc::new(TargetBindingSecret::new(requested_label, key));
        (
            Self {
                target: TargetKind::SelfChat,
                target_binding: Some(TargetBindingRequest {
                    secret: Arc::clone(&secret),
                }),
            },
            TargetBindingPermit { secret },
        )
    }
}

impl fmt::Debug for InspectRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InspectRequest")
            .field("target", &self.target)
            .field(
                "target_binding",
                &self.target_binding.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

type HmacSha256 = Hmac<Sha256>;

const TARGET_LABEL_DOMAIN: &[u8] = b"openkakao.windows.target-label.v1\0";
const TARGET_EVIDENCE_DOMAIN: &[u8] = b"openkakao.windows.target-evidence.v1\0";

struct TargetBindingSecret {
    key: [u8; 32],
    expected_label_tag: [u8; 32],
}

impl TargetBindingSecret {
    fn new(requested_label: &str, key: [u8; 32]) -> Self {
        // Stream the configured UTF-8 label through `encode_utf16` twice: once
        // for its exact unit count and once for HMAC input. No secondary label
        // buffer or freed allocation can retain a copy.
        let expected_label_tag = target_label_tag_from_str(&key, requested_label);
        Self {
            key,
            expected_label_tag,
        }
    }
}

impl Drop for TargetBindingSecret {
    fn drop(&mut self) {
        self.key.zeroize();
        self.expected_label_tag.zeroize();
    }
}

struct TargetBindingRequest {
    secret: Arc<TargetBindingSecret>,
}

impl TargetBindingRequest {
    fn bind_observed_target_utf16(
        &self,
        observed_label_utf16: &[u16],
        snapshot: &UiSnapshot,
    ) -> Option<TargetBindingEvidence> {
        if !target_label_matches(&self.secret, observed_label_utf16) {
            return None;
        }
        Some(TargetBindingEvidence(target_evidence_tag(
            &self.secret,
            snapshot,
        )))
    }
}

/// Opaque, request-scoped target evidence. The bytes have no public accessor,
/// are redacted by `Debug`, and are excluded from snapshot serialization.
#[derive(Clone, PartialEq, Eq)]
pub struct TargetBindingEvidence([u8; 32]);

impl fmt::Debug for TargetBindingEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TargetBindingEvidence(<redacted>)")
    }
}

impl Drop for TargetBindingEvidence {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) struct TargetBindingPermit {
    secret: Arc<TargetBindingSecret>,
}

impl TargetBindingPermit {
    pub(crate) fn verifies_snapshot(&self, snapshot: &UiSnapshot) -> bool {
        let Some(evidence) = snapshot.target.target_binding.as_ref() else {
            return false;
        };
        target_evidence_mac(&self.secret, snapshot)
            .verify_slice(&evidence.0)
            .is_ok()
    }

    #[allow(dead_code)] // Consumed only by the feature-gated native mutation observer.
    pub(crate) fn verifies_observed_target_utf16(
        &self,
        observed_label_utf16: &[u16],
        snapshot: &UiSnapshot,
    ) -> bool {
        target_label_matches(&self.secret, observed_label_utf16) && self.verifies_snapshot(snapshot)
    }
}

impl fmt::Debug for TargetBindingPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TargetBindingPermit(<redacted>)")
    }
}

fn target_label_tag_from_str(key: &[u8; 32], label: &str) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("SHA-256 HMAC accepts a 32-byte key");
    mac.update(TARGET_LABEL_DOMAIN);
    mac.update(&u64_len(label.encode_utf16().count()).to_le_bytes());
    for unit in label.encode_utf16() {
        mac.update(&unit.to_le_bytes());
    }
    mac.finalize().into_bytes().into()
}

fn target_label_matches(secret: &TargetBindingSecret, label_utf16: &[u16]) -> bool {
    target_label_mac(&secret.key, label_utf16)
        .verify_slice(&secret.expected_label_tag)
        .is_ok()
}

fn target_label_mac(key: &[u8; 32], label_utf16: &[u16]) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(key).expect("SHA-256 HMAC accepts a 32-byte key");
    mac.update(TARGET_LABEL_DOMAIN);
    mac.update(&u64_len(label_utf16.len()).to_le_bytes());
    for unit in label_utf16 {
        mac.update(&unit.to_le_bytes());
    }
    mac
}

fn target_evidence_tag(secret: &TargetBindingSecret, snapshot: &UiSnapshot) -> [u8; 32] {
    target_evidence_mac(secret, snapshot)
        .finalize()
        .into_bytes()
        .into()
}

fn target_evidence_mac(secret: &TargetBindingSecret, snapshot: &UiSnapshot) -> HmacSha256 {
    let mut mac =
        HmacSha256::new_from_slice(&secret.key).expect("SHA-256 HMAC accepts a 32-byte key");
    mac.update(TARGET_EVIDENCE_DOMAIN);
    mac.update(&secret.expected_label_tag);
    update_snapshot_binding(&mut mac, snapshot);
    mac
}

fn update_snapshot_binding(mac: &mut HmacSha256, snapshot: &UiSnapshot) {
    update_byte(mac, platform_code(snapshot.app.platform));
    update_bool(mac, snapshot.app.app_running);
    match snapshot.app.process.as_ref() {
        Some(process) => {
            update_byte(mac, 1);
            mac.update(&process.pid.to_le_bytes());
            update_str(mac, &process.executable);
            update_option_u32(mac, process.session_id);
        }
        None => update_byte(mac, 0),
    }
    update_option_str(mac, snapshot.app.app_version.as_deref());
    update_bool(mac, snapshot.app.interactive_session_match);
    update_bool(mac, snapshot.app.integrity_compatible);
    update_bool(mac, snapshot.app.known_ui_profile);
    mac.update(&u64_len(snapshot.app.top_level_window_count).to_le_bytes());
    let (ambiguity_code, blocker_bits) =
        read_only_window_ambiguity_binding(snapshot.app.read_only_window_ambiguity);
    update_byte(mac, ambiguity_code);
    update_byte(mac, blocker_bits);
    match snapshot.app.read_only_composer_selector_evidence {
        Some(evidence) => {
            update_byte(mac, 1);
            update_byte(mac, evidence.binding_bits());
        }
        None => {
            update_byte(mac, 0);
            update_byte(mac, 0);
        }
    }
    update_bool(mac, snapshot.app.modal_present);

    update_byte(mac, target_code(snapshot.target.kind));
    update_bool(mac, snapshot.target.self_chat_verified);
    update_bool(mac, snapshot.target.exact_match);
    update_bool(mac, snapshot.target.unique_match);
    update_option_str(mac, snapshot.target.window.as_deref());
    update_option_str(mac, snapshot.target.composer.as_deref());
    mac.update(&snapshot.target.observed_at_unix_ms.to_le_bytes());
    mac.update(&snapshot.target.expires_at_unix_ms.to_le_bytes());

    update_bool(mac, snapshot.input.present);
    update_bool(mac, snapshot.input.unique);
    update_bool(mac, snapshot.input.enabled);
    update_bool(mac, snapshot.input.writable);
    update_bool(mac, snapshot.input.draft_empty);
    update_bool(mac, snapshot.input.focused);
    update_option_str(mac, snapshot.input.selector_profile_id.as_deref());
}

fn update_byte(mac: &mut HmacSha256, value: u8) {
    mac.update(&[value]);
}

fn update_bool(mac: &mut HmacSha256, value: bool) {
    update_byte(mac, u8::from(value));
}

fn update_option_u32(mac: &mut HmacSha256, value: Option<u32>) {
    match value {
        Some(value) => {
            update_byte(mac, 1);
            mac.update(&value.to_le_bytes());
        }
        None => update_byte(mac, 0),
    }
}

fn update_option_str(mac: &mut HmacSha256, value: Option<&str>) {
    match value {
        Some(value) => {
            update_byte(mac, 1);
            update_str(mac, value);
        }
        None => update_byte(mac, 0),
    }
}

fn update_str(mac: &mut HmacSha256, value: &str) {
    mac.update(&u64_len(value.len()).to_le_bytes());
    mac.update(value.as_bytes());
}

fn u64_len(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn platform_code(value: UiPlatform) -> u8 {
    match value {
        UiPlatform::Macos => 1,
        UiPlatform::Windows => 2,
        UiPlatform::Unsupported => 3,
    }
}

fn target_code(value: TargetKind) -> u8 {
    match value {
        TargetKind::SelfChat => 1,
        TargetKind::Other => 2,
    }
}

const fn read_only_window_ambiguity_binding(value: Option<ReadOnlyWindowAmbiguity>) -> (u8, u8) {
    match value {
        None => (0, 0),
        Some(ReadOnlyWindowAmbiguity::CandidateLimit) => (1, 0),
        Some(ReadOnlyWindowAmbiguity::DuplicateComposer) => (2, 0),
        Some(ReadOnlyWindowAmbiguity::ComposerAmbiguous) => (3, 0),
        Some(ReadOnlyWindowAmbiguity::CandidateNotInspected(blockers)) => {
            (4, blockers.binding_bits())
        }
        Some(ReadOnlyWindowAmbiguity::NoComposer) => (5, 0),
    }
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

/// Opaque one-use correlation handed from policy to the durable ledger.
/// It is deliberately non-Clone, non-serializing, zeroized, and redacted.
pub(crate) struct TransactionCorrelation([u8; 16]);

impl TransactionCorrelation {
    fn from_policy(bytes: [u8; 16]) -> Result<Self, UiError> {
        if bytes == [0; 16] {
            Err(UiError::new(
                UiErrorKind::UnsupportedCapability,
                "policy_correlation_rng",
            ))
        } else {
            Ok(Self(bytes))
        }
    }

    #[cfg(any(test, all(target_os = "windows", feature = "windows-ui-write")))]
    pub(crate) fn into_bytes(mut self) -> [u8; 16] {
        let bytes = self.0;
        self.0.zeroize();
        bytes
    }
}

impl fmt::Debug for TransactionCorrelation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransactionCorrelation(<redacted>)")
    }
}

impl Drop for TransactionCorrelation {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Process-local, non-serializing expiry for one approval. Wall-clock expiry
/// remains part of the snapshot contract; this second clock prevents a system
/// clock rollback from extending the approved lifetime.
struct ApprovalDeadline(Instant);

impl ApprovalDeadline {
    fn reached_at(&self, now: Instant) -> bool {
        now >= self.0
    }
}

/// A safety-policy capability. Its fields are private and construction also
/// requires the unforgeable token owned by `crate::safety`.
pub struct ApprovedSend {
    intent: SendIntent,
    snapshot: UiSnapshot,
    target_binding: TargetBindingPermit,
    approved_at_unix_ms: u64,
    approval_deadline: ApprovalDeadline,
    execution_claimed: AtomicBool,
    transaction_correlation: Mutex<Option<TransactionCorrelation>>,
}

impl ApprovedSend {
    #[allow(dead_code)] // Consumed by the safety policy beginning in Wave 1.
    pub(crate) fn from_policy(
        intent: SendIntent,
        snapshot: UiSnapshot,
        target_binding: TargetBindingPermit,
        approved_at_unix_ms: u64,
        approval_deadline: Instant,
        transaction_correlation: [u8; 16],
        _token: ApprovalToken,
    ) -> Result<Self, UiError> {
        Ok(Self {
            intent,
            snapshot,
            target_binding,
            approved_at_unix_ms,
            approval_deadline: ApprovalDeadline(approval_deadline),
            execution_claimed: AtomicBool::new(false),
            transaction_correlation: Mutex::new(Some(TransactionCorrelation::from_policy(
                transaction_correlation,
            )?)),
        })
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

    /// Reports whether the policy-owned process-local deadline has been
    /// reached. The deadline itself remains private and non-serializing.
    #[allow(dead_code)] // Consumed by policy and the guarded Windows backend.
    pub(crate) fn monotonic_deadline_reached_at(&self, now: Instant) -> bool {
        self.approval_deadline.reached_at(now)
    }

    /// Confirms that the policy-carried permit validates the exact snapshot
    /// evidence stored in this approval. This is checked again by the guarded
    /// transaction before any native mutation path can proceed.
    #[allow(dead_code)] // Consumed by the guarded Windows backend feature.
    pub(crate) fn target_binding_verified(&self) -> bool {
        self.target_binding.verifies_snapshot(&self.snapshot)
    }

    /// Native target observers use this after an ephemeral UTF-16 read and
    /// before draft access or mutation. Verification is fixed to this
    /// approval's own policy-bound snapshot; callers cannot substitute a
    /// different snapshot. No observed label is retained.
    #[allow(dead_code)]
    pub(crate) fn target_binding_matches_observed_utf16(
        &self,
        observed_label_utf16: &[u16],
    ) -> bool {
        self.target_binding
            .verifies_observed_target_utf16(observed_label_utf16, &self.snapshot)
    }

    /// Atomically consumes this approval for its sole mutation attempt.
    ///
    /// Guarded platform backends call this only after all pre-mutation checks
    /// pass and immediately before the first mutation call. A failed attempt
    /// remains consumed so callers cannot retry an uncertain operation with
    /// the same capability.
    #[allow(dead_code)] // Consumed by the guarded Windows backend in Wave 2.
    pub(crate) fn try_claim_execution(&self) -> Result<(), UiError> {
        self.execution_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| UiError::new(UiErrorKind::InvalidInput, "approved_send_already_claimed"))
    }

    /// Moves the opaque policy-generated correlation into the guarded ledger
    /// exactly once. The token is non-Clone, non-serializing, and redacted.
    #[allow(dead_code)] // Consumed by the guarded Windows backend.
    pub(crate) fn take_transaction_correlation(&self) -> Result<TransactionCorrelation, UiError> {
        let mut correlation = self.transaction_correlation.lock().map_err(|_| {
            UiError::new(
                UiErrorKind::SubmissionUncertain,
                "approved_send_correlation_uncertain",
            )
        })?;
        correlation.take().ok_or_else(|| {
            UiError::new(
                UiErrorKind::InvalidInput,
                "approved_send_correlation_consumed",
            )
        })
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
            .field("target_binding", &"<redacted>")
            .field("transaction_correlation", &"<redacted>")
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
            Self::CommitIssued
                | Self::EchoConfirmed
                | Self::SubmittedUnverified
                | Self::Indeterminate
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

/// Sealing boundary for mutation implementations. External crates may call a
/// reviewed sender through [`crate::safety::ApprovedOperation`], but cannot
/// implement an adapter that reuses or reroutes the borrowed approval.
pub(crate) mod message_sender_seal {
    pub trait Sealed {}
}

pub trait MessageSender: message_sender_seal::Sealed {
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

    const TARGET_CANARY: &str = "SYNTHETIC_TARGET_CANARY";

    fn executable_unverified_blocker() -> ReadOnlyCandidateBlockers {
        ReadOnlyCandidateBlockers::from_observation(false, false, true, true, false, true, true)
    }

    fn target_snapshot() -> UiSnapshot {
        UiSnapshot {
            app: AppSnapshot {
                platform: UiPlatform::Windows,
                app_running: true,
                process: Some(ProcessFingerprint {
                    pid: 7,
                    executable: "run:11111111111111111111111111111111".to_string(),
                    session_id: Some(1),
                }),
                app_version: Some("synthetic-version".to_string()),
                interactive_session_match: true,
                integrity_compatible: true,
                known_ui_profile: true,
                top_level_window_count: 1,
                read_only_window_ambiguity: None,
                read_only_composer_selector_evidence: None,
                modal_present: false,
            },
            target: ChatTargetSnapshot {
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
                selector_profile_id: Some("synthetic-profile".to_string()),
            },
        }
    }

    #[test]
    fn approval_deadline_is_half_open_at_the_exact_monotonic_boundary() {
        let anchor = Instant::now();
        let deadline = ApprovalDeadline(
            anchor
                .checked_add(std::time::Duration::from_millis(10))
                .expect("synthetic deadline must be representable"),
        );
        let just_before = anchor
            .checked_add(std::time::Duration::from_millis(9))
            .expect("synthetic instant must be representable");
        let exact = anchor
            .checked_add(std::time::Duration::from_millis(10))
            .expect("synthetic instant must be representable");

        assert!(!deadline.reached_at(just_before));
        assert!(deadline.reached_at(exact));
        assert!(deadline.reached_at(
            anchor
                .checked_add(std::time::Duration::from_millis(11))
                .expect("synthetic instant must be representable")
        ));
    }

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
            SendOutcome::EchoConfirmed,
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

    #[test]
    fn read_only_diagnostics_are_not_part_of_the_serialized_snapshot_schema() {
        let mut snapshot = target_snapshot();
        snapshot.app.read_only_window_ambiguity = Some(
            ReadOnlyWindowAmbiguity::CandidateNotInspected(executable_unverified_blocker()),
        );
        snapshot.app.read_only_composer_selector_evidence = Some(
            ReadOnlyComposerSelectorEvidence::from_near_matches(false, true, true),
        );

        let json = serde_json::to_string(&snapshot).expect("snapshot should serialize");
        assert!(!json.contains("read_only_window_ambiguity"));
        assert!(!json.contains("candidate_not_inspected"));
        assert!(!json.contains("read_only_composer_selector_evidence"));
        assert!(!json.contains("near_match"));
        assert!(format!("{snapshot:?}").contains("ReadOnlyComposerSelectorEvidence(<fixed>)"));
    }

    #[test]
    fn candidate_blockers_are_fixed_bounded_and_union_without_counts() {
        let first = ReadOnlyCandidateBlockers::from_observation(
            false, false, false, true, false, false, true,
        );
        assert!(first.executable_unverified());
        assert!(!first.ui_profile_unknown());
        assert!(first.window_not_visible());
        assert!(!first.window_disabled());
        assert!(!first.modal_present());
        assert!(first.session_mismatch());
        assert!(!first.integrity_incompatible());

        let second = ReadOnlyCandidateBlockers::from_observation(
            true, false, true, false, true, true, false,
        );
        let aggregate = first.union(second);
        assert!(aggregate.executable_unverified());
        assert!(aggregate.ui_profile_unknown());
        assert!(aggregate.window_not_visible());
        assert!(aggregate.window_disabled());
        assert!(aggregate.modal_present());
        assert!(aggregate.session_mismatch());
        assert!(aggregate.integrity_incompatible());
        assert_eq!(
            format!("{aggregate:?}"),
            "ReadOnlyCandidateBlockers(<fixed>)"
        );
    }

    #[test]
    fn candidate_blockers_preserve_the_existing_composer_inspection_gate() {
        for state in 0_u8..=0x7f {
            let executable_verified = state & (1 << 0) != 0;
            let known_ui_profile = state & (1 << 1) != 0;
            let visible = state & (1 << 2) != 0;
            let enabled = state & (1 << 3) != 0;
            let modal_present = state & (1 << 4) != 0;
            let interactive_session_match = state & (1 << 5) != 0;
            let integrity_compatible = state & (1 << 6) != 0;
            let blockers = ReadOnlyCandidateBlockers::from_observation(
                executable_verified,
                known_ui_profile,
                visible,
                enabled,
                modal_present,
                interactive_session_match,
                integrity_compatible,
            );
            let existing_gate = executable_verified
                && known_ui_profile
                && visible
                && enabled
                && !modal_present
                && interactive_session_match
                && integrity_compatible;

            assert_eq!(
                blockers.is_empty(),
                existing_gate,
                "gate mismatch for synthetic state {state:#04x}"
            );
        }
    }

    #[test]
    fn composer_selector_evidence_maps_only_exact_near_match_pairs() {
        for state in 0_u8..8 {
            let class_and_automation_id = state & (1 << 0) != 0;
            let class_and_control_type = state & (1 << 1) != 0;
            let automation_id_and_control_type = state & (1 << 2) != 0;
            let evidence = ReadOnlyComposerSelectorEvidence::from_near_matches(
                class_and_automation_id,
                class_and_control_type,
                automation_id_and_control_type,
            );

            assert_eq!(
                evidence.near_match_without_control_type(),
                class_and_automation_id
            );
            assert_eq!(
                evidence.near_match_without_automation_id(),
                class_and_control_type
            );
            assert_eq!(
                evidence.near_match_without_class_name(),
                automation_id_and_control_type
            );
            assert_eq!(evidence.no_two_property_near_match(), state == 0);
            assert_eq!(
                format!("{evidence:?}"),
                "ReadOnlyComposerSelectorEvidence(<fixed>)"
            );
        }
    }

    #[test]
    fn target_binding_is_exact_redacted_nonserializing_and_state_bound() {
        let (request, permit) = InspectRequest::bound_self_chat(TARGET_CANARY, [0xab; 32]);
        assert!(request.requires_target_binding());
        let request_debug = format!("{request:?}");
        assert!(!request_debug.contains(TARGET_CANARY));
        assert!(!request_debug.contains("abababab"));
        assert!(request_debug.contains("<redacted>"));

        let snapshot = target_snapshot();
        let wrong_case: Vec<u16> = "synthetic_target_canary".encode_utf16().collect();
        assert!(request
            .bind_observed_target_utf16(&wrong_case, &snapshot)
            .is_none());

        let observed: Vec<u16> = TARGET_CANARY.encode_utf16().collect();
        let mut bound = snapshot;
        bound.target.target_binding = request.bind_observed_target_utf16(&observed, &bound);
        assert!(permit.verifies_snapshot(&bound));
        assert!(permit.verifies_observed_target_utf16(&observed, &bound));

        let rendered = format!("{bound:?}");
        let json = serde_json::to_string(&bound).expect("bound snapshot should serialize");
        for output in [&rendered, &json] {
            assert!(!output.contains(TARGET_CANARY));
            assert!(!output.contains("abababab"));
        }
        assert!(rendered.contains("TargetBindingEvidence(<redacted>)"));
        assert!(!json.contains("target_binding"));

        let mut moved = bound.clone();
        moved.target.composer = Some("run:44444444444444444444444444444444".to_string());
        assert!(!permit.verifies_snapshot(&moved));

        let (_, different_request_permit) =
            InspectRequest::bound_self_chat(TARGET_CANARY, [0xcd; 32]);
        assert!(!different_request_permit.verifies_snapshot(&bound));
    }

    #[test]
    fn unbound_inspection_cannot_mint_target_evidence() {
        let request = InspectRequest::self_chat();
        let observed: Vec<u16> = TARGET_CANARY.encode_utf16().collect();
        assert!(!request.requires_target_binding());
        assert!(request
            .bind_observed_target_utf16(&observed, &target_snapshot())
            .is_none());
    }

    fn assert_binding_rejects_mutation(
        permit: &TargetBindingPermit,
        snapshot: &UiSnapshot,
        mutate: impl FnOnce(&mut UiSnapshot),
    ) {
        let mut changed = snapshot.clone();
        mutate(&mut changed);
        assert!(!permit.verifies_snapshot(&changed));
    }

    #[test]
    fn target_binding_commits_every_current_snapshot_field() {
        let (request, permit) = InspectRequest::bound_self_chat(TARGET_CANARY, [0x6b; 32]);
        let mut bound = target_snapshot();
        let observed: Vec<u16> = TARGET_CANARY.encode_utf16().collect();
        bound.target.target_binding = request.bind_observed_target_utf16(&observed, &bound);
        assert!(permit.verifies_snapshot(&bound));

        assert_binding_rejects_mutation(&permit, &bound, |value| {
            value.app.platform = UiPlatform::Unsupported
        });
        assert_binding_rejects_mutation(&permit, &bound, |value| value.app.app_running = false);
        assert_binding_rejects_mutation(&permit, &bound, |value| value.app.process = None);
        assert_binding_rejects_mutation(&permit, &bound, |value| {
            value.app.process.as_mut().unwrap().pid += 1
        });
        assert_binding_rejects_mutation(&permit, &bound, |value| {
            value.app.process.as_mut().unwrap().executable.push('x')
        });
        assert_binding_rejects_mutation(&permit, &bound, |value| {
            value.app.process.as_mut().unwrap().session_id = None
        });
        assert_binding_rejects_mutation(&permit, &bound, |value| value.app.app_version = None);
        assert_binding_rejects_mutation(&permit, &bound, |value| {
            value.app.interactive_session_match = false
        });
        assert_binding_rejects_mutation(&permit, &bound, |value| {
            value.app.integrity_compatible = false
        });
        assert_binding_rejects_mutation(&permit, &bound, |value| {
            value.app.known_ui_profile = false
        });
        assert_binding_rejects_mutation(&permit, &bound, |value| {
            value.app.top_level_window_count += 1
        });
        assert_binding_rejects_mutation(&permit, &bound, |value| {
            value.app.read_only_window_ambiguity = Some(
                ReadOnlyWindowAmbiguity::CandidateNotInspected(executable_unverified_blocker()),
            )
        });
        assert_binding_rejects_mutation(&permit, &bound, |value| {
            value.app.read_only_composer_selector_evidence = Some(
                ReadOnlyComposerSelectorEvidence::from_near_matches(true, false, false),
            )
        });
        assert_binding_rejects_mutation(&permit, &bound, |value| value.app.modal_present = true);

        assert_binding_rejects_mutation(&permit, &bound, |value| {
            value.target.kind = TargetKind::Other
        });
        assert_binding_rejects_mutation(&permit, &bound, |value| {
            value.target.self_chat_verified = false
        });
        assert_binding_rejects_mutation(&permit, &bound, |value| value.target.exact_match = false);
        assert_binding_rejects_mutation(&permit, &bound, |value| value.target.unique_match = false);
        assert_binding_rejects_mutation(&permit, &bound, |value| value.target.window = None);
        assert_binding_rejects_mutation(&permit, &bound, |value| value.target.composer = None);
        assert_binding_rejects_mutation(&permit, &bound, |value| {
            value.target.observed_at_unix_ms += 1
        });
        assert_binding_rejects_mutation(&permit, &bound, |value| {
            value.target.expires_at_unix_ms += 1
        });

        assert_binding_rejects_mutation(&permit, &bound, |value| value.input.present = false);
        assert_binding_rejects_mutation(&permit, &bound, |value| value.input.unique = false);
        assert_binding_rejects_mutation(&permit, &bound, |value| value.input.enabled = false);
        assert_binding_rejects_mutation(&permit, &bound, |value| value.input.writable = false);
        assert_binding_rejects_mutation(&permit, &bound, |value| value.input.draft_empty = false);
        assert_binding_rejects_mutation(&permit, &bound, |value| value.input.focused = true);
        assert_binding_rejects_mutation(&permit, &bound, |value| {
            value.input.selector_profile_id = None
        });
    }

    #[test]
    fn target_binding_commits_candidate_blocker_details() {
        let (request, permit) = InspectRequest::bound_self_chat(TARGET_CANARY, [0x7c; 32]);
        let mut bound = target_snapshot();
        let initial = executable_unverified_blocker();
        bound.app.read_only_window_ambiguity =
            Some(ReadOnlyWindowAmbiguity::CandidateNotInspected(initial));
        let observed: Vec<u16> = TARGET_CANARY.encode_utf16().collect();
        bound.target.target_binding = request.bind_observed_target_utf16(&observed, &bound);
        assert!(permit.verifies_snapshot(&bound));

        let mut changed = bound.clone();
        let profile_unknown =
            ReadOnlyCandidateBlockers::from_observation(true, false, true, true, false, true, true);
        changed.app.read_only_window_ambiguity = Some(
            ReadOnlyWindowAmbiguity::CandidateNotInspected(initial.union(profile_unknown)),
        );
        assert!(!permit.verifies_snapshot(&changed));
    }

    #[test]
    fn target_binding_commits_composer_selector_evidence_details() {
        let (request, permit) = InspectRequest::bound_self_chat(TARGET_CANARY, [0x9d; 32]);
        let mut bound = target_snapshot();
        bound.app.read_only_composer_selector_evidence = Some(
            ReadOnlyComposerSelectorEvidence::from_near_matches(true, false, false),
        );
        let observed: Vec<u16> = TARGET_CANARY.encode_utf16().collect();
        bound.target.target_binding = request.bind_observed_target_utf16(&observed, &bound);
        assert!(permit.verifies_snapshot(&bound));

        let mut changed = bound.clone();
        changed.app.read_only_composer_selector_evidence = Some(
            ReadOnlyComposerSelectorEvidence::from_near_matches(true, true, false),
        );
        assert!(!permit.verifies_snapshot(&changed));
    }

    #[test]
    fn target_binding_never_normalizes_unicode_whitespace_or_surrogates() {
        const COMPOSED: &str = "SYNTHETIC_CAF\u{00c9}_\u{1f642}";
        let (request, permit) = InspectRequest::bound_self_chat(COMPOSED, [0x5a; 32]);
        let mut snapshot = target_snapshot();
        let exact: Vec<u16> = COMPOSED.encode_utf16().collect();
        snapshot.target.target_binding = request.bind_observed_target_utf16(&exact, &snapshot);
        assert!(permit.verifies_snapshot(&snapshot));

        for candidate in [
            "SYNTHETIC_CAFE\u{0301}_\u{1f642}".encode_utf16().collect(),
            "SYNTHETIC_CAF\u{00c9}_\u{1f642} ".encode_utf16().collect(),
            "synthetic_CAF\u{00c9}_\u{1f642}".encode_utf16().collect(),
            vec![0xd800],
        ] {
            assert!(request
                .bind_observed_target_utf16(&candidate, &target_snapshot())
                .is_none());
        }
    }
}
