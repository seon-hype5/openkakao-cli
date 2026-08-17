use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Barrier, Mutex as StdMutex};
use std::time::Duration;

use openkakao_cli::platform::fake::FakeBackend;
use openkakao_cli::platform::{
    AppSnapshot, ChatTargetSnapshot, InputSnapshot, InspectRequest, PlatformProbe,
    ProcessFingerprint, ReadOnlyWindowAmbiguity, SecretMessage, SendIntent, SendMode, SendOutcome,
    TargetKind, UiCapabilities, UiError, UiErrorKind, UiPlatform, UiSnapshot,
};
use openkakao_cli::safety::{
    PolicyClock, WindowsPolicyConfig, WindowsSafetyPolicy, MAX_MESSAGE_SCALARS,
    MAX_MESSAGE_UTF8_BYTES, MAX_NONCE_BYTES, MAX_SNAPSHOT_TTL_MS, SUPPORTED_APP_VERSION,
    SUPPORTED_SELECTOR_PROFILE_ID,
};

const LABEL: &str = "SYNTHETIC_SELF_CHAT";
const NOW_MS: u64 = 10_000;
const PROCESS_FINGERPRINT: &str = "run:11111111111111111111111111111111";
const WINDOW_FINGERPRINT: &str = "run:22222222222222222222222222222222";
const COMPOSER_FINGERPRINT: &str = "run:33333333333333333333333333333333";
const OPERATION_LEAK_CANARY: &str = "SYNTHETIC_PRIVATE_OPERATION_CANARY";

#[derive(Debug, Clone, Copy)]
struct FixedClock(u64);

impl PolicyClock for FixedClock {
    fn now_unix_ms(&self) -> Result<u64, UiError> {
        Ok(self.0)
    }
}

struct ErrorClock;

impl PolicyClock for ErrorClock {
    fn now_unix_ms(&self) -> Result<u64, UiError> {
        Err(UiError::new(
            UiErrorKind::InvalidInput,
            OPERATION_LEAK_CANARY,
        ))
    }
}

#[derive(Default)]
struct ErrorProbe {
    inspect_calls: AtomicUsize,
}

impl ErrorProbe {
    fn inspect_calls(&self) -> usize {
        self.inspect_calls.load(Ordering::SeqCst)
    }
}

impl PlatformProbe for ErrorProbe {
    fn capabilities(&self) -> UiCapabilities {
        UiCapabilities {
            inspect: true,
            send_open_chat: true,
            open_chat_by_name: false,
            read_visible: false,
            watch_unread: false,
        }
    }

    fn inspect(&self, _request: &InspectRequest) -> Result<UiSnapshot, UiError> {
        self.inspect_calls.fetch_add(1, Ordering::SeqCst);
        Err(UiError {
            kind: UiErrorKind::Timeout,
            operation: OPERATION_LEAK_CANARY,
            retry_safe: false,
        })
    }
}

fn config_for(label: &str) -> WindowsPolicyConfig {
    WindowsPolicyConfig::new([label]).expect("synthetic allowlist should be valid")
}

fn policy() -> WindowsSafetyPolicy<FixedClock> {
    WindowsSafetyPolicy::with_clock(config_for(LABEL), FixedClock(NOW_MS))
}

fn safe_snapshot() -> UiSnapshot {
    UiSnapshot {
        app: AppSnapshot {
            platform: UiPlatform::Windows,
            app_running: true,
            process: Some(ProcessFingerprint {
                pid: 7,
                executable: PROCESS_FINGERPRINT.to_string(),
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
        target: ChatTargetSnapshot {
            kind: TargetKind::SelfChat,
            self_chat_verified: true,
            exact_match: true,
            unique_match: true,
            window: Some(WINDOW_FINGERPRINT.to_string()),
            composer: Some(COMPOSER_FINGERPRINT.to_string()),
            observed_at_unix_ms: 9_000,
            expires_at_unix_ms: 11_000,
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

fn intent(
    target: TargetKind,
    message: impl Into<String>,
    mode: SendMode,
    explicit_yes: bool,
    nonce: &str,
) -> SendIntent {
    SendIntent::new(
        target,
        SecretMessage::new(message),
        mode,
        explicit_yes,
        nonce,
    )
}

fn dry_intent(message: impl Into<String>, nonce: &str) -> SendIntent {
    intent(
        TargetKind::SelfChat,
        message,
        SendMode::DryRun,
        false,
        nonce,
    )
}

fn dry_run_error(snapshot: UiSnapshot) -> UiError {
    let backend = bound_backend(snapshot);
    policy()
        .dry_run(&backend, LABEL, &dry_intent("SYNTHETIC_BODY", "nonce-1"))
        .expect_err("unsafe synthetic snapshot must be refused")
}

#[test]
fn dry_run_is_non_approved_and_never_calls_mutation() {
    let backend = bound_backend(safe_snapshot());
    let request = dry_intent("SYNTHETIC_DRY_RUN_CANARY", "dry-run-nonce");

    let plan = policy()
        .dry_run(&backend, LABEL, &request)
        .expect("safe dry-run should validate");

    assert!(!plan.approval_issued);
    assert!(!plan.attempted);
    assert_eq!(plan.outcome, SendOutcome::DryRun);
    assert!(plan.retry_safe);
    assert_eq!(backend.inspect_calls(), 1);
    assert_eq!(backend.stage_calls(), 0);
    assert_eq!(backend.commit_calls(), 0);
}

#[test]
fn target_binding_requires_the_exact_observed_label_and_never_mutates() {
    for backend in [
        FakeBackend::new(safe_snapshot()),
        FakeBackend::new(safe_snapshot()).with_observed_target_label("SYNTHETIC_WRONG_TARGET"),
    ] {
        let error = policy()
            .dry_run(
                &backend,
                LABEL,
                &dry_intent("SYNTHETIC_BODY", "binding-refusal"),
            )
            .expect_err("missing or mismatched binding evidence must fail closed");
        assert_eq!(error.kind, UiErrorKind::TargetNotSelf);
        assert_eq!(error.operation, "policy_target_binding");
        assert_eq!(backend.inspect_calls(), 1);
        assert_eq!(backend.stage_calls(), 0);
        assert_eq!(backend.commit_calls(), 0);
    }
}

#[test]
fn non_self_intent_is_refused_before_inspection() {
    let backend = bound_backend(safe_snapshot());
    let request = intent(
        TargetKind::Other,
        "SYNTHETIC_BODY",
        SendMode::DryRun,
        false,
        "nonce-1",
    );

    let error = policy()
        .dry_run(&backend, LABEL, &request)
        .expect_err("non-self target must fail");

    assert_eq!(error.kind, UiErrorKind::TargetNotSelf);
    assert_eq!(backend.inspect_calls(), 0);
}

#[test]
fn allowlist_requires_exact_bytes_and_rejects_duplicates() {
    let duplicate = WindowsPolicyConfig::new([LABEL, LABEL])
        .expect_err("duplicate exact entries must fail configuration");
    assert_eq!(duplicate.kind, UiErrorKind::AmbiguousTarget);
    assert_eq!(duplicate.operation, "policy_allowlist_config");

    let whitespace = WindowsPolicyConfig::new([" \u{2003}\u{3000}"])
        .expect_err("an all-whitespace allowlist entry must fail configuration");
    assert_eq!(whitespace.kind, UiErrorKind::InvalidInput);
    assert_eq!(whitespace.operation, "policy_allowlist_config");

    for variant in [
        "SYNTHETIC",
        "synthetic_self_chat",
        "SYNTHETIC_SELF_CHAT ",
        " SYNTHETIC_SELF_CHAT",
        "SYNTHETIC_SELF_CHAT\u{00a0}",
        "SYNTHETIC_SELF_CHAT\u{200b}",
        "SYNTHETIC_SELF_CHAT\u{3000}",
        "SYNTHET\u{0406}C_SELF_CHAT",
    ] {
        let backend = bound_backend(safe_snapshot());
        let error = policy()
            .dry_run(&backend, variant, &dry_intent("SYNTHETIC_BODY", "nonce-1"))
            .expect_err("partial/case/whitespace variant must fail");
        assert_eq!(error.kind, UiErrorKind::TargetNotFound, "{variant:?}");
        assert_eq!(backend.inspect_calls(), 0);
    }
}

#[test]
fn allowlist_does_not_normalize_unicode() {
    const COMPOSED: &str = "SYNTHETIC_CAF\u{00c9}";
    const DECOMPOSED: &str = "SYNTHETIC_CAFE\u{0301}";
    let configured = WindowsSafetyPolicy::with_clock(config_for(COMPOSED), FixedClock(NOW_MS));
    let backend = FakeBackend::new(safe_snapshot()).with_observed_target_label(COMPOSED);

    let error = configured
        .dry_run(
            &backend,
            DECOMPOSED,
            &dry_intent("SYNTHETIC_BODY", "nonce-1"),
        )
        .expect_err("canonically equivalent bytes must not be normalized");
    assert_eq!(error.kind, UiErrorKind::TargetNotFound);
    assert_eq!(backend.inspect_calls(), 0);

    configured
        .dry_run(&backend, COMPOSED, &dry_intent("SYNTHETIC_BODY", "nonce-2"))
        .expect("byte-for-byte exact Unicode label should pass");
}

#[test]
fn app_snapshot_refusal_mapping_is_deterministic() {
    let mut cases = Vec::new();

    let mut state = safe_snapshot();
    state.app.platform = UiPlatform::Unsupported;
    cases.push((state, UiErrorKind::UnsupportedCapability));

    let mut state = safe_snapshot();
    state.app.app_running = false;
    cases.push((state, UiErrorKind::ProcessNotFound));

    let mut state = safe_snapshot();
    state.app.process = None;
    cases.push((state, UiErrorKind::ProcessNotFound));

    let mut state = safe_snapshot();
    state.app.process.as_mut().expect("process").pid = 0;
    cases.push((state, UiErrorKind::ProcessNotFound));

    let mut state = safe_snapshot();
    state.app.top_level_window_count = 0;
    cases.push((state, UiErrorKind::ProcessNotFound));

    let mut state = safe_snapshot();
    state.app.top_level_window_count = 2;
    cases.push((state, UiErrorKind::AmbiguousTarget));

    let mut state = safe_snapshot();
    state.app.read_only_window_ambiguity = Some(ReadOnlyWindowAmbiguity::NoComposer);
    cases.push((state, UiErrorKind::AmbiguousTarget));

    let mut state = safe_snapshot();
    state.app.process.as_mut().expect("process").session_id = None;
    cases.push((state, UiErrorKind::SessionMismatch));

    let mut state = safe_snapshot();
    state.app.interactive_session_match = false;
    cases.push((state, UiErrorKind::SessionMismatch));

    let mut state = safe_snapshot();
    state.app.integrity_compatible = false;
    cases.push((state, UiErrorKind::IntegrityMismatch));

    let mut state = safe_snapshot();
    state
        .app
        .process
        .as_mut()
        .expect("process")
        .executable
        .clear();
    cases.push((state, UiErrorKind::UnknownUiProfile));

    let mut state = safe_snapshot();
    state.app.known_ui_profile = false;
    cases.push((state, UiErrorKind::UnknownUiProfile));

    let mut state = safe_snapshot();
    state.app.app_version = Some("0.0.0-synthetic".to_string());
    cases.push((state, UiErrorKind::UnknownUiProfile));

    let mut state = safe_snapshot();
    state.app.modal_present = true;
    cases.push((state, UiErrorKind::ModalPresent));

    for (state, expected) in cases {
        let error = dry_run_error(state);
        assert_eq!(error.kind, expected);
        assert_eq!(error.operation, "policy_app_snapshot");
    }
}

#[test]
fn ambiguous_discovery_wins_over_untrusted_absent_process_state() {
    let mut state = safe_snapshot();
    state.app.top_level_window_count = 2;
    state.app.app_running = false;
    state.app.process = None;

    let error = dry_run_error(state);
    assert_eq!(error.kind, UiErrorKind::AmbiguousTarget);
    assert_eq!(error.operation, "policy_app_snapshot");
}

#[test]
fn unredacted_or_wrong_profile_evidence_is_refused_without_leaking_values() {
    const LEAK_CANARY: &str = "SYNTHETIC_PRIVATE_EVIDENCE_CANARY";
    const RETIRED_EDIT_PROFILE: &str = "kakaotalk-windows-x64-stable-26.7.0.5255-v1";
    let mut cases = Vec::new();

    let mut state = safe_snapshot();
    state.app.process.as_mut().expect("process").executable = LEAK_CANARY.to_string();
    cases.push((state, UiErrorKind::UnknownUiProfile, "policy_app_snapshot"));

    let mut state = safe_snapshot();
    state.target.window = Some(LEAK_CANARY.to_string());
    cases.push((state, UiErrorKind::TargetNotFound, "policy_target_snapshot"));

    let mut state = safe_snapshot();
    state.target.composer = Some(LEAK_CANARY.to_string());
    cases.push((
        state,
        UiErrorKind::ComposerNotFound,
        "policy_target_snapshot",
    ));

    let mut state = safe_snapshot();
    state.target.composer = state.target.window.clone();
    cases.push((
        state,
        UiErrorKind::UnknownUiProfile,
        "policy_target_snapshot",
    ));

    let mut state = safe_snapshot();
    state.input.selector_profile_id = Some(LEAK_CANARY.to_string());
    cases.push((
        state,
        UiErrorKind::UnknownUiProfile,
        "policy_input_snapshot",
    ));

    let mut state = safe_snapshot();
    state.input.selector_profile_id = Some(RETIRED_EDIT_PROFILE.to_string());
    cases.push((
        state,
        UiErrorKind::UnknownUiProfile,
        "policy_input_snapshot",
    ));

    for (state, expected_kind, expected_operation) in cases {
        let error = dry_run_error(state);
        assert_eq!(error.kind, expected_kind);
        assert_eq!(error.operation, expected_operation);
        assert!(!format!("{error}").contains(LEAK_CANARY));
        assert!(!format!("{error:?}").contains(LEAK_CANARY));
        assert!(!format!("{error}").contains(RETIRED_EDIT_PROFILE));
        assert!(!format!("{error:?}").contains(RETIRED_EDIT_PROFILE));
    }
}

#[test]
fn target_and_input_snapshot_refusal_mapping_is_deterministic() {
    let mut cases = Vec::new();

    let mut state = safe_snapshot();
    state.target.kind = TargetKind::Other;
    cases.push((state, UiErrorKind::TargetNotSelf, "policy_target_snapshot"));

    let mut state = safe_snapshot();
    state.target.self_chat_verified = false;
    cases.push((state, UiErrorKind::TargetNotSelf, "policy_target_snapshot"));

    let mut state = safe_snapshot();
    state.target.exact_match = false;
    cases.push((state, UiErrorKind::TargetNotFound, "policy_target_snapshot"));

    let mut state = safe_snapshot();
    state.target.unique_match = false;
    cases.push((
        state,
        UiErrorKind::AmbiguousTarget,
        "policy_target_snapshot",
    ));

    let mut state = safe_snapshot();
    state.target.window = None;
    cases.push((state, UiErrorKind::TargetNotFound, "policy_target_snapshot"));

    let mut state = safe_snapshot();
    state.target.composer = None;
    cases.push((
        state,
        UiErrorKind::ComposerNotFound,
        "policy_target_snapshot",
    ));

    let mut state = safe_snapshot();
    state.input.present = false;
    cases.push((
        state,
        UiErrorKind::ComposerNotFound,
        "policy_input_snapshot",
    ));

    let mut state = safe_snapshot();
    state.input.unique = false;
    cases.push((
        state,
        UiErrorKind::AmbiguousComposer,
        "policy_input_snapshot",
    ));

    let mut state = safe_snapshot();
    state.input.enabled = false;
    cases.push((
        state,
        UiErrorKind::PermissionDenied,
        "policy_input_snapshot",
    ));

    let mut state = safe_snapshot();
    state.input.writable = false;
    cases.push((
        state,
        UiErrorKind::PermissionDenied,
        "policy_input_snapshot",
    ));

    let mut state = safe_snapshot();
    state.input.draft_empty = false;
    cases.push((state, UiErrorKind::ExistingDraft, "policy_input_snapshot"));

    let mut state = safe_snapshot();
    state.input.focused = true;
    cases.push((state, UiErrorKind::UserActive, "policy_input_snapshot"));

    let mut state = safe_snapshot();
    state.input.selector_profile_id = None;
    cases.push((
        state,
        UiErrorKind::UnknownUiProfile,
        "policy_input_snapshot",
    ));

    for (state, expected, operation) in cases {
        let error = dry_run_error(state);
        assert_eq!(error.kind, expected);
        assert_eq!(error.operation, operation);
    }
}

#[test]
fn stale_future_and_overlong_ttl_snapshots_are_refused() {
    let mut cases = Vec::new();

    let mut state = safe_snapshot();
    state.target.expires_at_unix_ms = NOW_MS;
    cases.push(state);

    let mut state = safe_snapshot();
    state.target.observed_at_unix_ms = NOW_MS + 1;
    state.target.expires_at_unix_ms = NOW_MS + 2;
    cases.push(state);

    let mut state = safe_snapshot();
    state.target.expires_at_unix_ms = state.target.observed_at_unix_ms;
    cases.push(state);

    let mut state = safe_snapshot();
    state.target.expires_at_unix_ms = state.target.observed_at_unix_ms + MAX_SNAPSHOT_TTL_MS + 1;
    cases.push(state);

    let mut state = safe_snapshot();
    state.target.observed_at_unix_ms = NOW_MS + 2;
    state.target.expires_at_unix_ms = NOW_MS + 1;
    cases.push(state);

    for state in cases {
        let error = dry_run_error(state);
        assert_eq!(error.kind, UiErrorKind::StaleSnapshot);
        assert_eq!(error.operation, "policy_snapshot_time");
    }
}

#[test]
fn message_boundaries_and_controls_are_refused_without_inspection() {
    assert_eq!(MAX_MESSAGE_UTF8_BYTES, MAX_MESSAGE_SCALARS * 4);
    let accepted = "\u{1f642}".repeat(MAX_MESSAGE_SCALARS);
    let backend = bound_backend(safe_snapshot());
    policy()
        .dry_run(&backend, LABEL, &dry_intent(accepted, "nonce-ok"))
        .expect("exact scalar limit should pass");

    let invalid = [
        String::new(),
        "x".repeat(MAX_MESSAGE_SCALARS + 1),
        "synthetic\0body".to_string(),
        "synthetic\nbody".to_string(),
        "synthetic\rbody".to_string(),
        "synthetic\tbody".to_string(),
        "synthetic\u{007f}body".to_string(),
        "synthetic\u{0085}body".to_string(),
        "synthetic\u{2028}body".to_string(),
        "synthetic\u{2029}body".to_string(),
        " \u{2003}\u{3000}".to_string(),
    ];

    for (index, value) in invalid.into_iter().enumerate() {
        let backend = bound_backend(safe_snapshot());
        let error = policy()
            .dry_run(
                &backend,
                LABEL,
                &dry_intent(value, &format!("nonce-{index}")),
            )
            .expect_err("invalid message must fail");
        assert_eq!(error.kind, UiErrorKind::InvalidInput);
        assert_eq!(error.operation, "policy_validate_message");
        assert_eq!(backend.inspect_calls(), 0);
    }
}

#[test]
fn nonce_is_bounded_and_syntax_checked_before_inspection() {
    let invalid = [
        String::new(),
        "n".repeat(MAX_NONCE_BYTES + 1),
        "nonce with space".to_string(),
        "nonce/slash".to_string(),
        "nonce-\u{03b1}".to_string(),
    ];

    for value in invalid {
        let backend = bound_backend(safe_snapshot());
        let error = policy()
            .dry_run(&backend, LABEL, &dry_intent("SYNTHETIC_BODY", &value))
            .expect_err("invalid nonce must fail");
        assert_eq!(error.kind, UiErrorKind::InvalidInput);
        assert_eq!(error.operation, "policy_validate_nonce");
        assert_eq!(backend.inspect_calls(), 0);
    }
}

#[test]
fn stage_and_commit_require_yes_and_can_be_represented_without_mutation() {
    for mode in [SendMode::StageOnly, SendMode::Commit] {
        let backend = bound_backend(safe_snapshot());
        let no = intent(
            TargetKind::SelfChat,
            "SYNTHETIC_BODY",
            mode,
            false,
            "nonce-no",
        );
        let error = policy()
            .authorize(&backend, LABEL, no)
            .expect_err("write mode without yes must fail");
        assert_eq!(error.kind, UiErrorKind::InvalidInput);
        assert_eq!(error.operation, "policy_validate_confirmation");
        assert_eq!(backend.inspect_calls(), 0);

        let yes = intent(
            TargetKind::SelfChat,
            "SYNTHETIC_BODY",
            mode,
            true,
            "nonce-yes",
        );
        let policy = policy();
        let approval = policy
            .authorize(&backend, LABEL, yes)
            .expect("explicit write intent may be represented by policy");
        assert_eq!(approval.mode(), mode);
        assert_eq!(backend.stage_calls(), 0);
        assert_eq!(backend.commit_calls(), 0);
    }
}

#[test]
fn authorize_refuses_adversarial_state_without_calling_mutation() {
    let mut cases = Vec::new();

    let mut state = safe_snapshot();
    state.app.app_running = false;
    cases.push((state, UiErrorKind::ProcessNotFound));

    let mut state = safe_snapshot();
    state.app.top_level_window_count = 2;
    cases.push((state, UiErrorKind::AmbiguousTarget));

    let mut state = safe_snapshot();
    state.app.known_ui_profile = false;
    cases.push((state, UiErrorKind::UnknownUiProfile));

    let mut state = safe_snapshot();
    state.app.modal_present = true;
    cases.push((state, UiErrorKind::ModalPresent));

    let mut state = safe_snapshot();
    state.target.kind = TargetKind::Other;
    cases.push((state, UiErrorKind::TargetNotSelf));

    let mut state = safe_snapshot();
    state.target.unique_match = false;
    cases.push((state, UiErrorKind::AmbiguousTarget));

    let mut state = safe_snapshot();
    state.input.draft_empty = false;
    cases.push((state, UiErrorKind::ExistingDraft));

    let mut state = safe_snapshot();
    state.input.focused = true;
    cases.push((state, UiErrorKind::UserActive));

    let mut state = safe_snapshot();
    state.target.expires_at_unix_ms = NOW_MS;
    cases.push((state, UiErrorKind::StaleSnapshot));

    for (index, (state, expected_kind)) in cases.into_iter().enumerate() {
        let backend = bound_backend(state);
        let error = policy()
            .authorize(
                &backend,
                LABEL,
                intent(
                    TargetKind::SelfChat,
                    "SYNTHETIC_BODY",
                    SendMode::Commit,
                    true,
                    &format!("adversarial-{index}"),
                ),
            )
            .expect_err("unsafe state must not mint an approval");
        assert_eq!(error.kind, expected_kind);
        assert_eq!(backend.stage_calls(), 0);
        assert_eq!(backend.commit_calls(), 0);
    }
}

#[test]
fn message_label_and_nonce_never_appear_in_formats_or_json() {
    const SECRET: &str = "SYNTHETIC_SECRET_MESSAGE_CANARY";
    const NONCE: &str = "synthetic-secret-nonce";
    let config = config_for(LABEL);
    assert!(!format!("{config:?}").contains(LABEL));

    let dry_policy = WindowsSafetyPolicy::with_clock(config, FixedClock(NOW_MS));
    assert!(!format!("{dry_policy:?}").contains(LABEL));
    let backend = bound_backend(safe_snapshot());
    let plan = dry_policy
        .dry_run(&backend, LABEL, &dry_intent(SECRET, NONCE))
        .expect("dry-run should validate");
    let plan_debug = format!("{plan:?}");
    let plan_json = serde_json::to_string(&plan).expect("plan should serialize");
    for forbidden in [SECRET, LABEL, NONCE] {
        assert!(!plan_debug.contains(forbidden));
        assert!(!plan_json.contains(forbidden));
    }

    let write_policy = policy();
    let approval = write_policy
        .authorize(
            &backend,
            LABEL,
            intent(TargetKind::SelfChat, SECRET, SendMode::Commit, true, NONCE),
        )
        .expect("write intent should approve");
    for rendered in [format!("{approval:?}")] {
        for forbidden in [SECRET, LABEL, NONCE] {
            assert!(!rendered.contains(forbidden));
        }
    }

    let invalid = dry_intent(format!("{SECRET}\n"), "error-nonce");
    let error = dry_policy
        .dry_run(&backend, LABEL, &invalid)
        .expect_err("control character must fail");
    for rendered in [format!("{error}"), format!("{error:?}")] {
        assert!(!rendered.contains(SECRET));
        assert!(!rendered.contains(LABEL));
    }
}

#[test]
fn external_probe_and_clock_errors_are_rewritten_to_fixed_policy_operations() {
    let probe = ErrorProbe::default();
    let dry_policy = policy();
    let dry_error = dry_policy
        .dry_run(
            &probe,
            LABEL,
            &dry_intent("SYNTHETIC_BODY", "probe-error-dry"),
        )
        .expect_err("probe error must be propagated safely");
    assert_eq!(dry_error.kind, UiErrorKind::Timeout);
    assert_eq!(dry_error.operation, "policy_dry_run_inspect");
    assert!(!dry_error.retry_safe);

    let authorize_error = dry_policy
        .authorize(
            &probe,
            LABEL,
            intent(
                TargetKind::SelfChat,
                "SYNTHETIC_BODY",
                SendMode::Commit,
                true,
                "probe-error-write",
            ),
        )
        .expect_err("authorization probe error must be propagated safely");
    assert_eq!(authorize_error.kind, UiErrorKind::Timeout);
    assert_eq!(authorize_error.operation, "policy_authorize_inspect");
    assert!(!authorize_error.retry_safe);
    assert_eq!(probe.inspect_calls(), 2);

    let clock_policy = WindowsSafetyPolicy::with_clock(config_for(LABEL), ErrorClock);
    let backend = bound_backend(safe_snapshot());
    let clock_error = clock_policy
        .dry_run(
            &backend,
            LABEL,
            &dry_intent("SYNTHETIC_BODY", "clock-error"),
        )
        .expect_err("clock error must fail closed");
    assert_eq!(clock_error.kind, UiErrorKind::StaleSnapshot);
    assert_eq!(clock_error.operation, "policy_current_time");

    for error in [dry_error, authorize_error, clock_error] {
        assert!(!format!("{error}").contains(OPERATION_LEAK_CANARY));
        assert!(!format!("{error:?}").contains(OPERATION_LEAK_CANARY));
    }
}

#[test]
fn approved_nonce_is_one_shot_but_dry_run_does_not_consume_it() {
    let backend = bound_backend(safe_snapshot());
    let policy = policy();
    let request = dry_intent("SYNTHETIC_BODY", "reusable-dry-run");
    policy
        .dry_run(&backend, LABEL, &request)
        .expect("first dry-run should pass");
    policy
        .dry_run(&backend, LABEL, &request)
        .expect("second dry-run should not be replay-refused");

    let first = policy
        .authorize(
            &backend,
            LABEL,
            intent(
                TargetKind::SelfChat,
                "SYNTHETIC_BODY",
                SendMode::StageOnly,
                true,
                "one-shot",
            ),
        )
        .expect("first approval should pass");
    drop(first);

    let replay = policy
        .authorize(
            &backend,
            LABEL,
            intent(
                TargetKind::SelfChat,
                "SYNTHETIC_BODY",
                SendMode::StageOnly,
                true,
                "one-shot",
            ),
        )
        .expect_err("approved nonce must not be reusable");
    assert_eq!(replay.kind, UiErrorKind::InvalidInput);
    assert_eq!(replay.operation, "policy_nonce_replay");
}

struct SequenceProbe {
    snapshots: StdMutex<VecDeque<UiSnapshot>>,
    inspect_calls: AtomicUsize,
}

impl SequenceProbe {
    fn new(snapshots: impl IntoIterator<Item = UiSnapshot>) -> Self {
        Self {
            snapshots: StdMutex::new(snapshots.into_iter().collect()),
            inspect_calls: AtomicUsize::new(0),
        }
    }

    fn inspect_calls(&self) -> usize {
        self.inspect_calls.load(Ordering::SeqCst)
    }
}

impl PlatformProbe for SequenceProbe {
    fn capabilities(&self) -> UiCapabilities {
        UiCapabilities {
            inspect: true,
            send_open_chat: true,
            open_chat_by_name: false,
            read_visible: false,
            watch_unread: false,
        }
    }

    fn inspect(&self, request: &InspectRequest) -> Result<UiSnapshot, UiError> {
        self.inspect_calls.fetch_add(1, Ordering::SeqCst);
        let snapshot = self
            .snapshots
            .lock()
            .expect("synthetic sequence mutex")
            .pop_front()
            .ok_or_else(|| {
                UiError::new(UiErrorKind::ProcessNotFound, "synthetic_sequence_empty")
            })?;
        Ok(bind_snapshot_for_request(request, snapshot, LABEL))
    }
}

#[test]
fn audit_existing_approval_retains_old_snapshot_after_backend_state_changes() {
    let initial = safe_snapshot();
    let mut changed = safe_snapshot();
    changed.app.process.as_mut().expect("process").pid = 8;
    changed.app.process.as_mut().expect("process").executable =
        "run:44444444444444444444444444444444".to_string();
    changed.app.modal_present = true;
    changed.target.window = Some("run:55555555555555555555555555555555".to_string());
    changed.target.composer = Some("run:66666666666666666666666666666666".to_string());
    changed.input.draft_empty = false;
    changed.input.focused = true;

    let probe = SequenceProbe::new([initial.clone(), changed.clone()]);
    let policy = policy();
    let approval = policy
        .authorize(
            &probe,
            LABEL,
            intent(
                TargetKind::SelfChat,
                "SYNTHETIC_BODY",
                SendMode::Commit,
                true,
                "toctou-audit",
            ),
        )
        .expect("initial snapshot approves");
    assert_eq!(probe.inspect_calls(), 1);

    let later = probe
        .inspect(&InspectRequest::self_chat())
        .expect("synthetic later state");
    assert_ne!(approval.snapshot(), &later);
    let mut approved_snapshot = approval.snapshot().clone();
    approved_snapshot.target.target_binding = None;
    assert_eq!(approved_snapshot, initial);
    assert_ne!(
        approval
            .snapshot()
            .app
            .process
            .as_ref()
            .expect("approved process")
            .pid,
        later.app.process.as_ref().expect("later process").pid
    );
    assert!(later.app.modal_present);
    assert!(!later.input.draft_empty);
    assert!(later.input.focused);
}

#[test]
fn approved_operation_consumes_the_only_public_execution_capability() {
    let backend = bound_backend(safe_snapshot());
    let policy = policy();
    let approval = policy
        .authorize(
            &backend,
            LABEL,
            intent(
                TargetKind::SelfChat,
                "SYNTHETIC_BODY",
                SendMode::Commit,
                true,
                "repeatable-approval",
            ),
        )
        .expect("synthetic approval should succeed");

    let outcome = approval
        .execute(&backend)
        .expect("the consuming fake commit should return its outcome");

    assert_eq!(outcome, SendOutcome::CommitIssued);
    assert!(!outcome.retry_safe());
    assert_eq!(backend.commit_calls(), 1);
    assert_eq!(backend.stage_calls(), 0);
}

fn bound_backend(snapshot: UiSnapshot) -> FakeBackend {
    FakeBackend::new(snapshot).with_observed_target_label(LABEL)
}

fn bind_snapshot_for_request(
    request: &InspectRequest,
    mut snapshot: UiSnapshot,
    observed_label: &str,
) -> UiSnapshot {
    snapshot.target.target_binding = None;
    let observed_utf16: Vec<u16> = observed_label.encode_utf16().collect();
    snapshot.target.target_binding = request.bind_observed_target_utf16(&observed_utf16, &snapshot);
    snapshot
}

#[derive(Clone)]
struct ConcurrentProbe {
    snapshot: UiSnapshot,
    inspect_calls: Arc<AtomicUsize>,
    send_open_chat: bool,
}

impl ConcurrentProbe {
    fn new(snapshot: UiSnapshot, send_open_chat: bool) -> Self {
        Self {
            snapshot,
            inspect_calls: Arc::new(AtomicUsize::new(0)),
            send_open_chat,
        }
    }

    fn inspect_calls(&self) -> usize {
        self.inspect_calls.load(Ordering::SeqCst)
    }
}

impl PlatformProbe for ConcurrentProbe {
    fn capabilities(&self) -> UiCapabilities {
        UiCapabilities {
            inspect: true,
            send_open_chat: self.send_open_chat,
            open_chat_by_name: false,
            read_visible: false,
            watch_unread: false,
        }
    }

    fn inspect(&self, request: &InspectRequest) -> Result<UiSnapshot, UiError> {
        self.inspect_calls.fetch_add(1, Ordering::SeqCst);
        Ok(bind_snapshot_for_request(
            request,
            self.snapshot.clone(),
            LABEL,
        ))
    }
}

#[test]
fn authorize_requires_send_capability_before_inspection_or_nonce_consumption() {
    let policy = policy();
    let read_only_probe = ConcurrentProbe::new(safe_snapshot(), false);
    let request = || {
        intent(
            TargetKind::SelfChat,
            "SYNTHETIC_BODY",
            SendMode::Commit,
            true,
            "capability-nonce",
        )
    };

    let error = policy
        .authorize(&read_only_probe, LABEL, request())
        .expect_err("read-only capability must not authorize");
    assert_eq!(error.kind, UiErrorKind::UnsupportedCapability);
    assert_eq!(error.operation, "policy_send_capability");
    assert_eq!(read_only_probe.inspect_calls(), 0);

    let send_capable_probe = ConcurrentProbe::new(safe_snapshot(), true);
    policy
        .authorize(&send_capable_probe, LABEL, request())
        .expect("capability refusal must not consume the nonce");
    assert_eq!(send_capable_probe.inspect_calls(), 1);
}

#[test]
fn concurrent_same_nonce_has_exactly_one_winner() {
    let policy = Arc::new(policy());
    let probe = Arc::new(ConcurrentProbe::new(safe_snapshot(), true));
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();

    for _ in 0..2 {
        let policy = Arc::clone(&policy);
        let probe = Arc::clone(&probe);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            match policy.authorize(
                probe.as_ref(),
                LABEL,
                intent(
                    TargetKind::SelfChat,
                    "SYNTHETIC_BODY",
                    SendMode::Commit,
                    true,
                    "racing-nonce",
                ),
            ) {
                Ok(approval) => {
                    assert_eq!(approval.mode(), SendMode::Commit);
                    Ok(())
                }
                Err(error) => Err(error.kind),
            }
        }));
    }

    barrier.wait();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("worker must not panic"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| {
                matches!(
                    **result,
                    Err(UiErrorKind::InvalidInput | UiErrorKind::UnsupportedCapability)
                )
            })
            .count(),
        1
    );
    assert_eq!(probe.inspect_calls(), 1);
}

#[test]
fn approval_lease_refuses_distinct_nonce_contention_without_blocking() {
    let policy = Arc::new(policy());
    let probe = Arc::new(ConcurrentProbe::new(safe_snapshot(), true));
    let first = policy
        .authorize(
            probe.as_ref(),
            LABEL,
            intent(
                TargetKind::SelfChat,
                "SYNTHETIC_BODY",
                SendMode::StageOnly,
                true,
                "lease-one",
            ),
        )
        .expect("first lease should be issued");

    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let worker_policy = Arc::clone(&policy);
    let worker_probe = Arc::clone(&probe);
    let worker = std::thread::spawn(move || {
        started_tx.send(()).expect("start signal");
        let result = worker_policy.authorize(
            worker_probe.as_ref(),
            LABEL,
            intent(
                TargetKind::SelfChat,
                "SYNTHETIC_BODY",
                SendMode::Commit,
                true,
                "lease-two",
            ),
        );
        let result = result.map(|approval| approval.mode());
        done_tx.send(result).expect("completion signal");
    });

    started_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("worker should start");
    let contention = done_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("contended approval should fail without blocking")
        .expect_err("contended approval must fail closed");
    assert_eq!(contention.kind, UiErrorKind::UnsupportedCapability);
    assert_eq!(contention.operation, "policy_approval_mutex");
    assert_eq!(probe.inspect_calls(), 1);

    drop(first);
    worker.join().expect("worker must not panic");

    let second = policy
        .authorize(
            probe.as_ref(),
            LABEL,
            intent(
                TargetKind::SelfChat,
                "SYNTHETIC_BODY",
                SendMode::Commit,
                true,
                "lease-two",
            ),
        )
        .expect("contention refusal must not consume the second nonce");
    assert_eq!(second.mode(), SendMode::Commit);
    assert_eq!(probe.inspect_calls(), 2);
}

#[test]
fn poisoned_approval_mutex_fails_closed_before_reinspection() {
    let policy = Arc::new(policy());
    let probe = Arc::new(ConcurrentProbe::new(safe_snapshot(), true));
    let worker_policy = Arc::clone(&policy);
    let worker_probe = Arc::clone(&probe);

    let panic = std::thread::spawn(move || {
        let _approval = worker_policy
            .authorize(
                worker_probe.as_ref(),
                LABEL,
                intent(
                    TargetKind::SelfChat,
                    "SYNTHETIC_BODY",
                    SendMode::Commit,
                    true,
                    "poison-one",
                ),
            )
            .expect("synthetic approval should succeed before panic");
        panic!("synthetic mutex poison");
    })
    .join();
    assert!(panic.is_err());

    let error = policy
        .authorize(
            probe.as_ref(),
            LABEL,
            intent(
                TargetKind::SelfChat,
                "SYNTHETIC_BODY",
                SendMode::Commit,
                true,
                "poison-two",
            ),
        )
        .expect_err("poisoned mutex must refuse");
    assert_eq!(error.kind, UiErrorKind::UnsupportedCapability);
    assert_eq!(error.operation, "policy_approval_mutex");
    assert_eq!(probe.inspect_calls(), 1);
}

#[test]
fn audit_separate_policy_instances_do_not_share_nonce_or_mutex_state() {
    let first_policy = policy();
    let second_policy = policy();
    let first_probe = ConcurrentProbe::new(safe_snapshot(), true);
    let second_probe = ConcurrentProbe::new(safe_snapshot(), true);
    let request = || {
        intent(
            TargetKind::SelfChat,
            "SYNTHETIC_BODY",
            SendMode::Commit,
            true,
            "cross-policy-nonce",
        )
    };

    let first = first_policy
        .authorize(&first_probe, LABEL, request())
        .expect("first policy instance approves");
    let second = second_policy
        .authorize(&second_probe, LABEL, request())
        .expect("independent policy instance also approves");

    assert_eq!(first.mode(), SendMode::Commit);
    assert_eq!(second.mode(), SendMode::Commit);
    assert_eq!(first_probe.inspect_calls(), 1);
    assert_eq!(second_probe.inspect_calls(), 1);
}
