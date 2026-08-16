use std::cell::Cell;
use std::io::{self, Cursor, Read};

use clap::{Parser, Subcommand};
use serde_json::Value;

use super::*;
use crate::output::windows::{
    build_action_report, render_error, render_report, OutputMode, ReportAction, SCHEMA_VERSION,
};
use crate::platform::fake::FakeBackend;
use crate::platform::{
    AppSnapshot, BackendKind, ChatTargetSnapshot, ExitCode, InputSnapshot, ProcessFingerprint,
    SendOutcome, TargetKind, UiError, UiErrorKind, UiPlatform, UiSnapshot,
};

const TARGET_CANARY: &str = "SENSITIVE_TARGET_CANARY";
const MESSAGE_CANARY: &str = "SENSITIVE_MESSAGE_CANARY";
const PROCESS_CANARY: &str = "SENSITIVE_PROCESS_CANARY";
const WINDOW_CANARY: &str = "SENSITIVE_WINDOW_CANARY";
const COMPOSER_CANARY: &str = "SENSITIVE_COMPOSER_CANARY";
const SELECTOR_CANARY: &str = "SENSITIVE_SELECTOR_CANARY";
const ACTION_INJECTION_CANARY: &str = "SENSITIVE_ACTION_INJECTION_CANARY";
const PROFILE_INJECTION_CANARY: &str = "SENSITIVE_PROFILE_INJECTION_CANARY";
const EVIDENCE_INJECTION_CANARY: &str = "SENSITIVE_EVIDENCE_INJECTION_CANARY";
const OPERATION_INJECTION_CANARY: &str = "SENSITIVE_OPERATION_INJECTION_CANARY";

#[derive(Parser)]
#[command(name = "windows-cli-test")]
struct Harness {
    #[command(subcommand)]
    command: HarnessCommand,
}

#[derive(Subcommand)]
enum HarnessCommand {
    Doctor(UiDoctorOptions),
    LocalSend(LocalSendOptions),
}

fn safe_snapshot() -> UiSnapshot {
    UiSnapshot {
        app: AppSnapshot {
            platform: UiPlatform::Windows,
            app_running: true,
            process: Some(ProcessFingerprint {
                pid: 42_424_242,
                executable: PROCESS_CANARY.to_string(),
                session_id: Some(7),
            }),
            app_version: Some("SENSITIVE_VERSION_CANARY".to_string()),
            interactive_session_match: true,
            integrity_compatible: true,
            known_ui_profile: true,
            top_level_window_count: 1,
            modal_present: false,
        },
        target: ChatTargetSnapshot {
            kind: TargetKind::SelfChat,
            self_chat_verified: true,
            exact_match: true,
            unique_match: true,
            window: Some(WINDOW_CANARY.to_string()),
            composer: Some(COMPOSER_CANARY.to_string()),
            observed_at_unix_ms: 10,
            expires_at_unix_ms: 20,
            target_binding: None,
        },
        input: InputSnapshot {
            present: true,
            unique: true,
            enabled: true,
            writable: true,
            draft_empty: true,
            focused: false,
            selector_profile_id: Some(SELECTOR_CANARY.to_string()),
        },
    }
}

fn parsed_local_send(extra: &[&str]) -> LocalSendOptions {
    let mut argv = vec![
        "windows-cli-test",
        "local-send",
        TARGET_CANARY,
        "--stdin",
        "--opened-only",
    ];
    argv.extend_from_slice(extra);
    let harness = Harness::try_parse_from(argv).expect("synthetic arguments should parse");
    match harness.command {
        HarnessCommand::LocalSend(options) => options,
        HarnessCommand::Doctor(_) => panic!("expected local-send options"),
    }
}

#[test]
fn doctor_ui_option_parses() {
    let harness = Harness::try_parse_from(["windows-cli-test", "doctor", "--ui"])
        .expect("doctor --ui should parse");
    match harness.command {
        HarnessCommand::Doctor(options) => assert!(options.ui_requested()),
        HarnessCommand::LocalSend(_) => panic!("expected doctor options"),
    }
}

#[test]
fn local_send_defaults_to_dry_run_and_has_no_message_positional() {
    let options = parsed_local_send(&[]);
    assert_eq!(
        options.mode().expect("defaults should validate"),
        SendMode::DryRun
    );
    assert!(options.reads_stdin());
    assert!(options.opened_only());
    assert!(!options.explicit_yes());
    assert!(!options.dry_run_was_explicit());
    assert_eq!(options.self_chat_name_secret(), TARGET_CANARY);

    let extra_message = Harness::try_parse_from([
        "windows-cli-test",
        "local-send",
        TARGET_CANARY,
        MESSAGE_CANARY,
        "--stdin",
        "--opened-only",
    ]);
    assert!(extra_message.is_err(), "an argv message must be rejected");
}

#[test]
fn explicit_dry_run_parses_as_dry_run() {
    let options = parsed_local_send(&["--dry-run"]);
    assert_eq!(
        options.mode().expect("dry-run should validate"),
        SendMode::DryRun
    );
    assert!(options.dry_run_was_explicit());
}

#[test]
fn clap_rejects_missing_required_and_write_mode_conflicts() {
    let invalid = [
        vec!["windows-cli-test", "local-send", TARGET_CANARY],
        vec![
            "windows-cli-test",
            "local-send",
            TARGET_CANARY,
            "--stdin",
            "--opened-only",
            "--stage-only",
        ],
        vec![
            "windows-cli-test",
            "local-send",
            TARGET_CANARY,
            "--stdin",
            "--opened-only",
            "--commit",
        ],
        vec![
            "windows-cli-test",
            "local-send",
            TARGET_CANARY,
            "--stdin",
            "--opened-only",
            "--stage-only",
            "--commit",
            "--yes",
        ],
        vec![
            "windows-cli-test",
            "local-send",
            TARGET_CANARY,
            "--stdin",
            "--opened-only",
            "--dry-run",
            "--stage-only",
            "--yes",
        ],
    ];

    for argv in invalid {
        assert!(
            Harness::try_parse_from(argv).is_err(),
            "invalid options must fail during parsing"
        );
    }
}

struct CountingInput {
    reads: Cell<usize>,
}

impl CountingInput {
    fn new() -> Self {
        Self {
            reads: Cell::new(0),
        }
    }
}

impl MessageInput for CountingInput {
    fn read_message(&mut self) -> Result<SecretMessage, UiError> {
        self.reads.set(self.reads.get() + 1);
        Ok(SecretMessage::new(MESSAGE_CANARY))
    }
}

#[test]
fn runtime_validation_precedes_input_and_backend_calls() {
    let options = LocalSendOptions {
        self_chat_name: TARGET_CANARY.to_string(),
        stdin: true,
        opened_only: true,
        dry_run: false,
        stage_only: true,
        commit: true,
        yes: true,
    };
    let backend = FakeBackend::new(safe_snapshot());
    let mut input = CountingInput::new();

    let error = prepare_local_send(&options, &mut input, &backend)
        .err()
        .expect("conflicting modes must fail");

    assert_eq!(error.kind, UiErrorKind::InvalidInput);
    assert_eq!(input.reads.get(), 0);
    assert_eq!(backend.inspect_calls(), 0);
    assert_eq!(backend.stage_calls(), 0);
    assert_eq!(backend.commit_calls(), 0);
}

#[test]
fn reserved_write_modes_never_call_input_or_backend() {
    for flag in ["--stage-only", "--commit"] {
        let options = parsed_local_send(&[flag, "--yes"]);
        let backend = FakeBackend::new(safe_snapshot());
        let mut input = CountingInput::new();

        let error = prepare_local_send(&options, &mut input, &backend)
            .err()
            .expect("the dry-run preparation seam must refuse write modes");

        assert_eq!(error.kind, UiErrorKind::UnsupportedCapability);
        assert_eq!(input.reads.get(), 0);
        assert_eq!(backend.inspect_calls(), 0);
        assert_eq!(backend.stage_calls(), 0);
        assert_eq!(backend.commit_calls(), 0);
    }
}

#[test]
fn reader_message_input_is_testable_without_real_stdin() {
    let mut input = ReaderMessageInput::new(Cursor::new(MESSAGE_CANARY.as_bytes()));
    let message = input
        .read_message()
        .expect("in-memory message input should succeed");

    assert_eq!(message.len_chars(), MESSAGE_CANARY.chars().count());
    assert_eq!(format!("{message:?}"), "SecretMessage(<redacted>)");
    assert_eq!(format!("{input:?}"), "ReaderMessageInput(<redacted>)");
}

#[test]
fn reader_accepts_exact_utf8_byte_and_scalar_boundaries() {
    let boundary = "\u{1f7e6}".repeat(1_000);
    assert_eq!(boundary.len(), 4_000);
    let mut input = ReaderMessageInput::new(Cursor::new(boundary.into_bytes()));

    let message = input
        .read_message()
        .expect("exact 4,000-byte UTF-8 input should be accepted by the reader");

    assert_eq!(message.len_chars(), 1_000);
}

#[test]
fn reader_rejects_overflow_after_reading_at_most_4_001_bytes() {
    let overflow = "\u{1f7e6}".repeat(1_001).into_bytes();
    assert_eq!(overflow.len(), 4_004);
    let mut input = ReaderMessageInput::new(Cursor::new(overflow));

    let error = input
        .read_message()
        .expect_err("input over 4,000 UTF-8 bytes must be rejected");
    let cursor = input.into_inner();

    assert_eq!(error.kind, UiErrorKind::InvalidInput);
    assert_eq!(error.operation, STDIN_TOO_LARGE);
    assert_eq!(cursor.position(), 4_001);
}

#[test]
fn reader_rejects_invalid_utf8_with_static_error() {
    let mut input = ReaderMessageInput::new(Cursor::new(vec![0xff]));

    let error = input
        .read_message()
        .expect_err("invalid UTF-8 must be rejected");

    assert_eq!(error.kind, UiErrorKind::InvalidInput);
    assert_eq!(error.operation, STDIN_INVALID_UTF8);
}

struct PartialThenFail {
    emitted: bool,
}

impl Read for PartialThenFail {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.emitted {
            return Err(io::Error::other("synthetic read failure"));
        }
        self.emitted = true;
        let count = buffer.len().min(MESSAGE_CANARY.len());
        buffer[..count].copy_from_slice(&MESSAGE_CANARY.as_bytes()[..count]);
        Ok(count)
    }
}

#[test]
fn reader_rejects_partial_read_failure_with_static_error() {
    let mut input = ReaderMessageInput::new(PartialThenFail { emitted: false });

    let error = input
        .read_message()
        .expect_err("partial input followed by a read failure must be rejected");

    assert_eq!(error.kind, UiErrorKind::InvalidInput);
    assert_eq!(error.operation, READ_STDIN);
}

#[test]
fn dry_run_uses_only_probe_and_has_zero_mutations() {
    let options = parsed_local_send(&[]);
    let backend = FakeBackend::new(safe_snapshot());
    let mut input = CountingInput::new();

    let prepared = prepare_local_send(&options, &mut input, &backend)
        .expect("synthetic dry-run preparation should succeed");

    assert!(prepared.snapshot().target.self_chat_verified);
    assert_eq!(input.reads.get(), 1);
    assert_eq!(backend.inspect_calls(), 1);
    assert_eq!(backend.stage_calls(), 0);
    assert_eq!(backend.commit_calls(), 0);
}

#[test]
fn doctor_preserves_negative_snapshot_state_as_redacted_evidence() {
    let mut snapshot = safe_snapshot();
    snapshot.app.app_running = false;
    snapshot.app.known_ui_profile = false;
    snapshot.app.top_level_window_count = 0;
    snapshot.target.self_chat_verified = false;
    snapshot.target.exact_match = false;
    snapshot.target.unique_match = false;
    snapshot.input.present = false;
    let backend = FakeBackend::new(snapshot);
    let options = UiDoctorOptions { ui: true };

    let observed = inspect_ui_doctor(&options, &backend)
        .expect("observable negative states are status, not backend errors");
    let report = build_action_report(ReportAction::UiDoctor, BackendKind::Fake, &observed);

    assert_eq!(report.outcome, SendOutcome::NotSubmitted);
    assert!(report.evidence.contains(&"app_not_running".to_string()));
    assert!(report.evidence.contains(&"ui_profile_unknown".to_string()));
    assert!(report
        .evidence
        .contains(&"top_level_window_absent".to_string()));
    assert!(report
        .evidence
        .contains(&"self_chat_unverified".to_string()));
    assert_eq!(backend.inspect_calls(), 1);
    assert_eq!(backend.stage_calls(), 0);
    assert_eq!(backend.commit_calls(), 0);
}

#[test]
fn json_report_is_schema_v1_and_redacts_sensitive_snapshot_fields() {
    let report = build_action_report(ReportAction::LocalSend, BackendKind::Fake, &safe_snapshot());
    let rendered = render_report(&report, OutputMode::Json);
    let value: Value = serde_json::from_str(rendered.stdout.trim())
        .expect("JSON report should be valid machine output");

    assert_eq!(value["schema_version"], SCHEMA_VERSION);
    assert_eq!(value["action"], "local_send");
    assert_eq!(value["platform"], "windows");
    assert_eq!(value["backend"], "fake");
    assert_eq!(value["target"], "self_chat");
    assert_eq!(value["attempted"], false);
    assert_eq!(value["outcome"], "dry_run");
    assert_eq!(value["retry_safe"], true);
    assert!(value["evidence"].is_array());
    assert!(rendered.stderr.is_empty());
    assert_eq!(rendered.exit_code, ExitCode::Success);

    for canary in [
        TARGET_CANARY,
        MESSAGE_CANARY,
        PROCESS_CANARY,
        WINDOW_CANARY,
        COMPOSER_CANARY,
        SELECTOR_CANARY,
        "SENSITIVE_VERSION_CANARY",
        "42424242",
    ] {
        assert!(!rendered.stdout.contains(canary));
    }
}

#[test]
fn human_report_is_redacted_and_keeps_diagnostics_empty() {
    let report = build_action_report(ReportAction::LocalSend, BackendKind::Fake, &safe_snapshot());
    let rendered = render_report(&report, OutputMode::Human);

    assert!(rendered.stdout.contains("schema_version: 1"));
    assert!(rendered.stdout.contains("outcome: dry_run"));
    assert!(rendered.stderr.is_empty());
    for canary in [
        PROCESS_CANARY,
        WINDOW_CANARY,
        COMPOSER_CANARY,
        SELECTOR_CANARY,
    ] {
        assert!(!rendered.stdout.contains(canary));
    }
}

#[test]
fn renderer_drops_arbitrary_public_report_strings() {
    let mut report =
        build_action_report(ReportAction::LocalSend, BackendKind::Fake, &safe_snapshot());
    report.action = ACTION_INJECTION_CANARY.to_string();
    report.ui_profile = Some(PROFILE_INJECTION_CANARY.to_string());
    report.evidence = vec![
        "app_running".to_string(),
        EVIDENCE_INJECTION_CANARY.to_string(),
    ];

    for mode in [OutputMode::Human, OutputMode::Json] {
        let rendered = render_report(&report, mode);
        for canary in [
            ACTION_INJECTION_CANARY,
            PROFILE_INJECTION_CANARY,
            EVIDENCE_INJECTION_CANARY,
        ] {
            assert!(!rendered.stdout.contains(canary));
            assert!(!rendered.stderr.contains(canary));
        }
        assert!(rendered.stdout.contains("app_running"));
    }

    let json = render_report(&report, OutputMode::Json);
    let value: Value = serde_json::from_str(json.stdout.trim())
        .expect("sanitized report should remain valid JSON");
    assert_eq!(value["action"], "redacted");
    assert!(value["ui_profile"].is_null());
    assert_eq!(value["evidence"], serde_json::json!(["app_running"]));
}

#[test]
fn refusal_errors_map_to_stable_exit_codes_and_separate_streams() {
    let cases = [
        (UiErrorKind::TargetNotFound, ExitCode::TargetRefused),
        (UiErrorKind::ExistingDraft, ExitCode::InputStateRefused),
        (UiErrorKind::UnknownUiProfile, ExitCode::EnvironmentRefused),
        (UiErrorKind::Timeout, ExitCode::BackendFailure),
    ];

    for (kind, expected_exit) in cases {
        let rendered = render_error(&UiError::new(kind, "synthetic_operation"), OutputMode::Json);
        let value: Value = serde_json::from_str(rendered.stdout.trim())
            .expect("JSON error should remain valid machine output");

        assert_eq!(rendered.exit_code, expected_exit);
        assert_eq!(value["schema_version"], SCHEMA_VERSION);
        assert_eq!(value["status"], "error");
        assert_eq!(value["error"]["code"], kind.code());
        assert_eq!(value["exit_code"], expected_exit.as_i32());
        assert!(!rendered.stdout.contains("windows_ui_error"));
        assert!(rendered.stderr.starts_with("windows_ui_error "));
        assert!(!rendered.stderr.contains('{'));
    }
}

#[test]
fn error_operation_is_closed_and_unknown_values_are_redacted() {
    for mode in [OutputMode::Human, OutputMode::Json] {
        let rendered = render_error(
            &UiError::new(UiErrorKind::Timeout, OPERATION_INJECTION_CANARY),
            mode,
        );
        assert!(!rendered.stdout.contains(OPERATION_INJECTION_CANARY));
        assert!(!rendered.stderr.contains(OPERATION_INJECTION_CANARY));
        assert!(rendered.stderr.contains("operation=redacted_operation"));
        if mode == OutputMode::Json {
            let value: Value = serde_json::from_str(rendered.stdout.trim())
                .expect("redacted error JSON should parse");
            assert_eq!(value["error"]["operation"], "redacted_operation");
        }
    }

    let known = render_error(
        &UiError::new(UiErrorKind::InvalidInput, "policy_validate_message"),
        OutputMode::Json,
    );
    assert!(known.stdout.contains("policy_validate_message"));
    assert!(known.stderr.contains("policy_validate_message"));
}

#[test]
fn indeterminate_is_exit_21_and_never_retry_safe() {
    let error = UiError {
        kind: UiErrorKind::SubmissionUncertain,
        operation: "synthetic_commit",
        retry_safe: true,
    };
    let rendered = render_error(&error, OutputMode::Json);
    let value: Value =
        serde_json::from_str(rendered.stdout.trim()).expect("indeterminate JSON should parse");

    assert_eq!(rendered.exit_code, ExitCode::SubmissionIndeterminate);
    assert_eq!(value["outcome"], "indeterminate");
    assert_eq!(value["retry_safe"], false);

    for outcome in [
        SendOutcome::CommitIssued,
        SendOutcome::SubmittedUnverified,
        SendOutcome::Indeterminate,
    ] {
        let mut report =
            build_action_report(ReportAction::LocalSend, BackendKind::Fake, &safe_snapshot());
        report.schema_version = 99;
        report.outcome = outcome;
        report.attempted = false;
        report.retry_safe = true;
        let normalized = render_report(&report, OutputMode::Json);
        let normalized_value: Value = serde_json::from_str(normalized.stdout.trim())
            .expect("normalized report JSON should parse");

        assert_eq!(normalized.exit_code, ExitCode::SubmissionIndeterminate);
        assert_eq!(normalized_value["schema_version"], SCHEMA_VERSION);
        assert_eq!(normalized_value["attempted"], true);
        assert_eq!(normalized_value["retry_safe"], false);
    }
}
