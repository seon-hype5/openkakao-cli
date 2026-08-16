#![cfg(target_os = "windows")]

use std::io::Cursor;
use std::process::Command;

use clap::{Parser, Subcommand};
use openkakao_cli::cli::windows::{prepare_local_send, LocalSendOptions, ReaderMessageInput};
use openkakao_cli::platform::fake::FakeBackend;
use openkakao_cli::platform::{
    AppSnapshot, ChatTargetSnapshot, InputSnapshot, ProcessFingerprint, SendMode, TargetKind,
    UiPlatform, UiSnapshot,
};

const TARGET_CANARY: &str = "SYNTHETIC_SELF_CHAT";
const MESSAGE_CANARY: &str = "SYNTHETIC_MESSAGE";

#[derive(Parser)]
struct Harness {
    #[command(subcommand)]
    command: HarnessCommand,
}

#[derive(Subcommand)]
enum HarnessCommand {
    LocalSend(LocalSendOptions),
}

fn options(extra: &[&str]) -> LocalSendOptions {
    let mut arguments = vec![
        "windows-cli-test",
        "local-send",
        TARGET_CANARY,
        "--stdin",
        "--opened-only",
    ];
    arguments.extend_from_slice(extra);
    match Harness::try_parse_from(arguments)
        .expect("synthetic Windows local-send arguments should parse")
        .command
    {
        HarnessCommand::LocalSend(options) => options,
    }
}

fn snapshot() -> UiSnapshot {
    UiSnapshot {
        app: AppSnapshot {
            platform: UiPlatform::Windows,
            app_running: true,
            process: Some(ProcessFingerprint {
                pid: 7,
                executable: "synthetic-process-fingerprint".to_string(),
                session_id: Some(1),
            }),
            app_version: Some("synthetic-version".to_string()),
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
            window: Some("synthetic-window-fingerprint".to_string()),
            composer: Some("synthetic-composer-fingerprint".to_string()),
            observed_at_unix_ms: 1,
            expires_at_unix_ms: 2,
            target_binding: None,
        },
        input: InputSnapshot {
            present: true,
            unique: true,
            enabled: true,
            writable: true,
            draft_empty: true,
            focused: false,
            selector_profile_id: Some("synthetic-selector".to_string()),
        },
    }
}

#[test]
fn public_cli_seam_defaults_to_a_zero_mutation_dry_run() {
    let options = options(&[]);
    assert_eq!(
        options.mode().expect("mode should validate"),
        SendMode::DryRun
    );

    let backend = FakeBackend::new(snapshot());
    let mut input = ReaderMessageInput::new(Cursor::new(MESSAGE_CANARY.as_bytes()));
    let prepared = prepare_local_send(&options, &mut input, &backend)
        .expect("synthetic dry-run preparation should pass");

    assert_eq!(prepared.snapshot().target.kind, TargetKind::SelfChat);
    assert_eq!(backend.inspect_calls(), 1);
    assert_eq!(backend.stage_calls(), 0);
    assert_eq!(backend.commit_calls(), 0);
}

#[test]
fn rejected_legacy_argv_message_is_not_echoed_by_the_binary() {
    const ARGV_CANARY: &str = "SENSITIVE_ARGV_MESSAGE_CANARY";
    let output = Command::new(env!("CARGO_BIN_EXE_openkakao-cli"))
        .args([
            "local-send",
            TARGET_CANARY,
            ARGV_CANARY,
            "--stdin",
            "--opened-only",
        ])
        .output()
        .expect("binary should start and reject legacy syntax");

    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stdout.contains(ARGV_CANARY));
    assert!(!stderr.contains(ARGV_CANARY));
    assert!(stderr.contains("details redacted"));
}
