//! Schema-version-1 redacted rendering for the Windows UI surface.

use serde::Serialize;

use crate::platform::{
    ActionReport, BackendKind, ExitCode, SendOutcome, TargetKind, UiError, UiErrorKind, UiPlatform,
    UiSnapshot,
};

pub const SCHEMA_VERSION: u8 = 1;

const DOCTOR_ACTION: &str = "doctor_ui";
const LOCAL_SEND_ACTION: &str = "local_send";
const REDACTED_ACTION: &str = "redacted";
const REDACTED_OPERATION: &str = "redacted_operation";
const WINDOWS_PROFILE_V1: &str = "kakaotalk_windows_26_7_0_5255";
const SYNTHETIC_PROFILE_V1: &str = "synthetic_windows_profile_v1";
const OPERATION_CODES: &[&str] = &[
    "approved_send_already_claimed",
    "invalid_windows_local_send_options",
    "policy_allowlist_config",
    "policy_allowlist_match",
    "policy_app_snapshot",
    "policy_approval_mutex",
    "policy_authorize_inspect",
    "policy_current_time",
    "policy_dry_run_inspect",
    "policy_execute_mode",
    "policy_input_snapshot",
    "policy_inspect_capability",
    "policy_nonce_replay",
    "policy_send_capability",
    "policy_snapshot_time",
    "policy_target_snapshot",
    "policy_validate_confirmation",
    "policy_validate_message",
    "policy_validate_mode",
    "policy_validate_nonce",
    "read_windows_stdin",
    "windows_commit_not_in_wave_1",
    "windows_com_initialize",
    "windows_config_load",
    "windows_doctor_ui_loco_conflict",
    "windows_enumeration",
    "windows_enumeration_callback",
    "windows_inspect_target",
    "windows_probe_thread_failed",
    "windows_probe_thread_start",
    "windows_process_image",
    "windows_process_image_length",
    "windows_process_open",
    "windows_process_session",
    "windows_read_only_inspect",
    "windows_stage_not_in_wave_1",
    "windows_stdin_invalid_utf8",
    "windows_stdin_too_large",
    "windows_token_integrity",
    "windows_token_integrity_layout",
    "windows_token_integrity_sid",
    "windows_token_integrity_size",
    "windows_token_open",
    "windows_ui_doctor_required",
    "windows_ui_inspect_unavailable",
    "windows_uia_class_condition",
    "windows_uia_composer",
    "windows_uia_composer_class",
    "windows_uia_composer_count",
    "windows_uia_composer_enabled",
    "windows_uia_composer_focus",
    "windows_uia_composer_id",
    "windows_uia_composer_type",
    "windows_uia_create",
    "windows_uia_find_composer",
    "windows_uia_id_condition",
    "windows_uia_selector_condition",
    "windows_uia_selector_validation",
    "windows_uia_type_condition",
    "windows_uia_window",
    "windows_window_changed_during_inspect",
    "windows_window_enabled",
    "windows_write_mode_not_in_wave_1",
];
const EVIDENCE_CODES: &[&str] = &[
    "app_running",
    "app_not_running",
    "process_observed",
    "process_not_observed",
    "interactive_session_match",
    "interactive_session_mismatch",
    "integrity_compatible",
    "integrity_incompatible",
    "ui_profile_known",
    "ui_profile_unknown",
    "top_level_window_absent",
    "top_level_window_unique",
    "top_level_window_ambiguous",
    "modal_absent",
    "modal_present",
    "self_chat_verified",
    "self_chat_unverified",
    "target_exact_match",
    "target_not_exact",
    "target_unique_match",
    "target_not_unique",
    "target_window_observed",
    "target_window_not_observed",
    "composer_fingerprint_observed",
    "composer_fingerprint_not_observed",
    "composer_present",
    "composer_absent",
    "composer_unique",
    "composer_not_unique",
    "composer_enabled",
    "composer_disabled",
    "composer_writable",
    "composer_not_writable",
    "draft_empty",
    "draft_present",
    "composer_focused",
    "composer_not_focused",
    "selector_profile_observed",
    "selector_profile_not_observed",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Human,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportAction {
    UiDoctor,
    LocalSend,
}

impl ReportAction {
    const fn code(self) -> &'static str {
        match self {
            Self::UiDoctor => DOCTOR_ACTION,
            Self::LocalSend => LOCAL_SEND_ACTION,
        }
    }

    const fn outcome(self) -> SendOutcome {
        match self {
            Self::UiDoctor => SendOutcome::NotSubmitted,
            Self::LocalSend => SendOutcome::DryRun,
        }
    }
}

/// Fully separated output streams and process status for root-owned wiring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: ExitCode,
}

/// Builds a report using only fixed codes and snapshot booleans. Process,
/// window, composer, target, message, and draft values are never copied.
pub fn build_action_report(
    action: ReportAction,
    backend: BackendKind,
    snapshot: &UiSnapshot,
) -> ActionReport {
    let outcome = action.outcome();
    ActionReport {
        schema_version: SCHEMA_VERSION,
        action: action.code().to_string(),
        platform: snapshot.app.platform,
        backend,
        ui_profile: safe_profile_id(backend, snapshot),
        target: snapshot.target.kind,
        attempted: outcome.attempted(),
        outcome,
        evidence: redacted_evidence(snapshot),
        retry_safe: outcome.retry_safe(),
    }
}

pub fn render_report(report: &ActionReport, mode: OutputMode) -> RenderedOutput {
    let report = normalized_report(report);
    let exit_code = if report.outcome == SendOutcome::Indeterminate {
        ExitCode::SubmissionIndeterminate
    } else {
        ExitCode::Success
    };

    let stdout = match mode {
        OutputMode::Json => {
            let mut rendered = serde_json::to_string(&report)
                .expect("ActionReport contains only serializable values");
            rendered.push('\n');
            rendered
        }
        OutputMode::Human => render_human_report(&report),
    };

    RenderedOutput {
        stdout,
        stderr: String::new(),
        exit_code,
    }
}

pub fn render_error(error: &UiError, mode: OutputMode) -> RenderedOutput {
    let exit_code = ExitCode::for_error(error.kind);
    let retry_safe = effective_error_retry_safe(error);
    let outcome = error_outcome(error.kind);
    let operation = safe_operation(error.operation);
    let diagnostic = format!(
        "windows_ui_error operation={} code={} outcome={} retry_safe={} exit_code={}\n",
        operation,
        error.kind.code(),
        outcome,
        retry_safe,
        exit_code.as_i32()
    );

    let stdout = match mode {
        OutputMode::Human => String::new(),
        OutputMode::Json => {
            let envelope = ErrorEnvelope {
                schema_version: SCHEMA_VERSION,
                status: "error",
                error: ErrorBody {
                    code: error.kind.code(),
                    operation,
                },
                outcome,
                retry_safe,
                exit_code: exit_code.as_i32(),
            };
            let mut rendered = serde_json::to_string(&envelope)
                .expect("error envelope contains only serializable values");
            rendered.push('\n');
            rendered
        }
    };

    RenderedOutput {
        stdout,
        stderr: diagnostic,
        exit_code,
    }
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    schema_version: u8,
    status: &'static str,
    error: ErrorBody<'a>,
    outcome: &'static str,
    retry_safe: bool,
    exit_code: i32,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'static str,
    operation: &'a str,
}

fn normalized_report(report: &ActionReport) -> ActionReport {
    let mut normalized = report.clone();
    normalized.schema_version = SCHEMA_VERSION;
    normalized.attempted = normalized.outcome.attempted();
    normalized.retry_safe = normalized.outcome.retry_safe();
    normalized.action = match normalized.action.as_str() {
        DOCTOR_ACTION => DOCTOR_ACTION.to_string(),
        LOCAL_SEND_ACTION => LOCAL_SEND_ACTION.to_string(),
        _ => REDACTED_ACTION.to_string(),
    };
    normalized.ui_profile = match normalized.ui_profile.as_deref() {
        Some(WINDOWS_PROFILE_V1) => Some(WINDOWS_PROFILE_V1.to_string()),
        Some(SYNTHETIC_PROFILE_V1) => Some(SYNTHETIC_PROFILE_V1.to_string()),
        _ => None,
    };
    normalized
        .evidence
        .retain(|code| EVIDENCE_CODES.contains(&code.as_str()));
    normalized
}

fn effective_error_retry_safe(error: &UiError) -> bool {
    error.kind != UiErrorKind::SubmissionUncertain && error.retry_safe
}

fn safe_operation(operation: &'static str) -> &'static str {
    if OPERATION_CODES.contains(&operation) {
        operation
    } else {
        REDACTED_OPERATION
    }
}

const fn error_outcome(kind: UiErrorKind) -> &'static str {
    if matches!(kind, UiErrorKind::SubmissionUncertain) {
        "indeterminate"
    } else {
        "not_submitted"
    }
}

fn safe_profile_id(backend: BackendKind, snapshot: &UiSnapshot) -> Option<String> {
    if !snapshot.app.known_ui_profile {
        return None;
    }

    match backend {
        BackendKind::WindowsUia => Some(WINDOWS_PROFILE_V1.to_string()),
        BackendKind::Fake => Some(SYNTHETIC_PROFILE_V1.to_string()),
        BackendKind::MacosAx | BackendKind::Unsupported => None,
    }
}

fn redacted_evidence(snapshot: &UiSnapshot) -> Vec<String> {
    let mut evidence = Vec::with_capacity(19);
    push_state(
        &mut evidence,
        snapshot.app.app_running,
        "app_running",
        "app_not_running",
    );
    push_state(
        &mut evidence,
        snapshot.app.process.is_some(),
        "process_observed",
        "process_not_observed",
    );
    push_state(
        &mut evidence,
        snapshot.app.interactive_session_match,
        "interactive_session_match",
        "interactive_session_mismatch",
    );
    push_state(
        &mut evidence,
        snapshot.app.integrity_compatible,
        "integrity_compatible",
        "integrity_incompatible",
    );
    push_state(
        &mut evidence,
        snapshot.app.known_ui_profile,
        "ui_profile_known",
        "ui_profile_unknown",
    );
    evidence.push(
        match snapshot.app.top_level_window_count {
            0 => "top_level_window_absent",
            1 => "top_level_window_unique",
            _ => "top_level_window_ambiguous",
        }
        .to_string(),
    );
    push_state(
        &mut evidence,
        !snapshot.app.modal_present,
        "modal_absent",
        "modal_present",
    );
    push_state(
        &mut evidence,
        snapshot.target.self_chat_verified,
        "self_chat_verified",
        "self_chat_unverified",
    );
    push_state(
        &mut evidence,
        snapshot.target.exact_match,
        "target_exact_match",
        "target_not_exact",
    );
    push_state(
        &mut evidence,
        snapshot.target.unique_match,
        "target_unique_match",
        "target_not_unique",
    );
    push_state(
        &mut evidence,
        snapshot.target.window.is_some(),
        "target_window_observed",
        "target_window_not_observed",
    );
    push_state(
        &mut evidence,
        snapshot.target.composer.is_some(),
        "composer_fingerprint_observed",
        "composer_fingerprint_not_observed",
    );
    push_state(
        &mut evidence,
        snapshot.input.present,
        "composer_present",
        "composer_absent",
    );
    push_state(
        &mut evidence,
        snapshot.input.unique,
        "composer_unique",
        "composer_not_unique",
    );
    push_state(
        &mut evidence,
        snapshot.input.enabled,
        "composer_enabled",
        "composer_disabled",
    );
    push_state(
        &mut evidence,
        snapshot.input.writable,
        "composer_writable",
        "composer_not_writable",
    );
    push_state(
        &mut evidence,
        snapshot.input.draft_empty,
        "draft_empty",
        "draft_present",
    );
    push_state(
        &mut evidence,
        snapshot.input.focused,
        "composer_focused",
        "composer_not_focused",
    );
    push_state(
        &mut evidence,
        snapshot.input.selector_profile_id.is_some(),
        "selector_profile_observed",
        "selector_profile_not_observed",
    );
    evidence
}

fn push_state(evidence: &mut Vec<String>, state: bool, yes: &'static str, no: &'static str) {
    evidence.push(if state { yes } else { no }.to_string());
}

fn render_human_report(report: &ActionReport) -> String {
    let profile = report.ui_profile.as_deref().unwrap_or("unavailable");
    format!(
        "schema_version: {}\naction: {}\nplatform: {}\nbackend: {}\nui_profile: {}\ntarget: {}\nattempted: {}\noutcome: {}\nevidence: {}\nretry_safe: {}\n",
        report.schema_version,
        report.action,
        platform_code(report.platform),
        backend_code(report.backend),
        profile,
        target_code(report.target),
        report.attempted,
        outcome_code(report.outcome),
        report.evidence.join(","),
        report.retry_safe,
    )
}

const fn platform_code(platform: UiPlatform) -> &'static str {
    match platform {
        UiPlatform::Macos => "macos",
        UiPlatform::Windows => "windows",
        UiPlatform::Unsupported => "unsupported",
    }
}

const fn backend_code(backend: BackendKind) -> &'static str {
    match backend {
        BackendKind::MacosAx => "macos_ax",
        BackendKind::WindowsUia => "windows_uia",
        BackendKind::Fake => "fake",
        BackendKind::Unsupported => "unsupported",
    }
}

const fn target_code(target: TargetKind) -> &'static str {
    match target {
        TargetKind::SelfChat => "self_chat",
        TargetKind::Other => "other",
    }
}

const fn outcome_code(outcome: SendOutcome) -> &'static str {
    match outcome {
        SendOutcome::DryRun => "dry_run",
        SendOutcome::StagedAndRestored => "staged_and_restored",
        SendOutcome::CommitIssued => "commit_issued",
        SendOutcome::EchoConfirmed => "echo_confirmed",
        SendOutcome::SubmittedUnverified => "submitted_unverified",
        SendOutcome::NotSubmitted => "not_submitted",
        SendOutcome::Indeterminate => "indeterminate",
    }
}
