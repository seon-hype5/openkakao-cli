//! Platform-independent guard state machine for Windows UI mutations.
//!
//! The approval snapshot is only an expectation. Every fact that authorizes a
//! mutation must also be supplied by a fresh native observation. This module
//! contains no Win32/UIA calls, which lets refusal and uncertainty behavior be
//! exercised without touching a live desktop.

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::platform::{
    ApprovedSend, SendMode, SendOutcome, TargetKind, UiError, UiErrorKind, UiPlatform,
};

use super::ledger::{LedgerRecord, MutationLedger};
use super::{FileVersion, KNOWN_PROFILE_ID};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum DraftState {
    /// The value was deliberately not read, normally because target identity
    /// was not independently established.
    Unobserved,
    Empty,
    ExactMessage,
    Different,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Non-Unconfigured variants are exercised by synthetic selector seams.
pub(super) enum CommitSelectorState {
    Unconfigured,
    Absent,
    Ambiguous,
    UniqueInvokable,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct FreshState {
    pub now_unix_ms: u64,
    pub window_count: usize,
    pub pid: Option<u32>,
    pub executable_fingerprint: Option<String>,
    pub executable_verified: bool,
    pub version: Option<FileVersion>,
    pub session_id: Option<u32>,
    pub interactive_session_match: bool,
    pub integrity_compatible: bool,
    pub known_ui_profile: bool,
    pub window_visible: bool,
    pub window_enabled: bool,
    pub modal_present: bool,
    pub self_chat_verified: bool,
    pub exact_target: bool,
    pub unique_target: bool,
    pub window_fingerprint: Option<String>,
    pub composer_count: usize,
    pub composer_fingerprint: Option<String>,
    pub composer_enabled: bool,
    pub composer_writable: bool,
    pub composer_focused: bool,
    pub user_active: bool,
    pub selector_profile_id: Option<String>,
    pub draft: DraftState,
    pub commit_selector: CommitSelectorState,
}

impl FreshState {
    #[cfg_attr(all(test, not(feature = "windows-ui-write")), allow(dead_code))]
    pub(super) fn unavailable(now_unix_ms: u64, window_count: usize) -> Self {
        Self {
            now_unix_ms,
            window_count,
            pid: None,
            executable_fingerprint: None,
            executable_verified: false,
            version: None,
            session_id: None,
            interactive_session_match: false,
            integrity_compatible: false,
            known_ui_profile: false,
            window_visible: false,
            window_enabled: false,
            modal_present: false,
            self_chat_verified: false,
            exact_target: false,
            unique_target: false,
            window_fingerprint: None,
            composer_count: 0,
            composer_fingerprint: None,
            composer_enabled: false,
            composer_writable: false,
            composer_focused: false,
            user_active: false,
            selector_profile_id: None,
            draft: DraftState::Unobserved,
            commit_selector: CommitSelectorState::Unconfigured,
        }
    }
}

pub(super) struct ExpectedState<'a> {
    pub(super) pid: u32,
    pub(super) executable_fingerprint: &'a str,
    pub(super) version: FileVersion,
    pub(super) session_id: u32,
    pub(super) window_fingerprint: &'a str,
    pub(super) composer_fingerprint: &'a str,
    pub(super) observed_at_unix_ms: u64,
    pub(super) expires_at_unix_ms: u64,
    pub(super) approved_at_unix_ms: u64,
}

impl<'a> ExpectedState<'a> {
    #[cfg_attr(all(test, not(feature = "windows-ui-write")), allow(dead_code))]
    pub(super) fn from_approved(
        approved: &'a ApprovedSend,
        required_mode: SendMode,
        now_unix_ms: u64,
    ) -> Result<Self, UiError> {
        if approved.mode() != required_mode {
            return Err(error(UiErrorKind::InvalidInput, "windows_approval_mode"));
        }
        if approved.target() != TargetKind::SelfChat
            || approved.snapshot().target.kind != TargetKind::SelfChat
        {
            return Err(error(UiErrorKind::TargetNotSelf, "windows_approval_target"));
        }
        if approved.message_len_chars() == 0 {
            return Err(error(UiErrorKind::InvalidInput, "windows_approval_message"));
        }

        let snapshot = approved.snapshot();
        if snapshot.app.platform != UiPlatform::Windows {
            return Err(error(
                UiErrorKind::UnsupportedCapability,
                "windows_approval_platform",
            ));
        }
        if !snapshot.app.app_running {
            return Err(error(
                UiErrorKind::ProcessNotFound,
                "windows_approval_process",
            ));
        }
        match snapshot.app.top_level_window_count {
            0 => {
                return Err(error(
                    UiErrorKind::TargetNotFound,
                    "windows_approval_window",
                ))
            }
            1 => {}
            _ => {
                return Err(error(
                    UiErrorKind::AmbiguousTarget,
                    "windows_approval_window",
                ))
            }
        }
        let process = snapshot
            .app
            .process
            .as_ref()
            .ok_or_else(|| error(UiErrorKind::ProcessNotFound, "windows_approval_process"))?;
        if process.pid == 0 || !is_run_fingerprint(&process.executable) {
            return Err(error(UiErrorKind::InvalidInput, "windows_approval_process"));
        }
        let session_id = process.session_id.ok_or_else(|| {
            error(
                UiErrorKind::SessionMismatch,
                "windows_approval_process_session",
            )
        })?;
        if !snapshot.app.interactive_session_match {
            return Err(error(
                UiErrorKind::SessionMismatch,
                "windows_approval_process_session",
            ));
        }
        if !snapshot.app.integrity_compatible {
            return Err(error(
                UiErrorKind::IntegrityMismatch,
                "windows_approval_integrity",
            ));
        }
        if !snapshot.app.known_ui_profile
            || snapshot.app.app_version.as_deref() != Some("26.7.0.5255")
        {
            return Err(error(
                UiErrorKind::UnknownUiProfile,
                "windows_approval_profile",
            ));
        }
        if snapshot.app.modal_present {
            return Err(error(UiErrorKind::ModalPresent, "windows_approval_modal"));
        }
        if !snapshot.target.self_chat_verified
            || !snapshot.target.exact_match
            || !snapshot.target.unique_match
        {
            return Err(error(
                UiErrorKind::TargetNotSelf,
                "windows_approval_target_identity",
            ));
        }
        let window_fingerprint = snapshot
            .target
            .window
            .as_deref()
            .filter(|value| is_run_fingerprint(value))
            .ok_or_else(|| {
                error(
                    UiErrorKind::InvalidInput,
                    "windows_approval_window_identity",
                )
            })?;
        let composer_fingerprint = snapshot
            .target
            .composer
            .as_deref()
            .filter(|value| is_run_fingerprint(value))
            .ok_or_else(|| {
                error(
                    UiErrorKind::InvalidInput,
                    "windows_approval_composer_identity",
                )
            })?;

        let input = &snapshot.input;
        if !input.present {
            return Err(error(
                UiErrorKind::ComposerNotFound,
                "windows_approval_composer",
            ));
        }
        if !input.unique {
            return Err(error(
                UiErrorKind::AmbiguousComposer,
                "windows_approval_composer",
            ));
        }
        if !input.enabled || !input.writable {
            return Err(error(
                UiErrorKind::PermissionDenied,
                "windows_approval_composer_writable",
            ));
        }
        if !input.draft_empty {
            return Err(error(UiErrorKind::ExistingDraft, "windows_approval_draft"));
        }
        if input.focused {
            return Err(error(UiErrorKind::UserActive, "windows_approval_focus"));
        }
        if input.selector_profile_id.as_deref() != Some(KNOWN_PROFILE_ID) {
            return Err(error(
                UiErrorKind::UnknownUiProfile,
                "windows_approval_selector_profile",
            ));
        }

        let observed_at_unix_ms = snapshot.target.observed_at_unix_ms;
        let expires_at_unix_ms = snapshot.target.expires_at_unix_ms;
        let approved_at_unix_ms = approved.approved_at_unix_ms();
        if observed_at_unix_ms > approved_at_unix_ms
            || approved_at_unix_ms > expires_at_unix_ms
            || now_unix_ms < observed_at_unix_ms
            || now_unix_ms >= expires_at_unix_ms
        {
            return Err(error(
                UiErrorKind::StaleSnapshot,
                "windows_approval_staleness",
            ));
        }

        Ok(Self {
            pid: process.pid,
            executable_fingerprint: &process.executable,
            version: FileVersion::KNOWN,
            session_id,
            window_fingerprint,
            composer_fingerprint,
            observed_at_unix_ms,
            expires_at_unix_ms,
            approved_at_unix_ms,
        })
    }
}

pub(super) trait ExecutionClaim {
    fn try_claim(&self) -> Result<(), UiError>;
}

impl ExecutionClaim for ApprovedSend {
    fn try_claim(&self) -> Result<(), UiError> {
        self.try_claim_execution()
    }
}

pub(super) trait MutationPort: MutationLedger {
    fn observe(&mut self, expected_message_utf16: &[u16]) -> Result<FreshState, UiError>;
    fn prepare_set_value(&mut self, value_utf16: &[u16]) -> Result<(), UiError>;
    fn set_value(&mut self, value_utf16: &[u16]) -> Result<(), UiError>;
    fn prepare_invoke(&mut self) -> Result<(), UiError>;
    fn invoke_verified(&mut self) -> Result<(), UiError>;
}

pub(super) fn run_stage<C: ExecutionClaim, P: MutationPort>(
    expected: &ExpectedState<'_>,
    message_utf16: &[u16],
    claim: &C,
    port: &mut P,
) -> Result<SendOutcome, UiError> {
    port.ensure_clear()?;
    let before = port.observe(message_utf16)?;
    validate_fresh(expected, &before, DraftState::Empty, false)?;

    let stage_record = port.begin_stage()?;
    if let Err(preflight_error) = port.prepare_set_value(message_utf16) {
        return match port.resolve_restored_stage(stage_record) {
            Ok(()) => Err(preflight_error),
            Err(ledger_error) => Err(ledger_error),
        };
    }
    if let Err(claim_error) = claim.try_claim() {
        return match port.resolve_restored_stage(stage_record) {
            Ok(()) => Err(claim_error),
            Err(ledger_error) => Err(ledger_error),
        };
    }
    let correlation = stage_record.correlation();

    // From the first SetValue entry onward, a returned error or panic cannot
    // prove that the provider made no change. Normalize the entire remainder
    // of the transaction to a fixed, non-retryable uncertainty boundary.
    match catch_unwind(AssertUnwindSafe(|| {
        run_stage_after_claim(expected, message_utf16, port, stage_record)
    })) {
        Ok(Ok(outcome)) => Ok(outcome),
        Ok(Err(_)) | Err(_) => {
            let _ = port.mark_indeterminate(correlation);
            Err(post_set_value_error(SendMode::StageOnly))
        }
    }
}

fn run_stage_after_claim<P: MutationPort>(
    expected: &ExpectedState<'_>,
    message_utf16: &[u16],
    port: &mut P,
    stage_record: LedgerRecord,
) -> Result<SendOutcome, UiError> {
    let stage_error = port.set_value(message_utf16).err();
    let staged = match port.observe(message_utf16) {
        Ok(state) => state,
        Err(observe_error) => return Err(stage_error.unwrap_or(observe_error)),
    };
    if let Err(validation_error) =
        validate_fresh(expected, &staged, DraftState::ExactMessage, false)
    {
        return Err(stage_error.unwrap_or(validation_error));
    }

    // Clear only after the fresh observation proves that the exact value is
    // still ours and every window/composer/target invariant still holds.
    port.prepare_set_value(&[])?;
    port.set_value(&[])?;
    let restored = port.observe(message_utf16)?;
    validate_fresh(expected, &restored, DraftState::Empty, false)?;
    port.resolve_restored_stage(stage_record)?;

    if let Some(stage_error) = stage_error {
        Err(stage_error)
    } else {
        Ok(SendOutcome::StagedAndRestored)
    }
}

pub(super) fn run_commit<C: ExecutionClaim, P: MutationPort>(
    expected: &ExpectedState<'_>,
    message_utf16: &[u16],
    claim: &C,
    port: &mut P,
) -> Result<SendOutcome, UiError> {
    port.ensure_clear()?;
    let before = port.observe(message_utf16)?;
    validate_fresh(expected, &before, DraftState::Empty, true)?;

    let stage_record = port.begin_stage()?;
    if let Err(preflight_error) = port.prepare_set_value(message_utf16) {
        return match port.resolve_restored_stage(stage_record) {
            Ok(()) => Err(preflight_error),
            Err(ledger_error) => Err(ledger_error),
        };
    }
    if let Err(claim_error) = claim.try_claim() {
        return match port.resolve_restored_stage(stage_record) {
            Ok(()) => Err(claim_error),
            Err(ledger_error) => Err(ledger_error),
        };
    }
    let correlation = stage_record.correlation();

    match catch_unwind(AssertUnwindSafe(|| {
        run_commit_after_claim(expected, message_utf16, port, stage_record)
    })) {
        Ok(Ok(outcome)) => Ok(outcome),
        Ok(Err(error)) if error.kind == UiErrorKind::SubmissionUncertain => Err(error),
        Ok(Err(_)) | Err(_) => {
            let _ = port.mark_indeterminate(correlation);
            Err(post_set_value_error(SendMode::Commit))
        }
    }
}

fn run_commit_after_claim<P: MutationPort>(
    expected: &ExpectedState<'_>,
    message_utf16: &[u16],
    port: &mut P,
    stage_record: LedgerRecord,
) -> Result<SendOutcome, UiError> {
    let stage_error = port.set_value(message_utf16).err();
    let staged = match port.observe(message_utf16) {
        Ok(state) => state,
        Err(observe_error) => return Err(stage_error.unwrap_or(observe_error)),
    };

    let commit_validation = validate_fresh(expected, &staged, DraftState::ExactMessage, true);
    if let Some(stage_error) = stage_error {
        restore_if_proven_owned(expected, message_utf16, port, &staged)?;
        port.resolve_restored_stage(stage_record)?;
        return Err(stage_error);
    }
    if let Err(validation_error) = commit_validation {
        // A disappearing send selector is safe to recover from only when all
        // non-selector state still proves that the staged value is ours.
        restore_if_proven_owned(expected, message_utf16, port, &staged)?;
        port.resolve_restored_stage(stage_record)?;
        return Err(validation_error);
    }

    // Persist the commit boundary before the final native Invoke preflight.
    // Any failure from this point leaves a blocking record; it is never
    // automatically removed even when the exact staged value is restored.
    let commit_record = match port.mark_commit(stage_record) {
        Ok(record) => record,
        Err(ledger_error) => {
            let _ = restore_if_proven_owned(expected, message_utf16, port, &staged);
            return Err(ledger_error);
        }
    };

    if let Err(preflight_error) = port.prepare_invoke() {
        let _ = restore_if_proven_owned(expected, message_utf16, port, &staged);
        return Err(preflight_error);
    }

    // There is exactly one submission call and no retry. Any returned error or
    // panic after entry is uncertain because the provider may have acted. The
    // durable record remains terminal even after an apparently successful call.
    let invoke_result = catch_unwind(AssertUnwindSafe(|| port.invoke_verified()));
    let ledger_result = port.mark_indeterminate(commit_record.correlation());
    if ledger_result.is_err() {
        return Err(error(
            UiErrorKind::SubmissionUncertain,
            "windows_commit_invoke_uncertain",
        ));
    }
    match invoke_result {
        Ok(Ok(())) => Ok(SendOutcome::CommitIssued),
        Ok(Err(_)) | Err(_) => Err(error(
            UiErrorKind::SubmissionUncertain,
            "windows_commit_invoke_uncertain",
        )),
    }
}

fn post_set_value_error(mode: SendMode) -> UiError {
    let operation = match mode {
        SendMode::StageOnly => "windows_stage_after_set_value_uncertain",
        SendMode::Commit => "windows_commit_after_set_value_uncertain",
        SendMode::DryRun => "windows_write_after_set_value_uncertain",
    };
    error(UiErrorKind::SubmissionUncertain, operation)
}

fn restore_if_proven_owned<P: MutationPort>(
    expected: &ExpectedState<'_>,
    message_utf16: &[u16],
    port: &mut P,
    staged: &FreshState,
) -> Result<(), UiError> {
    // This deliberately ignores only commit-selector state. Any target,
    // process, focus, modal, fingerprint, or draft mismatch prevents clearing.
    validate_fresh(expected, staged, DraftState::ExactMessage, false)?;
    port.prepare_set_value(&[])?;
    port.set_value(&[])?;
    let restored = port.observe(message_utf16)?;
    validate_fresh(expected, &restored, DraftState::Empty, false)
}

fn validate_fresh(
    expected: &ExpectedState<'_>,
    fresh: &FreshState,
    required_draft: DraftState,
    require_commit_selector: bool,
) -> Result<(), UiError> {
    if fresh.now_unix_ms < expected.observed_at_unix_ms
        || fresh.now_unix_ms < expected.approved_at_unix_ms
        || fresh.now_unix_ms >= expected.expires_at_unix_ms
    {
        return Err(error(UiErrorKind::StaleSnapshot, "windows_fresh_staleness"));
    }
    match fresh.window_count {
        0 => return Err(error(UiErrorKind::TargetNotFound, "windows_fresh_window")),
        1 => {}
        _ => return Err(error(UiErrorKind::AmbiguousTarget, "windows_fresh_window")),
    }
    if fresh.pid != Some(expected.pid) {
        return Err(error(
            UiErrorKind::StaleSnapshot,
            "windows_fresh_process_identity",
        ));
    }
    if !fresh.executable_verified
        || fresh.executable_fingerprint.as_deref() != Some(expected.executable_fingerprint)
    {
        return Err(error(
            UiErrorKind::StaleSnapshot,
            "windows_fresh_executable_identity",
        ));
    }
    if fresh.session_id != Some(expected.session_id) || !fresh.interactive_session_match {
        return Err(error(
            UiErrorKind::SessionMismatch,
            "windows_fresh_process_session",
        ));
    }
    if !fresh.integrity_compatible {
        return Err(error(
            UiErrorKind::IntegrityMismatch,
            "windows_fresh_integrity",
        ));
    }
    if !fresh.known_ui_profile || fresh.version != Some(expected.version) {
        return Err(error(
            UiErrorKind::UnknownUiProfile,
            "windows_fresh_profile",
        ));
    }
    if !fresh.window_visible || !fresh.window_enabled {
        return Err(error(
            UiErrorKind::TargetNotFound,
            "windows_fresh_window_state",
        ));
    }
    if fresh.modal_present {
        return Err(error(UiErrorKind::ModalPresent, "windows_fresh_modal"));
    }
    if !fresh.self_chat_verified || !fresh.exact_target || !fresh.unique_target {
        return Err(error(
            UiErrorKind::TargetNotSelf,
            "windows_fresh_target_identity",
        ));
    }
    if fresh.window_fingerprint.as_deref() != Some(expected.window_fingerprint) {
        return Err(error(
            UiErrorKind::StaleSnapshot,
            "windows_fresh_window_identity",
        ));
    }
    match fresh.composer_count {
        0 => {
            return Err(error(
                UiErrorKind::ComposerNotFound,
                "windows_fresh_composer",
            ))
        }
        1 => {}
        _ => {
            return Err(error(
                UiErrorKind::AmbiguousComposer,
                "windows_fresh_composer",
            ))
        }
    }
    if fresh.composer_fingerprint.as_deref() != Some(expected.composer_fingerprint) {
        return Err(error(
            UiErrorKind::StaleSnapshot,
            "windows_fresh_composer_identity",
        ));
    }
    if !fresh.composer_enabled || !fresh.composer_writable {
        return Err(error(
            UiErrorKind::PermissionDenied,
            "windows_fresh_composer_writable",
        ));
    }
    if fresh.composer_focused || fresh.user_active {
        return Err(error(UiErrorKind::UserActive, "windows_fresh_user_active"));
    }
    if fresh.selector_profile_id.as_deref() != Some(KNOWN_PROFILE_ID) {
        return Err(error(
            UiErrorKind::UnknownUiProfile,
            "windows_fresh_selector_profile",
        ));
    }
    if fresh.draft != required_draft {
        return Err(error(
            UiErrorKind::ExistingDraft,
            "windows_fresh_draft_state",
        ));
    }
    if require_commit_selector {
        let (kind, operation) = match fresh.commit_selector {
            CommitSelectorState::UniqueInvokable => return Ok(()),
            CommitSelectorState::Unconfigured => (
                UiErrorKind::UnsupportedCapability,
                "windows_commit_selector_unconfigured",
            ),
            CommitSelectorState::Absent => (
                UiErrorKind::ComposerNotFound,
                "windows_commit_selector_absent",
            ),
            CommitSelectorState::Ambiguous => (
                UiErrorKind::AmbiguousComposer,
                "windows_commit_selector_ambiguous",
            ),
        };
        return Err(error(kind, operation));
    }
    Ok(())
}

#[cfg_attr(all(test, not(feature = "windows-ui-write")), allow(dead_code))]
fn is_run_fingerprint(value: &str) -> bool {
    value.starts_with("run:") && value.len() > "run:".len()
}

const fn error(kind: UiErrorKind, operation: &'static str) -> UiError {
    UiError::new(kind, operation)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::VecDeque;

    use super::super::ledger::{
        DurableLedgerStore, LedgerController, LedgerStoreError, RecordCorrelation,
    };
    use super::*;

    const MESSAGE: &[u16] = &[0x0043, 0x0041, 0x004E, 0x0041, 0x0052, 0x0059];

    struct FakeClaim {
        calls: Cell<usize>,
        result: Result<(), UiError>,
    }

    impl FakeClaim {
        fn accepting() -> Self {
            Self {
                calls: Cell::new(0),
                result: Ok(()),
            }
        }
    }

    impl ExecutionClaim for FakeClaim {
        fn try_claim(&self) -> Result<(), UiError> {
            self.calls.set(self.calls.get() + 1);
            self.result.clone()
        }
    }

    #[derive(Default)]
    struct FakeLedgerStore {
        record: Option<LedgerRecord>,
    }

    impl DurableLedgerStore for FakeLedgerStore {
        fn load(&mut self) -> Result<Option<LedgerRecord>, LedgerStoreError> {
            Ok(self.record)
        }

        fn durable_replace(
            &mut self,
            expected: Option<LedgerRecord>,
            next: LedgerRecord,
        ) -> Result<(), LedgerStoreError> {
            if self.record != expected {
                return Err(LedgerStoreError::InvalidRecord);
            }
            self.record = Some(next);
            Ok(())
        }

        fn durable_remove(&mut self, expected: LedgerRecord) -> Result<(), LedgerStoreError> {
            if self.record != Some(expected) {
                return Err(LedgerStoreError::InvalidRecord);
            }
            self.record = None;
            Ok(())
        }
    }

    struct FakePort {
        ledger: LedgerController<FakeLedgerStore>,
        ledger_preflight_error: Option<UiError>,
        ledger_begin_error: Option<UiError>,
        ledger_commit_error: Option<UiError>,
        ledger_indeterminate_error: Option<UiError>,
        ledger_resolve_error: Option<UiError>,
        ledger_preflight_calls: usize,
        ledger_begin_calls: usize,
        ledger_commit_calls: usize,
        ledger_indeterminate_calls: usize,
        ledger_resolve_calls: usize,
        states: VecDeque<Result<FreshState, UiError>>,
        set_results: VecDeque<Result<(), UiError>>,
        prepare_set_results: VecDeque<Result<(), UiError>>,
        prepare_invoke_result: Result<(), UiError>,
        invoke_result: Result<(), UiError>,
        panic_on_observe_call: Option<usize>,
        panic_on_prepare_invoke: bool,
        panic_on_invoke: bool,
        observe_calls: usize,
        prepare_set_calls: usize,
        set_calls: usize,
        clear_calls: usize,
        prepare_invoke_calls: usize,
        invoke_calls: usize,
        events: Vec<&'static str>,
    }

    impl FakePort {
        fn with_states(states: impl IntoIterator<Item = FreshState>) -> Self {
            Self {
                ledger: LedgerController::new(
                    FakeLedgerStore::default(),
                    RecordCorrelation::from_bytes([0x5A; 16]).unwrap(),
                ),
                ledger_preflight_error: None,
                ledger_begin_error: None,
                ledger_commit_error: None,
                ledger_indeterminate_error: None,
                ledger_resolve_error: None,
                ledger_preflight_calls: 0,
                ledger_begin_calls: 0,
                ledger_commit_calls: 0,
                ledger_indeterminate_calls: 0,
                ledger_resolve_calls: 0,
                states: states.into_iter().map(Ok).collect(),
                set_results: VecDeque::new(),
                prepare_set_results: VecDeque::new(),
                prepare_invoke_result: Ok(()),
                invoke_result: Ok(()),
                panic_on_observe_call: None,
                panic_on_prepare_invoke: false,
                panic_on_invoke: false,
                observe_calls: 0,
                prepare_set_calls: 0,
                set_calls: 0,
                clear_calls: 0,
                prepare_invoke_calls: 0,
                invoke_calls: 0,
                events: Vec::new(),
            }
        }

        fn assert_no_mutation(&self) {
            assert_eq!(self.set_calls, 0);
            assert_eq!(self.clear_calls, 0);
            assert_eq!(self.invoke_calls, 0);
        }
    }

    impl MutationLedger for FakePort {
        fn ensure_clear(&mut self) -> Result<(), UiError> {
            self.events.push("ledger_preflight");
            self.ledger_preflight_calls += 1;
            if let Some(error) = self.ledger_preflight_error.take() {
                return Err(error);
            }
            self.ledger.ensure_clear()
        }

        fn begin_stage(&mut self) -> Result<LedgerRecord, UiError> {
            self.events.push("ledger_stage");
            self.ledger_begin_calls += 1;
            if let Some(error) = self.ledger_begin_error.take() {
                return Err(error);
            }
            self.ledger.begin_stage()
        }

        fn mark_commit(&mut self, stage: LedgerRecord) -> Result<LedgerRecord, UiError> {
            self.events.push("ledger_commit");
            self.ledger_commit_calls += 1;
            if let Some(error) = self.ledger_commit_error.take() {
                return Err(error);
            }
            self.ledger.mark_commit(stage)
        }

        fn mark_indeterminate(
            &mut self,
            correlation: RecordCorrelation,
        ) -> Result<LedgerRecord, UiError> {
            self.events.push("ledger_indeterminate");
            self.ledger_indeterminate_calls += 1;
            if let Some(error) = self.ledger_indeterminate_error.take() {
                return Err(error);
            }
            self.ledger.mark_indeterminate(correlation)
        }

        fn resolve_restored_stage(&mut self, stage: LedgerRecord) -> Result<(), UiError> {
            self.events.push("ledger_resolve");
            self.ledger_resolve_calls += 1;
            if let Some(error) = self.ledger_resolve_error.take() {
                return Err(error);
            }
            self.ledger.resolve_restored_stage(stage)
        }
    }

    impl MutationPort for FakePort {
        fn observe(&mut self, _expected_message_utf16: &[u16]) -> Result<FreshState, UiError> {
            self.events.push("observe");
            self.observe_calls += 1;
            if self.panic_on_observe_call == Some(self.observe_calls) {
                panic!("synthetic post-SetValue provider panic");
            }
            self.states
                .pop_front()
                .expect("synthetic observation must be queued")
        }

        fn prepare_set_value(&mut self, value_utf16: &[u16]) -> Result<(), UiError> {
            self.events.push(if value_utf16.is_empty() {
                "prepare_clear"
            } else {
                "prepare_set"
            });
            if !value_utf16.is_empty() {
                assert_eq!(value_utf16, MESSAGE);
            }
            self.prepare_set_calls += 1;
            self.prepare_set_results.pop_front().unwrap_or(Ok(()))
        }

        fn set_value(&mut self, value_utf16: &[u16]) -> Result<(), UiError> {
            if value_utf16.is_empty() {
                self.events.push("clear");
                self.clear_calls += 1;
            } else {
                self.events.push("set");
                assert_eq!(value_utf16, MESSAGE);
                self.set_calls += 1;
            }
            self.set_results.pop_front().unwrap_or(Ok(()))
        }

        fn prepare_invoke(&mut self) -> Result<(), UiError> {
            self.events.push("prepare_invoke");
            self.prepare_invoke_calls += 1;
            if self.panic_on_prepare_invoke {
                panic!("synthetic final Invoke preflight panic");
            }
            self.prepare_invoke_result.clone()
        }

        fn invoke_verified(&mut self) -> Result<(), UiError> {
            self.events.push("invoke");
            self.invoke_calls += 1;
            if self.panic_on_invoke {
                panic!("synthetic Invoke provider panic");
            }
            self.invoke_result.clone()
        }
    }

    fn expected() -> ExpectedState<'static> {
        ExpectedState {
            pid: 42,
            executable_fingerprint: "run:process",
            version: FileVersion::KNOWN,
            session_id: 7,
            window_fingerprint: "run:window",
            composer_fingerprint: "run:composer",
            observed_at_unix_ms: 100,
            expires_at_unix_ms: 500,
            approved_at_unix_ms: 110,
        }
    }

    fn valid(draft: DraftState) -> FreshState {
        FreshState {
            now_unix_ms: 120,
            window_count: 1,
            pid: Some(42),
            executable_fingerprint: Some("run:process".to_string()),
            executable_verified: true,
            version: Some(FileVersion::KNOWN),
            session_id: Some(7),
            interactive_session_match: true,
            integrity_compatible: true,
            known_ui_profile: true,
            window_visible: true,
            window_enabled: true,
            modal_present: false,
            self_chat_verified: true,
            exact_target: true,
            unique_target: true,
            window_fingerprint: Some("run:window".to_string()),
            composer_count: 1,
            composer_fingerprint: Some("run:composer".to_string()),
            composer_enabled: true,
            composer_writable: true,
            composer_focused: false,
            user_active: false,
            selector_profile_id: Some(KNOWN_PROFILE_ID.to_string()),
            draft,
            commit_selector: CommitSelectorState::UniqueInvokable,
        }
    }

    #[derive(Clone, Copy)]
    enum Refusal {
        Expired,
        WindowAbsent,
        WindowAmbiguous,
        PidChanged,
        ExecutableChanged,
        SessionChanged,
        IntegrityChanged,
        ProfileChanged,
        WindowHidden,
        WindowDisabled,
        Modal,
        SelfUnverified,
        TargetInexact,
        TargetAmbiguous,
        WindowChanged,
        ComposerAbsent,
        ComposerAmbiguous,
        ComposerChanged,
        ComposerDisabled,
        ComposerReadOnly,
        ComposerFocused,
        UserActive,
        SelectorProfileChanged,
        ExistingDraft,
    }

    fn refused_state(refusal: Refusal) -> FreshState {
        let mut state = valid(DraftState::Empty);
        match refusal {
            Refusal::Expired => state.now_unix_ms = 500,
            Refusal::WindowAbsent => state.window_count = 0,
            Refusal::WindowAmbiguous => state.window_count = 2,
            Refusal::PidChanged => state.pid = Some(43),
            Refusal::ExecutableChanged => {
                state.executable_fingerprint = Some("run:other-process".to_string())
            }
            Refusal::SessionChanged => state.session_id = Some(8),
            Refusal::IntegrityChanged => state.integrity_compatible = false,
            Refusal::ProfileChanged => state.version = None,
            Refusal::WindowHidden => state.window_visible = false,
            Refusal::WindowDisabled => state.window_enabled = false,
            Refusal::Modal => state.modal_present = true,
            Refusal::SelfUnverified => state.self_chat_verified = false,
            Refusal::TargetInexact => state.exact_target = false,
            Refusal::TargetAmbiguous => state.unique_target = false,
            Refusal::WindowChanged => {
                state.window_fingerprint = Some("run:other-window".to_string())
            }
            Refusal::ComposerAbsent => state.composer_count = 0,
            Refusal::ComposerAmbiguous => state.composer_count = 2,
            Refusal::ComposerChanged => {
                state.composer_fingerprint = Some("run:other-composer".to_string())
            }
            Refusal::ComposerDisabled => state.composer_enabled = false,
            Refusal::ComposerReadOnly => state.composer_writable = false,
            Refusal::ComposerFocused => state.composer_focused = true,
            Refusal::UserActive => state.user_active = true,
            Refusal::SelectorProfileChanged => {
                state.selector_profile_id = Some("synthetic-other-profile".to_string())
            }
            Refusal::ExistingDraft => state.draft = DraftState::Different,
        }
        state
    }

    #[test]
    fn every_fresh_precondition_refusal_has_zero_mutations() {
        let refusals = [
            Refusal::Expired,
            Refusal::WindowAbsent,
            Refusal::WindowAmbiguous,
            Refusal::PidChanged,
            Refusal::ExecutableChanged,
            Refusal::SessionChanged,
            Refusal::IntegrityChanged,
            Refusal::ProfileChanged,
            Refusal::WindowHidden,
            Refusal::WindowDisabled,
            Refusal::Modal,
            Refusal::SelfUnverified,
            Refusal::TargetInexact,
            Refusal::TargetAmbiguous,
            Refusal::WindowChanged,
            Refusal::ComposerAbsent,
            Refusal::ComposerAmbiguous,
            Refusal::ComposerChanged,
            Refusal::ComposerDisabled,
            Refusal::ComposerReadOnly,
            Refusal::ComposerFocused,
            Refusal::UserActive,
            Refusal::SelectorProfileChanged,
            Refusal::ExistingDraft,
        ];

        for refusal in refusals {
            let claim = FakeClaim::accepting();
            let mut port = FakePort::with_states([refused_state(refusal)]);
            assert!(run_stage(&expected(), MESSAGE, &claim, &mut port).is_err());
            assert_eq!(claim.calls.get(), 0);
            port.assert_no_mutation();
        }
    }

    #[test]
    fn forged_approval_cannot_replace_fresh_self_target_evidence() {
        // `expected` represents an approval whose public booleans were all set
        // true. The live port independently reports that self-chat identity is
        // unverified, exactly as the current production observer must.
        let claim = FakeClaim::accepting();
        let mut fresh = valid(DraftState::Empty);
        fresh.self_chat_verified = false;
        fresh.exact_target = false;
        fresh.unique_target = false;
        fresh.draft = DraftState::Unobserved;
        let mut port = FakePort::with_states([fresh]);

        let error = run_stage(&expected(), MESSAGE, &claim, &mut port).unwrap_err();
        assert_eq!(error.kind, UiErrorKind::TargetNotSelf);
        assert_eq!(claim.calls.get(), 0);
        port.assert_no_mutation();
    }

    #[test]
    fn exact_expiry_refuses_before_claim_or_mutation() {
        let claim = FakeClaim::accepting();
        let mut fresh = valid(DraftState::Empty);
        fresh.now_unix_ms = expected().expires_at_unix_ms;
        let mut port = FakePort::with_states([fresh]);

        let error = run_stage(&expected(), MESSAGE, &claim, &mut port).unwrap_err();
        assert_eq!(error.kind, UiErrorKind::StaleSnapshot);
        assert_eq!(claim.calls.get(), 0);
        port.assert_no_mutation();
    }

    #[test]
    fn stage_sets_reads_back_exact_and_restores_once() {
        let claim = FakeClaim::accepting();
        let mut port = FakePort::with_states([
            valid(DraftState::Empty),
            valid(DraftState::ExactMessage),
            valid(DraftState::Empty),
        ]);

        assert_eq!(
            run_stage(&expected(), MESSAGE, &claim, &mut port).unwrap(),
            SendOutcome::StagedAndRestored
        );
        assert_eq!(claim.calls.get(), 1);
        assert_eq!(port.set_calls, 1);
        assert_eq!(port.clear_calls, 1);
        assert_eq!(port.invoke_calls, 0);
        assert_eq!(port.ledger_begin_calls, 1);
        assert_eq!(port.ledger_resolve_calls, 1);
        assert_eq!(port.ledger_indeterminate_calls, 0);
        assert_eq!(
            port.events,
            [
                "ledger_preflight",
                "observe",
                "ledger_stage",
                "prepare_set",
                "set",
                "observe",
                "prepare_clear",
                "clear",
                "observe",
                "ledger_resolve",
            ]
        );
    }

    #[test]
    fn stage_never_clears_a_changed_draft() {
        let claim = FakeClaim::accepting();
        let mut port =
            FakePort::with_states([valid(DraftState::Empty), valid(DraftState::Different)]);

        let error = run_stage(&expected(), MESSAGE, &claim, &mut port).unwrap_err();
        assert_eq!(error.kind, UiErrorKind::SubmissionUncertain);
        assert!(!error.retry_safe);
        assert_eq!(port.set_calls, 1);
        assert_eq!(port.clear_calls, 0);
        assert_eq!(port.invoke_calls, 0);
    }

    #[test]
    fn rejected_one_shot_claim_prevents_all_mutation() {
        let claim = FakeClaim {
            calls: Cell::new(0),
            result: Err(error(
                UiErrorKind::InvalidInput,
                "approved_send_already_claimed",
            )),
        };
        let mut port = FakePort::with_states([valid(DraftState::Empty)]);

        assert!(run_stage(&expected(), MESSAGE, &claim, &mut port).is_err());
        assert_eq!(claim.calls.get(), 1);
        port.assert_no_mutation();
        assert_eq!(port.ledger_begin_calls, 1);
        assert_eq!(port.ledger_resolve_calls, 1);
        assert_eq!(port.ledger_indeterminate_calls, 0);
    }

    #[test]
    fn unavailable_ledger_refuses_before_claim_or_ui_mutation() {
        let claim = FakeClaim::accepting();
        let mut port = FakePort::with_states([valid(DraftState::Empty)]);
        port.ledger_preflight_error = Some(error(
            UiErrorKind::UnsupportedCapability,
            "windows_ledger_unavailable",
        ));

        let refusal = run_stage(&expected(), MESSAGE, &claim, &mut port).unwrap_err();
        assert_eq!(refusal.kind, UiErrorKind::UnsupportedCapability);
        assert_eq!(refusal.operation, "windows_ledger_unavailable");
        assert_eq!(claim.calls.get(), 0);
        assert_eq!(port.ledger_preflight_calls, 1);
        assert_eq!(port.ledger_begin_calls, 0);
        assert_eq!(port.observe_calls, 0);
        assert_eq!(port.prepare_set_calls, 0);
        assert_eq!(port.events, ["ledger_preflight"]);
        port.assert_no_mutation();
    }

    #[test]
    fn existing_ledger_refuses_before_any_ui_observation() {
        let claim = FakeClaim::accepting();
        let mut port = FakePort::with_states([valid(DraftState::Empty)]);
        port.ledger
            .begin_stage()
            .expect("synthetic prior process marker");

        let refusal = run_stage(&expected(), MESSAGE, &claim, &mut port).unwrap_err();
        assert_eq!(refusal.kind, UiErrorKind::SubmissionUncertain);
        assert_eq!(refusal.operation, "windows_ledger_existing");
        assert!(!refusal.retry_safe);
        assert_eq!(claim.calls.get(), 0);
        assert_eq!(port.ledger_preflight_calls, 1);
        assert_eq!(port.observe_calls, 0);
        assert_eq!(port.events, ["ledger_preflight"]);
        port.assert_no_mutation();
    }

    #[test]
    fn final_native_preflight_refusal_does_not_claim_or_mutate() {
        let claim = FakeClaim::accepting();
        let mut port = FakePort::with_states([valid(DraftState::Empty)]);
        port.prepare_set_results.push_back(Err(error(
            UiErrorKind::StaleSnapshot,
            "synthetic_process_recycled",
        )));

        let error = run_stage(&expected(), MESSAGE, &claim, &mut port).unwrap_err();
        assert_eq!(error.kind, UiErrorKind::StaleSnapshot);
        assert_eq!(claim.calls.get(), 0);
        assert_eq!(port.prepare_set_calls, 1);
        assert_eq!(port.ledger_begin_calls, 1);
        assert_eq!(port.ledger_resolve_calls, 1);
        assert_eq!(
            port.events,
            [
                "ledger_preflight",
                "observe",
                "ledger_stage",
                "prepare_set",
                "ledger_resolve",
            ]
        );
        port.assert_no_mutation();
    }

    #[test]
    fn commit_selector_refusals_have_zero_mutations() {
        for selector in [
            CommitSelectorState::Unconfigured,
            CommitSelectorState::Absent,
            CommitSelectorState::Ambiguous,
        ] {
            let claim = FakeClaim::accepting();
            let mut state = valid(DraftState::Empty);
            state.commit_selector = selector;
            let mut port = FakePort::with_states([state]);

            assert!(run_commit(&expected(), MESSAGE, &claim, &mut port).is_err());
            assert_eq!(claim.calls.get(), 0);
            port.assert_no_mutation();
        }
    }

    #[test]
    fn verified_commit_stages_and_invokes_exactly_once() {
        let claim = FakeClaim::accepting();
        let mut port =
            FakePort::with_states([valid(DraftState::Empty), valid(DraftState::ExactMessage)]);

        assert_eq!(
            run_commit(&expected(), MESSAGE, &claim, &mut port).unwrap(),
            SendOutcome::CommitIssued
        );
        assert_eq!(claim.calls.get(), 1);
        assert_eq!(port.set_calls, 1);
        assert_eq!(port.clear_calls, 0);
        assert_eq!(port.invoke_calls, 1);
        assert_eq!(port.ledger_begin_calls, 1);
        assert_eq!(port.ledger_commit_calls, 1);
        assert_eq!(port.ledger_indeterminate_calls, 1);
        assert_eq!(port.ledger_resolve_calls, 0);
        assert_eq!(
            port.events,
            [
                "ledger_preflight",
                "observe",
                "ledger_stage",
                "prepare_set",
                "set",
                "observe",
                "ledger_commit",
                "prepare_invoke",
                "invoke",
                "ledger_indeterminate",
            ]
        );
    }

    #[test]
    fn post_invoke_failure_is_uncertain_and_never_retried() {
        let claim = FakeClaim::accepting();
        let mut port =
            FakePort::with_states([valid(DraftState::Empty), valid(DraftState::ExactMessage)]);
        port.invoke_result = Err(error(UiErrorKind::Timeout, "synthetic_invoke"));

        let error = run_commit(&expected(), MESSAGE, &claim, &mut port).unwrap_err();
        assert_eq!(error.kind, UiErrorKind::SubmissionUncertain);
        assert!(!error.retry_safe);
        assert_eq!(port.invoke_calls, 1);
        assert_eq!(port.clear_calls, 0);
        assert_eq!(port.ledger_commit_calls, 1);
        assert_eq!(port.ledger_indeterminate_calls, 1);
    }

    #[test]
    fn final_invoke_preflight_failure_restores_but_keeps_terminal_ledger() {
        let claim = FakeClaim::accepting();
        let mut port = FakePort::with_states([
            valid(DraftState::Empty),
            valid(DraftState::ExactMessage),
            valid(DraftState::Empty),
        ]);
        port.prepare_invoke_result = Err(error(
            UiErrorKind::StaleSnapshot,
            "synthetic_invoke_preflight",
        ));

        let refusal = run_commit(&expected(), MESSAGE, &claim, &mut port).unwrap_err();
        assert_eq!(refusal.kind, UiErrorKind::SubmissionUncertain);
        assert!(!refusal.retry_safe);
        assert_eq!(port.set_calls, 1);
        assert_eq!(port.clear_calls, 1);
        assert_eq!(port.invoke_calls, 0);
        assert_eq!(port.ledger_commit_calls, 1);
        assert_eq!(port.ledger_indeterminate_calls, 1);
        assert_eq!(port.ledger_resolve_calls, 0);
    }

    #[test]
    fn commit_marker_failure_restores_owned_draft_but_never_invokes_or_resolves() {
        let claim = FakeClaim::accepting();
        let mut port = FakePort::with_states([
            valid(DraftState::Empty),
            valid(DraftState::ExactMessage),
            valid(DraftState::Empty),
        ]);
        port.ledger_commit_error = Some(error(
            UiErrorKind::SubmissionUncertain,
            "windows_ledger_state_uncertain",
        ));

        let refusal = run_commit(&expected(), MESSAGE, &claim, &mut port).unwrap_err();
        assert_eq!(refusal.kind, UiErrorKind::SubmissionUncertain);
        assert!(!refusal.retry_safe);
        assert_eq!(port.set_calls, 1);
        assert_eq!(port.clear_calls, 1);
        assert_eq!(port.invoke_calls, 0);
        assert_eq!(port.ledger_commit_calls, 1);
        assert_eq!(port.ledger_indeterminate_calls, 0);
        assert_eq!(port.ledger_resolve_calls, 0);
    }

    #[test]
    fn post_invoke_ledger_failure_cannot_turn_a_commit_into_success() {
        let claim = FakeClaim::accepting();
        let mut port =
            FakePort::with_states([valid(DraftState::Empty), valid(DraftState::ExactMessage)]);
        port.ledger_indeterminate_error = Some(error(
            UiErrorKind::SubmissionUncertain,
            "windows_ledger_state_uncertain",
        ));

        let refusal = run_commit(&expected(), MESSAGE, &claim, &mut port).unwrap_err();
        assert_eq!(refusal.kind, UiErrorKind::SubmissionUncertain);
        assert!(!refusal.retry_safe);
        assert_eq!(port.invoke_calls, 1);
        assert_eq!(port.ledger_indeterminate_calls, 1);
        assert_eq!(port.clear_calls, 0);
    }

    #[test]
    fn panic_immediately_before_or_after_invoke_keeps_terminal_ledger() {
        for panic_site in ["preflight", "invoke"] {
            let claim = FakeClaim::accepting();
            let mut port =
                FakePort::with_states([valid(DraftState::Empty), valid(DraftState::ExactMessage)]);
            match panic_site {
                "preflight" => port.panic_on_prepare_invoke = true,
                "invoke" => port.panic_on_invoke = true,
                _ => unreachable!(),
            }

            let refusal = run_commit(&expected(), MESSAGE, &claim, &mut port).unwrap_err();
            assert_eq!(
                refusal.kind,
                UiErrorKind::SubmissionUncertain,
                "{panic_site}"
            );
            assert!(!refusal.retry_safe, "{panic_site}");
            assert_eq!(port.set_calls, 1, "{panic_site}");
            assert_eq!(port.ledger_commit_calls, 1, "{panic_site}");
            assert_eq!(port.ledger_indeterminate_calls, 1, "{panic_site}");
            assert_eq!(
                port.invoke_calls,
                usize::from(panic_site == "invoke"),
                "{panic_site}"
            );
            assert_eq!(port.clear_calls, 0, "{panic_site}");
        }
    }

    #[test]
    fn restored_stage_with_failed_ledger_removal_is_nonretryable() {
        let claim = FakeClaim::accepting();
        let mut port = FakePort::with_states([
            valid(DraftState::Empty),
            valid(DraftState::ExactMessage),
            valid(DraftState::Empty),
        ]);
        port.ledger_resolve_error = Some(error(
            UiErrorKind::SubmissionUncertain,
            "windows_ledger_state_uncertain",
        ));

        let refusal = run_stage(&expected(), MESSAGE, &claim, &mut port).unwrap_err();
        assert_eq!(refusal.kind, UiErrorKind::SubmissionUncertain);
        assert!(!refusal.retry_safe);
        assert_eq!(port.set_calls, 1);
        assert_eq!(port.clear_calls, 1);
        assert_eq!(port.ledger_resolve_calls, 1);
        assert_eq!(port.ledger_indeterminate_calls, 1);
    }

    #[test]
    fn lost_selector_after_staging_restores_only_exact_owned_value() {
        let claim = FakeClaim::accepting();
        let mut lost_selector = valid(DraftState::ExactMessage);
        lost_selector.commit_selector = CommitSelectorState::Absent;
        let mut port = FakePort::with_states([
            valid(DraftState::Empty),
            lost_selector,
            valid(DraftState::Empty),
        ]);

        let error = run_commit(&expected(), MESSAGE, &claim, &mut port).unwrap_err();
        assert_eq!(error.kind, UiErrorKind::SubmissionUncertain);
        assert!(!error.retry_safe);
        assert_eq!(port.set_calls, 1);
        assert_eq!(port.clear_calls, 1);
        assert_eq!(port.invoke_calls, 0);
    }

    #[test]
    fn every_post_set_value_stage_failure_is_nonretryable_uncertainty() {
        let cases = [
            "set_and_readback_error",
            "expired_readback",
            "clear_preflight_error",
            "clear_error",
            "restore_observe_error",
            "provider_panic",
        ];

        for case in cases {
            let claim = FakeClaim::accepting();
            let mut port = match case {
                "set_and_readback_error" => {
                    let mut port = FakePort::with_states([valid(DraftState::Empty)]);
                    port.states
                        .push_back(Err(error(UiErrorKind::Timeout, "synthetic_readback")));
                    port.set_results
                        .push_back(Err(error(UiErrorKind::Timeout, "synthetic_set_value")));
                    port
                }
                "expired_readback" => {
                    let mut expired = valid(DraftState::ExactMessage);
                    expired.now_unix_ms = expected().expires_at_unix_ms;
                    FakePort::with_states([valid(DraftState::Empty), expired])
                }
                "clear_preflight_error" => {
                    let mut port = FakePort::with_states([
                        valid(DraftState::Empty),
                        valid(DraftState::ExactMessage),
                    ]);
                    port.prepare_set_results.push_back(Ok(()));
                    port.prepare_set_results.push_back(Err(error(
                        UiErrorKind::StaleSnapshot,
                        "synthetic_clear_preflight",
                    )));
                    port
                }
                "clear_error" => {
                    let mut port = FakePort::with_states([
                        valid(DraftState::Empty),
                        valid(DraftState::ExactMessage),
                    ]);
                    port.set_results.push_back(Ok(()));
                    port.set_results
                        .push_back(Err(error(UiErrorKind::Timeout, "synthetic_clear")));
                    port
                }
                "restore_observe_error" => {
                    let mut port = FakePort::with_states([
                        valid(DraftState::Empty),
                        valid(DraftState::ExactMessage),
                    ]);
                    port.states.push_back(Err(error(
                        UiErrorKind::Timeout,
                        "synthetic_restore_observe",
                    )));
                    port
                }
                "provider_panic" => {
                    let mut port = FakePort::with_states([valid(DraftState::Empty)]);
                    port.panic_on_observe_call = Some(2);
                    port
                }
                _ => unreachable!(),
            };

            let error = run_stage(&expected(), MESSAGE, &claim, &mut port)
                .expect_err("post-SetValue failure must be uncertain");
            assert_eq!(error.kind, UiErrorKind::SubmissionUncertain, "{case}");
            assert!(!error.retry_safe, "{case}");
            assert_eq!(claim.calls.get(), 1, "{case}");
            assert_eq!(port.set_calls, 1, "{case}");
            assert!(port.clear_calls <= 1, "{case}");
            assert_eq!(port.invoke_calls, 0, "{case}");
            assert_eq!(port.ledger_begin_calls, 1, "{case}");
            assert_eq!(port.ledger_indeterminate_calls, 1, "{case}");
            assert_eq!(port.ledger_resolve_calls, 0, "{case}");
        }
    }

    #[test]
    fn commit_readback_failure_after_set_value_is_nonretryable_uncertainty() {
        let claim = FakeClaim::accepting();
        let mut port = FakePort::with_states([valid(DraftState::Empty)]);
        port.states.push_back(Err(error(
            UiErrorKind::Timeout,
            "synthetic_commit_readback",
        )));

        let error = run_commit(&expected(), MESSAGE, &claim, &mut port)
            .expect_err("post-SetValue commit failure must be uncertain");

        assert_eq!(error.kind, UiErrorKind::SubmissionUncertain);
        assert_eq!(error.operation, "windows_commit_after_set_value_uncertain");
        assert!(!error.retry_safe);
        assert_eq!(claim.calls.get(), 1);
        assert_eq!(port.set_calls, 1);
        assert_eq!(port.clear_calls, 0);
        assert_eq!(port.invoke_calls, 0);
    }
}
