use std::cell::Cell;

use super::{
    ApprovedSend, InspectRequest, MessageSender, PlatformProbe, SendOutcome, UiCapabilities,
    UiError, UiSnapshot,
};

/// Deterministic backend for unit and CLI tests. Counters make side effects
/// observable without touching a real desktop application.
pub struct FakeBackend {
    snapshot: UiSnapshot,
    inspect_calls: Cell<usize>,
    stage_calls: Cell<usize>,
    commit_calls: Cell<usize>,
}

impl FakeBackend {
    pub fn new(snapshot: UiSnapshot) -> Self {
        Self {
            snapshot,
            inspect_calls: Cell::new(0),
            stage_calls: Cell::new(0),
            commit_calls: Cell::new(0),
        }
    }

    pub fn inspect_calls(&self) -> usize {
        self.inspect_calls.get()
    }

    pub fn stage_calls(&self) -> usize {
        self.stage_calls.get()
    }

    pub fn commit_calls(&self) -> usize {
        self.commit_calls.get()
    }
}

impl PlatformProbe for FakeBackend {
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
        self.inspect_calls.set(self.inspect_calls.get() + 1);
        Ok(self.snapshot.clone())
    }
}

impl super::contract::message_sender_seal::Sealed for FakeBackend {}

impl MessageSender for FakeBackend {
    fn stage(&self, approved: &ApprovedSend) -> Result<SendOutcome, UiError> {
        if approved.mode() != super::SendMode::StageOnly {
            return Err(UiError::new(
                super::UiErrorKind::InvalidInput,
                "fake_stage_mode_mismatch",
            ));
        }
        self.stage_calls.set(self.stage_calls.get() + 1);
        Ok(SendOutcome::StagedAndRestored)
    }

    fn commit(&self, approved: &ApprovedSend) -> Result<SendOutcome, UiError> {
        if approved.mode() != super::SendMode::Commit {
            return Err(UiError::new(
                super::UiErrorKind::InvalidInput,
                "fake_commit_mode_mismatch",
            ));
        }
        self.commit_calls.set(self.commit_calls.get() + 1);
        Ok(SendOutcome::CommitIssued)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{
        inspect_dry_run, AppSnapshot, ChatTargetSnapshot, InputSnapshot, ProcessFingerprint,
        TargetKind, UiPlatform,
    };

    fn safe_snapshot() -> UiSnapshot {
        UiSnapshot {
            app: AppSnapshot {
                platform: UiPlatform::Windows,
                app_running: true,
                process: Some(ProcessFingerprint {
                    pid: 7,
                    executable: "run-local-digest".to_string(),
                    session_id: Some(1),
                }),
                app_version: Some("synthetic".to_string()),
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
                window: Some("window-digest".to_string()),
                composer: Some("composer-digest".to_string()),
                observed_at_unix_ms: 1,
                expires_at_unix_ms: 2,
            },
            input: InputSnapshot {
                present: true,
                unique: true,
                enabled: true,
                writable: true,
                draft_empty: true,
                focused: false,
                selector_profile_id: Some("synthetic".to_string()),
            },
        }
    }

    #[test]
    fn dry_run_can_only_inspect_and_never_mutates() {
        let backend = FakeBackend::new(safe_snapshot());
        let request = InspectRequest {
            target: TargetKind::SelfChat,
        };

        let result = inspect_dry_run(&backend, &request).expect("fake inspect should succeed");

        assert!(result.target.self_chat_verified);
        assert_eq!(backend.inspect_calls(), 1);
        assert_eq!(backend.stage_calls(), 0);
        assert_eq!(backend.commit_calls(), 0);
    }
}
