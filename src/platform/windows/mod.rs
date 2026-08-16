//! Windows backend placeholder frozen with the platform contract.
//!
//! Wave 1 replaces the read-only probe while preserving these trait and error
//! boundaries. No UI mutation is implemented in Wave 1.

use super::{
    ApprovedSend, InspectRequest, MessageSender, PlatformProbe, SendOutcome, UiCapabilities,
    UiError, UiErrorKind, UiSnapshot,
};

#[derive(Debug, Default)]
pub struct WindowsBackend;

impl PlatformProbe for WindowsBackend {
    fn capabilities(&self) -> UiCapabilities {
        UiCapabilities::windows_read_only()
    }

    fn inspect(&self, _request: &InspectRequest) -> Result<UiSnapshot, UiError> {
        Err(UiError::new(
            UiErrorKind::UnsupportedCapability,
            "windows_inspect_pending",
        ))
    }
}

impl MessageSender for WindowsBackend {
    fn stage(&self, _approved: &ApprovedSend) -> Result<SendOutcome, UiError> {
        Err(UiError::new(
            UiErrorKind::UnsupportedCapability,
            "windows_stage_not_in_wave_1",
        ))
    }

    fn commit(&self, _approved: &ApprovedSend) -> Result<SendOutcome, UiError> {
        Err(UiError::new(
            UiErrorKind::UnsupportedCapability,
            "windows_commit_not_in_wave_1",
        ))
    }
}
