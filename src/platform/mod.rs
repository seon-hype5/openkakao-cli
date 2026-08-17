//! Platform-neutral desktop UI contracts.
//!
//! Platform implementations may inspect UI state, but mutation methods are
//! deliberately separated behind [`MessageSender`] and require an
//! [`ApprovedSend`] produced by the safety module.

pub(crate) mod contract;
pub mod fake;
mod matcher;

pub use contract::{
    inspect_dry_run, ActionReport, AppSnapshot, ApprovedSend, BackendKind, ChatTargetSnapshot,
    ExitCode, InputSnapshot, InspectRequest, MessageSender, PlatformProbe, ProcessFingerprint,
    ReadOnlyWindowAmbiguity, SecretMessage, SendIntent, SendMode, SendOutcome,
    TargetBindingEvidence, TargetKind, UiCapabilities, UiError, UiErrorKind, UiPlatform,
    UiSnapshot,
};
pub use matcher::{exact_unique_match, ExactMatch};

#[cfg(target_os = "windows")]
pub mod windows;
