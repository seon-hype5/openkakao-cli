//! Safety-policy boundary for desktop UI sends.

mod policy;

pub use policy::{
    ApprovedOperation, DryRunPlan, PolicyClock, SystemPolicyClock, WindowsPolicyConfig,
    WindowsSafetyPolicy, MAX_MESSAGE_SCALARS, MAX_MESSAGE_UTF8_BYTES, MAX_NONCE_BYTES,
    MAX_SNAPSHOT_TTL_MS, SUPPORTED_APP_VERSION, SUPPORTED_SELECTOR_PROFILE_ID,
};

/// Construction token for `ApprovedSend`.
///
/// The type is crate-visible so the contract can name it, but its field and
/// constructor are private to this module and descendants. Platform and CLI
/// modules therefore cannot mint an approval.
#[allow(dead_code)]
pub(crate) struct ApprovalToken(());

impl ApprovalToken {
    #[allow(dead_code)]
    fn issue() -> Self {
        Self(())
    }
}
