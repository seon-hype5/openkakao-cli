//! Safety-policy boundary for desktop UI sends.

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
