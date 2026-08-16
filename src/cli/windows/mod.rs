//! Testable Windows command options and dry-run-only preparation.
//!
//! This module deliberately does not construct a concrete Windows backend.
//! Callers supply a [`PlatformProbe`], which keeps this preparation seam
//! unable to reach [`crate::platform::MessageSender`] by type. Root owns the
//! separately guarded write orchestration.

use std::fmt;
use std::io::Read;

use clap::Args;
use zeroize::Zeroize;

use crate::platform::{
    inspect_dry_run, InspectRequest, PlatformProbe, SecretMessage, SendMode, UiError, UiErrorKind,
    UiSnapshot,
};
use crate::safety::MAX_MESSAGE_UTF8_BYTES;

const INVALID_LOCAL_SEND_OPTIONS: &str = "invalid_windows_local_send_options";
const READ_STDIN: &str = "read_windows_stdin";
const STDIN_INVALID_UTF8: &str = "windows_stdin_invalid_utf8";
const STDIN_TOO_LARGE: &str = "windows_stdin_too_large";
const UI_INSPECT_UNAVAILABLE: &str = "windows_ui_inspect_unavailable";
const UI_DOCTOR_REQUIRED: &str = "windows_ui_doctor_required";
const WRITE_MODE_UNAVAILABLE: &str = "windows_write_mode_not_in_wave_1";

/// Windows-only options flattened into the existing `doctor` command.
#[derive(Args, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UiDoctorOptions {
    /// Inspect only the read-only Windows desktop UI surface.
    #[arg(long, help = "Inspect the read-only Windows desktop UI surface")]
    ui: bool,
}

impl UiDoctorOptions {
    pub const fn ui_requested(&self) -> bool {
        self.ui
    }
}

/// Windows-only `local-send` arguments.
///
/// There is intentionally no positional message field. Message bytes enter
/// through [`MessageInput`] only. The target name is kept private and this
/// type's `Debug` implementation always redacts it.
#[derive(Args)]
pub struct LocalSendOptions {
    #[arg(value_name = "SELF_CHAT_NAME", value_parser = parse_self_chat_name)]
    self_chat_name: String,

    /// Read the message from standard input.
    #[arg(long, required = true)]
    stdin: bool,

    /// Inspect only the already-open self-chat; never search for or open it.
    #[arg(long, required = true)]
    opened_only: bool,

    /// Preview the operation without mutating the UI (the default mode).
    #[arg(long, conflicts_with_all = ["stage_only", "commit"])]
    dry_run: bool,

    /// Request guarded staging; requires explicit approval and capability.
    #[arg(long, conflicts_with = "commit", requires = "yes")]
    stage_only: bool,

    /// Request guarded submission; requires explicit approval and capability.
    #[arg(long, conflicts_with = "stage_only", requires = "yes")]
    commit: bool,

    /// Explicitly acknowledge a guarded write mode.
    #[arg(long, short = 'y')]
    yes: bool,
}

impl LocalSendOptions {
    /// Returns the sensitive target only for composition with the safety
    /// policy. Callers must never format, log, or serialize this value.
    pub fn self_chat_name_secret(&self) -> &str {
        &self.self_chat_name
    }

    pub const fn reads_stdin(&self) -> bool {
        self.stdin
    }

    pub const fn opened_only(&self) -> bool {
        self.opened_only
    }

    pub const fn explicit_yes(&self) -> bool {
        self.yes
    }

    pub const fn dry_run_was_explicit(&self) -> bool {
        self.dry_run
    }

    /// Validates options again at the library boundary, before any input or
    /// backend call. Absence of a write flag means dry-run.
    pub fn mode(&self) -> Result<SendMode, UiError> {
        if !self.stdin
            || !self.opened_only
            || (self.stage_only && self.commit)
            || (self.dry_run && (self.stage_only || self.commit))
            || ((self.stage_only || self.commit) && !self.yes)
        {
            return Err(UiError::new(
                UiErrorKind::InvalidInput,
                INVALID_LOCAL_SEND_OPTIONS,
            ));
        }

        if self.stage_only {
            Ok(SendMode::StageOnly)
        } else if self.commit {
            Ok(SendMode::Commit)
        } else {
            Ok(SendMode::DryRun)
        }
    }
}

impl fmt::Debug for LocalSendOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalSendOptions")
            .field("self_chat_name", &"<redacted>")
            .field("stdin", &self.stdin)
            .field("opened_only", &self.opened_only)
            .field("dry_run", &self.dry_run)
            .field("stage_only", &self.stage_only)
            .field("commit", &self.commit)
            .field("yes", &self.yes)
            .finish()
    }
}

fn parse_self_chat_name(value: &str) -> Result<String, String> {
    if value.is_empty() || value.chars().any(char::is_control) {
        Err("SELF_CHAT_NAME must be non-empty and contain no control characters".to_string())
    } else {
        Ok(value.to_string())
    }
}

/// Source of a single secret message. Production wiring may wrap stdin;
/// tests use in-memory readers or fakes.
pub trait MessageInput {
    fn read_message(&mut self) -> Result<SecretMessage, UiError>;
}

/// [`MessageInput`] backed by any [`Read`] implementation.
pub struct ReaderMessageInput<R> {
    reader: R,
}

impl<R> ReaderMessageInput<R> {
    pub const fn new(reader: R) -> Self {
        Self { reader }
    }

    pub fn into_inner(self) -> R {
        self.reader
    }
}

impl<R> fmt::Debug for ReaderMessageInput<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReaderMessageInput(<redacted>)")
    }
}

impl<R: Read> MessageInput for ReaderMessageInput<R> {
    fn read_message(&mut self) -> Result<SecretMessage, UiError> {
        let mut bytes = Vec::with_capacity(MAX_MESSAGE_UTF8_BYTES + 1);
        if self
            .reader
            .by_ref()
            .take((MAX_MESSAGE_UTF8_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .is_err()
        {
            bytes.zeroize();
            return Err(UiError::new(UiErrorKind::InvalidInput, READ_STDIN));
        }

        if bytes.len() > MAX_MESSAGE_UTF8_BYTES {
            bytes.zeroize();
            return Err(UiError::new(UiErrorKind::InvalidInput, STDIN_TOO_LARGE));
        }

        let value = match String::from_utf8(bytes) {
            Ok(value) => value,
            Err(error) => {
                let mut bytes = error.into_bytes();
                bytes.zeroize();
                return Err(UiError::new(UiErrorKind::InvalidInput, STDIN_INVALID_UTF8));
            }
        };
        Ok(SecretMessage::new(value))
    }
}

/// Result of the Windows local-send preparation seam. It contains no raw
/// target name and has no formatting implementation.
pub struct PreparedLocalSend {
    message: SecretMessage,
    snapshot: UiSnapshot,
}

impl PreparedLocalSend {
    pub fn snapshot(&self) -> &UiSnapshot {
        &self.snapshot
    }

    pub fn into_parts(self) -> (SecretMessage, UiSnapshot) {
        (self.message, self.snapshot)
    }
}

/// Runs the read-only UI doctor probe. Negative observable states remain in
/// the returned redacted snapshot; native/backend failures remain `UiError`.
pub fn inspect_ui_doctor<P: PlatformProbe>(
    options: &UiDoctorOptions,
    probe: &P,
) -> Result<UiSnapshot, UiError> {
    if !options.ui_requested() {
        return Err(UiError::new(UiErrorKind::InvalidInput, UI_DOCTOR_REQUIRED));
    }
    inspect_self_chat(probe)
}

/// Reads stdin and inspects the already-open self-chat for a dry-run.
///
/// Stage/commit modes are refused before reading input or calling the probe.
/// This legacy preparation function has no `MessageSender` bound, so it cannot
/// stage or commit even when the supplied probe is also a sender.
pub fn prepare_local_send<P: PlatformProbe, I: MessageInput>(
    options: &LocalSendOptions,
    input: &mut I,
    probe: &P,
) -> Result<PreparedLocalSend, UiError> {
    let mode = options.mode()?;
    if mode != SendMode::DryRun {
        return Err(UiError::new(
            UiErrorKind::UnsupportedCapability,
            WRITE_MODE_UNAVAILABLE,
        ));
    }

    let message = input.read_message()?;
    let snapshot = inspect_self_chat(probe)?;
    Ok(PreparedLocalSend { message, snapshot })
}

fn inspect_self_chat<P: PlatformProbe>(probe: &P) -> Result<UiSnapshot, UiError> {
    if !probe.capabilities().inspect {
        return Err(UiError::new(
            UiErrorKind::UnsupportedCapability,
            UI_INSPECT_UNAVAILABLE,
        ));
    }

    inspect_dry_run(probe, &InspectRequest::self_chat())
}

#[cfg(test)]
#[path = "../../../tests/windows_cli/mod.rs"]
mod tests;
