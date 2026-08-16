//! Read-only Windows discovery backend.
//!
//! This module deliberately exposes only platform-neutral snapshots. Native
//! handles, executable paths, COM interfaces, and UI Automation element
//! identities remain inside [`native`]. Wave 1 never reads UI text and never
//! offers a mutation path.

mod native;

use std::fmt;
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

use super::{
    AppSnapshot, ApprovedSend, ChatTargetSnapshot, InputSnapshot, InspectRequest, MessageSender,
    PlatformProbe, ProcessFingerprint, SendOutcome, TargetKind, UiCapabilities, UiError,
    UiErrorKind, UiPlatform, UiSnapshot,
};

const INSPECTION_TIMEOUT: Duration = Duration::from_secs(8);
const SNAPSHOT_TTL_MS: u64 = 5_000;
const KNOWN_PROFILE_ID: &str = "kakaotalk-windows-26.7.0.5255";
const TOP_LEVEL_CLASS: &str = "EVA_Window_Dblclk";
const COMPOSER_CLASS: &str = "RICHEDIT50W";
const COMPOSER_AUTOMATION_ID: &str = "1006";
const UIA_EDIT_CONTROL_TYPE: i32 = 50_004;

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileVersion {
    major: u16,
    minor: u16,
    patch: u16,
    build: u16,
}

impl FileVersion {
    const KNOWN: Self = Self {
        major: 26,
        minor: 7,
        patch: 0,
        build: 5255,
    };
}

impl fmt::Display for FileVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}.{}.{}.{}",
            self.major, self.minor, self.patch, self.build
        )
    }
}

#[derive(Clone, Copy)]
struct UiProfile {
    id: &'static str,
    version: FileVersion,
    top_level_class: &'static str,
    composer_class: &'static str,
    composer_automation_id: &'static str,
    composer_control_type: i32,
}

impl UiProfile {
    fn matches_selector(&self, class_name: &str, automation_id: &str, control_type: i32) -> bool {
        class_name == self.composer_class
            && automation_id == self.composer_automation_id
            && control_type == self.composer_control_type
    }
}

const KNOWN_PROFILE: UiProfile = UiProfile {
    id: KNOWN_PROFILE_ID,
    version: FileVersion::KNOWN,
    top_level_class: TOP_LEVEL_CLASS,
    composer_class: COMPOSER_CLASS,
    composer_automation_id: COMPOSER_AUTOMATION_ID,
    composer_control_type: UIA_EDIT_CONTROL_TYPE,
};

fn profile_for(version: Option<FileVersion>) -> Option<&'static UiProfile> {
    (version == Some(KNOWN_PROFILE.version)).then_some(&KNOWN_PROFILE)
}

#[derive(Clone, Copy)]
struct FingerprintKey([u8; 32]);

impl FingerprintKey {
    fn random() -> Self {
        let mut key = [0_u8; 32];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    #[cfg(test)]
    const fn fixed(value: u8) -> Self {
        Self([value; 32])
    }

    fn digest(self, domain: &[u8], fields: &[&[u8]]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.0);
        hasher.update((domain.len() as u64).to_le_bytes());
        hasher.update(domain);
        for field in fields {
            hasher.update((field.len() as u64).to_le_bytes());
            hasher.update(field);
        }
        let digest = hasher.finalize();
        format!("run:{}", hex::encode(&digest[..16]))
    }

    fn executable(self, utf16_path: &[u16]) -> String {
        let mut bytes = Vec::with_capacity(utf16_path.len() * 2);
        for unit in utf16_path {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        self.digest(b"executable", &[&bytes])
    }

    fn window(self, handle: usize, pid: u32) -> String {
        self.digest(b"window", &[&handle.to_le_bytes(), &pid.to_le_bytes()])
    }

    fn composer(self, handle: usize, pid: u32) -> String {
        self.digest(
            b"composer",
            &[
                &handle.to_le_bytes(),
                &pid.to_le_bytes(),
                KNOWN_PROFILE_ID.as_bytes(),
            ],
        )
    }
}

impl fmt::Debug for FingerprintKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FingerprintKey(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
struct NativeProcess {
    pid: u32,
    executable_fingerprint: String,
    executable_verified: bool,
    version: Option<FileVersion>,
    session_id: u32,
    interactive_session_match: bool,
    integrity_compatible: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct NativeComposer {
    fingerprint: String,
    enabled: bool,
    value_pattern_present: bool,
    writable: bool,
    focused: bool,
}

#[derive(Clone, PartialEq, Eq)]
enum ComposerDiscovery {
    NotInspected,
    Absent,
    Unique(NativeComposer),
    Ambiguous(usize),
}

#[derive(Clone, PartialEq, Eq)]
struct NativeWindow {
    fingerprint: String,
    visible: bool,
    enabled: bool,
    process: NativeProcess,
    composer: ComposerDiscovery,
}

#[derive(Clone, PartialEq, Eq)]
enum WindowDiscovery {
    Absent,
    Unique(NativeWindow),
    Ambiguous(usize),
}

#[derive(Clone, PartialEq, Eq)]
struct NativeInspection {
    window: WindowDiscovery,
}

/// Per-process backend. Its random key makes every published native identity
/// an execution-scoped fingerprint rather than a reusable machine identifier.
pub struct WindowsBackend {
    fingerprints: FingerprintKey,
}

impl Default for WindowsBackend {
    fn default() -> Self {
        Self {
            fingerprints: FingerprintKey::random(),
        }
    }
}

impl fmt::Debug for WindowsBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsBackend")
    }
}

impl WindowsBackend {
    fn inspect_on_mta(&self) -> Result<NativeInspection, UiError> {
        let fingerprints = self.fingerprints;
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("openkakao-windows-probe".to_string())
            .spawn(move || {
                let result = native::inspect(fingerprints);
                let _ = sender.send(result);
            })
            .map_err(|_| {
                UiError::new(
                    UiErrorKind::UnsupportedCapability,
                    "windows_probe_thread_start",
                )
            })?;

        match receiver.recv_timeout(INSPECTION_TIMEOUT) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(UiError::new(
                UiErrorKind::Timeout,
                "windows_read_only_inspect",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(UiError::new(
                UiErrorKind::UnsupportedCapability,
                "windows_probe_thread_failed",
            )),
        }
    }
}

impl PlatformProbe for WindowsBackend {
    fn capabilities(&self) -> UiCapabilities {
        UiCapabilities::windows_read_only()
    }

    fn inspect(&self, request: &InspectRequest) -> Result<UiSnapshot, UiError> {
        if request.target != TargetKind::SelfChat {
            return Err(UiError::new(
                UiErrorKind::TargetNotSelf,
                "windows_inspect_target",
            ));
        }

        let native = self.inspect_on_mta()?;
        Ok(map_native(request.target, native, unix_now_ms()))
    }
}

impl super::contract::message_sender_seal::Sealed for WindowsBackend {}

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

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn map_native(target_kind: TargetKind, native: NativeInspection, observed_at: u64) -> UiSnapshot {
    let expires_at = observed_at.saturating_add(SNAPSHOT_TTL_MS);

    match native.window {
        WindowDiscovery::Absent => empty_snapshot(target_kind, 0, observed_at, expires_at),
        WindowDiscovery::Ambiguous(count) => {
            empty_snapshot(target_kind, count, observed_at, expires_at)
        }
        WindowDiscovery::Unique(window) => {
            map_unique_window(target_kind, window, observed_at, expires_at)
        }
    }
}

fn empty_snapshot(
    target_kind: TargetKind,
    window_count: usize,
    observed_at: u64,
    expires_at: u64,
) -> UiSnapshot {
    UiSnapshot {
        app: AppSnapshot {
            platform: UiPlatform::Windows,
            app_running: false,
            process: None,
            app_version: None,
            interactive_session_match: false,
            integrity_compatible: false,
            known_ui_profile: false,
            top_level_window_count: window_count,
            modal_present: false,
        },
        target: ChatTargetSnapshot {
            kind: target_kind,
            self_chat_verified: false,
            exact_match: false,
            unique_match: false,
            window: None,
            composer: None,
            observed_at_unix_ms: observed_at,
            expires_at_unix_ms: expires_at,
        },
        input: unavailable_input(None),
    }
}

fn map_unique_window(
    target_kind: TargetKind,
    window: NativeWindow,
    observed_at: u64,
    expires_at: u64,
) -> UiSnapshot {
    let process_verified = window.process.executable_verified;
    let profile = process_verified
        .then_some(window.process.version)
        .flatten()
        .and_then(|version| profile_for(Some(version)));
    let known_ui_profile = profile.is_some();

    let process = process_verified.then(|| ProcessFingerprint {
        pid: window.process.pid,
        executable: window.process.executable_fingerprint.clone(),
        session_id: Some(window.process.session_id),
    });

    let (input, composer) = if let Some(profile) = profile {
        match window.composer {
            ComposerDiscovery::Unique(composer) => (
                InputSnapshot {
                    present: true,
                    unique: true,
                    enabled: composer.enabled,
                    writable: composer.value_pattern_present && composer.writable,
                    // Reading CurrentValue would expose a private draft. Wave 1
                    // therefore leaves this false (unverified) and fails closed.
                    draft_empty: false,
                    focused: composer.focused,
                    selector_profile_id: Some(profile.id.to_string()),
                },
                Some(composer.fingerprint),
            ),
            ComposerDiscovery::Ambiguous(_) => (
                InputSnapshot {
                    present: true,
                    unique: false,
                    enabled: false,
                    writable: false,
                    draft_empty: false,
                    focused: false,
                    selector_profile_id: Some(profile.id.to_string()),
                },
                None,
            ),
            ComposerDiscovery::Absent | ComposerDiscovery::NotInspected => {
                (unavailable_input(Some(profile.id)), None)
            }
        }
    } else {
        (unavailable_input(None), None)
    };

    UiSnapshot {
        app: AppSnapshot {
            platform: UiPlatform::Windows,
            app_running: process_verified,
            process,
            app_version: process_verified
                .then_some(window.process.version)
                .flatten()
                .map(|version| version.to_string()),
            interactive_session_match: process_verified && window.process.interactive_session_match,
            integrity_compatible: process_verified && window.process.integrity_compatible,
            known_ui_profile,
            top_level_window_count: 1,
            modal_present: process_verified && !window.enabled,
        },
        target: ChatTargetSnapshot {
            kind: target_kind,
            // Wave 1 never reads a room/profile title, so it cannot assert
            // self-chat identity even when the app/composer selectors match.
            self_chat_verified: false,
            exact_match: false,
            unique_match: false,
            window: (process_verified && window.visible).then_some(window.fingerprint),
            composer,
            observed_at_unix_ms: observed_at,
            expires_at_unix_ms: expires_at,
        },
        input,
    }
}

fn unavailable_input(profile_id: Option<&str>) -> InputSnapshot {
    InputSnapshot {
        present: false,
        unique: false,
        enabled: false,
        writable: false,
        draft_empty: false,
        focused: false,
        selector_profile_id: profile_id.map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(version: Option<FileVersion>) -> NativeProcess {
        NativeProcess {
            pid: 42,
            executable_fingerprint: "run:synthetic-process".to_string(),
            executable_verified: true,
            version,
            session_id: 3,
            interactive_session_match: true,
            integrity_compatible: true,
        }
    }

    fn window(version: Option<FileVersion>, composer: ComposerDiscovery) -> NativeWindow {
        NativeWindow {
            fingerprint: "run:synthetic-window".to_string(),
            visible: true,
            enabled: true,
            process: process(version),
            composer,
        }
    }

    #[test]
    fn selector_is_exact_and_case_sensitive() {
        assert!(KNOWN_PROFILE.matches_selector("RICHEDIT50W", "1006", 50_004));
        assert!(!KNOWN_PROFILE.matches_selector("richedit50w", "1006", 50_004));
        assert!(!KNOWN_PROFILE.matches_selector("RICHEDIT50W", "1006 ", 50_004));
        assert!(!KNOWN_PROFILE.matches_selector("RICHEDIT50W", "1006", 50_000));

        let candidates = [
            ("RICHEDIT50W", "1006", 50_004),
            ("richedit50w", "1006", 50_004),
            ("RICHEDIT50W", "1006", 50_004),
        ];
        let exact_count = candidates
            .into_iter()
            .filter(|(class_name, automation_id, control_type)| {
                KNOWN_PROFILE.matches_selector(class_name, automation_id, *control_type)
            })
            .count();
        assert_eq!(exact_count, 2, "duplicate exact selectors are ambiguous");
    }

    #[test]
    fn absent_and_ambiguous_windows_are_structured_fail_closed_states() {
        let absent = map_native(
            TargetKind::SelfChat,
            NativeInspection {
                window: WindowDiscovery::Absent,
            },
            10,
        );
        assert!(!absent.app.app_running);
        assert_eq!(absent.app.top_level_window_count, 0);
        assert!(!absent.target.unique_match);

        let ambiguous = map_native(
            TargetKind::SelfChat,
            NativeInspection {
                window: WindowDiscovery::Ambiguous(2),
            },
            10,
        );
        assert!(!ambiguous.app.app_running);
        assert_eq!(ambiguous.app.top_level_window_count, 2);
        assert!(ambiguous.target.window.is_none());
    }

    #[test]
    fn unknown_version_gates_composer_and_write_capability() {
        let snapshot = map_native(
            TargetKind::SelfChat,
            NativeInspection {
                window: WindowDiscovery::Unique(window(
                    Some(FileVersion {
                        major: 99,
                        minor: 0,
                        patch: 0,
                        build: 1,
                    }),
                    ComposerDiscovery::NotInspected,
                )),
            },
            20,
        );

        assert!(snapshot.app.app_running);
        assert!(!snapshot.app.known_ui_profile);
        assert!(!snapshot.input.present);
        assert!(!snapshot.input.writable);
        assert!(snapshot.input.selector_profile_id.is_none());
        assert!(!WindowsBackend::default().capabilities().send_open_chat);
    }

    #[test]
    fn native_unique_composer_maps_without_claiming_draft_or_self_chat() {
        let snapshot = map_native(
            TargetKind::SelfChat,
            NativeInspection {
                window: WindowDiscovery::Unique(window(
                    Some(FileVersion::KNOWN),
                    ComposerDiscovery::Unique(NativeComposer {
                        fingerprint: "run:synthetic-composer".to_string(),
                        enabled: true,
                        value_pattern_present: true,
                        writable: true,
                        focused: false,
                    }),
                )),
            },
            30,
        );

        assert!(snapshot.app.app_running);
        assert!(snapshot.app.known_ui_profile);
        assert_eq!(snapshot.app.app_version.as_deref(), Some("26.7.0.5255"));
        assert!(!snapshot.target.exact_match);
        assert!(!snapshot.target.unique_match);
        assert!(!snapshot.target.self_chat_verified);
        assert_eq!(
            snapshot.target.composer.as_deref(),
            Some("run:synthetic-composer")
        );
        assert!(snapshot.input.present);
        assert!(snapshot.input.unique);
        assert!(snapshot.input.writable);
        assert!(!snapshot.input.draft_empty);
        assert_eq!(snapshot.target.expires_at_unix_ms, 5_030);
    }

    #[test]
    fn ambiguous_composer_never_publishes_an_identity() {
        let snapshot = map_native(
            TargetKind::SelfChat,
            NativeInspection {
                window: WindowDiscovery::Unique(window(
                    Some(FileVersion::KNOWN),
                    ComposerDiscovery::Ambiguous(2),
                )),
            },
            40,
        );

        assert!(snapshot.input.present);
        assert!(!snapshot.input.unique);
        assert!(!snapshot.input.writable);
        assert!(snapshot.target.composer.is_none());
    }

    #[test]
    fn fingerprints_are_scoped_and_domain_separated() {
        let first = FingerprintKey::fixed(1);
        let second = FingerprintKey::fixed(2);
        assert_eq!(first.window(7, 42), first.window(7, 42));
        assert_ne!(first.window(7, 42), second.window(7, 42));
        assert_ne!(first.window(7, 42), first.composer(7, 42));
    }
}
