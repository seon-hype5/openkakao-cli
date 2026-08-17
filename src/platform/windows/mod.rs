//! Read-only Windows discovery plus build-gated guarded transaction backend.
//!
//! This module deliberately exposes only platform-neutral snapshots. Native
//! handles, executable paths, COM interfaces, and UI Automation element
//! identities remain inside [`native`]. Default builds contain no UI write
//! boundary; the `windows-ui-write` feature compiles a transaction path that
//! still fails closed until live self-target and send selectors are verified.

mod executable_trust;
mod executable_trust_native;
#[cfg(any(feature = "windows-ui-write", test))]
mod ledger;
#[cfg(any(feature = "windows-ui-write", test))]
mod ledger_location;
#[cfg(feature = "windows-ui-write")]
mod ledger_native;
mod native;
#[cfg(any(feature = "windows-ui-write", test))]
mod transaction;

use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::{
    AppSnapshot, ApprovedSend, ChatTargetSnapshot, InputSnapshot, InspectRequest, MessageSender,
    PlatformProbe, ProcessFingerprint, ReadOnlyCandidateBlockers, ReadOnlyComposerSelectorEvidence,
    ReadOnlyWindowAmbiguity, SendOutcome, TargetKind, UiCapabilities, UiError, UiErrorKind,
    UiPlatform, UiSnapshot,
};

const INSPECTION_TIMEOUT: Duration = Duration::from_secs(8);
const SNAPSHOT_TTL_MS: u64 = 5_000;
const KNOWN_PROFILE_ID: &str = "kakaotalk-windows-x64-stable-26.7.0.5255-v3";
const TOP_LEVEL_CLASS: &str = "EVA_Window_Dblclk";
const COMPOSER_CLASS: &str = "RICHEDIT50W";
const COMPOSER_AUTOMATION_ID: &str = "1006";
const UIA_DOCUMENT_CONTROL_TYPE: i32 = 50_030;
const EMPTY_PLACEHOLDER_DIGEST_DOMAIN: &[u8] = b"openkakao.windows.composer-placeholder.v1\0";
const KNOWN_EMPTY_PLACEHOLDER_UTF16_SHA256: [u8; 32] = [
    0x15, 0x73, 0x09, 0xf2, 0x22, 0xf0, 0x4a, 0x0c, 0x36, 0x99, 0xd9, 0x6f, 0x2d, 0x0f, 0x01, 0x59,
    0xe6, 0x2d, 0x29, 0xf1, 0xf7, 0xe8, 0x15, 0x0b, 0xf9, 0x80, 0xc9, 0x75, 0x8a, 0x24, 0x5f, 0x12,
];
static READ_ONLY_PROBE_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, PartialEq, Eq)]
enum SubmitStrategy {
    /// KakaoTalk 26.7 exposes no separate send element or InvokePattern.
    /// Activate the exact verified root, then enqueue one complete Enter
    /// keystroke to the exact composer HWND's owning thread without
    /// synthesizing global keyboard input.
    ForegroundQueuedComposerEnterV3,
}

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
    empty_placeholder_utf16_sha256: [u8; 32],
    empty_control_utf16: [u16; 2],
    set_value_appends_carriage_return: bool,
    submit_strategy: Option<SubmitStrategy>,
}

impl UiProfile {
    fn matches_selector(&self, class_name: &str, automation_id: &str, control_type: i32) -> bool {
        class_name == self.composer_class
            && automation_id == self.composer_automation_id
            && control_type == self.composer_control_type
    }

    fn matches_empty_placeholder(&self, units: &[u16]) -> bool {
        let mut observed = empty_placeholder_utf16_digest(units);
        let matches = observed == self.empty_placeholder_utf16_sha256;
        observed.zeroize();
        matches
    }

    fn matches_empty_provider_value(&self, units: &[u16]) -> bool {
        units == self.empty_control_utf16 || self.matches_empty_placeholder(units)
    }

    fn matches_staged_value(&self, current: &[u16], expected: &[u16]) -> bool {
        current == expected
            || (self.set_value_appends_carriage_return
                && current.len() == expected.len() + 1
                && current.starts_with(expected)
                && current.last() == Some(&u16::from(b'\r')))
    }
}

fn empty_placeholder_utf16_digest(units: &[u16]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(EMPTY_PLACEHOLDER_DIGEST_DOMAIN);
    hasher.update((units.len() as u64).to_le_bytes());
    for unit in units {
        hasher.update(unit.to_le_bytes());
    }
    hasher.finalize().into()
}

const KNOWN_PROFILE: UiProfile = UiProfile {
    id: KNOWN_PROFILE_ID,
    version: FileVersion::KNOWN,
    top_level_class: TOP_LEVEL_CLASS,
    composer_class: COMPOSER_CLASS,
    composer_automation_id: COMPOSER_AUTOMATION_ID,
    composer_control_type: UIA_DOCUMENT_CONTROL_TYPE,
    empty_placeholder_utf16_sha256: KNOWN_EMPTY_PLACEHOLDER_UTF16_SHA256,
    empty_control_utf16: [0x000D, 0x000D],
    set_value_appends_carriage_return: true,
    submit_strategy: Some(SubmitStrategy::ForegroundQueuedComposerEnterV3),
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

    fn executable(self, utf16_path: &[u16], creation_time_100ns: u64) -> String {
        let mut bytes = Vec::with_capacity(utf16_path.len() * 2);
        for unit in utf16_path {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        self.digest(
            b"executable-instance",
            &[&bytes, &creation_time_100ns.to_le_bytes()],
        )
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
    creation_time_100ns: u64,
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
    NotInspected(ReadOnlyCandidateBlockers),
    Absent(Option<ReadOnlyComposerSelectorEvidence>),
    Unique(NativeComposer),
    Ambiguous(usize),
}

#[derive(Clone, PartialEq, Eq)]
struct NativeWindow {
    fingerprint: String,
    visible: bool,
    enabled: bool,
    modal_present: bool,
    process: NativeProcess,
    composer: ComposerDiscovery,
}

#[derive(Clone, PartialEq, Eq)]
enum WindowDiscovery {
    Absent,
    Unique(NativeWindow),
    Ambiguous {
        count: usize,
        reason: ReadOnlyWindowAmbiguity,
    },
}

/// Narrows read-only discovery without treating a shared KakaoTalk window
/// class as target identity. With multiple exact-class windows, selection is
/// allowed only when one window has one exact composer and every other window
/// has no exact composer. Any duplicate composer evidence remains ambiguous.
///
/// This helper is deliberately not used by the mutation path, which retains
/// its stricter requirement that native enumeration itself return one window.
#[cfg(test)]
fn select_read_only_window(mut candidates: Vec<NativeWindow>) -> WindowDiscovery {
    match classify_read_only_windows(&candidates) {
        ReadOnlyWindowSelection::Absent => WindowDiscovery::Absent,
        ReadOnlyWindowSelection::Unique(index) => {
            WindowDiscovery::Unique(candidates.swap_remove(index))
        }
        ReadOnlyWindowSelection::Ambiguous { count, reason } => {
            WindowDiscovery::Ambiguous { count, reason }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadOnlyWindowSelection {
    Absent,
    Unique(usize),
    Ambiguous {
        count: usize,
        reason: ReadOnlyWindowAmbiguity,
    },
}

/// Classifies without consuming candidates so the native worker can retain
/// the selected candidate's HWND only until its ephemeral label comparison is
/// complete. Native handles still never enter a platform-neutral snapshot.
fn classify_read_only_windows(candidates: &[NativeWindow]) -> ReadOnlyWindowSelection {
    match candidates.len() {
        0 => ReadOnlyWindowSelection::Absent,
        1 => ReadOnlyWindowSelection::Unique(0),
        candidate_count => {
            let mut selected_index = None;
            let mut unique_count = 0_usize;
            let mut composer_ambiguous = false;
            let mut candidate_blockers: Option<ReadOnlyCandidateBlockers> = None;
            for (index, candidate) in candidates.iter().enumerate() {
                match &candidate.composer {
                    ComposerDiscovery::Unique(_) => {
                        unique_count += 1;
                        selected_index.get_or_insert(index);
                    }
                    ComposerDiscovery::Ambiguous(_) => composer_ambiguous = true,
                    ComposerDiscovery::NotInspected(blockers) => {
                        candidate_blockers = Some(
                            candidate_blockers
                                .map_or(*blockers, |aggregate| aggregate.union(*blockers)),
                        );
                    }
                    ComposerDiscovery::Absent(_) => {}
                }
            }

            // Use a fixed priority independent of EnumWindows ordering. An
            // internally ambiguous selector is strongest, followed by a
            // duplicate exact selector, an uninspected candidate, and finally
            // the all-absent case.
            let reason = if composer_ambiguous {
                Some(ReadOnlyWindowAmbiguity::ComposerAmbiguous)
            } else if unique_count > 1 {
                Some(ReadOnlyWindowAmbiguity::DuplicateComposer)
            } else if let Some(blockers) = candidate_blockers {
                Some(ReadOnlyWindowAmbiguity::CandidateNotInspected(blockers))
            } else if unique_count == 0 {
                Some(ReadOnlyWindowAmbiguity::NoComposer)
            } else {
                None
            };

            reason.map_or_else(
                || {
                    ReadOnlyWindowSelection::Unique(
                        selected_index.expect("one unique composer has a selected index"),
                    )
                },
                |reason| ReadOnlyWindowSelection::Ambiguous {
                    count: candidate_count,
                    reason,
                },
            )
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct NativeInspection {
    window: WindowDiscovery,
}

enum ReadOnlyProbeEvent<T> {
    CancellationReady(u32),
    Complete(Result<T, UiError>),
}

/// Process-wide single-flight guard for the detached read-only worker. A
/// cancellation request may be unsupported or may not stop provider-side
/// work, so a timed-out worker retains this lease until it actually returns.
/// This prevents repeated probes (including through newly constructed
/// backends) from accumulating workers.
struct ReadOnlyProbeLease<'flag>(&'flag AtomicBool);

impl<'flag> ReadOnlyProbeLease<'flag> {
    fn claim(flag: &'flag AtomicBool) -> Result<Self, UiError> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self(flag))
            .map_err(|_| read_only_timeout_error())
    }
}

impl Drop for ReadOnlyProbeLease<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn read_only_timeout_error() -> UiError {
    let mut error = UiError::new(UiErrorKind::Timeout, "windows_read_only_inspect");
    error.retry_safe = false;
    error
}

fn read_only_worker_failed_error() -> UiError {
    UiError::new(
        UiErrorKind::UnsupportedCapability,
        "windows_probe_thread_failed",
    )
}

fn remaining_inspection_timeout(budget: Duration, elapsed: Duration) -> Duration {
    budget.saturating_sub(elapsed)
}

fn finish_read_only_probe<T>(
    worker: std::thread::JoinHandle<()>,
    release_sender: mpsc::Sender<()>,
    result: Result<T, UiError>,
) -> Result<T, UiError> {
    // The worker waits only to keep its thread ID alive until the caller has
    // either consumed the result or attempted cancellation. Dropping the last
    // sender releases that wait before the join.
    drop(release_sender);
    worker.join().map_err(|_| read_only_worker_failed_error())?;
    result
}

fn await_read_only_probe<T>(
    started: Instant,
    timeout: Duration,
    worker: std::thread::JoinHandle<()>,
    release_sender: mpsc::Sender<()>,
    inspection_sender: mpsc::Sender<()>,
    event_receiver: mpsc::Receiver<ReadOnlyProbeEvent<T>>,
    cancel: impl FnOnce(u32),
) -> Result<T, UiError> {
    let first =
        event_receiver.recv_timeout(remaining_inspection_timeout(timeout, started.elapsed()));
    let thread_id = match first {
        Ok(ReadOnlyProbeEvent::Complete(result)) => {
            return finish_read_only_probe(worker, release_sender, result);
        }
        Ok(ReadOnlyProbeEvent::CancellationReady(thread_id)) => thread_id,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // Close the inspection permit before releasing the worker. A
            // readiness event racing this timeout can then never authorize
            // native inspection after the caller has returned.
            drop(inspection_sender);
            drop(release_sender);
            drop(worker);
            return Err(read_only_timeout_error());
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            return finish_read_only_probe(
                worker,
                release_sender,
                Err(read_only_worker_failed_error()),
            );
        }
    };

    if inspection_sender.send(()).is_err() {
        return finish_read_only_probe(
            worker,
            release_sender,
            Err(read_only_worker_failed_error()),
        );
    }
    drop(inspection_sender);

    match event_receiver.recv_timeout(remaining_inspection_timeout(timeout, started.elapsed())) {
        Ok(ReadOnlyProbeEvent::Complete(result)) => {
            finish_read_only_probe(worker, release_sender, result)
        }
        Ok(ReadOnlyProbeEvent::CancellationReady(_)) => {
            // Production emits readiness exactly once. Preserve the first
            // thread ID, request cancellation while that worker is pinned,
            // and refuse this inconsistent event stream.
            cancel(thread_id);
            drop(release_sender);
            drop(worker);
            Err(read_only_worker_failed_error())
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // The release sender deliberately stays alive through this call
            // so the target thread ID cannot be recycled underneath
            // CoCancelCall. Failure or unsupported custom marshaling keeps
            // the existing single-flight lease until the worker returns.
            cancel(thread_id);
            drop(release_sender);
            drop(worker);
            Err(read_only_timeout_error())
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            finish_read_only_probe(worker, release_sender, Err(read_only_worker_failed_error()))
        }
    }
}

#[cfg(any(feature = "windows-ui-write", test))]
fn mutation_thread_uncertainty_error() -> UiError {
    UiError::new(
        UiErrorKind::SubmissionUncertain,
        "windows_transaction_thread_uncertain",
    )
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
    fn inspect_on_mta(&self, request: InspectRequest) -> Result<UiSnapshot, UiError> {
        let probe_lease = ReadOnlyProbeLease::claim(&READ_ONLY_PROBE_IN_FLIGHT)?;
        let fingerprints = self.fingerprints;
        let observe_target_label = request.requires_target_binding();
        let target_kind = request.target;
        let started = Instant::now();
        let (event_sender, event_receiver) =
            mpsc::sync_channel::<ReadOnlyProbeEvent<UiSnapshot>>(1);
        let (release_sender, release_receiver) = mpsc::channel::<()>();
        let (inspection_sender, inspection_receiver) = mpsc::channel::<()>();
        let spawn_result = std::thread::Builder::new()
            .name("openkakao-windows-probe".to_string())
            .spawn(move || {
                // Keep a post-readiness panic from letting the OS recycle this
                // thread ID before the caller has made its cancellation
                // decision. Native RAII guards still unwind before the fixed
                // error is published.
                let rebind_request = request.clone_for_worker();
                let result = catch_unwind(AssertUnwindSafe(|| {
                    native::inspect(
                        fingerprints,
                        observe_target_label,
                        |thread_id| {
                            event_sender
                                .send(ReadOnlyProbeEvent::CancellationReady(thread_id))
                                .map_err(|_| read_only_worker_failed_error())?;
                            inspection_receiver
                                .recv()
                                .map_err(|_| read_only_worker_failed_error())?;
                            if started.elapsed() >= INSPECTION_TIMEOUT {
                                return Err(read_only_timeout_error());
                            }
                            Ok(())
                        },
                        |native, observed_label_utf16| {
                            bind_observed_target(
                                map_native(target_kind, native, unix_now_ms()),
                                &request,
                                observed_label_utf16,
                            )
                        },
                        |snapshot, observed_label_utf16| {
                            rebind_observed_target_after_draft(
                                snapshot,
                                &rebind_request,
                                observed_label_utf16,
                            )
                        },
                    )
                }))
                .unwrap_or_else(|_| Err(read_only_worker_failed_error()));
                let _ = event_sender.send(ReadOnlyProbeEvent::Complete(result));

                // Keep this OS thread alive until the caller has either
                // consumed completion or issued its one cancellation request.
                // This prevents thread-ID reuse from targeting an unrelated
                // COM call during the timeout race.
                let _ = release_receiver.recv();
                drop(probe_lease);
            });
        let worker = match spawn_result {
            Ok(worker) => worker,
            Err(_) => {
                // `spawn` owns and drops its closure on failure, so the
                // captured lease clears the flag without a racy manual store.
                return Err(UiError::new(
                    UiErrorKind::UnsupportedCapability,
                    "windows_probe_thread_start",
                ));
            }
        };

        await_read_only_probe(
            started,
            INSPECTION_TIMEOUT,
            worker,
            release_sender,
            inspection_sender,
            event_receiver,
            |thread_id| {
                let _ = native::cancel_read_only_call(thread_id);
            },
        )
    }

    #[cfg(feature = "windows-ui-write")]
    fn mutation_on_mta(
        &self,
        approved: &ApprovedSend,
        mode: super::SendMode,
    ) -> Result<SendOutcome, UiError> {
        let expected = transaction::ExpectedState::from_approved(approved, mode, unix_now_ms())?;
        let fingerprints = self.fingerprints;

        // Unlike read-only inspection, a mutation worker is scoped and always
        // joined. Returning while a detached UIA call could still mutate would
        // make the outcome unknowable and allow unsafe caller behavior.
        std::thread::scope(|scope| {
            let worker = std::thread::Builder::new()
                .name("openkakao-windows-transaction".to_string())
                .spawn_scoped(scope, move || match mode {
                    super::SendMode::StageOnly => native::stage(fingerprints, approved, &expected),
                    super::SendMode::Commit => native::commit(fingerprints, approved, &expected),
                    super::SendMode::DryRun => Err(UiError::new(
                        UiErrorKind::InvalidInput,
                        "windows_transaction_mode",
                    )),
                })
                .map_err(|_| {
                    UiError::new(
                        UiErrorKind::UnsupportedCapability,
                        "windows_transaction_thread_start",
                    )
                })?;
            worker
                .join()
                .map_err(|_| mutation_thread_uncertainty_error())?
        })
    }
}

impl PlatformProbe for WindowsBackend {
    fn capabilities(&self) -> UiCapabilities {
        #[cfg(feature = "windows-ui-write")]
        {
            UiCapabilities::windows_guarded_write()
        }
        #[cfg(not(feature = "windows-ui-write"))]
        {
            UiCapabilities::windows_read_only()
        }
    }

    fn inspect(&self, request: &InspectRequest) -> Result<UiSnapshot, UiError> {
        if request.target != TargetKind::SelfChat {
            return Err(UiError::new(
                UiErrorKind::TargetNotSelf,
                "windows_inspect_target",
            ));
        }

        self.inspect_on_mta(request.clone_for_worker())
    }
}

impl super::contract::message_sender_seal::Sealed for WindowsBackend {}

impl MessageSender for WindowsBackend {
    fn stage(&self, approved: &ApprovedSend) -> Result<SendOutcome, UiError> {
        #[cfg(feature = "windows-ui-write")]
        {
            self.mutation_on_mta(approved, super::SendMode::StageOnly)
        }
        #[cfg(not(feature = "windows-ui-write"))]
        {
            let _ = approved;
            Err(UiError::new(
                UiErrorKind::UnsupportedCapability,
                "windows_ui_write_feature_disabled",
            ))
        }
    }

    fn commit(&self, approved: &ApprovedSend) -> Result<SendOutcome, UiError> {
        #[cfg(feature = "windows-ui-write")]
        {
            self.mutation_on_mta(approved, super::SendMode::Commit)
        }
        #[cfg(not(feature = "windows-ui-write"))]
        {
            let _ = approved;
            Err(UiError::new(
                UiErrorKind::UnsupportedCapability,
                "windows_ui_write_feature_disabled",
            ))
        }
    }
}

pub(super) fn unix_now_ms() -> u64 {
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
        WindowDiscovery::Absent => empty_snapshot(target_kind, 0, None, observed_at, expires_at),
        WindowDiscovery::Ambiguous { count, reason } => {
            empty_snapshot(target_kind, count, Some(reason), observed_at, expires_at)
        }
        WindowDiscovery::Unique(window) => {
            map_unique_window(target_kind, window, observed_at, expires_at)
        }
    }
}

/// Converts one ephemeral, uniquely selected live label into request-scoped
/// evidence. The label is borrowed only while the native COM worker owns its
/// scrub-on-drop buffer; this function never decodes, formats, or retains it.
fn bind_observed_target(
    mut snapshot: UiSnapshot,
    request: &InspectRequest,
    observed_label_utf16: Option<&[u16]>,
) -> UiSnapshot {
    if !request.requires_target_binding()
        || snapshot.target.kind != TargetKind::SelfChat
        || snapshot.target.window.is_none()
        || snapshot.target.composer.is_none()
        || !snapshot.input.present
        || !snapshot.input.unique
    {
        return snapshot;
    }

    let Some(observed_label_utf16) = observed_label_utf16 else {
        return snapshot;
    };

    // The native side supplies a label only after selecting one exact-profile
    // root/composer path. Preserve that unique-but-inexact state on mismatch.
    snapshot.target.unique_match = true;
    snapshot.target.self_chat_verified = true;
    snapshot.target.exact_match = true;
    snapshot.target.target_binding =
        request.bind_observed_target_utf16(observed_label_utf16, &snapshot);
    if snapshot.target.target_binding.is_none() {
        snapshot.target.self_chat_verified = false;
        snapshot.target.exact_match = false;
    }
    snapshot
}

fn bound_snapshot_authorizes_draft_read(snapshot: &UiSnapshot) -> bool {
    snapshot.target.kind == TargetKind::SelfChat
        && snapshot.target.self_chat_verified
        && snapshot.target.exact_match
        && snapshot.target.unique_match
        && snapshot.target.target_binding.is_some()
        && snapshot.input.present
        && snapshot.input.unique
        && snapshot.input.enabled
        && snapshot.input.writable
        && !snapshot.input.focused
}

/// Rebinds the final snapshot from a second root-Name observation made after
/// the draft read. A mismatch is returned only as a fixed refusal, so the
/// empty/nonempty bit read from a concurrently selected room is never emitted.
fn rebind_observed_target_after_draft(
    snapshot: UiSnapshot,
    request: &InspectRequest,
    observed_label_utf16: &[u16],
) -> Result<UiSnapshot, UiError> {
    let rebound = bind_observed_target(snapshot, request, Some(observed_label_utf16));
    if !bound_snapshot_authorizes_draft_read(&rebound) {
        return Err(UiError::new(
            UiErrorKind::TargetNotSelf,
            "windows_target_changed_during_draft_read",
        ));
    }
    Ok(rebound)
}

fn empty_snapshot(
    target_kind: TargetKind,
    window_count: usize,
    read_only_window_ambiguity: Option<ReadOnlyWindowAmbiguity>,
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
            read_only_window_ambiguity,
            read_only_composer_selector_evidence: None,
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
            target_binding: None,
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
    let modal_present = process_verified && window.modal_present;

    let process = process_verified.then(|| ProcessFingerprint {
        pid: window.process.pid,
        executable: window.process.executable_fingerprint.clone(),
        session_id: Some(window.process.session_id),
    });

    let mut composer_selector_evidence = None;
    let (input, composer) = if modal_present {
        (unavailable_input(profile.map(|profile| profile.id)), None)
    } else if let Some(profile) = profile {
        match window.composer {
            ComposerDiscovery::Unique(composer) => (
                InputSnapshot {
                    present: true,
                    unique: true,
                    enabled: composer.enabled,
                    writable: composer.value_pattern_present && composer.writable,
                    // The mapper starts fail-closed. A bound native inspection
                    // may replace this with the sole empty/nonempty bit only
                    // after an exact ephemeral target-label match.
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
            ComposerDiscovery::Absent(evidence) => {
                composer_selector_evidence = evidence;
                (unavailable_input(Some(profile.id)), None)
            }
            ComposerDiscovery::NotInspected(_) => (unavailable_input(Some(profile.id)), None),
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
            read_only_window_ambiguity: None,
            read_only_composer_selector_evidence: composer_selector_evidence,
            modal_present,
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
            target_binding: None,
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
    use std::sync::Arc;

    fn process(version: Option<FileVersion>) -> NativeProcess {
        NativeProcess {
            pid: 42,
            executable_fingerprint: "run:synthetic-process".to_string(),
            creation_time_100ns: 123,
            executable_verified: true,
            version,
            session_id: 3,
            interactive_session_match: true,
            integrity_compatible: true,
        }
    }

    fn window(version: Option<FileVersion>, composer: ComposerDiscovery) -> NativeWindow {
        window_with_fingerprint("run:synthetic-window", version, composer)
    }

    fn profile_unknown_blocker() -> ReadOnlyCandidateBlockers {
        ReadOnlyCandidateBlockers::from_observation(true, false, true, true, false, true, true)
    }

    fn absent_composer() -> ComposerDiscovery {
        ComposerDiscovery::Absent(Some(ReadOnlyComposerSelectorEvidence::from_near_matches(
            false, false, false,
        )))
    }

    fn window_with_fingerprint(
        fingerprint: &str,
        version: Option<FileVersion>,
        composer: ComposerDiscovery,
    ) -> NativeWindow {
        NativeWindow {
            fingerprint: fingerprint.to_string(),
            visible: true,
            enabled: true,
            modal_present: false,
            process: process(version),
            composer,
        }
    }

    #[test]
    fn selector_is_exact_and_case_sensitive() {
        assert_eq!(
            KNOWN_PROFILE.id,
            crate::safety::SUPPORTED_SELECTOR_PROFILE_ID
        );
        assert!(KNOWN_PROFILE.matches_selector("RICHEDIT50W", "1006", 50_030));
        assert!(!KNOWN_PROFILE.matches_selector("richedit50w", "1006", 50_030));
        assert!(!KNOWN_PROFILE.matches_selector("RICHEDIT50W", "1006 ", 50_030));
        assert!(!KNOWN_PROFILE.matches_selector("RICHEDIT50W", "1006", 50_004));
        assert!(!KNOWN_PROFILE.matches_selector("RICHEDIT50W", "1006", 50_000));

        let candidates = [
            ("RICHEDIT50W", "1006", 50_030),
            ("richedit50w", "1006", 50_030),
            ("RICHEDIT50W", "1006", 50_030),
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
    fn empty_placeholder_digest_is_exact_domain_separated_and_profile_bound() {
        let units: Vec<u16> = "SYNTHETIC_EMPTY_CHROME".encode_utf16().collect();
        let profile = UiProfile {
            empty_placeholder_utf16_sha256: empty_placeholder_utf16_digest(&units),
            ..KNOWN_PROFILE
        };
        assert!(profile.matches_empty_placeholder(&units));

        let changed: Vec<u16> = "SYNTHETIC_EMPTY_CHROME ".encode_utf16().collect();
        assert!(!profile.matches_empty_placeholder(&changed));
        assert!(!KNOWN_PROFILE.matches_empty_placeholder(&units));
    }

    #[test]
    fn empty_provider_control_value_is_exactly_two_carriage_returns() {
        assert!(KNOWN_PROFILE.matches_empty_provider_value(&[u16::from(b'\r'), u16::from(b'\r'),]));
        assert!(!KNOWN_PROFILE.matches_empty_provider_value(&[u16::from(b'\r')]));
        assert!(!KNOWN_PROFILE.matches_empty_provider_value(&[u16::from(b'\r'), u16::from(b'\n'),]));
    }

    #[test]
    fn staged_value_accepts_only_exact_or_profile_carriage_return_form() {
        let expected: Vec<u16> = "SYNTHETIC_MESSAGE".encode_utf16().collect();
        assert!(KNOWN_PROFILE.matches_staged_value(&expected, &expected));

        let mut provider_form = expected.clone();
        provider_form.push(u16::from(b'\r'));
        assert!(KNOWN_PROFILE.matches_staged_value(&provider_form, &expected));

        let mut line_feed = expected.clone();
        line_feed.push(u16::from(b'\n'));
        assert!(!KNOWN_PROFILE.matches_staged_value(&line_feed, &expected));

        let mut extra = expected.clone();
        extra.extend([u16::from(b'\r'), u16::from(b'\r')]);
        assert!(!KNOWN_PROFILE.matches_staged_value(&extra, &expected));
    }

    #[test]
    fn read_only_probe_is_single_flight_and_timeout_is_not_retryable() {
        let in_flight = AtomicBool::new(false);
        let first = ReadOnlyProbeLease::claim(&in_flight)
            .expect("the first synthetic probe lease must be available");

        let error = match ReadOnlyProbeLease::claim(&in_flight) {
            Ok(_) => panic!("a second synthetic probe lease must fail closed"),
            Err(error) => error,
        };
        assert_eq!(error.kind, UiErrorKind::Timeout);
        assert_eq!(error.operation, "windows_read_only_inspect");
        assert!(!error.retry_safe);

        drop(first);
        assert!(ReadOnlyProbeLease::claim(&in_flight).is_ok());
        assert!(!read_only_timeout_error().retry_safe);
    }

    #[test]
    fn read_only_probe_startup_and_inspection_share_one_timeout_budget() {
        assert_eq!(
            remaining_inspection_timeout(INSPECTION_TIMEOUT, Duration::ZERO),
            INSPECTION_TIMEOUT
        );
        assert_eq!(
            remaining_inspection_timeout(
                INSPECTION_TIMEOUT,
                INSPECTION_TIMEOUT - Duration::from_millis(1)
            ),
            Duration::from_millis(1)
        );
        assert_eq!(
            remaining_inspection_timeout(INSPECTION_TIMEOUT, INSPECTION_TIMEOUT),
            Duration::ZERO
        );
        assert_eq!(
            remaining_inspection_timeout(
                INSPECTION_TIMEOUT,
                INSPECTION_TIMEOUT + Duration::from_secs(1)
            ),
            Duration::ZERO
        );
    }

    #[test]
    fn read_only_timeout_cancels_before_releasing_the_worker_thread() {
        let (event_sender, event_receiver) = mpsc::sync_channel::<ReadOnlyProbeEvent<()>>(1);
        let (release_sender, release_receiver) = mpsc::channel();
        let (inspection_sender, inspection_receiver) = mpsc::channel();
        let (published_sender, published_receiver) = mpsc::sync_channel(0);
        let (done_sender, done_receiver) = mpsc::sync_channel(0);
        let released = Arc::new(AtomicBool::new(false));
        let released_by_worker = Arc::clone(&released);

        let worker = std::thread::spawn(move || {
            event_sender
                .send(ReadOnlyProbeEvent::CancellationReady(42))
                .expect("the synthetic readiness receiver must remain live");
            published_sender
                .send(())
                .expect("the synthetic publication receiver must remain live");
            inspection_receiver
                .recv()
                .expect("the synthetic inspection permit must be published");
            let _ = release_receiver.recv();
            released_by_worker.store(true, Ordering::Release);
            let _ = done_sender.send(());
        });
        published_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("the synthetic worker must publish readiness");

        let cancellation_called = Arc::new(AtomicBool::new(false));
        let cancellation_observation = Arc::clone(&cancellation_called);
        let released_during_cancellation = Arc::clone(&released);
        let started = Instant::now();
        let error = match await_read_only_probe(
            started,
            Duration::ZERO,
            worker,
            release_sender,
            inspection_sender,
            event_receiver,
            move |thread_id| {
                assert_eq!(thread_id, 42);
                assert!(!released_during_cancellation.load(Ordering::Acquire));
                assert!(!cancellation_observation.swap(true, Ordering::AcqRel));
            },
        ) {
            Ok(_) => panic!("an expired synthetic probe must time out"),
            Err(error) => error,
        };

        assert_eq!(error.kind, UiErrorKind::Timeout);
        assert!(!error.retry_safe);
        assert!(cancellation_called.load(Ordering::Acquire));
        done_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("the synthetic worker must be released after cancellation");
        assert!(released.load(Ordering::Acquire));
    }

    #[test]
    fn read_only_timeout_before_readiness_closes_the_inspection_permit() {
        let (event_sender, event_receiver) = mpsc::sync_channel::<ReadOnlyProbeEvent<()>>(1);
        let (release_sender, release_receiver) = mpsc::channel();
        let (inspection_sender, inspection_receiver) = mpsc::channel();
        let (done_sender, done_receiver) = mpsc::sync_channel(0);

        let worker = std::thread::spawn(move || {
            let _event_sender = event_sender;
            assert!(inspection_receiver.recv().is_err());
            assert!(release_receiver.recv().is_err());
            let _ = done_sender.send(());
        });
        let error = match await_read_only_probe(
            Instant::now(),
            Duration::ZERO,
            worker,
            release_sender,
            inspection_sender,
            event_receiver,
            |_| panic!("a worker without readiness must not be cancelled"),
        ) {
            Ok(_) => panic!("an unready synthetic probe must time out"),
            Err(error) => error,
        };

        assert_eq!(error.kind, UiErrorKind::Timeout);
        assert!(!error.retry_safe);
        done_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("both synthetic worker gates must close after timeout");
    }

    #[test]
    fn mutation_worker_panic_is_always_nonretryable_uncertainty() {
        let error = mutation_thread_uncertainty_error();
        assert_eq!(error.kind, UiErrorKind::SubmissionUncertain);
        assert_eq!(error.operation, "windows_transaction_thread_uncertain");
        assert!(!error.retry_safe);
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
                window: WindowDiscovery::Ambiguous {
                    count: 2,
                    reason: ReadOnlyWindowAmbiguity::CandidateLimit,
                },
            },
            10,
        );
        assert!(!ambiguous.app.app_running);
        assert_eq!(ambiguous.app.top_level_window_count, 2);
        assert_eq!(
            ambiguous.app.read_only_window_ambiguity,
            Some(ReadOnlyWindowAmbiguity::CandidateLimit)
        );
        assert!(ambiguous.target.window.is_none());
    }

    #[test]
    fn read_only_discovery_narrows_multiple_windows_by_exact_unique_composer() {
        let selected = select_read_only_window(vec![
            window_with_fingerprint(
                "run:non-composer-window",
                Some(FileVersion::KNOWN),
                absent_composer(),
            ),
            window_with_fingerprint(
                "run:exact-composer-window",
                Some(FileVersion::KNOWN),
                ComposerDiscovery::Unique(NativeComposer {
                    fingerprint: "run:exact-composer".to_string(),
                    enabled: true,
                    value_pattern_present: true,
                    writable: true,
                    focused: false,
                }),
            ),
            window_with_fingerprint(
                "run:second-non-composer-window",
                Some(FileVersion::KNOWN),
                absent_composer(),
            ),
        ]);

        let WindowDiscovery::Unique(window) = selected else {
            panic!("one exact unique composer must select one diagnostic window");
        };
        assert_eq!(window.fingerprint, "run:exact-composer-window");

        let snapshot = map_native(
            TargetKind::SelfChat,
            NativeInspection {
                window: WindowDiscovery::Unique(window),
            },
            25,
        );
        assert_eq!(snapshot.app.top_level_window_count, 1);
        assert!(snapshot.input.unique);
        assert!(!snapshot.target.self_chat_verified);
        assert!(!snapshot.target.exact_match);
        assert!(!snapshot.target.unique_match);
    }

    #[test]
    fn read_only_discovery_keeps_duplicate_or_uncertain_composers_ambiguous() {
        let exact_composer = || {
            ComposerDiscovery::Unique(NativeComposer {
                fingerprint: "run:synthetic-composer".to_string(),
                enabled: true,
                value_pattern_present: true,
                writable: true,
                focused: false,
            })
        };

        for (candidates, expected_reason) in [
            (
                vec![
                    window(Some(FileVersion::KNOWN), exact_composer()),
                    window(Some(FileVersion::KNOWN), exact_composer()),
                ],
                ReadOnlyWindowAmbiguity::DuplicateComposer,
            ),
            (
                vec![
                    window(Some(FileVersion::KNOWN), exact_composer()),
                    window(Some(FileVersion::KNOWN), ComposerDiscovery::Ambiguous(2)),
                ],
                ReadOnlyWindowAmbiguity::ComposerAmbiguous,
            ),
            (
                vec![
                    window(Some(FileVersion::KNOWN), absent_composer()),
                    window(
                        None,
                        ComposerDiscovery::NotInspected(profile_unknown_blocker()),
                    ),
                ],
                ReadOnlyWindowAmbiguity::CandidateNotInspected(profile_unknown_blocker()),
            ),
            (
                vec![
                    window(Some(FileVersion::KNOWN), exact_composer()),
                    window(
                        None,
                        ComposerDiscovery::NotInspected(profile_unknown_blocker()),
                    ),
                ],
                ReadOnlyWindowAmbiguity::CandidateNotInspected(profile_unknown_blocker()),
            ),
            (
                vec![
                    window(Some(FileVersion::KNOWN), absent_composer()),
                    window(
                        Some(FileVersion::KNOWN),
                        ComposerDiscovery::NotInspected(
                            ReadOnlyCandidateBlockers::from_observation(
                                true, true, true, true, false, true, true,
                            ),
                        ),
                    ),
                ],
                ReadOnlyWindowAmbiguity::CandidateNotInspected(
                    ReadOnlyCandidateBlockers::from_observation(
                        true, true, true, true, false, true, true,
                    ),
                ),
            ),
            (
                vec![
                    window(Some(FileVersion::KNOWN), absent_composer()),
                    window(Some(FileVersion::KNOWN), absent_composer()),
                ],
                ReadOnlyWindowAmbiguity::NoComposer,
            ),
        ] {
            let WindowDiscovery::Ambiguous { count, reason } = select_read_only_window(candidates)
            else {
                panic!("duplicate or uncertain composers must remain ambiguous");
            };
            assert_eq!(count, 2);
            assert_eq!(reason, expected_reason);
        }
    }

    #[test]
    fn read_only_ambiguity_reason_priority_is_independent_of_candidate_order() {
        let exact_composer = || {
            ComposerDiscovery::Unique(NativeComposer {
                fingerprint: "run:synthetic-composer".to_string(),
                enabled: true,
                value_pattern_present: true,
                writable: true,
                focused: false,
            })
        };
        let candidates = vec![
            window(Some(FileVersion::KNOWN), exact_composer()),
            window(
                None,
                ComposerDiscovery::NotInspected(profile_unknown_blocker()),
            ),
            window(Some(FileVersion::KNOWN), exact_composer()),
            window(Some(FileVersion::KNOWN), ComposerDiscovery::Ambiguous(2)),
        ];

        for candidates in [candidates.clone(), candidates.into_iter().rev().collect()] {
            let WindowDiscovery::Ambiguous { count, reason } = select_read_only_window(candidates)
            else {
                panic!("mixed uncertainty must remain ambiguous");
            };
            assert_eq!(count, 4);
            assert_eq!(reason, ReadOnlyWindowAmbiguity::ComposerAmbiguous);
        }
    }

    #[test]
    fn unknown_version_gates_composer_snapshot() {
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
                    ComposerDiscovery::NotInspected(profile_unknown_blocker()),
                )),
            },
            20,
        );

        assert!(snapshot.app.app_running);
        assert!(!snapshot.app.known_ui_profile);
        assert!(!snapshot.input.present);
        assert!(!snapshot.input.writable);
        assert!(snapshot.input.selector_profile_id.is_none());
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
        assert!(snapshot.app.read_only_composer_selector_evidence.is_none());
        assert_eq!(snapshot.app.app_version.as_deref(), Some("26.7.0.5255"));
        assert!(!snapshot.target.exact_match);
        assert!(!snapshot.target.unique_match);
        assert!(!snapshot.target.self_chat_verified);
        assert!(snapshot.target.target_binding.is_none());
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
    fn exact_ephemeral_target_label_mints_only_redacted_state_bound_evidence() {
        const LABEL: &str = "SYNTHETIC_SELF_TARGET";
        let (request, permit) = InspectRequest::bound_self_chat(LABEL, [0x61; 32]);
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
            40,
        );
        let observed: Vec<u16> = LABEL.encode_utf16().collect();
        let bound = bind_observed_target(snapshot, &request, Some(&observed));

        assert!(bound.target.self_chat_verified);
        assert!(bound.target.exact_match);
        assert!(bound.target.unique_match);
        assert!(bound.target.target_binding.is_some());
        assert!(permit.verifies_snapshot(&bound));
        assert!(bound_snapshot_authorizes_draft_read(&bound));
        let mut user_active = bound.clone();
        user_active.input.focused = true;
        assert!(!bound_snapshot_authorizes_draft_read(&user_active));
        let mut draft_observed = bound.clone();
        draft_observed.input.draft_empty = true;
        assert!(!permit.verifies_snapshot(&draft_observed));
        let draft_observed =
            rebind_observed_target_after_draft(draft_observed, &request, &observed)
                .expect("a second exact observation must bind the changed snapshot");
        assert!(permit.verifies_snapshot(&draft_observed));
        assert!(draft_observed.input.draft_empty);

        let mut changed_during_read = bound.clone();
        changed_during_read.input.draft_empty = true;
        let different: Vec<u16> = "SYNTHETIC_DIFFERENT_TARGET".encode_utf16().collect();
        let error = rebind_observed_target_after_draft(changed_during_read, &request, &different)
            .expect_err("a target change during the draft read must fail closed");
        assert_eq!(error.kind, UiErrorKind::TargetNotSelf);
        assert_eq!(error.operation, "windows_target_changed_during_draft_read");
        let json = serde_json::to_string(&bound).expect("snapshot must serialize");
        assert!(!json.contains(LABEL));
        assert!(!json.contains("target_binding"));
    }

    #[test]
    fn mismatched_or_unrequested_target_label_never_claims_exact_self_chat() {
        const EXPECTED: &str = "SYNTHETIC_EXPECTED_TARGET";
        let make_snapshot = || {
            map_native(
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
                41,
            )
        };
        let (request, permit) = InspectRequest::bound_self_chat(EXPECTED, [0x62; 32]);
        let wrong: Vec<u16> = "SYNTHETIC_OTHER_TARGET".encode_utf16().collect();
        let mismatched = bind_observed_target(make_snapshot(), &request, Some(&wrong));
        assert!(!mismatched.target.self_chat_verified);
        assert!(!mismatched.target.exact_match);
        assert!(mismatched.target.unique_match);
        assert!(mismatched.target.target_binding.is_none());
        assert!(!permit.verifies_snapshot(&mismatched));
        assert!(!bound_snapshot_authorizes_draft_read(&mismatched));

        let unbound =
            bind_observed_target(make_snapshot(), &InspectRequest::self_chat(), Some(&wrong));
        assert!(!unbound.target.self_chat_verified);
        assert!(!unbound.target.exact_match);
        assert!(!unbound.target.unique_match);
        assert!(unbound.target.target_binding.is_none());
        assert!(!bound_snapshot_authorizes_draft_read(&unbound));
    }

    #[test]
    fn absent_composer_retains_only_bounded_selector_near_match_evidence() {
        let evidence = ReadOnlyComposerSelectorEvidence::from_near_matches(true, false, true);
        let snapshot = map_native(
            TargetKind::SelfChat,
            NativeInspection {
                window: WindowDiscovery::Unique(window(
                    Some(FileVersion::KNOWN),
                    ComposerDiscovery::Absent(Some(evidence)),
                )),
            },
            30,
        );

        assert_eq!(
            snapshot.app.read_only_composer_selector_evidence,
            Some(evidence)
        );
        assert!(snapshot.target.window.is_some());
        assert!(snapshot.target.composer.is_none());
        assert!(!snapshot.input.present);
        assert_eq!(
            snapshot.input.selector_profile_id.as_deref(),
            Some(KNOWN_PROFILE.id)
        );
    }

    #[test]
    fn modal_evidence_suppresses_composer_identity_and_input_evidence() {
        let mut native_window = window(
            Some(FileVersion::KNOWN),
            ComposerDiscovery::Unique(NativeComposer {
                fingerprint: "run:synthetic-composer".to_string(),
                enabled: true,
                value_pattern_present: true,
                writable: true,
                focused: false,
            }),
        );
        native_window.modal_present = true;

        let snapshot = map_native(
            TargetKind::SelfChat,
            NativeInspection {
                window: WindowDiscovery::Unique(native_window),
            },
            31,
        );

        assert!(snapshot.app.modal_present);
        assert!(snapshot.app.known_ui_profile);
        assert!(snapshot.app.read_only_composer_selector_evidence.is_none());
        assert!(snapshot.target.composer.is_none());
        assert!(!snapshot.input.present);
        assert!(!snapshot.input.unique);
        assert!(!snapshot.input.enabled);
        assert!(!snapshot.input.writable);
        assert_eq!(
            snapshot.input.selector_profile_id.as_deref(),
            Some(KNOWN_PROFILE.id)
        );
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
        assert!(snapshot.app.read_only_composer_selector_evidence.is_none());
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
        assert_ne!(
            first.executable(&[b'C' as u16], 100),
            first.executable(&[b'C' as u16], 101),
            "recycled PIDs must produce a different executable-instance digest"
        );
    }
}
