//! Content-free durable replay state machine for guarded Windows mutations.
//!
//! This module deliberately contains no filesystem, DPAPI, ACL, or Win32
//! calls. Those operations belong behind [`DurableLedgerStore`]. Keeping the
//! transition rules platform-independent lets crash/restart behavior be
//! verified without touching a user's desktop or persistent state.

#![cfg_attr(
    not(test),
    allow(dead_code),
    doc = "The controller/wire codec remain compiled for all-feature review while production uses the fail-closed placeholder."
)]

use std::fmt;

use sha2::{Digest, Sha256};

use crate::platform::contract::TransactionCorrelation;
use crate::platform::{UiError, UiErrorKind};

const RECORD_MAGIC: [u8; 4] = *b"OKWL";
const RECORD_VERSION: u8 = 1;
const RECORD_PREFIX_LEN: usize = 32;
const RECORD_CHECKSUM_LEN: usize = 16;
pub(super) const ENCODED_RECORD_LEN: usize = RECORD_PREFIX_LEN + RECORD_CHECKSUM_LEN;

/// Copyable only inside the ledger codec/controller. A future policy-owned
/// capability must consume a separate non-Clone token to create this value.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct RecordCorrelation([u8; 16]);

impl RecordCorrelation {
    pub(super) fn from_bytes(bytes: [u8; 16]) -> Result<Self, LedgerStoreError> {
        if bytes == [0; 16] {
            Err(LedgerStoreError::InvalidRecord)
        } else {
            Ok(Self(bytes))
        }
    }

    #[cfg_attr(all(test, not(feature = "windows-ui-write")), allow(dead_code))]
    pub(super) fn from_policy(correlation: TransactionCorrelation) -> Result<Self, UiError> {
        Self::from_bytes(correlation.into_bytes())
            .map_err(|_| UiError::new(UiErrorKind::InvalidInput, "windows_ledger_correlation"))
    }
}

impl fmt::Debug for RecordCorrelation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecordCorrelation(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum LedgerPhase {
    StageMayHaveStarted = 1,
    CommitMayHaveStarted = 2,
    Indeterminate = 3,
}

impl LedgerPhase {
    fn from_byte(value: u8) -> Result<Self, LedgerStoreError> {
        match value {
            1 => Ok(Self::StageMayHaveStarted),
            2 => Ok(Self::CommitMayHaveStarted),
            3 => Ok(Self::Indeterminate),
            _ => Err(LedgerStoreError::InvalidRecord),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct LedgerRecord {
    version: u8,
    phase: LedgerPhase,
    correlation: RecordCorrelation,
    sequence: u64,
}

impl LedgerRecord {
    fn stage(correlation: RecordCorrelation) -> Self {
        Self {
            version: RECORD_VERSION,
            phase: LedgerPhase::StageMayHaveStarted,
            correlation,
            sequence: 1,
        }
    }

    fn next(self, phase: LedgerPhase) -> Result<Self, UiError> {
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(ledger_state_error)?;
        Ok(Self {
            version: RECORD_VERSION,
            phase,
            correlation: self.correlation,
            sequence,
        })
    }

    pub(super) fn correlation(self) -> RecordCorrelation {
        self.correlation
    }

    fn schema_valid(self) -> bool {
        self.version == RECORD_VERSION
            && self.correlation.0 != [0; 16]
            && matches!(
                (self.phase, self.sequence),
                (LedgerPhase::StageMayHaveStarted, 1)
                    | (LedgerPhase::CommitMayHaveStarted, 2)
                    | (LedgerPhase::Indeterminate, 2 | 3)
            )
    }
}

impl fmt::Debug for LedgerRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LedgerRecord")
            .field("version", &self.version)
            .field("phase", &self.phase)
            .field("correlation", &"<redacted>")
            .field("sequence", &self.sequence)
            .finish()
    }
}

/// A deliberately small error vocabulary. Store implementations must not
/// attach paths, account names, record bytes, or OS error text to this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LedgerStoreError {
    Unavailable,
    AccessDenied,
    InvalidRecord,
    IoUncertain,
}

/// Atomic/durable storage boundary. Implementations must compare the expected
/// current record before replacing/removing and must not follow reparse points.
/// A successful call means the operation and its containing-directory metadata
/// have been durably flushed; the controller independently reloads and checks.
pub(super) trait DurableLedgerStore {
    fn load(&mut self) -> Result<Option<LedgerRecord>, LedgerStoreError>;

    fn durable_replace(
        &mut self,
        expected: Option<LedgerRecord>,
        next: LedgerRecord,
    ) -> Result<(), LedgerStoreError>;

    fn durable_remove(&mut self, expected: LedgerRecord) -> Result<(), LedgerStoreError>;
}

/// The transaction-facing subset. It intentionally exposes no reset or
/// age-based expiry operation: a nonempty ledger requires human resolution.
pub(super) trait MutationLedger {
    fn ensure_clear(&mut self) -> Result<(), UiError>;
    fn begin_stage(&mut self) -> Result<LedgerRecord, UiError>;
    fn mark_commit(&mut self, stage: LedgerRecord) -> Result<LedgerRecord, UiError>;
    fn mark_indeterminate(
        &mut self,
        correlation: RecordCorrelation,
    ) -> Result<LedgerRecord, UiError>;
    fn resolve_restored_stage(&mut self, stage: LedgerRecord) -> Result<(), UiError>;
}

pub(super) struct LedgerController<S> {
    store: S,
    correlation: RecordCorrelation,
}

impl<S> LedgerController<S> {
    pub(super) fn new(store: S, correlation: RecordCorrelation) -> Self {
        Self { store, correlation }
    }

    #[cfg(test)]
    fn into_store(self) -> S {
        self.store
    }
}

impl<S: DurableLedgerStore> LedgerController<S> {
    fn load(&mut self) -> Result<Option<LedgerRecord>, UiError> {
        self.store.load().map_err(|_| ledger_state_error())
    }

    fn replace_verified(
        &mut self,
        expected: Option<LedgerRecord>,
        next: LedgerRecord,
    ) -> Result<(), UiError> {
        self.store
            .durable_replace(expected, next)
            .map_err(|_| ledger_state_error())?;
        if self.load()? != Some(next) {
            return Err(ledger_state_error());
        }
        Ok(())
    }
}

impl<S: DurableLedgerStore> MutationLedger for LedgerController<S> {
    fn ensure_clear(&mut self) -> Result<(), UiError> {
        if self.load()?.is_some() {
            Err(ledger_existing_error())
        } else {
            Ok(())
        }
    }

    fn begin_stage(&mut self) -> Result<LedgerRecord, UiError> {
        self.ensure_clear()?;
        let stage = LedgerRecord::stage(self.correlation);
        self.replace_verified(None, stage)?;
        Ok(stage)
    }

    fn mark_commit(&mut self, stage: LedgerRecord) -> Result<LedgerRecord, UiError> {
        if stage.version != RECORD_VERSION
            || stage.phase != LedgerPhase::StageMayHaveStarted
            || stage.sequence != 1
            || stage.correlation != self.correlation
            || self.load()? != Some(stage)
        {
            return Err(ledger_state_error());
        }

        let commit = stage.next(LedgerPhase::CommitMayHaveStarted)?;
        self.replace_verified(Some(stage), commit)?;
        Ok(commit)
    }

    fn mark_indeterminate(
        &mut self,
        correlation: RecordCorrelation,
    ) -> Result<LedgerRecord, UiError> {
        let current = self.load()?.ok_or_else(ledger_state_error)?;
        if !current.schema_valid() || current.correlation != correlation {
            return Err(ledger_state_error());
        }
        if current.phase == LedgerPhase::Indeterminate {
            return Ok(current);
        }

        let indeterminate = current.next(LedgerPhase::Indeterminate)?;
        self.replace_verified(Some(current), indeterminate)?;
        Ok(indeterminate)
    }

    fn resolve_restored_stage(&mut self, stage: LedgerRecord) -> Result<(), UiError> {
        if stage.version != RECORD_VERSION
            || stage.phase != LedgerPhase::StageMayHaveStarted
            || stage.sequence != 1
            || stage.correlation != self.correlation
            || self.load()? != Some(stage)
        {
            return Err(ledger_state_error());
        }

        self.store
            .durable_remove(stage)
            .map_err(|_| ledger_state_error())?;
        if self.load()?.is_some() {
            return Err(ledger_state_error());
        }
        Ok(())
    }
}

/// Production placeholder used until the separately reviewed DPAPI/ACL store
/// exists. Its first method always refuses before an execution claim or UI call.
pub(super) struct UnavailableLedger {
    _correlation: RecordCorrelation,
}

impl UnavailableLedger {
    pub(super) fn new(correlation: RecordCorrelation) -> Self {
        Self {
            _correlation: correlation,
        }
    }
}

impl MutationLedger for UnavailableLedger {
    fn ensure_clear(&mut self) -> Result<(), UiError> {
        Err(UiError::new(
            UiErrorKind::UnsupportedCapability,
            "windows_ledger_unavailable",
        ))
    }

    fn begin_stage(&mut self) -> Result<LedgerRecord, UiError> {
        Err(UiError::new(
            UiErrorKind::UnsupportedCapability,
            "windows_ledger_unavailable",
        ))
    }

    fn mark_commit(&mut self, _stage: LedgerRecord) -> Result<LedgerRecord, UiError> {
        Err(ledger_state_error())
    }

    fn mark_indeterminate(
        &mut self,
        _correlation: RecordCorrelation,
    ) -> Result<LedgerRecord, UiError> {
        Err(ledger_state_error())
    }

    fn resolve_restored_stage(&mut self, _stage: LedgerRecord) -> Result<(), UiError> {
        Err(ledger_state_error())
    }
}

fn ledger_existing_error() -> UiError {
    UiError::new(UiErrorKind::SubmissionUncertain, "windows_ledger_existing")
}

fn ledger_state_error() -> UiError {
    UiError::new(
        UiErrorKind::SubmissionUncertain,
        "windows_ledger_state_uncertain",
    )
}

pub(super) fn encode_record(
    record: LedgerRecord,
) -> Result<[u8; ENCODED_RECORD_LEN], LedgerStoreError> {
    if !record.schema_valid() {
        return Err(LedgerStoreError::InvalidRecord);
    }
    let mut encoded = [0_u8; ENCODED_RECORD_LEN];
    encoded[0..4].copy_from_slice(&RECORD_MAGIC);
    encoded[4] = record.version;
    encoded[5] = record.phase as u8;
    // bytes 6..8 are reserved and must remain zero.
    encoded[8..16].copy_from_slice(&record.sequence.to_le_bytes());
    encoded[16..32].copy_from_slice(&record.correlation.0);
    let checksum = Sha256::digest(&encoded[..RECORD_PREFIX_LEN]);
    encoded[RECORD_PREFIX_LEN..].copy_from_slice(&checksum[..RECORD_CHECKSUM_LEN]);
    Ok(encoded)
}

pub(super) fn decode_record(encoded: &[u8]) -> Result<LedgerRecord, LedgerStoreError> {
    if encoded.len() != ENCODED_RECORD_LEN
        || encoded[0..4] != RECORD_MAGIC
        || encoded[4] != RECORD_VERSION
        || encoded[6..8] != [0, 0]
    {
        return Err(LedgerStoreError::InvalidRecord);
    }

    let checksum = Sha256::digest(&encoded[..RECORD_PREFIX_LEN]);
    if encoded[RECORD_PREFIX_LEN..] != checksum[..RECORD_CHECKSUM_LEN] {
        return Err(LedgerStoreError::InvalidRecord);
    }

    let phase = LedgerPhase::from_byte(encoded[5])?;
    let sequence = u64::from_le_bytes(
        encoded[8..16]
            .try_into()
            .map_err(|_| LedgerStoreError::InvalidRecord)?,
    );
    if sequence == 0 {
        return Err(LedgerStoreError::InvalidRecord);
    }
    let correlation = RecordCorrelation::from_bytes(
        encoded[16..32]
            .try_into()
            .map_err(|_| LedgerStoreError::InvalidRecord)?,
    )?;

    let record = LedgerRecord {
        version: RECORD_VERSION,
        phase,
        correlation,
        sequence,
    };
    record
        .schema_valid()
        .then_some(record)
        .ok_or(LedgerStoreError::InvalidRecord)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Barrier, Mutex};

    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Fault {
        Load,
        ReplaceBefore,
        ReplaceAfter,
        ReplaceWrongValue,
        RemoveBefore,
        RemoveAfter,
    }

    #[derive(Default)]
    struct MemoryStore {
        record: Option<LedgerRecord>,
        faults: VecDeque<Fault>,
    }

    impl MemoryStore {
        fn with_record(record: LedgerRecord) -> Self {
            Self {
                record: Some(record),
                faults: VecDeque::new(),
            }
        }

        fn fault(&mut self, fault: Fault) {
            self.faults.push_back(fault);
        }

        fn take_fault(&mut self, expected: Fault) -> bool {
            if self.faults.front() == Some(&expected) {
                self.faults.pop_front();
                true
            } else {
                false
            }
        }
    }

    impl DurableLedgerStore for MemoryStore {
        fn load(&mut self) -> Result<Option<LedgerRecord>, LedgerStoreError> {
            if self.take_fault(Fault::Load) {
                return Err(LedgerStoreError::IoUncertain);
            }
            Ok(self.record)
        }

        fn durable_replace(
            &mut self,
            expected: Option<LedgerRecord>,
            next: LedgerRecord,
        ) -> Result<(), LedgerStoreError> {
            if self.take_fault(Fault::ReplaceBefore) {
                return Err(LedgerStoreError::IoUncertain);
            }
            if self.record != expected {
                return Err(LedgerStoreError::InvalidRecord);
            }
            if self.take_fault(Fault::ReplaceWrongValue) {
                self.record = Some(next.next(LedgerPhase::Indeterminate).unwrap());
                return Ok(());
            }
            self.record = Some(next);
            if self.take_fault(Fault::ReplaceAfter) {
                return Err(LedgerStoreError::IoUncertain);
            }
            Ok(())
        }

        fn durable_remove(&mut self, expected: LedgerRecord) -> Result<(), LedgerStoreError> {
            if self.take_fault(Fault::RemoveBefore) {
                return Err(LedgerStoreError::IoUncertain);
            }
            if self.record != Some(expected) {
                return Err(LedgerStoreError::InvalidRecord);
            }
            self.record = None;
            if self.take_fault(Fault::RemoveAfter) {
                return Err(LedgerStoreError::IoUncertain);
            }
            Ok(())
        }
    }

    #[derive(Clone)]
    struct SharedMemoryStore {
        record: Arc<Mutex<Option<LedgerRecord>>>,
        first_load_barrier: Arc<Barrier>,
        synchronize_first_load: bool,
    }

    impl DurableLedgerStore for SharedMemoryStore {
        fn load(&mut self) -> Result<Option<LedgerRecord>, LedgerStoreError> {
            let snapshot = *self
                .record
                .lock()
                .map_err(|_| LedgerStoreError::IoUncertain)?;
            if self.synchronize_first_load {
                self.synchronize_first_load = false;
                self.first_load_barrier.wait();
            }
            Ok(snapshot)
        }

        fn durable_replace(
            &mut self,
            expected: Option<LedgerRecord>,
            next: LedgerRecord,
        ) -> Result<(), LedgerStoreError> {
            let mut record = self
                .record
                .lock()
                .map_err(|_| LedgerStoreError::IoUncertain)?;
            if *record != expected {
                return Err(LedgerStoreError::InvalidRecord);
            }
            *record = Some(next);
            Ok(())
        }

        fn durable_remove(&mut self, expected: LedgerRecord) -> Result<(), LedgerStoreError> {
            let mut record = self
                .record
                .lock()
                .map_err(|_| LedgerStoreError::IoUncertain)?;
            if *record != Some(expected) {
                return Err(LedgerStoreError::InvalidRecord);
            }
            *record = None;
            Ok(())
        }
    }

    fn correlation(value: u8) -> RecordCorrelation {
        RecordCorrelation::from_bytes([value; 16]).unwrap()
    }

    fn controller(value: u8) -> LedgerController<MemoryStore> {
        LedgerController::new(MemoryStore::default(), correlation(value))
    }

    fn assert_uncertain(error: UiError) {
        assert_eq!(error.kind, UiErrorKind::SubmissionUncertain);
        assert!(!error.retry_safe);
    }

    fn resign(encoded: &mut [u8; ENCODED_RECORD_LEN]) {
        let checksum = Sha256::digest(&encoded[..RECORD_PREFIX_LEN]);
        encoded[RECORD_PREFIX_LEN..].copy_from_slice(&checksum[..RECORD_CHECKSUM_LEN]);
    }

    #[test]
    fn fixed_record_round_trip_is_content_free_and_debug_redacted() {
        let record = LedgerRecord::stage(correlation(0xA5));
        let encoded = encode_record(record).unwrap();
        assert_eq!(encoded.len(), ENCODED_RECORD_LEN);
        assert_eq!(decode_record(&encoded).unwrap(), record);

        let debug = format!("{record:?} {:?}", record.correlation());
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("a5a5"));
        assert!(!debug.contains("OPENKAKAO_LEDGER_CANARY"));
    }

    #[test]
    fn strict_decoder_rejects_every_malformed_shape() {
        let valid = encode_record(LedgerRecord::stage(correlation(7))).unwrap();
        let mut cases = vec![valid[..valid.len() - 1].to_vec(), {
            let mut oversized = valid.to_vec();
            oversized.push(0);
            oversized
        }];
        for index in [0_usize, 4, 5, 6, 8, 16, 31, 47] {
            let mut corrupt = valid;
            corrupt[index] ^= 0xFF;
            cases.push(corrupt.to_vec());
        }
        for (index, value) in [(0_usize, b'X'), (4, 2), (5, 99), (6, 1)] {
            let mut structurally_invalid = valid;
            structurally_invalid[index] = value;
            resign(&mut structurally_invalid);
            cases.push(structurally_invalid.to_vec());
        }
        let mut zero_sequence = valid;
        zero_sequence[8..16].fill(0);
        resign(&mut zero_sequence);
        cases.push(zero_sequence.to_vec());
        let mut zero_correlation = valid;
        zero_correlation[16..32].fill(0);
        resign(&mut zero_correlation);
        cases.push(zero_correlation.to_vec());
        let mut unexpected_sequence = valid;
        unexpected_sequence[8..16].copy_from_slice(&99_u64.to_le_bytes());
        resign(&mut unexpected_sequence);
        cases.push(unexpected_sequence.to_vec());

        for malformed in cases {
            assert_eq!(
                decode_record(&malformed),
                Err(LedgerStoreError::InvalidRecord)
            );
        }
    }

    #[test]
    fn stage_record_is_durable_and_exactly_verified_before_return() {
        let mut ledger = controller(1);
        let stage = ledger.begin_stage().unwrap();
        assert_eq!(stage.phase, LedgerPhase::StageMayHaveStarted);
        assert_eq!(stage.sequence, 1);
        assert_eq!(ledger.store.record, Some(stage));
    }

    #[test]
    fn every_nonempty_state_blocks_same_or_different_restart() {
        for phase in [
            LedgerPhase::StageMayHaveStarted,
            LedgerPhase::CommitMayHaveStarted,
            LedgerPhase::Indeterminate,
        ] {
            let base = LedgerRecord {
                version: RECORD_VERSION,
                phase,
                correlation: correlation(1),
                sequence: phase as u64,
            };
            for restarted_correlation in [correlation(1), correlation(2)] {
                let mut ledger =
                    LedgerController::new(MemoryStore::with_record(base), restarted_correlation);
                let error = ledger.begin_stage().unwrap_err();
                assert_eq!(error.operation, "windows_ledger_existing");
                assert_uncertain(error);
                assert_eq!(ledger.store.record, Some(base));
            }
        }
    }

    #[test]
    fn restored_stage_is_the_only_automatic_removal_transition() {
        let mut ledger = controller(3);
        let stage = ledger.begin_stage().unwrap();
        ledger.resolve_restored_stage(stage).unwrap();
        assert_eq!(ledger.store.record, None);

        let error = ledger.resolve_restored_stage(stage).unwrap_err();
        assert_uncertain(error);
    }

    #[test]
    fn commit_then_indeterminate_is_monotonic_and_never_auto_removed() {
        let mut ledger = controller(4);
        let stage = ledger.begin_stage().unwrap();
        let commit = ledger.mark_commit(stage).unwrap();
        assert_eq!(commit.phase, LedgerPhase::CommitMayHaveStarted);
        assert_eq!(commit.sequence, 2);
        let terminal = ledger.mark_indeterminate(commit.correlation()).unwrap();
        assert_eq!(terminal.phase, LedgerPhase::Indeterminate);
        assert_eq!(terminal.sequence, 3);
        assert_eq!(
            ledger.mark_indeterminate(commit.correlation()).unwrap(),
            terminal
        );

        let store = ledger.into_store();
        let mut restarted = LedgerController::new(store, correlation(9));
        assert_uncertain(restarted.begin_stage().unwrap_err());
        assert_eq!(restarted.store.record, Some(terminal));
    }

    #[test]
    fn identical_and_distinct_concurrent_correlations_have_one_winner() {
        for correlations in [[11_u8, 11_u8], [12_u8, 13_u8]] {
            let record = Arc::new(Mutex::new(None));
            let barrier = Arc::new(Barrier::new(2));
            let mut workers = Vec::new();
            for value in correlations {
                let store = SharedMemoryStore {
                    record: Arc::clone(&record),
                    first_load_barrier: Arc::clone(&barrier),
                    synchronize_first_load: true,
                };
                workers.push(std::thread::spawn(move || {
                    LedgerController::new(store, correlation(value)).begin_stage()
                }));
            }

            let results: Vec<_> = workers
                .into_iter()
                .map(|worker| worker.join().expect("synthetic ledger worker"))
                .collect();
            assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
            assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
            assert!(record.lock().unwrap().is_some());
            let loser = results.into_iter().find_map(Result::err).unwrap();
            assert_uncertain(loser);
        }
    }

    #[test]
    fn replace_failures_before_after_and_verify_all_fail_closed() {
        for fault in [
            Fault::ReplaceBefore,
            Fault::ReplaceAfter,
            Fault::ReplaceWrongValue,
        ] {
            let mut ledger = controller(5);
            ledger.store.fault(fault);
            assert_uncertain(ledger.begin_stage().unwrap_err());
            if fault == Fault::ReplaceBefore {
                assert_eq!(ledger.store.record, None);
            } else {
                assert!(ledger.store.record.is_some());
            }
        }
    }

    #[test]
    fn crash_like_errors_during_commit_and_terminal_writes_leave_a_blocker() {
        for phase in [
            LedgerPhase::CommitMayHaveStarted,
            LedgerPhase::Indeterminate,
        ] {
            let mut ledger = controller(14);
            let stage = ledger.begin_stage().unwrap();
            if phase == LedgerPhase::CommitMayHaveStarted {
                ledger.store.fault(Fault::ReplaceAfter);
                assert_uncertain(ledger.mark_commit(stage).unwrap_err());
                assert_eq!(
                    ledger.store.record.unwrap().phase,
                    LedgerPhase::CommitMayHaveStarted
                );
            } else {
                let commit = ledger.mark_commit(stage).unwrap();
                ledger.store.fault(Fault::ReplaceAfter);
                assert_uncertain(ledger.mark_indeterminate(commit.correlation()).unwrap_err());
                assert_eq!(
                    ledger.store.record.unwrap().phase,
                    LedgerPhase::Indeterminate
                );
            }

            let store = ledger.into_store();
            let mut restarted = LedgerController::new(store, correlation(15));
            assert_uncertain(restarted.begin_stage().unwrap_err());
        }
    }

    #[test]
    fn load_and_remove_failures_never_report_success() {
        let mut read_failure = controller(6);
        read_failure.store.fault(Fault::Load);
        assert_uncertain(read_failure.begin_stage().unwrap_err());

        for fault in [Fault::RemoveBefore, Fault::RemoveAfter] {
            let mut ledger = controller(7);
            let stage = ledger.begin_stage().unwrap();
            ledger.store.fault(fault);
            assert_uncertain(ledger.resolve_restored_stage(stage).unwrap_err());
            if fault == Fault::RemoveBefore {
                assert_eq!(ledger.store.record, Some(stage));
            } else {
                assert_eq!(ledger.store.record, None);
            }
        }
    }

    #[test]
    fn wrong_transition_or_correlation_cannot_replace_a_record() {
        let mut ledger = controller(8);
        let stage = ledger.begin_stage().unwrap();
        let forged = LedgerRecord {
            correlation: correlation(9),
            ..stage
        };
        assert_uncertain(ledger.mark_commit(forged).unwrap_err());
        assert_uncertain(ledger.mark_indeterminate(correlation(9)).unwrap_err());
        assert_eq!(ledger.store.record, Some(stage));
    }

    #[test]
    fn unavailable_production_placeholder_refuses_without_a_record() {
        let mut ledger = UnavailableLedger::new(correlation(10));
        let error = ledger.begin_stage().unwrap_err();
        assert_eq!(error.kind, UiErrorKind::UnsupportedCapability);
        assert_eq!(error.operation, "windows_ledger_unavailable");
        assert!(error.retry_safe);
    }

    #[test]
    fn store_error_vocabulary_has_no_dynamic_payload() {
        for error in [
            LedgerStoreError::Unavailable,
            LedgerStoreError::AccessDenied,
            LedgerStoreError::InvalidRecord,
            LedgerStoreError::IoUncertain,
        ] {
            let rendered = format!("{error:?}");
            assert!(!rendered.contains("OPENKAKAO_LEDGER_CANARY"));
            assert!(rendered.len() < 32);
        }
    }
}
