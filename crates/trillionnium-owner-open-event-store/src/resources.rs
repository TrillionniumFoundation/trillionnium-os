//! Conservative logical reservations for this in-memory read model.
//!
//! These reservations include spare Vec capacity, repeated index strings and
//! generous container slots. They are not a claim about allocator/process RSS.
use super::*;

pub(crate) const FIXED_RESIDENT_RESERVE: usize = 1024 * 1024;
/// Resident read models and temporary codecs have disjoint shared envelopes.
pub const MAX_EVENT_PROCESS_TEMPORARY_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const TEMPORARY_FIXED_RESERVE: usize = 64 * 1024;
pub(crate) const MAX_TEMPORARY_ALLOCATION: usize =
    MAX_EVENT_PROCESS_TEMPORARY_BYTES - TEMPORARY_FIXED_RESERVE;
// Two read/encoder buffers can overlap during realloc/shrink; reserve their
// peak plus fixed codec scratch, including two bytes of bounded read-ahead.
pub(crate) const MAX_ENCODED_RECORD_BYTES: usize = MAX_TEMPORARY_ALLOCATION / 2 - 2;
const OBJECT_ENTRY_RESERVE: usize = 256;

static RESIDENT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static TEMPORARY: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static WORKING_LANE: Mutex<()> = Mutex::new(());
thread_local! {
    static WORKING_ACTIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Noncloneable, real linked-module reservation. Fields owning allocations
/// must precede this lease so their destructors run before capacity is returned.
#[derive(Debug)]
pub(crate) struct ResidentLease {
    bytes: usize,
}
impl ResidentLease {
    pub(crate) fn acquire(bytes: usize) -> Result<Self> {
        acquire(&RESIDENT, bytes, MAX_EVENT_RESIDENT_BYTES)?;
        Ok(Self { bytes })
    }
    pub(crate) fn merge(&mut self, mut extra: Self) {
        self.bytes = self
            .bytes
            .checked_add(extra.bytes)
            .expect("shared pool is bounded");
        extra.bytes = 0;
    }
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }
}
impl Drop for ResidentLease {
    fn drop(&mut self) {
        release(&RESIDENT, self.bytes);
    }
}

fn acquire(pool: &std::sync::atomic::AtomicUsize, bytes: usize, maximum: usize) -> Result<()> {
    use std::sync::atomic::Ordering;
    let mut current = pool.load(Ordering::Acquire);
    loop {
        let next = reserve(current, bytes, maximum)?;
        match pool.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(()),
            Err(observed) => current = observed,
        }
    }
}
fn release(pool: &std::sync::atomic::AtomicUsize, bytes: usize) {
    let previous = pool.fetch_sub(bytes, std::sync::atomic::Ordering::AcqRel);
    debug_assert!(previous >= bytes);
}

/// Heavy operations serialize on a separate lane. The accounting atomics are
/// never locked across I/O/callbacks. No callback may recursively allocate an
/// EventStore response: refuse it before either the lane or a store lock waits.
pub(crate) struct WorkingGuard {
    _lane: MutexGuard<'static, ()>,
}
impl WorkingGuard {
    pub(crate) fn acquire() -> Result<Self> {
        if WORKING_ACTIVE.get() {
            return Err(EventStoreError::CapacityExhausted);
        }
        let lane = WORKING_LANE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        acquire(
            &TEMPORARY,
            MAX_EVENT_PROCESS_TEMPORARY_BYTES,
            MAX_EVENT_PROCESS_TEMPORARY_BYTES,
        )?;
        WORKING_ACTIVE.set(true);
        Ok(Self { _lane: lane })
    }

    /// Caller-built owned arguments cannot accumulate uncharged while their
    /// thread waits for another codec. A free lane admits them into its
    /// temporary envelope; otherwise reserve their actual owned capacity in
    /// the resident pool until custody transfers to the acquired working lane.
    pub(crate) fn acquire_input(input: &EventInput) -> Result<Self> {
        validate_input_allocation(input)?;
        if WORKING_ACTIVE.get() {
            return Err(EventStoreError::CapacityExhausted);
        }
        let mut pending = None;
        let lane = match WORKING_LANE.try_lock() {
            Ok(lane) => lane,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                pending = Some(ResidentLease::acquire(input_heap(input)?)?);
                WORKING_LANE
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
            }
        };
        acquire(
            &TEMPORARY,
            MAX_EVENT_PROCESS_TEMPORARY_BYTES,
            MAX_EVENT_PROCESS_TEMPORARY_BYTES,
        )?;
        WORKING_ACTIVE.set(true);
        drop(pending);
        Ok(Self { _lane: lane })
    }
}
impl Drop for WorkingGuard {
    fn drop(&mut self) {
        WORKING_ACTIVE.set(false);
        release(&TEMPORARY, MAX_EVENT_PROCESS_TEMPORARY_BYTES);
    }
}

fn add(left: usize, right: usize) -> Result<usize> {
    left.checked_add(right)
        .ok_or(EventStoreError::CapacityExhausted)
}
fn mul(left: usize, right: usize) -> Result<usize> {
    left.checked_mul(right)
        .ok_or(EventStoreError::CapacityExhausted)
}

fn scope_heap(scope: &TurnScope) -> Result<usize> {
    [
        &scope.session_id,
        &scope.profile_id,
        &scope.task_id,
        &scope.turn_id,
        &scope.turn_stream_id,
    ]
    .into_iter()
    .try_fold(0, |sum, value| add(sum, value.capacity()))
}

fn value_heap(value: &Value, depth: usize) -> Result<usize> {
    if depth > 128 {
        return Err(EventStoreError::CapacityExhausted);
    }
    match value {
        Value::String(value) => Ok(value.capacity()),
        Value::Array(values) => values.iter().try_fold(
            mul(values.capacity(), std::mem::size_of::<Value>())?,
            |sum, value| add(sum, value_heap(value, depth + 1)?),
        ),
        Value::Object(values) => values.iter().try_fold(
            mul(values.len(), OBJECT_ENTRY_RESERVE)?,
            |sum, (key, value)| add(add(sum, key.capacity())?, value_heap(value, depth + 1)?),
        ),
        _ => Ok(0),
    }
}

pub(crate) fn validate_input_allocation(input: &EventInput) -> Result<()> {
    reserve(0, mul(2, input_heap(input)?)?, MAX_EVENT_RESIDENT_BYTES).map(|_| ())
}

pub(crate) fn input_heap(input: &EventInput) -> Result<usize> {
    let heap = add(
        add(scope_heap(&input.scope)?, input.event_id.capacity())?,
        input.kind.capacity(),
    )?;
    add(heap, value_heap(&input.payload, 0)?)
}

pub(crate) fn segment_reservation(path: &Path) -> Result<usize> {
    // Pin/meta nodes plus pathname custody and short sync/read path clones.
    add(1024, mul(3, path.as_os_str().len())?)
}

fn index_reserve(record: &EventRecord) -> Result<usize> {
    // Covers both backends: records' growth slots, two key maps, scope maps,
    // per-scope sequence and index Vec growth. Scope strings are charged on
    // every record even when shared by one turn. No identity is evicted.
    let slots = 2 * std::mem::size_of::<EventRecord>()
        + 2 * std::mem::size_of::<EventKey>()
        + 2 * std::mem::size_of::<TurnScope>()
        + std::mem::size_of::<SegmentLocation>()
        + std::mem::size_of::<Vec<usize>>()
        + 4 * std::mem::size_of::<usize>();
    mul(
        8,
        add(
            slots,
            add(scope_heap(&record.scope)?, record.event_id.capacity())?,
        )?,
    )
}

pub(crate) fn record_reservation(record: &EventRecord, encoded: &[u8]) -> Result<usize> {
    let heap = record_heap(record)?;
    // Reserve two owned copies for append results/one read operation, and a
    // larger pre-decode envelope for dense JSON/array spare capacity.
    add(
        mul(2, heap)?.max(json_allocation_bound(encoded)?),
        index_reserve(record)?,
    )
}

fn record_heap(record: &EventRecord) -> Result<usize> {
    let mut heap = add(scope_heap(&record.scope)?, value_heap(&record.payload, 0)?)?;
    for value in [
        &record.schema,
        &record.event_id,
        &record.kind,
        &record.payload_sha256,
        &record.previous_record_sha256,
        &record.record_sha256,
    ] {
        heap = add(heap, value.capacity())?;
    }
    Ok(heap)
}

pub(crate) fn copy_reservation(record: &EventRecord) -> Result<usize> {
    add(
        mul(2, record_heap(record)?)?,
        3 * std::mem::size_of::<EventRecord>(),
    )
}

/// Count serialized bytes without an encoded Vec/DOM, then reserve simultaneous
/// input and encoder growth (old and new buffers) before the first allocation.
pub(crate) fn encode_record(record: &EventRecord, maximum: usize) -> Result<Vec<u8>> {
    let bytes = encoded_size(record, maximum)?;
    reserve(
        record_heap(record)?,
        mul(2, bytes)?,
        MAX_TEMPORARY_ALLOCATION,
    )?;
    let mut encoded = encode_bounded(record, bytes)?;
    // A later newline must never cause unchecked geometric Vec growth.
    encoded
        .try_reserve_exact(1)
        .map_err(|_| EventStoreError::CapacityExhausted)?;
    // New records must remain readable under exactly the recovery codec gate.
    check_record_decode(&encoded, encoded.capacity())?;
    Ok(encoded)
}

pub(crate) fn encoded_size(value: &impl Serialize, maximum: usize) -> Result<usize> {
    struct Counter {
        bytes: usize,
        maximum: usize,
        exhausted: bool,
    }
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            match self
                .bytes
                .checked_add(bytes.len())
                .filter(|bytes| *bytes <= self.maximum)
            {
                Some(length) => {
                    self.bytes = length;
                    Ok(bytes.len())
                }
                None => {
                    self.exhausted = true;
                    Err(std::io::Error::other("encoded capacity exhausted"))
                }
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter {
        bytes: 0,
        maximum,
        exhausted: false,
    };
    serde_json::to_writer(&mut counter, value).map_err(|error| {
        if counter.exhausted {
            EventStoreError::CapacityExhausted
        } else {
            EventStoreError::InvalidRecord(error.to_string())
        }
    })?;
    Ok(counter.bytes)
}

pub(crate) fn header_reservation(record: &EventRecord) -> Result<usize> {
    let mut heap = scope_heap(&record.scope)?;
    for value in [
        &record.schema,
        &record.event_id,
        &record.kind,
        &record.payload_sha256,
        &record.previous_record_sha256,
        &record.record_sha256,
    ] {
        heap = add(heap, value.capacity())?;
    }
    add(mul(2, heap)?, index_reserve(record)?)
}

pub(crate) fn reserve(current: usize, additional: usize, maximum: usize) -> Result<usize> {
    let total = add(current, additional)?;
    if total > maximum {
        Err(EventStoreError::CapacityExhausted)
    } else {
        Ok(total)
    }
}

/// Quote/escape-aware lexical upper reservation before allocating a JSON DOM.
/// Every scalar/container reserves two Value slots; each object member also
/// reserves a BTreeMap node slot. Twice encoded bytes covers decoded strings,
/// parser scratch and their growth. Syntax/duplicate keys still use strict_json.
pub(crate) fn json_allocation_bound(encoded: &[u8]) -> Result<usize> {
    let mut bound = mul(2, encoded.len())?;
    let mut quoted = false;
    let mut escaped = false;
    let mut scalar = false;
    for byte in encoded {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => {
                quoted = true;
                scalar = false;
                bound = add(bound, 2 * std::mem::size_of::<Value>())?;
            }
            b'[' | b'{' => {
                scalar = false;
                bound = add(bound, 2 * std::mem::size_of::<Value>())?;
            }
            b':' => {
                scalar = false;
                bound = add(bound, OBJECT_ENTRY_RESERVE)?;
            }
            b',' | b']' | b'}' | b' ' | b'\r' | b'\n' | b'\t' => scalar = false,
            _ if !scalar => {
                scalar = true;
                bound = add(bound, 2 * std::mem::size_of::<Value>())?;
            }
            _ => {}
        }
        if bound > MAX_EVENT_WORKING_BYTES {
            return Err(EventStoreError::CapacityExhausted);
        }
    }
    Ok(bound)
}

pub(crate) fn check_decode(current: usize, encoded: &[u8], maximum: usize) -> Result<()> {
    reserve(current, json_allocation_bound(encoded)?, maximum).map(|_| ())
}

pub(crate) fn check_sidecar(current: usize, encoded: &[u8]) -> Result<()> {
    check_decode(
        add(current, encoded.len())?,
        encoded,
        MAX_TEMPORARY_ALLOCATION,
    )
}

pub(crate) fn check_record_decode(encoded: &[u8], capacity: usize) -> Result<()> {
    check_decode(capacity, encoded, MAX_TEMPORARY_ALLOCATION)
}

/// BufRead::read_until may double a nearly-16 MiB line to a 32 MiB capacity.
/// Limit growth explicitly, including read-ahead used for oversize detection.
pub(crate) fn read_line(reader: &mut impl BufRead, maximum: usize) -> Result<Vec<u8>> {
    let limit = usize::try_from(read_ahead_limit(maximum)?)
        .map_err(|_| EventStoreError::CapacityExhausted)?;
    let mut output = Vec::new();
    while output.len() < limit {
        let available = reader
            .fill_buf()
            .map_err(|error| EventStoreError::Io(error.to_string()))?;
        if available.is_empty() {
            break;
        }
        let length = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1)
            .min(limit - output.len());
        let next = add(output.len(), length)?;
        if next > output.capacity() {
            let capacity = output.capacity().saturating_mul(2).max(next).min(limit);
            output
                .try_reserve_exact(capacity - output.len())
                .map_err(|_| EventStoreError::CapacityExhausted)?;
        }
        output.extend_from_slice(&available[..length]);
        reader.consume(length);
        if output.last() == Some(&b'\n') {
            break;
        }
    }
    // Decode admission must not depend on geometric growth's spare capacity.
    // This reallocation happens before DOM allocation and its old+new buffers
    // fit MAX_ENCODED_RECORD_BYTES's shared temporary peak.
    output.shrink_to_fit();
    Ok(output)
}

pub(crate) fn encode_bounded(value: &impl Serialize, maximum: usize) -> Result<Vec<u8>> {
    struct Bounded {
        bytes: Vec<u8>,
        maximum: usize,
        exhausted: bool,
    }
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let length = self.bytes.len().checked_add(bytes.len());
            if length.is_none_or(|length| length > self.maximum) {
                self.exhausted = true;
                return Err(std::io::Error::other("encoded event capacity exhausted"));
            }
            let required = length.expect("checked above");
            if required > self.bytes.capacity() {
                let capacity = self
                    .bytes
                    .capacity()
                    .saturating_mul(2)
                    .max(required)
                    .min(self.maximum);
                self.bytes
                    .try_reserve_exact(capacity - self.bytes.len())
                    .map_err(std::io::Error::other)?;
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Bounded {
        bytes: Vec::new(),
        maximum,
        exhausted: false,
    };
    serde_json::to_writer(&mut writer, value).map_err(|error| {
        if writer.exhausted {
            EventStoreError::CapacityExhausted
        } else {
            EventStoreError::InvalidRecord(error.to_string())
        }
    })?;
    Ok(writer.bytes)
}

pub(crate) fn json_digest(value: &impl Serialize) -> Result<String> {
    struct DigestWriter(Sha256);
    impl Write for DigestWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = DigestWriter(Sha256::new());
    serde_json::to_writer(&mut writer, value)
        .map_err(|error| EventStoreError::InvalidRecord(error.to_string()))?;
    Ok(format!("{:x}", writer.0.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lexical_reservation_counts_dense_arrays_and_ignores_quoted_punctuation() {
        assert!(json_allocation_bound(b"[0,0,0]").unwrap() > 8 * 7);
        assert!(json_allocation_bound(br#"{"x":"[,]\\\"[,]"}"#).unwrap() < 1024);
        assert_eq!(reserve(3, 7, 10).unwrap(), 10);
        assert!(reserve(usize::MAX, 1, usize::MAX).is_err());
    }
    #[test]
    fn bounded_encoder_rejects_escaped_expansion() {
        let value = serde_json::json!({"x": "\u{0001}".repeat(100)});
        assert!(matches!(
            encode_bounded(&value, 100),
            Err(EventStoreError::CapacityExhausted)
        ));
        assert_eq!(
            json_digest(&value).unwrap(),
            sha256_hex(&serde_json::to_vec(&value).unwrap())
        );
    }
}

/// Shared within this linked module; unrelated OS descriptors belong to their
/// owner. Each store reserves control/recovery headroom before touching paths.
pub const MAX_EVENT_PROCESS_DESCRIPTORS: usize = 256;
pub const EVENT_STORE_CONTROL_DESCRIPTORS: usize = 16;
static DESCRIPTORS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[derive(Debug)]
pub(crate) struct DescriptorLease {
    count: usize,
}
impl DescriptorLease {
    pub(crate) fn acquire(count: usize) -> Result<Self> {
        use std::sync::atomic::Ordering;
        let mut current = DESCRIPTORS.load(Ordering::Acquire);
        loop {
            let next = current
                .checked_add(count)
                .filter(|next| *next <= MAX_EVENT_PROCESS_DESCRIPTORS)
                .ok_or(EventStoreError::CapacityExhausted)?;
            match DESCRIPTORS.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(Self { count }),
                Err(observed) => current = observed,
            }
        }
    }
}
impl Drop for DescriptorLease {
    fn drop(&mut self) {
        let previous = DESCRIPTORS.fetch_sub(self.count, std::sync::atomic::Ordering::AcqRel);
        debug_assert!(previous >= self.count);
    }
}
