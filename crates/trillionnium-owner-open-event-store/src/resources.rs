//! Conservative logical reservations for this in-memory read model.
//!
//! These reservations include spare Vec capacity, repeated index strings and
//! generous container slots. They are not a claim about allocator/process RSS.
use super::*;

pub(crate) const FIXED_RESIDENT_RESERVE: usize = 1024 * 1024;
const OBJECT_ENTRY_RESERVE: usize = 256;

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
    let heap = add(
        add(scope_heap(&input.scope)?, input.event_id.capacity())?,
        input.kind.capacity(),
    )?;
    reserve(
        0,
        mul(2, add(heap, value_heap(&input.payload, 0)?)?)?,
        MAX_EVENT_RESIDENT_BYTES,
    )
    .map(|_| ())
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
    // Reserve two owned copies for append results/one read operation, and a
    // larger pre-decode envelope for dense JSON/array spare capacity.
    add(
        mul(2, heap)?.max(json_allocation_bound(encoded)?),
        index_reserve(record)?,
    )
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
        MAX_EVENT_WORKING_BYTES,
    )
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
