//! Local requested-allocation accounting, never RSS or a whole-family quota.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
struct Accounting;
fn added(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}
unsafe impl GlobalAlloc for Accounting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            added(layout.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            added(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(p, layout) }
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(p, layout, size) };
        if !new.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            added(size);
        }
        new
    }
}
#[global_allocator]
static ALLOCATOR: Accounting = Accounting;
fn main() -> Result<(), String> {
    let mode = std::env::args()
        .nth(1)
        .ok_or("burst or lifetime required")?;
    if mode != "burst" && mode != "lifetime" {
        return Err("closed probe mode".into());
    }
    let before = LIVE.load(Ordering::SeqCst);
    PEAK.store(before, Ordering::SeqCst);
    trillionnium_owner_open_trace::configure_from_env("allocation-probe")?;
    let configured = LIVE.load(Ordering::SeqCst);
    let mut actual_records = 0;
    let inflight_live;
    if mode == "burst" {
        let mut spans = Vec::with_capacity(1024);
        for _ in 0..512 {
            spans.push(trillionnium_owner_open_trace::span(
                trillionnium_owner_open_trace::Stage::ToolSpawn,
                "owned physical allocation probe",
            ));
        }
        trillionnium_owner_open_trace::drain_stream_from_env()?;
        for _ in 0..512 {
            spans.push(trillionnium_owner_open_trace::span(
                trillionnium_owner_open_trace::Stage::ToolSpawn,
                "owned physical allocation probe",
            ));
        }
        inflight_live = LIVE.load(Ordering::SeqCst);
        for (index, span) in spans.into_iter().enumerate() {
            span.finish();
            actual_records += 1;
            // Start-credit capacity is 1024; completion banks have 512 slots.
            // Preserve all 1024 real pending spans while measuring, then ACK
            // the first completed bank before publishing the remaining half.
            if index == 511 {
                trillionnium_owner_open_trace::drain_stream_from_env()?;
            }
        }
    } else {
        inflight_live = configured;
        for i in 0..13000 {
            trillionnium_owner_open_trace::span(
                trillionnium_owner_open_trace::Stage::ToolSpawn,
                "owned physical allocation probe",
            )
            .finish();
            actual_records += 1;
            if (i + 1) % 200 == 0 {
                trillionnium_owner_open_trace::drain_stream_from_env()?;
            }
        }
    }
    trillionnium_owner_open_trace::export_from_env()?;
    let final_live = LIVE.load(Ordering::SeqCst);
    let peak = PEAK.load(Ordering::SeqCst);
    println!(
        "{}",
        serde_json::json!({"schema":"org.trillionnium.actual-stream-requested-allocation-probe.v1",
      "mode":mode,"actual_records":actual_records,"baseline_requested_live_bytes":before,
      "configured_requested_live_bytes":configured,"inflight_requested_live_bytes":inflight_live,
      "final_requested_live_bytes":final_live,"peak_requested_live_bytes":peak,
      "record_size":std::mem::size_of::<trillionnium_owner_open_trace::Record>(),
      "span_size":std::mem::size_of::<trillionnium_owner_open_trace::Span>(),
      "allocator_overhead_measured":false,"rss_peak_measured":false,"whole_family_budget_qualified":false,"installed_qualified":false})
    );
    Ok(())
}
