# CPU negative closure: exact repaired Root capture reference

This is a narrow source-only increment on the four originals in `cpu_cancel_closure_cache`. It retains NEG08/NEG09, their actual CPU safe-point and full original closure requirements, all limits, and the mandatory `FINAL_DEPENDENCIES = None` early rejection. It starts no case, phone operation, model, process or signal.

## Why the existing source would refuse the repaired transport

The original `negative_originals.root_source()` required `execute_process` to equal the old 45952-byte Q2 Root source `53b5f9a3…`. The reviewed repaired R8 source is 71820 bytes, `50a500e0…`, and contains the exact `0374a885…` local capture repair. Its host `INTENT.json` also has explicit input/capture/deadline fields. The old whole-dictionary intent comparison therefore rejects a real repaired phase even after the first source gate is changed.

The final repaired success `RESULT.json` still has exactly seven fields. It does **not** contain an `output_capture` pointer. `OUTPUT-CAPTURE.json` is a separate original sidecar.

## Narrow changes

`normalized_capture_root()` parses the actual Root source and replaces only the RHS byte spans of `PKG`, `COMBINATION`, `VERIFIER_SHA`, `VERIFIER_BYTES`, `POLICY_SHA`, `ADOPTION_SHA` and `ROOT_SCOPE_SHA` with `None`. Offsets are UTF-8 byte offsets. The entire resulting source must be exactly 71820 bytes with SHA256 `50a500e0c1cc014d3d4043f8c86172bf0b6068719473eb5646aca818416ed649`. No other byte is variable. Actual slot values must be bounded digests or the bounded integer verifier size. `load_sources()` additionally ties package, combination, actual policy and adoption to the existing final-dependency object.

The old Q2 source remains an original input. `REMOTE_IO`, `SSH`, `ACTOR`, and the complete `remote`, `remote_program`, and `phone` source functions still must equal it. The new local execution/capture helpers and real async join are covered by the full-source inverse, rather than an exception that permits arbitrary function edits.

Every host execution record now has a seventh mandatory descriptor, `output_capture`, pointing to the same original phase directory's `OUTPUT-CAPTURE.json`. The success result remains exact7. The closer requires:

- one exact new intent, one child, return code zero, and the original stdout/stderr descriptors;
- actual child wait, both output EOFs, reader worker joined and closed, no prefix/unknown/error/close failure;
- the same original child deadline, with actual child join and both EOFs no later than that deadline;
- both stream byte counts and SHA256s equal to the complete retained stdout/stderr;
- initial zero-length output metadata from `CHILD.json` and final capture metadata having the same created inode, device, owner, mode and single link; each file must explicitly carry `original_created_inode_bound: true`;
- no transport-side signal, automatic retry, or claim that local capture proves remote cleanup.

All seven phase input descriptors are consumed by the existing pinned `Originals` reader, so the new sidecar enters the complete Root original input index and its final readback check. P4 collector `transport_originals` retains its existing four copied members; those copies do not replace the independent Root sidecar proof. No unconsumed sidecar is inserted into the CPU verifier's separate closed input set.

`close_cpu_negative.py` (`5c431419…`) and `ledger_prefix_negative.py` (`7ed57c65…`) remain byte-identical. `root_cpu_negative.py` changes only the static `negative_originals` byte/hash descriptor. The original four source files and both Root references are preserved in `reference/`; exact patches are in `validation/`.

## Interface increment

The existing closure plan schema and top-level groups remain. Add `output_capture` to these host record objects before any future actual closure:

| Plan path | Exact phase directory |
| --- | --- |
| `phone.execution` | `phone-negative-capture` |
| `p4.execution.host` | `negative-p4-capture` |
| `actor_execution.host` | `negative-cancel-actor` |
| `sender.execution` | `negative-sender` |

`HOST-PHASE.template.json` describes the additional descriptor. It is an interface template, not an executable case plan. Its null placeholders have no authority and do not freeze future source or policy values.

The final-dependency source/hash cascade is unchanged: freeze the actual CPU verifier, phone collector, P4 collector, sender and Root source plus the actual UI package, shared active runtime, runtime package, consumer, readiness, policy/adoption, configuration/service and combination. Then fill the existing final-dependency literal and update Root's pure module descriptors in one reviewed generation. This candidate deliberately performs none of those future freezes.

## Verification and scope

`test_capture_compatibility.py` reports 22 narrow checks in `validation/COMPATIBILITY-TESTS.json`. It reads an already-retained real final-0374 phase with Unicode/binary stdin, stdout and complete capture. It starts no new child or case. In-memory negative controls cover missing sidecar, unknown prefix, missing EOF, reader not joined, different child, inode replacement, deadline violation, digest mismatch, a false remote-cleanup claim, and an invented success-result capture pointer. Synthetic Root slot values are source-gate test controls only; no physical evidence or final dependency uses them.

This increment does not extend NEG08/09 to NEG04/05/07. Those cases require separate signal-actor capture plans and a fault-specific full original closure. See `PHYSICAL-FAULT-CLOSURE-REUSE.md` for the exact reusable pieces and remaining original inputs.
