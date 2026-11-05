# Pure inventory ancestry optimization candidate

This is a source-only candidate derived from the exact `67dc` runtime's
`late_boundary.py`. It does not replace that runtime, publish a new manifest,
extend a lease, retry a case, or establish physical acceptance.

The candidate is **67,005 bytes** with SHA-256
`147cf49e91fb4bcbddeba6591d48c8782efe20452db2b2d6179e7addd68c27e4`.
Reversing its one expression change reproduces the complete original
**66,996-byte** source with SHA-256
`c50a219efd992ce1353494ace2656af20c932cbc32530b0085e38a79975d8add`.

## Change and equivalence

Within `inventory_value`, the original predicate counts the roots equal to a
path or present in its lexical ancestors:

```python
sum(p == q or q in p.parents for q in paths) == 1
```

The candidate counts identical complete path-component prefixes:

```python
sum(p.parts[:len(q.parts)] == q.parts for q in paths) == 1
```

The preceding absolute-path, canonical-string and no-`..` checks remain in the
same short-circuit expression. On the fixed POSIX runtime, equality or lexical
ancestry is exactly the full-component-prefix relation. A sibling such as
`/scope/ab` does not match `/scope/a`. The distinct `/` and `//` anchors retain
their original `Path` semantics. Unlike materializing every ancestor into a
set, this change does not retain a collection of increasingly long paths.

Every other source byte is unchanged. All row fields, metadata, directory
topology, digest syntax, unique-root and byte-accounting checks still run.
The result is not memoized. No source module or proof is cached. Every current
inventory read, original-file identity check, process-group/endpoint absence
observation and lock admission still occurs at its original call site. R7,
R6 and R4 historical reference source bytes are unchanged.

## Evidence

The exact retained archive is 469,829 bytes, SHA-256
`9aacc5789a65dd875ab9fe7456e2258e0bf4e54575d3be71a50d5542a489b288`.
The original stage parser checks its canonical archive form, all 56 members,
all 32 runtime members, the actual lease and the exact original manifest before
the harness loads pure functions. Candidate mode then explicitly substitutes
the one derived source for pure local comparison. It does **not** claim that
this changed source is valid under the unchanged original manifest.

The equivalence harness compares the original and candidate functions directly
on the actual historical inventory and 23 relevant acceptance/rejection cases.
All **24/24** cases passed, including distinct roots sharing a string prefix,
Unicode/emoji components, double-slash anchors, a 150-component tree, relative
and dot paths, overlapping roots, missing or fabricated children, hard links,
metadata size/type errors, byte accounting, digest format and explicit ENOENT.
Both functions return identical canonical data or the same rejection type and
message. The harness also checks that neither function changes its input.

Two measured pure operations produced identical full data fingerprints before
and after the change. The single sequential uninstrumented measurements were:

| Pure operation | Original | Candidate |
| --- | ---: | ---: |
| Fixed non-native historical branch | 1.13449 s | 0.36905 s |
| Actual08 boundary original | 3.53120 s | 1.11408 s |

These are local observations with visible timing variability, not guaranteed
speedups and not phone admission budgets. cProfile materially increases costs.
The original profile identifies repeated `Path.parents` membership as the
major local cost; source compilation accounts for only milliseconds. The
candidate leaves the historical R7 reader's own ancestry work intact.

The first profile report is retained. Its summary used `pstats.Stats`, which can
lose counts when separately recompiled code objects share a filename, line and
name. The final harness retains all `Profile.getstats()` entries and explicitly
sums matching counters. The initial report's observed elapsed times remain
history; they are not silently overwritten.

## Reproduce locally

From the delivery package root, use a new output directory for each command:

```bash
python check_inventory_equivalence.py \
  --archive ../evidence/inputs/component-inputs.original.tar.gz \
  --stage-source reference/stage_component.original.py \
  --candidate-source source/late_boundary.py \
  --out local-equivalence-01

python profile_pure_history.py \
  --archive ../evidence/inputs/component-inputs.original.tar.gz \
  --stage-source reference/stage_component.original.py \
  --out local-baseline-profile-01

python profile_pure_history.py \
  --archive ../evidence/inputs/component-inputs.original.tar.gz \
  --stage-source reference/stage_component.original.py \
  --candidate-source source/late_boundary.py \
  --out local-candidate-profile-01
```

Run the two timing commands sequentially. Measured calls are fenced against
file opens, subprocesses, sockets and signals. They invoke neither
`verify_current` nor a live entrypoint. Actual phone profiling and any new
runtime generation remain separate Root-owned operations.

## Adoption boundary

The `600/510/420/120/300` time gates and all one-start/no-retry rules remain
unchanged. This candidate has not been deployed and has no actual runtime,
Root, consumer or acceptance-generation pins. Independent source review and
the exact original phone profile should inform whether this narrow change
is useful enough for a separately reviewed runtime successor. Passing these
local checks does not authorize a new nonce or claim that a future phone case
will fit the original lease.

## Split delivery

The small source-stage archive is exactly this source manifest plus its declared members. The immutable archive input and detailed profile history are in the full-evidence archive, under `evidence/`. When using the small source package alone, pass an independently retained exact `9aacc` archive path to `--archive`. Its complete byte pin is checked before any loader use. No runtime or case entrypoint is called by staging this package.
