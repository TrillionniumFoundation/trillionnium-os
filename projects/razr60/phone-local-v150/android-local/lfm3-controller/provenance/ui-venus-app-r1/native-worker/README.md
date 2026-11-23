# UI-Venus ordinary-App Q4_0 native candidate

This is a new model-only candidate, not the frozen Q4_K_M runtime and not a visual controller.
Native code differs in exactly four model-identity literals in venus-runtime.inc.
All other 18 original native members, UID/EUID, direct App parent, private files,
held-FD hashing, same-directory bootstrap, VLM calls and budgets retain exact bytes.
The original Q4_K_M source and build remain unchanged.

Main: UI-Venus-2-9B-Q4_0.gguf / 5,482,832,672 B /
2e881d6e74899b47b1f0c9052abeeb0a7ff55913dfb18d942a3de3cadb3d1adb.
Projector: original F16 / 918,165,664 B /
6ef77c3bf87391664be7cd71c595352e7281dabe52f24e961e2deace550f3af2.
Profile: ui-venus2-9b-q4_0-f16-mmproj. Fixed same repository/revision applies.
The worker still requires actual qwen35 architecture/pre and the exact 7,740-byte
chat template SHA4a3d47f53cc133e5dc859e9532fcb74baf0459ef426b8f107a3ac6e5926533e5.
Partial header/download metadata is not complete model qualification.

Output and app-process binding schema v1 remain structurally unchanged. Model
profile, weight pins, native source identity, new ELF and build receipt are distinct.
The build receipt truthfully has original_core_byte_unchanged=false and the narrow
only_model_identity_literals_changed=true proof. The new source boundary is against
all19 frozen App native members:18 unchanged and one exact four-literal delta.

Compiler/link/strip/readelf checks and12 SDK pins are retained. Actual NDK
source.properties revision and compiler SHA, not the directory's nominal label,
remain mandatory. The original BUILD-RECEIPT is provenance only.
Source preparation is not a successful compile, phone load, backend or model test.
Only the subsequently produced actual BUILD-RECEIPT may claim host compile success.
8192 context,1024 output,300000ms, thinking=true, raw official Mobile protocol,
ordinary App identity/no shell fallback, no INTERNET, no tool dispatch remain.
Full multimodal token admission and no-context-shift proofs remain false.
