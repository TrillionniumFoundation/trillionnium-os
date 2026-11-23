# Code15: isolated MNN diagnostic loader candidate

Code15 derives from the frozen Code14 source manifest
`ae815ddf677ab3591f9d588cae19d9067fe86d04445d562b9f2583a9147f7edf`.
Its sole application-code change is in `MobiMindModelEngine`: the separately
launched MNN diagnostic child receives the exact library search path
`/system/lib64:/system_ext/lib64:/vendor/lib64`. It still removes `LD_PRELOAD`,
`LD_AUDIT`, all existing GenieX/plugin overrides and the ADSP search override.
The installed application library directory is not inserted into that global
path. The fixed worker's non-transitive `$ORIGIN` RUNPATH remains responsible
for its directly needed, pinned MNN and C++ libraries.

The child's configured environment is recorded as
`origin-runpath-system-first.v1`. This records configuration, not proof of actual
loader resolution. The unchanged static ELF verifier's platform-defaults label
describes the ELF's direct `$ORIGIN` dependency contract only; it is not the
Code15 launcher environment. Actual maps and OpenCL receipts must be collected
from a fresh ordinary-App run before claiming GPU qualification.

This candidate follows a successful isolated `run-as` model-only observation
with the same three native files and system-first environment. That observation
does not establish the normal application's SELinux/domain execution result.
No such qualification is claimed by source checks or APK assembly.

All three MNN ELF full hashes, the GenieX runtime and worker source, model
profiles/defaults, text planner prompts/history, target/dispatch guards, shared
process slot, cancellation, and recovery journals remain unchanged. MobiMind
remains a separate model-only endpoint with no phone action dispatch. There is
no native-tools or visual-planner integration in Code15. No INTERNET permission,
external model fallback, new signing key, model switch, or phone operation is
introduced by these build scripts.

VersionCode is 15 and versionName is `0.15.0-local-mnn-loader`. The complete
source manifest and new host/build receipts identify this candidate separately
from Code14; historical failed evidence is not overwritten.
