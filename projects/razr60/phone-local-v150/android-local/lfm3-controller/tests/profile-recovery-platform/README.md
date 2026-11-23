# Profile recovery platform host regression

Host-only tests. No Phone, ADB, Android checker, or production /system/bin/cmd execution.

Dependencies: Python 3 and JDK supporting javac --release 8 (validated JDK 17). The unchanged Java boot test requires /usr/bin/python3 for its actual host-process cases. All output directories must be new.

From the component root:

    python3 tests/profile-recovery-platform/run_boot_host.py --jdk-bin /absolute/jdk/bin --out /absolute/new-output/boot
    python3 tests/profile-recovery-platform/run_fd_host.py --jdk-bin /absolute/jdk/bin --out /absolute/new-output/fd

The default component root is relative to this test directory; --source-root selects an explicit checkout. --compile-only checks packaging and compilation without executing Java tests; its receipt explicitly has tests_executed=false.

Boot: existing 11 cases/38 assertions, injected real host processes and process doubles; no Android qualification. FD: existing 20 cases/46 assertions, full actual MobiMindPrivateFiles and byte-exact AndroidProc block, with explicit fake Os/clock/UID/request DTO/Proc boundary. Synthetic UID values are not device evidence. The reviewed Main/Private source pins remain required; intentional production changes require deliberate review/rebinding of these pins.

A close failure proves an attempted close, not an actually closed Android FD. Watchdog abort requests termination only; observed exit and EOF are separate. A blocked platform start can delay the watchdog; no unconditional hard-exit timing claim.

The original portability revision adapted source/JDK paths and added compile-only packaging mode. This follow-up also extends the FD runner with the pinned adapter projection and a separate errno test entry. The original Boot and FD Java test files remain byte-identical; the adapter checks are in their own new Java file. Device diagnostics, installation and owner recovery remain separate root-operated workflows.

## Proc disappearance adapter follow-up

The FD runner also executes the separate ProcErrnoAdapterHostTest after the unchanged 20-case FD test. Its 12 scoped cases cover directory/open errno classification, fresh directory-absence confirmation, original deadline, and acquired-FD read/fstat/close errors. Pure census retry tests are separate and not executed here.

The fixture copies the actual ProcessGone class and entire AndroidProc block from pinned production files. Android Os/clock/UID and the remaining Proc/request DTO are explicit doubles. Main is pinned to 069970c4, Processes to 14f73515, and PrivateFiles remains 9bf20793. Future source changes require deliberate rebinding. Original Java tests and the Boot runner are byte-identical to the prior portable package; Boot logic is not rerun for this adapter change.
