# Owner-open ADB qualification v1

Status: **R5 executable host-process contract; physical evidence pending**

## 1. Purpose

The qualification runner executes an owner-supplied ordinary-adb argv plan
through the byte-transparent smart-socket relay:

```text
tools/owner-open/qualify_owner_open_adb.py
```

It is deliberately not an ADB action catalogue. The runner does not know which
subcommands exist or what they mean.

## 2. Explicit execution

The runner requires `--execute`. It also requires absolute paths for the adb
executable, Python interpreter, relay source, private workspace/state
directories and a new evidence directory.

Without `--execute`, no relay, adb process or target operation starts.

## 3. Plan format

The plan schema is:

```text
org.trillionnium.owner-open.adb-qualification-plan.v1
```

Example:

```json
{
  "schema": "org.trillionnium.owner-open.adb-qualification-plan.v1",
  "plan_id": "physical-device-qualification-1",
  "steps": [
    {
      "operation_id": "devices-1",
      "argv": ["devices", "-l"],
      "timeout_seconds": 15,
      "expected_exit_codes": [0]
    },
    {
      "operation_id": "shell-1",
      "argv": ["shell", "id"],
      "timeout_seconds": 30,
      "expected_exit_codes": [0]
    }
  ]
}
```

Every operation ID is unique. Each step is dispatched exactly once in plan
order.

## 4. Exact argv

For each step the process invocation is exactly:

```text
[measured adb executable] + plan argv
```

The runner does not insert:

```text
-s
serial
-H
-P
-L
transport selection
root/remount/verity operations
```

It removes inherited `ANDROID_SERIAL` and sets only the selected
`ADB_SERVER_SOCKET` for relay routing. Other owner environment, including ADB
key configuration, remains explicit deployment state.

Unknown subcommands and future service names are not rejected by the runner.
Only mechanical string/count/NUL/byte bounds apply.

## 5. No automatic retry

Timeout, non-expected exit, relay loss or output-bound failure terminates the
qualification. The runner records `automatic_redispatch=false` and never
repeats the failed operation ID.

The caller must inspect target/adb state and choose a new operation explicitly.

## 6. Measurements

The runner records stable descriptor-bound measurements for:

```text
adb executable
Python interpreter
relay source
```

Optional expected SHA-256 values make those measurements mandatory. Symlinked,
changing, group/world-writable, multiply linked or oversized files are
rejected.

## 7. Step evidence

Each successful step records:

```text
operation_id
exact argv and canonical argv digest
spawn_count = 1
return code
elapsed time
stdout/stderr byte counts
stdout/stderr SHA-256
base64 stdout/stderr
automatic_redispatch = false
```

Binary output is preserved. The qualification report does not reinterpret adb
stderr or exit codes beyond the plan's explicit expected exit-code set.

## 8. Relay evidence

The evidence directory also receives the relay descriptor and lifecycle event
log. Relay events contain only connection IDs, counts, timing and terminal
reason; payload bytes are not logged.

## 9. Physical plan requirements

A physical L4 plan should cover, as applicable:

```text
version
devices -l
get-state
explicit no-serial and serial-selected cases
shell success and non-zero shell result
push/pull binary round-trip
install/update result
unknown subcommand transparency
offline target
unauthorized target
USB loss
adb server restart
device reboot/recovery transition
```

Destructive or rebooting steps must be owner-authored and reviewed; the runner
does not synthesize them.

## 10. Promotion boundary

A host-process fixture using a fake adb executable can prove exact argv,
`ADB_SERVER_SOCKET`, no serial injection, one spawn per operation and finite
failure. It cannot prove a physical Android effect.

L4 requires the evidence package to bind the real adb/relay/Host/Codex/source
and device fingerprint, with same-turn Codex continuation and no blind
redispatch after uncertainty.
