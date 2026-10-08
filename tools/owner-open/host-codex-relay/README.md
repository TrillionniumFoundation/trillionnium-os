# Host Codex relay

This host-only provider converts decisions from an existing authenticated Codex CLI into the owner-open provider JSONL protocol. It never executes a tool. The phone-side `provider_host_relay.py` forwards bytes once; the Root Linux R5 Host/Core executes effects and owns durable effect recovery. Keep these two Python files together: the Codex adapter imports its paired protocol dependency from this directory. They are separate from the phone payload's optional HTTP adapter.

## Run on the authenticated host

Resolve an installed Codex executable and pass its absolute path explicitly. Select the default from that entrypoint's actual model catalog and verify inference; do not copy another host's configured alias or login files. Only Codex CLI 0.158.0 on the original local host with its catalog default `gpt-6-astra` has completed the attached qualification. The Mac entrypoint remains unqualified, including compatibility of its CLI flags.

```sh
python3 provider_codex_host.py \
  --codex /absolute/path/to/installed/codex \
  --model CATALOG_VERIFIED_MODEL \
  --evidence /absolute/private/durable/evidence \
  --cwd /absolute/private/empty/workdir
```

The listener uses host loopback port 18082 by default. For the selected workstation route, establish a trusted SSH reverse forward from AI MAX loopback 18081 to host loopback 18082. On AI MAX, bind the exact authorized phone serial with `adb -s SERIAL reverse tcp:18080 tcp:18081`. A phone provider connection is a finite single connection. A lost stream is an unknown outcome; no endpoint fallback or reconnect resends a turn. Do not change SSH host-key checks or move login material to the phone.

## Durable boundary and operation

Each accepted identity `(session_id, profile_id, task_id, turn_id)` is claimed with create-only publication and file/directory fsync before inference. A replacement stream ID does not create another turn. Dispatch intent and correlated results are persisted before forwarding. Cancellation, EOF, timeouts and unknown results stop the current model round and never relaunch it or redispatch an accepted call. Duplicate command bytes are allowed under distinct authorized call identities. Codex's own bounded network retries can occur before a decision; there is no relay retry or model fallback.

Restart the service with the same evidence directory and preserve its `claims` directory. Never clear claims to recover a timeout or create extra capacity. Keep the evidence directory private and on durable storage; its bounded capacity stops new admission rather than deleting accepted identity. Moving to another host requires preserving accepted identity custody and the phone's retained Host/Core journals, while leaving the existing login credentials on their original host. Observe existing unknown/completed outcomes instead of resubmitting their effects.

## Evidence

`qualification-summary.json` contains source hashes and redacted receipt summaries. The original qualified host adapter hash is distinguished from this packaging change requiring a portable CLI path. Packaging validation covers CLI admission and paired protocol mechanics; real inference has not been rerun for the parameter-only change. Actual Linux x86_64 Rust R5 Host/Core plus real Codex passed one effect, readback, durable completion, cancellation before/after effect, retained-journal replay, and terminal-journal-failure recovery without redispatch. These results do not qualify Android init, SELinux, the ARM64 Rust runtime, the phone UI, hardware, emergency stop, or a new phone OS image.
