# Phone-local client r6

This is a new source candidate. The frozen 8,399-byte client `b298ac86fdf57dd0c7dc5159febf114ed176398d32ea672c9abda4a6eb621539` and all existing claims remain unchanged.

Install target: `/var/lib/trillionnium/owner-open/phone-local-v150/tool_client_r6.py`.
Default endpoint: `hepta_phone_executor_v150_r6`; protocol string remains `hepta_phone_local_v150`. There is no endpoint fallback. The client verifies UID 0, GID 0 and exact server context `u:r:trillionnium_owner_open_phone_executor:s0` before sending a request. SO_PEERSEC uses a 256-byte buffer; it does not repeat the earlier capture helper's unsupported 4,096-byte argument.

## Transport evidence

An execute claim is durable before any connection. A new `<action_id>.transport-r6/` directory holds exclusive, fsynced, hash-linked phase files. They cover socket creation, connect, peer identity query, the write-ahead send boundary, full request completion, response header/body and final validation. Final error evidence retains the exact failed phase, errno, confirmed send/receive bytes and request/response frame hashes. The trace contains hashes, never duplicated command text or raw output.

A failure before the write-ahead send boundary records `request_definitely_not_sent=true`. Once that boundary is crossed, any unknown transport result remains dispatch-possible, even if no positive send count survived. Execute still returns 71 and retains `state=indeterminate, can_redispatch=false`; this transport fact is not a fabricated sidecar terminal or automatic ledger resolution. Any phase persistence failure also fails closed. A single absolute transport deadline is never extended by partial I/O.

A repeated current-r6 action can only inspect its original r6 receipt and returns 76. A legacy claim is not retargeted to the new namespace: it returns 76 without a socket connection and requires inspection of the original executor. Neither path edits or releases the original claim.

## Actual terminal versus business result

Client 0 requires the original output lengths/hashes, action/command binding and the strict frozen-r6 receipt: terminal true, completed, one dispatch, PID=PGID, process group established/joined/absent, wait identity retained, exact executor/bootstrap/worker contexts, verified shell UID/GID 2000 and cleared supplementary groups, and the worker-entry handshake stage. exit_code must be an integer, not a boolean. This proves the controlled command's terminal only. Provider postconditions and public App readback still determine business success.

There are no invented NNP or SID receipt fields. Frozen r6 entry assertions and independent runtime/proc evidence supply those checks. Java helpers, App permissions, display/focus and Unicode business behavior require separate physical qualification.

## Read-only health

`python3 -I -B tool_client_r6.py health` and `inspect --action-id ... --command-sha256 ...` do not create execute claims. A health CLI exit of 0 means a valid protocol response was received. Root must separately check state=ready, actual peer/executor contexts and execute_authorized. A Magisk read-only health result cannot qualify bootstrap execution, a worker transition, model health or an App action.

## Validation

61 isolated host assertions passed with actual process exit 0 and stderr 0. Socket outcomes were injected, with no real phone, network connection, shell execution or model request. Tests cover connect/peer/send/partial-send/receive failures; no-replay claims; exact raw stdout; context/identity/handshake rejection; boolean-exit rejection; deadline bounds; and read-only health's explicit nonexecute authority. These are component fixtures, not a physical acceptance result.

Independent focused review confirmed the final success predicate against frozen r6 RC1 and the unchanged phase/no-replay implementation. Root alone installs or executes this candidate after the original executor's retirement evidence is closed.
