"""Typed retirement of one unresolved original, without rewriting its outcome.

The positive path is a persistent namespace cut plus complete, source-bound
producer and current-state evidence. This module neither cancels nor replays
anything. All observations are private pinned originals; no caller eligibility
flag, missing directory, elapsed timeout, or recovery summary grants admission.
"""
import base64
from collections import defaultdict
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import time
import xml.etree.ElementTree as ET
import zlib

from build_fence_plan import ORIGINAL, BASE, LABEL, NONCE, canonical, fence_rows
import verify_retained_preaccept as RETAINED
import verify_retained_staged_r8 as STAGED
import verify_retained_transport_r9 as TRANSPORT

BOOT = "f8019f83-20a7-4f18-bea1-51c980621e4d"
BOUND01 = {"label": "root-r10-neg01-fc33-r6-bound01", "nonce": "5f94c6a88805eefb0e2320cae5265d46"}
META_PIN = (1255, "c3d979f61989a384d859144d0aba7d5f00b07f944ff0c4dd699febabf42399b9")
CANCEL_PIN = (182, "5f0646f9deefaa026258095a3fe49ef5defc1475ef87bec6119962d1dd4fc639")
BOUND01_PIN = (704, "09eb6d6a460c893f7da5ad6a0fbb383cbffb5d29f78a5ba7b373520fd92ed00b")
PREVIOUS_SHA = "fcdf8a456f663d6963d3cd9caf231a210aad92d8f5e192a71917381d10ea10f0"
P4_CENSUS_SOURCE = "9045fa81e7ae7d4928b9333730dd80af36752246abf721f6c201956ec1b918d0"
P4_CENSUS_V2_SOURCE = "6601dad76e36c239f212bcd485b8da4bedd0f38b23ef92d88b0d650b7c4b4ef9"
RUNTIME_RUNNER_SOURCE = "222cfe5463f9fdf3d215c918ec187110fb80270d064a1f65e3e0659c62392619"
MAC_CENSUS_PIN = (22946, "058b82c0b566b02bed01216d759b735fa4f9418df5ed2ee78c3655eb82fdd0c2")
MAC_ARCHIVE_PIN = (6885809, "0959f76fe0733baa85eb62687ef4826f2665fce024adc87f7d20112b6bae564c")
MAC_CAPTURE_PIN = (29527440, "f77b1234de05f5b85793e6d7d472c443012ec5885bbabca98fee46df4ccd58f0")
PHONE_READER_PIN = (56567, "faeb79855f066c6d69dca4261e6c5648745c44b6b6192ab9af187ebc9d6cfc1a")
PHONE_REQUEST_PIN = (42502, "36e0a617901ee368abd272c4565da0eef967dceeedfe7cc9550810b52de4323f")
PHONE_CAPTURE_PIN = (7165341, "4192ed1ee9c96dbdd77d72f1c69a4f3bd0f9db90add83f9d493a8d857f4be87f")
HISTORICAL_INVENTORY_PIN = (1345535, "4bd70b72d2a92a6c963912159d9e978fc681a35ddb30c03a2c741700bf47cde4")
DRAFT_OBSERVER_PIN = (20109, "4c01f9a04c420243fabe2b117dcb2141f1949d6f26101091186d86030691efe8")
DRAFT_REQUEST_PIN = (833, "bd3bdf4619a5f181ecec9fe4fe62946e1ebccb8b6bba504dafaf29496c7da6c0")
CURRENT_ROOT = BASE + "/native-guard-r10-r1-operator-fc33-native-v3-r10"
CURRENT_LABELS = {"NEG-01": "root-r10-neg01-fc33-r10-bound01", "NEG-02": "root-r10-neg02-fc33-r10-bound01"}
ORIGINAL_SOURCE_PINS = {
    "run_component_root_once.py": (78567, "53c2e7c26c960d76ac5d3201420d33f13fb06c241d30d40fc7b2b7577e690257"),
    "phone_chain_bridge.py": (8101, "0d5e073ba4e31f896e1234a3896b281108e0272ba5e3476adb01c7dde307fa15"),
    "send_new_native_guard_task_r10_r4.py": (41745, "de6c90187ad15995cbd85c662fb7d0a0ee40809bc54d9c1a51c46e164d75b354"),
    "control_send_once.py": (6301, "ca200ab35d39ec42232e853c785ab298958858cb4f03e2092231d1ccc638fc70"),
    "phone_once.py": (5652, "179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22"),
    "run_root_fixture_phase.py": (10498, "bf65791c252d0b4d9416717ffca44fe43c9021211c2f2189be5553ab8967a6b2"),
    "root_fixture_once.py": (18725, "5d78ad21fede0044c6b4d7dd1def5df005008ed994116ea61332ed064abd1870"),
}
RESOLUTION_SCHEMA = "hepta.r6.bound02.disposition-inputs.v1"
FRESH_SCHEMA = 'hepta.r10.original-dispositions.fresh-admission-inputs.v1'
CONTEXT_SCHEMA = 'hepta.r10.original-dispositions.admission-context.v1'
OPERATOR_SCHEMA = 'hepta.r10.original-dispositions.admission-operator-input.v1'
EFFECT_FIELDS = ("phone_calls", "native_send_attempts", "model_requests", "root_fixture_attempts", "ui_mutation_attempts", "resource_mutation_attempts")
FIXED_STAGES = {"prepare-before-create", "root-before-init", "root-before-run", "sender-before-execute"}


class Refused(RuntimeError):
    pass


def need(value, message):
    if not value:
        raise Refused(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def same(a, b):
    return canonical(a) == canonical(b)


def strict(raw):
    def pairs(rows):
        result = {}
        for k, v in rows:
            need(k not in result, "duplicate JSON key")
            result[k] = v
        return result
    def constant(_):
        raise Refused("nonfinite JSON")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, TypeError) as error:
        raise Refused("invalid complete JSON original") from error


def exact(value, keys, what):
    need(type(value) is dict and set(value) == set(keys), what + ": exact fields required")


def descriptor(row):
    exact(row, ("path", "bytes", "sha256"), "original descriptor")
    need(type(row["path"]) is str and row["path"] and "\0" not in row["path"], "original path")
    path = PurePosixPath(row["path"])
    need(path.is_absolute() and str(path) == row["path"] and ".." not in path.parts, "canonical absolute original path")
    need(type(row["bytes"]) is int and 0 < row["bytes"] <= 16 * 1024 * 1024, "existing 16 MiB bounded original bytes")
    need(type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]), "original SHA256")
    return row


def read(row, read_pinned, pin=None):
    descriptor(row)
    if pin is not None:
        need((row["bytes"], row["sha256"]) == pin, "fixed original pin differs")
    raw = read_pinned(row)
    need(type(raw) is bytes and len(raw) == row["bytes"] and sha(raw) == row["sha256"], "original bytes differ")
    return raw


def document(row, read_pinned, pin=None):
    return strict(read(row, read_pinned, pin))


def mcp_value(value):
    need(type(value) is dict and value.get("isError") is False, "original MCP operation did not succeed")
    content = value.get("content")
    need(type(content) is list and len(content) == 1 and content[0].get("type") == "text", "one complete original MCP text value")
    return strict(content[0]["text"])


def verify_fence_readback(raw_value, expected, version=None):
    need(type(raw_value) is list and len(raw_value) == 2, "independent file_info and whole read required")
    values = []
    for item in raw_value:
        need(item.get("status") == "fulfilled", "unknown fence readback")
        values.append(mcp_value(item["value"]))
    info, reading = values
    need(info.get("path") == expected["path"] and info.get("mode") == 0o600, "exact private regular fence path/mode")
    metadata = info.get("metadata", {})
    need(metadata.get("link_count") == 1 and metadata.get("uid") == {"mac": 501, "pocket4": 1000}[expected["host"]], "fence ownership or links differ")
    need(reading.get("truncated") is False and len(reading.get("files", [])) == 1, "complete independent fence read")
    file = reading["files"][0]
    need(file.get("eof") is True and file.get("path") == expected["path"], "fence original path/EOF")
    payload = base64.b64decode(expected["payload_base64"], validate=True)
    need(file.get("text", "").encode() == payload, "fence payload differs")
    for row in (info, file):
        need(row.get("size") == len(payload) and row.get("sha256") == sha(payload), "fence read bytes/hash differ")
        need(type(row.get("version")) is str and row["version"], "fence immutable-read version absent")
    need(info["version"] == file["version"], "fence read versions differ")
    if version is not None:
        need(info["version"] == version, "persistent fence inode/version changed")
    return {"fence_id": expected["fence_id"], "host": expected["host"], "path": expected["path"],
            "bytes": len(payload), "sha256": sha(payload), "version": info["version"]}


def verify_namespace_fences(rows, *, read_pinned):
    expected = {r["fence_id"]: r for r in fence_rows()}
    exact(rows, expected, "all four fixed original namespace fences")
    result = {}
    for name, wanted in expected.items():
        exact(rows[name], ("write_original", "readback_original"), "fence originals")
        original_write = document(rows[name]["write_original"], read_pinned)
        need(same(original_write.get("fence"), wanted), "create-only fence request differs")
        receipt = mcp_value(original_write["write"])
        need(receipt.get("written") == wanted["payload_bytes"] and receipt.get("size") == wanted["payload_bytes"]
             and receipt.get("sha256") == wanted["payload_sha256"] and receipt.get("mode") == 0o600,
             "create-only publication did not return exact written bytes")
        result[name] = verify_fence_readback(document(rows[name]["readback_original"], read_pinned), wanted, receipt.get("version"))
    return result


def tcp_clients(tables):
    need(type(tables) is dict and all(type(tables.get(n)) is str for n in ("tcp", "tcp6")), "both complete kernel TCP tables required")
    listeners = []
    clients = []
    for name in ("tcp", "tcp6"):
        lines = tables[name].splitlines()
        need(lines and "local_address" in lines[0], "complete TCP table header")
        for line in lines[1:]:
            fields = line.split()
            need(len(fields) >= 10, "invalid kernel TCP row")
            local, remote = int(fields[1].split(":")[1], 16), int(fields[2].split(":")[1], 16)
            if local not in (5037, 5061) and remote not in (5037, 5061):
                continue
            row = {"table": name, "local_port": local, "remote_port": remote, "state": fields[3], "inode": int(fields[9])}
            (listeners if fields[3] == "0A" and remote == 0 else clients).append(row)
    need({r["local_port"] for r in listeners} == {5037, 5061} and len(listeners) == 2, "fixed two ADB listeners differ")
    return listeners, clients


def original_path_match(value):
    if type(value) is not str:
        return False
    return any(token in value for token in (NONCE, LABEL, ORIGINAL["job_id"]))


def p4_snapshot(snapshot, *, source_raw, independent_stdin_owners=()):
    """Classify the entire actual /proc census using the fixed R6 invocation forms.

    Long-lived unrelated file/module interpreters are not killed or called idle.
    The original P4 workload can appear as a fixed-token file/inline process or
    a generic stdin interpreter. Every latter process needs a different exact
    original job binding, or remains unresolved.
    """
    source_sha = sha(source_raw)
    need(source_sha in (P4_CENSUS_SOURCE, P4_CENSUS_V2_SOURCE), "reviewed actual P4 collector source differs")
    need(snapshot.get("schema") == "hepta.r6.bound02.host-producer-census.v1" and snapshot.get("host") == "pocket4", "exact P4 census schema")
    need(snapshot.get("observer_uid") == 1000 and snapshot.get("snapshot_atomic") is False
         and snapshot.get("environment_read") is False and snapshot.get("effect_count_asserted") is False,
         "P4 census scope differs")
    for key in ("native_sends", "phone_commands", "signals_sent"):
        need(type(snapshot.get(key)) is int and snapshot[key] == 0, "census must remain read-only")
    begin, end = snapshot["pid_enumeration_begin"], snapshot["pid_enumeration_end"]
    need(type(begin) is list and type(end) is list and 0 < len(begin) <= 65536
         and begin == sorted(set(begin)) and end == sorted(set(end)), "complete bounded PID enumeration")
    need(snapshot["new_pids"] == sorted(set(end) - set(begin)) == [], "new unobserved producer during census")
    need(snapshot["gone_pids"] == sorted(set(begin) - set(end)), "census disappeared PID accounting")
    rows = {row["pid"]: row for row in snapshot["processes"]}
    need(len(rows) == len(snapshot["processes"]) and set(end) <= set(rows) <= set(begin), "complete current process rows")
    for error in snapshot["read_errors"]:
        need(error["pid"] in snapshot["gone_pids"] and error.get("errno") == 2, "unreadable extant process is unknown")
    need(set(rows) | {e["pid"] for e in snapshot["read_errors"]} == set(begin), "omitted process from census")
    owners = {r["pid"]: r for r in independent_stdin_owners}
    classifications = []
    unresolved = []
    for pid, row in rows.items():
        need(row.get("start_identity_stable") is True, "process identity raced")
        if source_sha == P4_CENSUS_V2_SOURCE:
            need(row.get("command_identity_stable") is True and row.get("command_sha256_after") == row.get("command_sha256"),
                 "process command raced in the strengthened complete census")
        candidate = bool(row.get("owner_token_matches") or "python" in (row.get("exe") or row.get("comm", "")).lower()
                         or row.get("comm") in ("adb", "ssh", "sh", "bash", "dash", "timeout", "nc", "socat", "hepta-runtime-jobctl"))
        need(row.get("producer_candidate") is candidate, "collector candidate derivation differs")
        if not candidate:
            continue
        bound_path = original_path_match(row.get("cwd")) or any(original_path_match(fd.get("target")) for fd in row.get("fds", []))
        if pid == snapshot["observer_pid"]:
            need(row.get("inline_source_sha256") == source_sha and row.get("interpreter_mode") == "inline", "census self exception source binding")
            role = "EXACT_CURRENT_READ_ONLY_OBSERVER"
        elif row.get("owner_token_matches") or bound_path:
            unresolved.append(pid); role = "POSSIBLE_ORIGINAL_PRODUCER"
        elif row.get("interpreter_mode") == "stdin":
            owner = owners.get(pid)
            if owner is None:
                unresolved.append(pid); role = "OPAQUE_STDIN_OWNER_UNRESOLVED"
            else:
                need(owner["host_boot_id"] == snapshot["boot_id"] and owner["start_ticks"] == row["start_ticks"]
                     and owner["command_sha256"] == row["command_sha256"], "stdin owner generation differs")
                need(owner["job_id"] != ORIGINAL["job_id"] and owner["parent_pid"] == row["ppid"], "stdin foreign-owner binding")
                parent = rows.get(row["ppid"])
                need(parent is not None and parent.get("inline_source_sha256") == RUNTIME_RUNNER_SOURCE, "exact installed runtime runner parent")
                directory = "/home/alex/.local/state/hepta-runtime-mac-worker/jobs/" + owner["job_id"]
                need(parent.get("cwd") == directory, "foreign owner job cwd differs")
                fds = {r["fd"]: r for r in row.get("fds", [])}
                need(row.get("fd_errors") == [] and parent.get("fd_errors") == []
                     and fds.get(0, {}).get("target") == directory + "/stdin.bin"
                     and fds[0]["inode"] == owner["stdin_inode"] and fds[0]["dev"] == owner["stdin_device"], "exact foreign stdin OFD differs")
                need(any(fd.get("target") == fds[0]["target"] and fd.get("inode") == fds[0]["inode"]
                         for fd in parent.get("fds", [])), "stdin file is not held by actual parent")
                role = "EXACT_INDEPENDENT_STDIN_JOB"
        else:
            # The fixed original source never execs into a differently named
            # file/module or arbitrary -c payload. Generic stdin is handled
            # above; this is not a claim that other owners have no effects.
            need(row.get("command_bytes", 0) > 0 and row.get("interpreter_mode") in ("inline", "file_or_other"), "unclassified command form")
            role = "OUTSIDE_FIXED_ORIGINAL_INVOCATION_FORMS"
        classifications.append({"pid": pid, "start_ticks": row["start_ticks"], "command_sha256": row["command_sha256"], "classification": role})
    listeners, clients = tcp_clients(snapshot["network_tables"])
    need(not clients, "original-capable ADB client channel remains; no transport drain")
    return {"host": "pocket4", "boot_id": snapshot["boot_id"], "classifications": classifications,
            "complete_pids": len(rows), "adb_listeners": listeners, "adb_client_channels": [],
            "unresolved_pids": unresolved, "observed_unix_ms": snapshot["ended_unix_ms"], "historical_effect_count": None}


def raw_record(row):
    need(type(row) is dict and all(k in row for k in ("bytes", "sha256", "base64")), "complete raw record")
    try:
        raw = base64.b64decode(row["base64"], validate=True)
    except (TypeError, ValueError) as error:
        raise Refused("invalid raw record encoding") from error
    need(type(row["bytes"]) is int and len(raw) == row["bytes"] and sha(raw) == row["sha256"], "raw record bytes/hash differ")
    return raw


def mac_snapshot(value, *, source_raw):
    need((len(source_raw), sha(source_raw)) == MAC_CENSUS_PIN, "exact independently reviewed Mac collector")
    need(value.get("schema") == "hepta.r6.bound02.mac-producer-census.v1" and value.get("host") == "mac", "Mac census schema")
    need(value.get("uid") == value.get("euid") == 501 and value.get("boot_before") == value.get("boot_after")
         and type(value.get("boot_before")) is str and value["boot_before"], "Mac owner/boot changed")
    need(value.get("source", {}).get("sha256") == MAC_CENSUS_PIN[1] and value["source"].get("bytes") == MAC_CENSUS_PIN[0], "Mac invocation/source descriptor")
    need(value.get("original_terminal") is None and value.get("historical_effect_count") is None
         and value.get("signals") == [] and value.get("phone_calls") == 0, "Mac observation must not invent termination")
    snapshots, details = value["snapshots"], value["python_and_ancestor_details"]
    need(len(snapshots) == len(details) == 2, "two complete Mac process censuses")
    observer = value["observer_pid"]
    current = []
    for snapshot, enrichment in zip(snapshots, details):
        need(snapshot.get("complete_ps_capture") is True and snapshot.get("parse_errors") == []
             and snapshot.get("argv_bytes_claimed") is False, "complete Mac ps rendering required")
        for key in ("full_command_result", "identity_command_result"):
            result = snapshot[key]
            need(result.get("returncode") == 0 and raw_record(result["stderr"]) == b"", "incomplete Mac ps command")
        need(raw_record(snapshot["raw"]) == raw_record(snapshot["full_command_result"]["stdout"]), "Mac ps raw differs")
        rows = {r["pid"]: r for r in snapshot["records"]}
        need(len(rows) == len(snapshot["records"]) == snapshot["unique_pid_count"] and set(snapshot["pids"]) == set(rows), "complete Mac PID rows")
        python_pids = {pid for pid, r in rows.items() if r.get("python_candidate") is True}
        need(set(enrichment["python_pids"]) == python_pids, "missing Python candidate")
        detail_rows = {r["pid"]: r for r in enrichment["processes"]}
        need(python_pids <= set(detail_rows), "all Python commands require actual capture")
        classified = []
        for pid in sorted(python_pids):
            r, d = rows[pid], detail_rows[pid]
            need(r.get("identity_stable_during_enrichment") is True and d.get("identity_stable") is True, "Mac process identity raced")
            need(d["identity_before"]["start_identity"] == d["identity_after"]["start_identity"] == r["start_identity"], "Mac kernel start identity changed")
            command = d["command_capture"]
            need(command.get("returncode") == 0 and raw_record(command["stderr"]) == b"", "Mac Python command unavailable")
            raw = raw_record(command["stdout"])
            need(sha(raw) == d["command_sha256"] and len(raw) == d["command_bytes"], "actual Mac command rendering hash")
            rendered = raw.decode("utf-8", errors="strict")
            markers = original_path_match(rendered) or "run_component_root_once.py" in rendered or "send_new_native_guard_task_r10_r4.py" in rendered
            if pid == observer:
                need(MAC_CENSUS_PIN[1] in rendered and str(MAC_CENSUS_PIN[0]) in rendered,
                     "observer command/source binding unavailable")
                role = "EXACT_CURRENT_READ_ONLY_OBSERVER"
            elif markers:
                raise Refused("Mac possible original producer remains: " + str(pid))
            elif d["python_mode"] == "stdin":
                raise Refused("Mac opaque stdin interpreter requires exact independent owner: " + str(pid))
            else:
                role = "OUTSIDE_FIXED_ORIGINAL_MAC_INVOCATION_FORMS"
            classified.append({"pid": pid, "start_identity": r["start_identity"], "command_sha256": sha(raw), "classification": role})
        current.append(classified)
    for snap in value["fd_snapshots"]:
        need(snap.get("permission_or_race_gaps_are_not_absence") is True, "FD observation scope")
        for row in snap.get("namespace_related_descriptors", []):
            # A matching descriptor needs explicit ownership review. The known
            # observer may read the tombstone itself; it may not own old output.
            need(row.get("pid") == observer, "original namespace still held by another Mac process")
    transports = mac_transport_residuals(value)
    return {"host": "mac", "boot_id": value["boot_after"], "classifications": current[-1],
            "transport_residuals": transports, "all_transport_channels_retired": None,
            "observed_unix_ms": value["finished_unix_ns"] // 1000000, "historical_effect_count": None}


def mac_capture_from_archive(desc, *, read_pinned):
    """Read the complete original archive within the old 16 MiB file limit."""
    archive = document(desc, read_pinned, MAC_ARCHIVE_PIN)
    exact(archive, ("schema", "codec", "compressed_base64", "compressed_bytes", "compressed_sha256",
                    "payload_bytes", "payload_sha256", "private_payload"), "complete Mac census archive")
    need(archive["schema"] == "hepta.r6.bound02.mac-producer-census.v1.archive.zlib.v1"
         and archive["codec"] == "zlib+base64" and archive["private_payload"] is True
         and (archive["payload_bytes"], archive["payload_sha256"]) == MAC_CAPTURE_PIN,
         "actual complete Mac archive/payload binding")
    packed = base64.b64decode(archive["compressed_base64"], validate=True)
    need(len(packed) == archive["compressed_bytes"] and sha(packed) == archive["compressed_sha256"], "exact complete Mac packed bytes")
    decoder = zlib.decompressobj()
    raw = decoder.decompress(packed, MAC_CAPTURE_PIN[0] + 1)
    need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
         and (len(raw), sha(raw)) == MAC_CAPTURE_PIN, "bounded Mac archive EOF/raw integrity")
    return strict(raw)


def mac_transport_residuals(value):
    """Keep complete ps transport facts without pretending mux channels idle.

    A buffered exact old payload still enters one of the three P4 exclusive
    namespaces. Already-past-entry Python producers are a different check.
    This is why a shared master need not be killed and marker absence alone
    is never a positive retirement proof.
    """
    header = re.compile(rb"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(-?\d+)\s+([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.*?)(?:\r?\n)?$")
    names = {"ssh", "sshd", "sshd-session", "sh", "bash", "zsh", "dash", "fish", "csh", "tcsh", "ksh",
             "nc", "ncat", "netcat", "socat", "timeout", "gtimeout", "scp", "sftp", "sftp-server", "rsync", "adb"}
    summaries = []
    for snapshot in value["snapshots"]:
        raw = raw_record(snapshot["raw"])
        identities = {r["pid"]: r for r in snapshot["records"]}
        rows = []
        for line in raw.splitlines(keepends=True):
            match = header.match(line)
            if match:
                rows.append([match, [line]])
            else:
                need(rows, "unassigned Mac ps prefix")
                rows[-1][1].append(line)
        seen = set()
        selected = []
        for match, segments in rows:
            pid, ppid, pgid, uid = [int(match[n]) for n in range(1, 5)]
            need(pid not in seen, "duplicate Mac full ps PID header")
            seen.add(pid)
            start = "ps_lstart:" + " ".join(match[5].decode().split())
            tail = match[6].split(None, 1)
            displayed = tail[0].decode() if tail else ""
            command = (tail[1] if len(tail) == 2 else b"") + (b"\n" + b"".join(segments[1:]).rstrip(b"\r\n") if len(segments) > 1 else b"")
            identity = identities.get(pid)
            if identity is not None:
                need((pid, ppid, pgid, uid, start) == tuple(identity[k] for k in ("pid", "ppid", "pgid", "uid", "ps_start_identity")),
                     "Mac full ps/identity correlation raced")
            else:
                need(PurePosixPath(displayed).name == "ps", "non-observer process lacks identity-only census binding")
            sources = [displayed, command.decode().split(None, 1)[0] if command.strip() else ""]
            if identity is not None:
                sources += [identity.get("comm", ""), identity.get("executable", {}).get("path") or ""]
            matched = sorted({PurePosixPath(p).name.lstrip("-").rstrip(":") for p in sources if p} & names)
            if not matched:
                continue
            selected.append({"pid": pid, "ppid": ppid, "start_identity": identity.get("start_identity") if identity else None,
                "names": matched, "command_sha256": sha(command), "command_bytes": len(command),
                "original_marker_match": original_path_match(command.decode()), "channel_state": "UNKNOWN",
                "disposition_scope": "CHANNEL_STATE_UNKNOWN_LATE_ENTRY_STILL_FENCED"})
        for missing in set(identities) - seen:
            need(PurePosixPath(identities[missing]["comm"]).name == "ps", "non-observer identity lacks full command rendering")
        summaries.append({"phase": snapshot["label"], "complete_full_ps_rows": len(rows), "transports": selected,
                          "all_channels_drained": None, "marker_absence_is_retirement": False})
    return summaries


def independent_p4_stdin_owners(snapshot, status_originals, *, read_pinned):
    """Derive foreign ownership from actual kernel FD/parent facts.

    The fixed original SSH path feeds an anonymous pipe to python stdin. It
    cannot become this different runtime job's regular stdin.bin. A caller
    supplied 'independent' boolean is never accepted. Terminal receipts are
    kept separately; they do not change the original bound02 outcome.
    """
    statuses = {}
    for desc in status_originals:
        raw = document(desc, read_pinned)
        need(type(raw) is list, "independent job status original list")
        for item in raw:
            need(item.get("status") == "fulfilled", "independent job status unavailable")
            value = mcp_value(item["value"])
            job = value.get("job_id")
            need(type(job) is str and job != ORIGINAL["job_id"], "foreign status cannot retire original")
            need(value.get("state") == "succeeded" and type(value.get("exit_code")) is int and value["exit_code"] == 0
                 and value.get("terminal_publication_confirmed") is True and value.get("terminal_publication_protocol") == 1
                 and value.get("output_complete") is True and value.get("output_durable") is True
                 and value.get("automatic_retry") is False and type(value.get("at_unix_ms")) is int,
                 "authoritative complete independent terminal required")
            need(job not in statuses, "duplicate independent terminal receipt")
            statuses[job] = value
    owners = []
    for r in snapshot["processes"]:
        if r.get("interpreter_mode") != "stdin":
            continue
        fd = next((f for f in r.get("fds", []) if f["fd"] == 0), None)
        if fd is None:
            continue
        match = re.fullmatch(r"/home/alex/\.local/state/hepta-runtime-mac-worker/jobs/([0-9a-f]+-fc05-[0-9a-f]+)/stdin\.bin", fd.get("target", ""))
        if not match or match.group(1) not in statuses:
            continue
        status = statuses[match.group(1)]
        need(status["at_unix_ms"] >= snapshot["ended_unix_ms"], "independent terminal predates observed live generation")
        need(stat.S_ISREG(fd["mode"]), "independent stdin must be the exact regular job input")
        owners.append({"pid": r["pid"], "host_boot_id": snapshot["boot_id"], "start_ticks": r["start_ticks"],
            "command_sha256": r["command_sha256"], "job_id": match.group(1), "parent_pid": r["ppid"],
            "stdin_inode": fd["inode"], "stdin_device": fd["dev"], "terminal_observed_unix_ms": status["at_unix_ms"]})
    return owners


def verify_host_producer_cut(row, fences, *, read_pinned):
    exact(row, ("mac_source", "mac_census", "pocket4_observations", "independent_job_status_originals"), "complete two-host producer cut")
    mac_source = read(row["mac_source"], read_pinned, MAC_CENSUS_PIN)
    mac_value = mac_capture_from_archive(row["mac_census"], read_pinned=read_pinned)
    mac = mac_snapshot(mac_value, source_raw=mac_source)
    need(type(row["pocket4_observations"]) is list and len(row["pocket4_observations"]) == 2, "two independent complete P4 observations")
    snapshots, observed, foreign = [], [], []
    for item in row["pocket4_observations"]:
        exact(item, ("source", "census"), "source-bound P4 census")
        source = read(item["source"], read_pinned)
        value = document(item["census"], read_pinned)
        owners = independent_p4_stdin_owners(value, row["independent_job_status_originals"], read_pinned=read_pinned)
        foreign.extend(owners)
        snapshots.append(value)
        observed.append(p4_snapshot(value, source_raw=source, independent_stdin_owners=owners))
    need(sha(read(row["pocket4_observations"][1]["source"], read_pinned)) == P4_CENSUS_V2_SOURCE,
         "final P4 confirmation must include command identity bookends")
    need(observed[0]["boot_id"] == observed[1]["boot_id"], "P4 census changed boot")
    need(snapshots[0]["ended_unix_ms"] <= snapshots[1]["started_unix_ms"], "P4 ordered distinct complete observations")
    need(not observed[0]["unresolved_pids"] and not observed[1]["unresolved_pids"], "P4 original/opaque producer remains at either observation")
    # Every fence publication must precede the matching host's completed cut.
    for fence in fences.values():
        parts = fence["version"].split(":")
        need(len(parts) == 5 and all(re.fullmatch(r"[0-9]+", p) for p in parts), "actual immutable-read fence version shape")
        observed_ms = mac["observed_unix_ms"] if fence["host"] == "mac" else observed[0]["observed_unix_ms"]
        need(max(int(parts[3]), int(parts[4])) // 1000000 <= observed_ms, "fence published after producer observation")
    expected_mac = next(r for r in fence_rows() if r["host"] == "mac")
    for key in ("fences_before", "fences_after"):
        entries = mac_value[key]
        need(type(entries) is list and len(entries) == 1, "actual Mac fence bookend")
        f = entries[0]
        metadata = f["metadata"]
        version = ":".join(str(metadata[k]) for k in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))
        need(f.get("stable") is True and f["path"] == expected_mac["path"]
             and raw_record(f["raw"]) == base64.b64decode(expected_mac["payload_base64"], validate=True)
             and version == fences[expected_mac["fence_id"]]["version"], "Mac fence changed during producer cut")
    # The first complete P4 observation excludes the exact original forms;
    # its sole opaque interpreter is bound to a different regular job input.
    # The later strengthened census is confirmation, not a claim that the
    # accepted cut happened only after already captured phone originals.
    cut = max([mac["observed_unix_ms"], observed[0]["observed_unix_ms"]]
              + [r["terminal_observed_unix_ms"] for r in foreign])
    return {"schema": "hepta.r6.bound02.source-bounded-producer-cut.v1", "mac": mac, "pocket4": observed[-1],
            "cut_unix_ms": cut, "pocket4_first_observation": observed[0], "independent_stdin_jobs": foreign,
            "confirmation_unix_ms": observed[-1]["observed_unix_ms"],
            "original_outcome": "UNKNOWN", "effects_before_cut": None, "new_original_entry_fenced": True,
            "scope": "Only the exact frozen original invocation forms; other owners remain independently active."}


def observed(value, key):
    row = value.get(key)
    need(type(row) is dict and set(row) == {"state", "value"} and row["state"] == "OBSERVED", "phone observation incomplete: " + key)
    return row["value"]


def phone_census(value, observer_pid, bootstrap):
    pids, final = value["complete_enumerated_pids"], value["complete_enumerated_pids_after"]
    need(pids == sorted(set(pids)) and final == sorted(set(final)) and 0 < len(pids) <= 4096, "full phone PID census")
    need(value["new_pids_not_read"] == sorted(set(final) - set(pids)) == [], "unread new phone process")
    records = {r["pid"]: r for r in value["records"]}
    need(len(records) == len(pids) and set(records) == set(pids), "omitted phone process")
    decoded = {}
    for pid, row in records.items():
        if row["state"] == "DISAPPEARED_BEFORE_READ":
            need(pid not in final, "unread extant phone process")
            continue
        need(row["state"] == "READ", "phone process unreadable, not absent: " + str(pid))
        cmd = base64.b64decode(row["argv_b64"], validate=True)
        need(sha(cmd) == row["argv_sha256"] == row["argv_after_sha256"] and row["argv_before_after_equal"] is True,
             "phone process command changed")
        need(same(row["process_identity_before"], row["process_identity_after"]), "phone kernel process generation changed")
        decoded[pid] = [w.decode("utf-8", errors="strict") for w in cmd.split(b"\0") if w]
    need(observer_pid in decoded and bootstrap in decoded[observer_pid], "exact current phone read-only observer command")
    ancestors = set()
    pid = observer_pid
    while pid in records and pid not in ancestors:
        ancestors.add(pid)
        record = records[pid]
        if record["state"] != "READ":
            break
        pid = record["stat"]["ppid"]
    for pid, words in decoded.items():
        if not words or pid in ancestors:
            continue
        row = records[pid]
        base = PurePosixPath(words[0]).name
        original = any(original_path_match(word) for word in words)
        uids = [int(x) for x in row["status"]["Uid"].split()]
        # Actual Android main classes matter; a live zygote is not an Input
        # command merely because its executable is app_process64.
        ui = uids[0] in (0, 2000) and (base in ("input", "uiautomator") or
             any(word.startswith("com.android.commands.input.") or word.startswith("com.android.commands.uiautomator.")
                 or word == "org.trillionnium.hepta.input.UnicodeInput" for word in words))
        ambiguous_python = ("python" in base.lower() or "pypy" in base.lower()) and ("-" in words[1:] or "-c" in words[1:])
        need(not original and not ui and not ambiguous_python, "unretired original-capable phone actor: " + str(pid))
    return {"process_count": len(records), "observer_ancestor_pids": sorted(ancestors), "unresolved_original_capable_processes": []}


def phone_endpoints(value):
    need("verification_error" not in value, "native endpoint verification failed")
    for key in ("original_tables", "verification_tables"):
        raw = {n: raw_record(value[key][n]) for n in ("tcp", "tcp6", "unix")}
        for name in ("tcp", "tcp6"):
            lines = raw[name].splitlines()
            need(lines and b"local_address" in lines[0], "phone TCP original header")
            for line in lines[1:]:
                fields = line.split(); need(len(fields) >= 10, "phone TCP row")
                need(not (int(fields[1].split(b":")[1], 16) == 18080 and fields[3] == b"0A"), "original-capable listener 18080 remains")
        for line in raw["unix"].splitlines()[1:]:
            fields = line.split(); need(len(fields) >= 7, "phone UNIX row")
            need(not (len(fields) > 7 and b"hepta" in fields[7] and b"r6" in fields[7]), "original-capable abstract endpoint remains")


def verify_phone_reconciliation(row, host_cut, *, read_pinned):
    exact(row, ("source", "request", "phone_intent", "phone_wrapper", "capture_digest", "historical_inventory"), "actual phone reconciliation originals")
    read(row["source"], read_pinned, PHONE_READER_PIN)
    request_raw = read(row["request"], read_pinned, PHONE_REQUEST_PIN)
    request = strict(request_raw)
    need(request["kind"] == "shell" and request["root"] is True, "fixed readonly phone request")
    wrapper = document(row["phone_wrapper"], read_pinned)
    need(wrapper.get("status") == "command_exited" and wrapper.get("phone", {}).get("rc") == 0, "actual original phone command did not return zero")
    intent = document(row["phone_intent"], read_pinned)
    need(intent.get("schema") == "hepta.phone-local.operator-intent.v150.1"
         and intent.get("request_sha256") == PHONE_REQUEST_PIN[1] and same(intent.get("request"), request)
         and intent.get("automatic_replay") is False and intent.get("label") == wrapper.get("label"),
         "actual phone intent/request/result linkage differs")
    need(wrapper["phone"].get("command") == "/debug_ramdisk/su -c " + shlex.quote(request["command"]),
         "actual phone command differs from the exact readonly request")
    envelope = strict(wrapper["phone"]["stdout"])
    need(envelope.get("schema") == "hepta.r6-bound02.readonly-residual-observation-envelope.v1", "complete residual envelope")
    packed = base64.b64decode(envelope["data_base64"], validate=True)
    need(len(packed) == envelope["compressed_bytes"] and sha(packed) == envelope["compressed_sha256"], "residual archive pin")
    unpacker = zlib.decompressobj()
    raw = unpacker.decompress(packed, 7 * 1024 * 1024 + 1)
    need(unpacker.eof and not unpacker.unused_data and not unpacker.unconsumed_tail and len(raw) <= 7 * 1024 * 1024,
         "complete bounded residual archive")
    exact(row["capture_digest"], ("bytes", "sha256"), "lossless phone capture digest has no fictional file path")
    need((row["capture_digest"]["bytes"], row["capture_digest"]["sha256"]) == PHONE_CAPTURE_PIN
         and (len(raw), sha(raw)) == PHONE_CAPTURE_PIN
         and len(raw) == envelope["raw_bytes"] and sha(raw) == envelope["raw_sha256"], "actual capture/archive bytes differ")
    value = strict(raw)
    need(value.get("schema") == "hepta.r6-bound02.readonly-residual-observation.v1"
         and value.get("state") == "OBSERVATION_ONLY_NO_DISPOSITION", "residual observation provenance")
    need(value.get("boot_id") == value.get("boot_id_after") == BOOT and value.get("original_job_outcome") == "UNKNOWN"
         and value.get("original_native_send_count") is None and value.get("original_effect_counts") is None,
         "original unknown/boot semantics changed")
    need(value["at_unix_ms"] >= host_cut["cut_unix_ms"], "phone observation predates completed host producer cut")
    expected = document(row["historical_inventory"], read_pinned, HISTORICAL_INVENTORY_PIN)
    expected_stable = validate_complete_inventory(expected)
    history = observed(value, "historical_inventory")
    need(len(expected["roots"]) == 44, "exact cumulative historical root census")
    before = validate_complete_inventory(history["before"])
    after = validate_complete_inventory(history["after"])
    need(same(before, expected_stable) and same(after, expected_stable), "historical full9 originals changed; explicit separate disposition needed")
    retained = {}
    all_role_ids = []
    for identity in (BOUND01, {"label": LABEL, "nonce": NONCE}):
        attempt = observed(value, identity["label"])
        need(attempt["label"] == identity["label"] and attempt["original_job_outcome"] == "UNKNOWN" and attempt["original_counts"] is None,
             "retained attempt identity/outcome changed")
        inventories = []
        for namespace_key, inventory_key in (("home_namespace", "inventory"), ("android_namespace", "android_inventory")):
            namespace = attempt[namespace_key]
            names = namespace["parent_names"]
            need(type(namespace["parent_metadata"]) is list and len(namespace["parent_metadata"]) == 9
                 and stat.S_ISDIR(namespace["parent_metadata"][2]) and names == sorted(set(names)), "actual parent descriptor census")
            leaf = PurePosixPath(namespace["path"]).name
            if namespace["kind"] == "absent":
                need(namespace.get("absence") == "ENOENT" and leaf not in names and inventory_key not in attempt, "actual absence fact only")
            else:
                need(namespace["kind"] == "directory" and leaf in names, "unknown/special retained namespace")
                inventory = validate_complete_inventory(attempt[inventory_key])
                need(inventory["roots"] == [namespace["path"]]
                     and same(inventory["entries"][namespace["path"]]["metadata"], namespace["metadata"]), "complete retained current directory inventory")
                inventories.append(inventory)
        fixture = validate_complete_inventory(attempt["fixture"])
        need(fixture["roots"] == ["/proc/1/root/data/local/tmp/hepta-native-guard-" + identity["nonce"]], "fixed original fixture namespace")
        inventories.append(fixture)
        for name, original in attempt["retained_originals"].items():
            body = raw_record(original)
            doc = strict(body)
            if name == "LEASE.json":
                need(doc.get("nonce") == identity["nonce"] and doc.get("label") == identity["label"]
                     and doc.get("boot_id") == BOOT, "retained original lease binding")
                need(type(doc.get("expires_unix_ms")) is int and doc["expires_unix_ms"] < value["at_unix_ms"], "retained lease has not expired")
            if "identity" in doc:
                all_role_ids.append(doc["identity"])
        retained[identity["label"]] = {"nonce": identity["nonce"], "inventories": inventories,
            "home_namespace": attempt["home_namespace"], "android_namespace": attempt["android_namespace"],
            "historical_effect_count": None}
    role_history = observed(value, "historical_role_originals")
    need(type(role_history["absence_observations"]) is list and len(role_history["absence_observations"]) == 2,
         "two complete original role absence observations")
    for result in role_history["absence_observations"]:
        need(result.get("state") == "OBSERVED" and result.get("value", {}).get("kernel_group_absence") is True
             and result["value"].get("members") == [] and type(result["value"].get("numeric_pids")) is int
             and 0 < result["value"]["numeric_pids"] <= 4096, "historical role group absence unverified")
    all_role_ids.extend(role_history["identities"])
    # Request wraps the exact reviewed source in a compressed bootstrap. The
    # executing phone argv contains that actual bootstrap, not a claimed hash.
    words = shlex.split(request["command"])
    python_index = words.index("/usr/bin/python3")
    bootstrap = words[words.index("-c", python_index) + 1]
    censuses = [observed(value, "process_census_before"), observed(value, "process_census_after")]
    summaries = [phone_census(c, value["observer_pid"], bootstrap) for c in censuses]
    for census in censuses:
        for process in census["records"]:
            if process.get("state") != "READ":
                continue
            status = process["stat"]
            for identity in all_role_ids:
                need(type(identity) is list and len(identity) == 4 and all(type(x) is int for x in identity), "exact retained role generation")
                need(status["pid"] != identity[0] or status["start_ticks"] != identity[3], "original retained role is still alive")
                need(status["pgid"] != identity[1] and status["sid"] != identity[2], "original retained role group/session survives")
    phone_endpoints(observed(value, "endpoints"))
    selected = observed(value, "selected_client_identity")
    need(selected["pending_before"]["kind"] == selected["pending_after"]["kind"] == "absent"
         and same(selected["pending_before"], selected["pending_after"]), "pending or changed selected identity")
    selected_raw = raw_record(selected["original"])
    need(selected["decoded"].get("checksum_valid") is True and selected["decoded"].get("record_sha256") == sha(selected_raw)
         and selected["decoded"].get("record_bytes") == len(selected_raw), "actual selected client record/checksum differs")
    inventory_identity = {"historical": expected_stable, "retained": retained}
    return {"state": "EXACT_RETAINED_CURRENT_STATE_ACCEPTED_WITH_UNKNOWN_HISTORY", "boot_id": BOOT,
            "inventory_sha256": sha(canonical(inventory_identity)), "historical_inventory_sha256": HISTORICAL_INVENTORY_PIN[1],
            "retained_attempts": retained, "selected_identity": selected["decoded"], "process_censuses": summaries,
            "observed_unix_ms": value["at_unix_ms_end"], "original_terminal": None, "original_effect_counts": None,
            "case_credit": 0, "draft_current_state": "REQUIRES_SEPARATE_UI_ORIGINALS"}


def validate_complete_inventory(value):
    """Keep the existing full9 metadata/content/topology contract, not a count."""
    exact(value, ("schema", "roots", "entries", "file_bytes_hashed", "elapsed_seconds", "inventory_is_closure_or_retirement"), "complete inventory")
    need(value["schema"] == "hepta.native-guard.complete-inventory.v1" and value["inventory_is_closure_or_retirement"] is False, "inventory is not a terminal")
    roots, entries = value["roots"], value["entries"]
    need(type(roots) is list and 1 <= len(roots) <= 64 and len(set(roots)) == len(roots), "complete unique inventory roots")
    need(type(entries) is dict and 1 <= len(entries) <= 30000, "bounded complete inventory entries")
    paths = [PurePosixPath(p) for p in roots]
    need(all(p.is_absolute() and str(p) == s and ".." not in p.parts for p, s in zip(paths, roots)), "canonical inventory roots")
    need(all(a == b or not (a in b.parents or b in a.parents) for a in paths for b in paths), "overlapping inventory roots")
    total = 0
    children_by_parent = defaultdict(list)
    for name in entries:
        p = PurePosixPath(name)
        children_by_parent[str(p.parent)].append(p.name)
    for name, entry in entries.items():
        p = PurePosixPath(name)
        need(str(p) == name and any(p == r or r in p.parents for r in paths), "inventory entry outside selected roots")
        kind = entry.get("kind")
        if kind == "absent":
            need(name in roots and re.fullmatch(r"/proc/1/root/data/local/tmp/hepta-native-guard-[0-9a-f]{32}", name)
                 and same(entry, {"kind": "absent", "absence": "ENOENT"}), "only explicit actual fixture root ENOENT entries")
            continue
        metadata = entry.get("metadata")
        need(type(metadata) is list and len(metadata) == 9 and all(type(x) is int for x in metadata), "full9 original inode metadata")
        if kind == "directory":
            need(stat.S_ISDIR(metadata[2]) and set(entry) == {"metadata", "kind", "names"}, "directory metadata/type")
            names = entry["names"]
            need(type(names) is list and names == sorted(set(names)) and all(type(n) is str and n and "/" not in n and n not in (".", "..") for n in names), "complete immediate child names")
            children = sorted(children_by_parent.get(name, ()))
            need(children == names, "directory census has omitted or extra descendants")
        elif kind == "file":
            need(stat.S_ISREG(metadata[2]) and metadata[5] == 1 and set(entry) == {"metadata", "kind", "bytes", "sha256"}, "regular single-link inventory original")
            need(type(entry["bytes"]) is int and entry["bytes"] == metadata[6] and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]), "exact file size/content pin")
            total += entry["bytes"]
        else:
            raise Refused("unknown inventory entry kind")
        if name not in roots:
            need(str(p.parent) in entries and entries[str(p.parent)].get("kind") == "directory", "inventory topology gap")
    need(all(r in entries for r in roots) and total == value["file_bytes_hashed"] <= 512 * 1024 * 1024, "complete inventory byte total")
    return {k: v for k, v in value.items() if k != "elapsed_seconds"}


def current_editor_text(wire_raw):
    """Parse the actual wire, never a caller's 'restored' or 'empty' boolean."""
    wire = strict(wire_raw)
    need(type(wire.get("rc")) is int and wire["rc"] == 0 and type(wire.get("stdout")) is str
         and type(wire.get("stderr")) is str, "complete successful current UI wire")
    text = wire["stdout"]
    need(text.count("<?xml") == text.count("<hierarchy") == text.count("</hierarchy>") == 1,
         "one complete current XML hierarchy required")
    raw = text[text.index("<?xml"):text.index("</hierarchy>") + len("</hierarchy>")].encode()
    need(len(raw) <= 4 * 1024 * 1024 and b"<!DOCTYPE" not in raw and b"<!ENTITY" not in raw,
         "bounded current XML without expansion declarations")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as error:
        raise Refused("incomplete current XML") from error
    nodes = list(root.iter("node"))
    need(root.tag == "hierarchy" and len(nodes) <= 20000, "bounded Android hierarchy")
    editors = [n for n in nodes if n.attrib.get("package") == "org.trillionnium.owneropen"
               and n.attrib.get("resource-id") == "org.trillionnium.owneropen:id/ui_prompt"]
    need(len(editors) == 1, "actual editor missing/ambiguous; lock screen is not draft closure")
    editor = editors[0]
    need(editor.attrib.get("class") == "android.widget.EditText" and editor.attrib.get("password") == "false"
         and type(editor.attrib.get("text")) is str, "actual non-password app editor text")
    return editor.attrib["text"].encode()


def verify_draft_state(value, *, preserved_raw, cut_unix_ms, read_pinned):
    """One real current-state observation can close a current draft mismatch.

    This confers no historical restoration credit. The existing sender still
    performs its independent selected-identity and actual editor CAS before
    any input. A lockscreen, hint, missing editor, or caller flag cannot pass.
    """
    exact(value, ("schema", "original", "bound01_original_state", "source", "request", "intent", "result",
                  "baseline", "wire", "restore_original"), "draft reconciliation originals")
    need(value["schema"] == "hepta.r6.bound02.current-draft-reconciliation.v1" and same(value["original"], ORIGINAL), "draft reconciliation identity")
    need(value["bound01_original_state"] == "RESTORE_NOT_AUTOMATED_INPUT_OUTCOME_UNCONFIRMED", "bound01 history must remain unchanged")
    read(value["source"], read_pinned, DRAFT_OBSERVER_PIN)
    request = document(value["request"], read_pinned, DRAFT_REQUEST_PIN)
    intent = document(value["intent"], read_pinned)
    result = document(value["result"], read_pinned)
    need(intent.get("schema") == "hepta.r6.draft-read-observer-intent.v1"
         and result.get("schema") == "hepta.r6.draft-read-observer-result.v1", "actual draft observer originals")
    for observed in (intent, result):
        need(observed.get("label") == request["label"] and observed.get("source_sha256") == DRAFT_OBSERVER_PIN[1]
             and observed.get("request_sha256") == DRAFT_REQUEST_PIN[1] and observed.get("automatic_retry") is False,
             "draft observer actual source/request/label binding")
    need(result.get("state") == "DUMP_COMMAND_TERMINAL_OBSERVED" and type(result.get("phone_rc")) is int
         and result["phone_rc"] == 0 and type(result.get("dump_dispatch_attempts")) is int and result["dump_dispatch_attempts"] == 1,
         "one actual successful draft dump required")
    for key in ("native_sends", "model_requests"):
        need(type(result.get(key)) is int and result[key] == 0, "draft observer exceeded its scope")
    for key in ("app_start", "tap", "input_text", "draft_restore"):
        need(result.get(key) is False, "read-only draft observation cannot conceal restoration")
    need(result.get("original_job_outcome") == "UNKNOWN", "draft observation rewrote the original outcome")
    start, end = result.get("started_unix_ms"), result.get("ended_unix_ms")
    need(type(start) is int and type(end) is int and start == intent.get("started_unix_ms")
         and cut_unix_ms <= start <= end and type(result.get("elapsed_seconds")) in (int, float)
         and 0 <= result["elapsed_seconds"] <= 55, "draft original time/budget does not follow the producer cut")
    baseline_raw = read(value["baseline"], read_pinned)
    wire_raw = read(value["wire"], read_pinned)
    for name, raw in (("baseline_original", baseline_raw), ("wire_original", wire_raw)):
        desc = result[name]
        descriptor(desc)
        need((desc["bytes"], desc["sha256"]) == (len(raw), sha(raw)), "actual draft result original pin differs")
    baseline = strict(baseline_raw)
    need(type(baseline.get("rc")) is int and baseline["rc"] == 0 and baseline.get("stdout", "").splitlines()[0] == BOOT,
         "draft observation boot differs")
    protected = strict(preserved_raw)
    body = base64.b64decode(protected["exact_utf8_b64"], validate=True)
    need(protected.get("schema") == "hepta.user-draft-preservation.v150.1"
         and body and sha(body) == protected["utf8_sha256"], "exact nonempty protected private draft")
    need(current_editor_text(wire_raw) == body, "current actual editor is not the exact preserved draft")
    if value["restore_original"] is not None:
        # Preserve the separately authorized action's bytes; this observation
        # only proves the current text. It never infers an earlier action ran.
        read(value["restore_original"], read_pinned)
    return {"state": "CURRENT_PROTECTED_DRAFT_VERIFIED", "original_bound01_state": value["bound01_original_state"],
            "historical_ui_effect_count": None, "historical_restore_confirmed": None,
            "draft_publication": "PRIVATE_ORIGINAL_ONLY", "fresh_selected_identity_check": "EXISTING_SENDER_CAS_REQUIRED",
            "observed_unix_ms": end}


def verify_disposition(resolution_descriptor, *, read_pinned):
    value = document(resolution_descriptor, read_pinned)
    exact(value, ("schema", "original", "original_plan", "original_metadata", "original_cancel_response", "bound01_sender_result", "source_coverage",
                  "fences", "host_producer_cut", "phone_reconciliation", "draft_reconciliation"), "typed original disposition")
    need(value["schema"] == RESOLUTION_SCHEMA and same(value["original"], ORIGINAL), "fixed bound02 disposition identity")
    plan = document(value["original_plan"], read_pinned, (4842, ORIGINAL["plan_sha256"]))
    metadata = document(value["original_metadata"], read_pinned, META_PIN)
    need(metadata.get("launch_state") == "launch_unknown" and metadata.get("id") == ORIGINAL["job_id"], "original launch metadata must remain unknown")
    read(value["original_cancel_response"], read_pinned, CANCEL_PIN)
    read(value["bound01_sender_result"], read_pinned, BOUND01_PIN)
    exact(value["source_coverage"], ORIGINAL_SOURCE_PINS, "all exact original producer entry sources")
    for name, pin in ORIGINAL_SOURCE_PINS.items():
        read(value["source_coverage"][name], read_pinned, pin)
    fences = verify_namespace_fences(value["fences"], read_pinned=read_pinned)
    host = verify_host_producer_cut(value["host_producer_cut"], fences, read_pinned=read_pinned)
    phone = verify_phone_reconciliation(value["phone_reconciliation"], host, read_pinned=read_pinned)
    preserved = read({k: plan["preserved_draft"][k] for k in ("path", "bytes", "sha256")}, read_pinned)
    draft = verify_draft_state(document(value["draft_reconciliation"], read_pinned), preserved_raw=preserved,
                               cut_unix_ms=host["cut_unix_ms"], read_pinned=read_pinned)
    need(draft["observed_unix_ms"] >= host["cut_unix_ms"], "draft observed before producer cut")
    return {"schema": "hepta.r6.bound02.accepted-disposition.v1", "state": "RETIRED_WITH_ORIGINAL_OUTCOME_UNKNOWN",
            "resolution": resolution_descriptor, "original": ORIGINAL, "original_launch_state": "launch_unknown",
            "original_terminal": None, "original_output_complete": None,
            "effect_counts": {k: None for k in EFFECT_FIELDS}, "cancellation_observation": "TIMEOUT_NO_CANCELLATION_RECEIPT",
            "native_case_credit": False, "business_credit": False, "original_replay_allowed": False,
            "producer_cut": host, "fences": fences, "phone_current_state": phone, "draft_current_state": draft,
            "late_transport_payloads": "PHONE_UI_FIXTURE_ENTRY_FENCED_CHANNEL_OCCUPANCY_UNKNOWN",
            "late_host_request_staging": "EXCLUSIVE_OLD_REQUEST_FILE_CREATION_MAY_OCCUR_BEFORE_FENCED_DISPATCH_NO_ZERO_WRITE_CLAIM",
            "source_coverage": value["source_coverage"],
            "fresh_execution_eligible": False}


def verify_retained_preaccept(retained_descriptor, *, read_pinned):
    """Verify the separate failed R7 originals; never promote it to native prior.

    The pinned reader revalidates every original from its lossless archive.
    Neither an execution flag, a case label nor an inventory count substitutes
    for the original host, child, phone, draft and retained-inventory evidence.
    """
    descriptor(retained_descriptor)
    value = RETAINED.verify_retained_preaccept_archive(retained_descriptor, read_pinned=read_pinned)
    need(value.get("schema") == "hepta.r7.retained-preaccept-verification.v1"
         and value.get("state") == "ACTUAL_FAILED_PREACCEPT_SPAWNED_SCOPE_RETIRED_ORIGINALS_RETAINED"
         and value.get("label") == "root-r10-neg01-fc33-r7-bound01" and value.get("boot_id") == BOOT,
         "exact original failed R7 retained scope required")
    need(type(value.get("nonce")) is str and re.fullmatch(r"[0-9a-f]{32}", value["nonce"])
         and type(value.get("native_case_credit")) is int and value["native_case_credit"] == 0
         and value.get("standalone_execution_authorized") is False
         and value.get("original_roles_joined_and_groups_absent") is False
         and value.get("supervisor_wait_exit_code") is None and value.get("native_terminal") is None
         and value.get("global_unknown_effect_count") is None,
         "original failure, missing terminal and unknown counts must remain unchanged")
    inventory = validate_complete_inventory(value["inventory_value"])
    need(len(inventory["roots"]) == 47 and len(value["private_roots"]) == 3
         and set(value["private_roots"]) <= set(inventory["roots"]),
         "exact retained R7 47-root cumulative inventory required")
    binding = value["retained_preaccept_binding"]
    need(binding.get("schema") == "hepta.r7.retained-preaccept-binding.v1"
         and binding.get("label") == value["label"] and binding.get("nonce") == value["nonce"]
         and binding.get("boot_id") == value["boot_id"]
         and same(binding.get("inventory"), value["inventory"])
         and binding.get("native_case_credit") == 0 and binding.get("component_qualified") is False,
         "same authoritative retained binding required")
    anchor = value["original_root_namespace_anchor"]
    need(anchor["path"] == BASE + "/native-guard-root-chains-r10-r1/" + value["label"] + "/ROOT-FAILURE.json",
         "live original failed Root namespace anchor differs")
    read(anchor, read_pinned)
    return value


def verify_retained_failed_staged(retained_descriptor, *, retained, read_pinned):
    """Read the fixed failed R8 proof separately from the native predecessor.

    Only the one explicit R7 archive dependency is relocated for the Mac
    reader. The typed proof still validates every original and keeps the
    missing native terminal, historical offender and effect counts unknown.
    """
    expected = {'path': BASE + '/retained-staged-r8-failed01-ast02/RETENTION-INPUTS.json',
                'bytes': 422, 'sha256': 'b005ba692ea1f31e93858628eb9ae64c936c83193c632002eafa1dfb84f7f7f0'}
    descriptor(retained_descriptor)
    need(same(retained_descriptor, expected), "one exact fixed failed R8 proof descriptor")
    r7_phone = {'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/4808fbf1e81fd1542e7ffb60d7f57ca6/ORIGINALS.zlib',
                'bytes': 3000200, 'sha256': '4010779b9a3810dc7d0d51072dc76dd52be2327301b857df2b04ddb004a5edca'}
    r7_host = {'path': BASE + '/retained-preaccept-r7-failed01/ORIGINALS.zlib',
               'bytes': r7_phone['bytes'], 'sha256': r7_phone['sha256']}
    need(same(STAGED.R7_ARCHIVE, r7_phone), "typed R8 reader exact external R7 dependency")
    def host_read(row):
        descriptor(row)
        return read_pinned(r7_host if same(row, r7_phone) else row)
    value = STAGED.verify_retained_staged_archive(retained_descriptor, read_pinned=host_read)
    need(value.get("schema") == "hepta.r8.retained-staged-failure-verification.v1"
         and value.get("state") == "ACTUAL_FAILED_STAGED_BEFORE_DETACHED_FORK_SCOPE_RETIRED_ORIGINALS_RETAINED"
         and value.get("scope_profile") == "fixed_failed_admission_before_detached_native_fork"
         and value.get("label") == "root-r10-neg01-fc33-r8-bound01"
         and value.get("nonce") == "aa06c3b8d035dcd0c0047105f620b3bf" and value.get("boot_id") == BOOT,
         "exact original failed staged R8 scope required")
    need(type(value.get("native_case_credit")) is int and value["native_case_credit"] == 0
         and value.get("standalone_execution_authorized") is False
         and value.get("component_qualified") is False and value.get("business_qualified") is False
         and value.get("four_role_qualification") is False and value.get("native_scope_assigned") is False
         and value.get("native_terminal") is None and value.get("global_unknown_effect_count") is None
         and value.get("historical_gate_failure_cause") == "UNKNOWN"
         and value.get("original_failure_offender_identified") is False
         and value.get("original_remote_cleanup_boolean") is False
         and value.get("current_kernel_ESRCH_asserted") is False
         and value.get("original_nonce_consumed") is True and value.get("new_nonce_issued_by_reader") is False
         and value.get("automatic_retry") is False and value.get("original_root_failure_preserved") is True,
         "failed R8 unknowns, consumed nonce and zero qualification must remain unchanged")
    need(type(value.get("component_role_identities")) is dict and value["component_role_identities"] == {}
         and type(value.get("spawned_component_roles")) is list and value["spawned_component_roles"] == [],
         "failed staged R8 contributes no process role")
    private = [
        '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r8-bound01',
        '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r8-bound01/executor']
    fixture = '/proc/1/root/data/local/tmp/hepta-native-guard-aa06c3b8d035dcd0c0047105f620b3bf'
    inventory = validate_complete_inventory(value["inventory_value"])
    need(value["private_roots"] == private and len(inventory["roots"]) == 49
         and set(retained["inventory_value"]["roots"]).isdisjoint(private)
         and set(inventory["roots"]) == set(retained["inventory_value"]["roots"]) | set(private)
         and fixture not in inventory["roots"] and fixture not in inventory["entries"],
         "native44 and retained R7three remain separate from exactly two retained R8 roots")
    need(same(value.get("retained_preaccept_binding"), retained["retained_preaccept_binding"])
         and same(value.get("original_native_predecessor"), retained["original_native_predecessor"]),
         "both retained families bind the same actual R7 proof and final04 native predecessor")
    RETAINED.validate_private_preservation(retained, value["inventory_value"],
                                          inventory_reader=validate_complete_inventory)
    absence = value["separate_absent_fixture"]
    need(absence.get("path") == fixture and absence.get("included_as_inventory_root") is False
         and absence.get("absence_is_not_zero_effect") is True,
         "actual R8 fixture ENOENT remains separate and grants no zero-effect inference")
    binding = value["retained_failed_staged_binding"]
    need(binding.get("schema") == "hepta.r8.retained-staged-failure-binding.v1"
         and binding.get("component_qualified") is False and type(binding.get("native_case_credit")) is int
         and binding["native_case_credit"] == 0 and binding.get("standalone_execution_authorized") is False
         and binding.get("fixture_is_inventory_root") is False and binding.get("absent_fixture_path") == fixture,
         "one authoritative failed R8 binding without qualification")
    for key in ("label", "nonce", "boot_id", "inventory", "private_roots", "package", "combination", "lease",
                "original_native_predecessor", "retained_preaccept_binding", "component_role_identities",
                "native_terminal", "global_unknown_effect_count", "original_nonce_consumed",
                "original_remote_cleanup_boolean", "original_root_namespace_anchor", "evidence_archive"):
        need(same(binding.get(key), value[key]), "failed R8 binding differs: " + key)
    anchor = value["original_root_namespace_anchor"]
    need(anchor["path"] == BASE + "/native-guard-root-chains-r10-r1/" + value["label"] + "/ROOT-FAILURE.json",
         "live original failed R8 Root namespace anchor differs")
    read(anchor, read_pinned)
    return value



# This successor remains source-only until the actual R9 proof is accepted.
RETAINED_FAILED_TRANSPORT_MANIFEST = {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/retained-transport-r9-failed01/RETENTION-INPUTS.json', 'bytes': 431, 'sha256': 'a49f04c7e6be09e9d46b00176b9a0baf4489b12d764abbfe4482f5c839fee01d'}
RETAINED_FAILED_TRANSPORT_BINDING = {'schema': 'hepta.r9.retained-transport-failure-binding.v1', 'label': 'root-r10-neg01-fc33-r9-bound01', 'nonce': '299483481a678cbd589aeba54ed8b68f', 'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'package': {'bytes': 73225, 'sha256': 'bcabd6171f84738300b1a1e1bbac5263356339f9d9c5e9ee3079db16ca820734'}, 'combination': {'bytes': 4695, 'sha256': '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}, 'lease': {'bytes': 2506, 'sha256': 'c56261e8a905de9a3e12d81d16c2a9fb15e90103a4fc0324d6f93c74ec5a6c17'}, 'evidence_archive': {'archive': {'bytes': 2174339, 'sha256': '18da9626e5ae687adb4087b5a5484d9d2a8dc8885fdaabfd57b829ec02d20fd3'}, 'raw_archive': {'bytes': 3788800, 'sha256': 'ca76e0854be12cb004bef057df668374b851c0a2a90604f1ae7c8ea422b368d6'}}, 'inventory': {'bytes': 1403290, 'sha256': 'bb8cfb6dd2f108046e8296956e514f7b3eec0ea5aaac5794ad86c70174478609'}, 'private_roots': [], 'component_role_identities': {}, 'original_native_predecessor': {'bytes': 29342, 'metadata': [65086, 154717, 33152, 0, 0, 1, 29342, 1793954246107886895, 1793954246107886895], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json', 'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'}, 'original_root_namespace_anchor': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-fc33-r9-bound01/ROOT-FAILURE.json', 'bytes': 3274, 'sha256': '29b5b67cc99280b36c3250d87aaf3ecfeec8a19a79d22e715338447bd6095763'}, 'retained_preaccept_binding': {'schema': 'hepta.r7.retained-preaccept-binding.v1', 'label': 'root-r10-neg01-fc33-r7-bound01', 'nonce': '4808fbf1e81fd1542e7ffb60d7f57ca6', 'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'package': {'bytes': 61701, 'sha256': '643d4e17475293532aa02489194c01175d263f54d8a5979ae96ff802d4f5150a'}, 'combination': {'bytes': 4695, 'sha256': '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}, 'lease': {'bytes': 2506, 'sha256': '03f1d2a383384e74743e3331adf39a50bdd8e3d4c9a8d4e618bd8b6012557a5c'}, 'evidence_archive': {'archive': {'bytes': 3000200, 'sha256': '4010779b9a3810dc7d0d51072dc76dd52be2327301b857df2b04ddb004a5edca'}, 'raw_archive': {'bytes': 11427840, 'sha256': 'a50abed2fea44393468bd058c9c97d72330e9bf0b98e36aa196f0a0d05affcdd'}}, 'inventory': {'bytes': 1378036, 'sha256': 'dfdadedaded0eced586cc680f39d8ab58c336db2d25d75daf7460fc32ae74f7f'}, 'component_role_identities': {'supervisor': [12513, 12513, 12513, 39102689], 'sidecar': [14026, 14026, 14026, 39106597]}, 'private_roots': ['/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r7-bound01', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r7-bound01/executor', '/proc/1/root/data/local/tmp/hepta-native-guard-4808fbf1e81fd1542e7ffb60d7f57ca6'], 'original_native_predecessor': {'bytes': 29342, 'metadata': [65086, 154717, 33152, 0, 0, 1, 29342, 1793954246107886895, 1793954246107886895], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json', 'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'}, 'native_case_credit': 0, 'component_qualified': False}, 'retained_failed_staged_binding': {'schema': 'hepta.r8.retained-staged-failure-binding.v1', 'label': 'root-r10-neg01-fc33-r8-bound01', 'nonce': 'aa06c3b8d035dcd0c0047105f620b3bf', 'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'package': {'bytes': 65655, 'sha256': '654f8b0ad50a4d930d7beff9421b5e9f988ecb74b55badc70cec9efeaa63130c'}, 'combination': {'bytes': 4695, 'sha256': '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}, 'lease': {'bytes': 2506, 'sha256': 'f05ee53a7609972c18f6bab2263008a4c3de3b49b12b8654df94790b25c30a44'}, 'evidence_archive': {'archive': {'bytes': 2066079, 'sha256': 'd66d286bfb7890e0b32358326b669ac4a47d5f4ba43c524bc3f129f5bf631e93'}, 'raw_archive': {'bytes': 6389760, 'sha256': '2f0e98f48f0f1449cf1fe588ffe6b5a30f69f252fae67e5fd1682a25b713a213'}}, 'inventory': {'bytes': 1403291, 'sha256': '2008db913728ff0c3836cb6edb361e37f427d7663f2832163fe93b2adb18f432'}, 'component_role_identities': {}, 'private_roots': ['/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r8-bound01', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r8-bound01/executor'], 'original_native_predecessor': {'bytes': 29342, 'metadata': [65086, 154717, 33152, 0, 0, 1, 29342, 1793954246107886895, 1793954246107886895], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json', 'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'}, 'original_root_namespace_anchor': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-fc33-r8-bound01/ROOT-FAILURE.json', 'bytes': 12992, 'sha256': 'ab8c85f7d403c6427931db66acfecb12137143cf3b78573a654346584dab7a31'}, 'retained_preaccept_binding': {'schema': 'hepta.r7.retained-preaccept-binding.v1', 'label': 'root-r10-neg01-fc33-r7-bound01', 'nonce': '4808fbf1e81fd1542e7ffb60d7f57ca6', 'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'package': {'bytes': 61701, 'sha256': '643d4e17475293532aa02489194c01175d263f54d8a5979ae96ff802d4f5150a'}, 'combination': {'bytes': 4695, 'sha256': '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}, 'lease': {'bytes': 2506, 'sha256': '03f1d2a383384e74743e3331adf39a50bdd8e3d4c9a8d4e618bd8b6012557a5c'}, 'evidence_archive': {'archive': {'bytes': 3000200, 'sha256': '4010779b9a3810dc7d0d51072dc76dd52be2327301b857df2b04ddb004a5edca'}, 'raw_archive': {'bytes': 11427840, 'sha256': 'a50abed2fea44393468bd058c9c97d72330e9bf0b98e36aa196f0a0d05affcdd'}}, 'inventory': {'bytes': 1378036, 'sha256': 'dfdadedaded0eced586cc680f39d8ab58c336db2d25d75daf7460fc32ae74f7f'}, 'component_role_identities': {'supervisor': [12513, 12513, 12513, 39102689], 'sidecar': [14026, 14026, 14026, 39106597]}, 'private_roots': ['/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r7-bound01', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r7-bound01/executor', '/proc/1/root/data/local/tmp/hepta-native-guard-4808fbf1e81fd1542e7ffb60d7f57ca6'], 'original_native_predecessor': {'bytes': 29342, 'metadata': [65086, 154717, 33152, 0, 0, 1, 29342, 1793954246107886895, 1793954246107886895], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json', 'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'}, 'native_case_credit': 0, 'component_qualified': False}, 'absent_fixture_path': '/proc/1/root/data/local/tmp/hepta-native-guard-aa06c3b8d035dcd0c0047105f620b3bf', 'fixture_is_inventory_root': False, 'original_nonce_consumed': True, 'original_remote_cleanup_boolean': False, 'global_unknown_effect_count': None, 'native_terminal': None, 'native_case_credit': 0, 'component_qualified': False, 'standalone_execution_authorized': False}, 'first_launch_receipt_gap': True, 'original_start_reused': True, 'original_retried_launch': False, 'original_wrapper_status': 'failed_or_unknown_no_retry', 'historical_failed_route_callsite': None, 'historical_failed_listener_identity': None, 'baseline_device_shell_wire_dispatched': None, 'global_unknown_effect_count': None, 'native_terminal': None, 'native_case_credit': 0, 'component_qualified': False, 'business_qualified': False, 'standalone_execution_authorized': False, 'original_nonce_consumed': True, 'replay_authorized': False, 'new_nonce_authorized': False, 'remote_cleanup_proven': False, 'same_boot_complete_scope_original': {'bytes': 11658275, 'sha256': '7323e266eed8e2e0413f4a04e4368b703953103c214a569a0fe175bcc76b2ddd'}, 'first_push_scope_only': True, 'current_kernel_ESRCH_asserted': False}
R9_HOST_DEPENDENCIES = {'r7_phone_archive': {'bytes': 3000200, 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/4808fbf1e81fd1542e7ffb60d7f57ca6/ORIGINALS.zlib', 'sha256': '4010779b9a3810dc7d0d51072dc76dd52be2327301b857df2b04ddb004a5edca'}, 'r7_host_archive': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/retained-preaccept-r7-failed01/ORIGINALS.zlib', 'bytes': 3000200, 'sha256': '4010779b9a3810dc7d0d51072dc76dd52be2327301b857df2b04ddb004a5edca'}, 'r8_phone_manifest': {'bytes': 409, 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/aa06c3b8d035dcd0c0047105f620b3bf/RETENTION-INPUTS.json', 'sha256': '247ebf979d69cfd5b9b55b5cdbe55b2d1a57c481d3ceb67ef5e4ece91f7d78f6'}, 'r8_host_manifest': {'bytes': 422, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/retained-staged-r8-failed01-ast02/RETENTION-INPUTS.json', 'sha256': 'b005ba692ea1f31e93858628eb9ae64c936c83193c632002eafa1dfb84f7f7f0'}, 'r8_phone_archive': {'bytes': 2066079, 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/aa06c3b8d035dcd0c0047105f620b3bf/ORIGINALS.zlib', 'sha256': 'd66d286bfb7890e0b32358326b669ac4a47d5f4ba43c524bc3f129f5bf631e93'}, 'r8_host_archive': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/retained-staged-r8-failed01-ast02/ORIGINALS.zlib', 'bytes': 2066079, 'sha256': 'd66d286bfb7890e0b32358326b669ac4a47d5f4ba43c524bc3f129f5bf631e93'}, 'r8_phone_reader': {'bytes': 96088, 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/aa06c3b8d035dcd0c0047105f620b3bf/verify_retained_staged_r8.py', 'sha256': '614f44d6eb75f47b02e32b463f18534e2d0bc5a3e8fd928535e7da17909679ae'}, 'r8_host_reader': {'bytes': 96088, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/retained-staged-r8-failed01-ast02/verify_retained_staged_r8.py', 'sha256': '614f44d6eb75f47b02e32b463f18534e2d0bc5a3e8fd928535e7da17909679ae'}, 'r8_phone_manifest_base64': 'eyJhcmNoaXZlIjp7ImJ5dGVzIjoyMDY2MDc5LCJwYXRoIjoiL3Zhci9saWIvdHJpbGxpb25uaXVtL293bmVyLW9wZW4vcGhvbmUtbG9jYWwtdjE1MC9uYXRpdmUtZ3VhcmQtbm9ubmF0aXZlLWJvdW5kYXJpZXMtcjEwLXIxL2FhMDZjM2I4ZDAzNWRjZDBjMDA0NzEwNWY2MjBiM2JmL09SSUdJTkFMUy56bGliIiwic2hhMjU2IjoiZDY2ZDI4NmJmYjc4OTBlMGIzMjM1ODMyNmI2NjlhYzRhNDdkNWY0YmE0M2M1MjRiYzNmMTI5ZjViZjYzMWU5MyJ9LCJyYXdfYXJjaGl2ZSI6eyJieXRlcyI6NjM4OTc2MCwic2hhMjU2IjoiMmYwZTk4ZjQ4ZjBmMTQ0OWNmMWZlNTg4ZmZlNmI1YTMwZjY5ZjI1MmZhZTY3ZTVmZDE2ODJhMjViNzEzYTIxMyJ9LCJzY2hlbWEiOiJoZXB0YS5yOC5yZXRhaW5lZC1zdGFnZWQtYXJjaGl2ZS52MSJ9Cg=='}


def require_retained_transport_binding():
    need(type(RETAINED_FAILED_TRANSPORT_MANIFEST) is dict
         and type(RETAINED_FAILED_TRANSPORT_BINDING) is dict
         and type(R9_HOST_DEPENDENCIES) is dict,
         "UNBOUND_ACTUAL_RETAINED_R9_TRANSPORT_PROOF_NO_ORIGINAL_READ_OR_CREATION")
    descriptor(RETAINED_FAILED_TRANSPORT_MANIFEST)
    need(RETAINED_FAILED_TRANSPORT_BINDING.get("label") == "root-r10-neg01-fc33-r9-bound01"
         and RETAINED_FAILED_TRANSPORT_BINDING.get("nonce") == "299483481a678cbd589aeba54ed8b68f"
         and RETAINED_FAILED_TRANSPORT_BINDING.get("boot_id") == BOOT,
         "one exact failed R9 binding required")


def verify_retained_failed_transport(retained_descriptor, *, retained, staged, read_pinned):
    """Consume the exact Mac manifest and canonical R9 archive through fixed mappings.

    The new reader receives ORIGINALS.zlib, not a manifest descriptor. Every
    old R7/R8 function stays unchanged, and a canonical phone manifest is
    returned only after its separate actual Mac original is fully consumed.
    """
    require_retained_transport_binding()
    descriptor(retained_descriptor)
    need(same(retained_descriptor, RETAINED_FAILED_TRANSPORT_MANIFEST),
         "one exact actual failed R9 manifest original")
    need(TRANSPORT.MANIFEST_SCHEMA == "hepta.r9.retained-transport-failure-manifest.v1"
         and type(TRANSPORT.ARCHIVE) is dict and type(TRANSPORT.RAW_ARCHIVE) is dict,
         "bound canonical R9 reader constants required")
    descriptor(TRANSPORT.ARCHIVE)
    exact(TRANSPORT.RAW_ARCHIVE, ("bytes", "sha256"), "fixed R9 raw archive pin")
    manifest_raw = read(retained_descriptor, read_pinned)
    manifest = strict(manifest_raw)
    exact(manifest, ("schema", "archive", "raw_archive"), "complete actual R9 host manifest")
    descriptor(manifest["archive"])
    need(PurePosixPath(retained_descriptor["path"]).name == "RETENTION-INPUTS.json"
         and manifest["archive"]["path"] == str(PurePosixPath(retained_descriptor["path"]).parent / "ORIGINALS.zlib")
         and manifest["schema"] == TRANSPORT.MANIFEST_SCHEMA
         and same(manifest["raw_archive"], TRANSPORT.RAW_ARCHIVE)
         and same({k: manifest["archive"][k] for k in ("bytes", "sha256")},
                  {k: TRANSPORT.ARCHIVE[k] for k in ("bytes", "sha256")}),
         "same canonical archive and raw bytes with only the exact Mac path relocation")
    deps = R9_HOST_DEPENDENCIES
    exact(deps, ("r7_phone_archive", "r7_host_archive", "r8_phone_manifest", "r8_host_manifest",
                 "r8_phone_archive", "r8_host_archive", "r8_phone_reader", "r8_host_reader",
                 "r8_phone_manifest_base64"), "exact four old proof dependency mapping")
    need(same(STAGED.R7_ARCHIVE, deps["r7_phone_archive"]), "same unchanged R8 reader R7 dependency")
    phone_raw = base64.b64decode(deps["r8_phone_manifest_base64"], validate=True)
    need((len(phone_raw), sha(phone_raw)) ==
         (deps["r8_phone_manifest"]["bytes"], deps["r8_phone_manifest"]["sha256"]),
         "exact accepted 409-byte canonical R8 manifest")
    phone = strict(phone_raw)
    def host_r8_manifest():
        raw = read(deps["r8_host_manifest"], read_pinned)
        value = strict(raw)
        exact(value, ("schema", "archive", "raw_archive"), "actual complete R8 Mac manifest")
        exact(phone, ("schema", "archive", "raw_archive"), "actual complete R8 phone manifest")
        need(value["schema"] == phone["schema"] == "hepta.r8.retained-staged-archive.v1"
             and same(value["raw_archive"], phone["raw_archive"])
             and same(value["archive"], deps["r8_host_archive"])
             and same(phone["archive"], deps["r8_phone_archive"]),
             "same R8 archive with explicit canonical Mac/phone path relocation")
        return raw
    r8_before = host_r8_manifest()
    def host_read(row):
        descriptor(row)
        if same(row, TRANSPORT.ARCHIVE):
            target = manifest["archive"]
        elif same(row, deps["r7_phone_archive"]):
            target = deps["r7_host_archive"]
        elif same(row, deps["r8_phone_manifest"]):
            host_r8_manifest()
            return phone_raw
        elif same(row, deps["r8_phone_archive"]):
            target = deps["r8_host_archive"]
        elif same(row, deps["r8_phone_reader"]):
            target = deps["r8_host_reader"]
        else:
            raise Refused("R9 host proof callback left its exact archive and four old dependencies")
        raw = read(target, read_pinned)
        need((len(raw), sha(raw)) == (row["bytes"], row["sha256"]),
             "mapped original is byte-identical to the requested canonical proof")
        return raw
    value = TRANSPORT.verify_retained_transport_archive(TRANSPORT.ARCHIVE, read_pinned=host_read)
    need(read(retained_descriptor, read_pinned) == manifest_raw and host_r8_manifest() == r8_before,
         "R9 and R8 actual manifest originals changed across complete proof consumption")
    required = ("schema", "state", "label", "nonce", "boot_id", "inventory", "inventory_roots",
                "inventory_value", "private_roots", "component_role_identities",
                "retained_preaccept_binding", "retained_failed_staged_binding",
                "retained_failed_transport_binding", "original_native_predecessor",
                "original_root_namespace_anchor", "first_launch_receipt_gap",
                "original_start_reused", "original_retried_launch", "original_wrapper_status",
                "historical_failed_route_callsite", "historical_failed_listener_identity",
                "global_unknown_effect_count", "native_terminal", "native_case_credit",
                "component_qualified", "business_qualified", "standalone_execution_authorized",
                "original_nonce_consumed", "replay_authorized", "new_nonce_authorized",
                "remote_cleanup_proven")
    need(type(value) is dict and all(k in value for k in required), "complete typed failed R9 result")
    need(value["schema"] == "hepta.r9.retained-transport-failure-verification.v1"
         and value["state"] == "EXACT_FAILED_R9_FIRST_PUSH_ORIGINALS_RECONCILED_UNKNOWN_RETAINED"
         and value["label"] == "root-r10-neg01-fc33-r9-bound01"
         and value["nonce"] == "299483481a678cbd589aeba54ed8b68f" and value["boot_id"] == BOOT,
         "the one original failed R9 transport family")
    need(value["first_launch_receipt_gap"] is True and value["original_start_reused"] is True
         and value["original_retried_launch"] is False
         and value["original_wrapper_status"] == "failed_or_unknown_no_retry"
         and value["historical_failed_route_callsite"] is None
         and value["historical_failed_listener_identity"] is None
         and value["global_unknown_effect_count"] is None and value["native_terminal"] is None
         and type(value["native_case_credit"]) is int and value["native_case_credit"] == 0
         and value["component_qualified"] is False and value["business_qualified"] is False
         and value["standalone_execution_authorized"] is False
         and value["original_nonce_consumed"] is True and value["replay_authorized"] is False
         and value["new_nonce_authorized"] is False and value["remote_cleanup_proven"] is False,
         "failed R9 uncertainty, first reply gap, consumed nonce and zero qualification remain explicit")
    need(type(value["private_roots"]) is list and value["private_roots"] == []
         and type(value["component_role_identities"]) is dict and value["component_role_identities"] == {},
         "this R10 profile requires actual accepted proof of no additional R9 roots or component roles")
    inventory = validate_complete_inventory(value["inventory_value"])
    old = validate_complete_inventory(staged["inventory_value"])
    need(same(inventory, old) and len(inventory["roots"]) == 49
         and same(value["inventory_roots"], inventory["roots"])
         and same(value["inventory"], {"bytes": len(canonical(value["inventory_value"])),
                                       "sha256": sha(canonical(value["inventory_value"]))}),
         "all original native44 plus retained R7three and R8two entries are preserved exactly")
    need(same(value["retained_preaccept_binding"], retained["retained_preaccept_binding"])
         and same(value["retained_failed_staged_binding"], staged["retained_failed_staged_binding"])
         and same(value["original_native_predecessor"], retained["original_native_predecessor"])
         and same(value["original_native_predecessor"], staged["original_native_predecessor"]),
         "separate failed R9 proof binds the same accepted R7/R8 and native final04 predecessor")
    binding = value["retained_failed_transport_binding"]
    need(same(binding, RETAINED_FAILED_TRANSPORT_BINDING), "one exact accepted failed R9 binding")
    for key in ("label", "nonce", "boot_id", "inventory", "private_roots", "component_role_identities",
                "retained_preaccept_binding", "retained_failed_staged_binding",
                "original_native_predecessor", "original_root_namespace_anchor",
                "native_terminal", "global_unknown_effect_count", "original_nonce_consumed"):
        need(key in binding and same(binding[key], value[key]), "failed R9 binding differs: " + key)
    anchor = value["original_root_namespace_anchor"]
    need(anchor["path"] == BASE + "/native-guard-root-chains-r10-r1/" + value["label"] + "/ROOT-FAILURE.json",
         "actual failed R9 Root namespace anchor")
    read(anchor, read_pinned)
    return value


def validate_retained_transport_preservation(transport, inventory):
    """All already retained roots remain original when this R10 NEG01 is closed."""
    require_retained_transport_binding()
    need(same(transport["retained_failed_transport_binding"], RETAINED_FAILED_TRANSPORT_BINDING),
         "current predecessor must retain the same accepted failed R9 binding")
    prior = validate_complete_inventory(transport["inventory_value"])
    current = validate_complete_inventory(inventory)
    need(len(prior["roots"]) == 49 and set(prior["roots"]).issubset(current["roots"])
         and all(name in current["entries"] and same(row, current["entries"][name])
                 for name, row in prior["entries"].items()),
         "every actual retained old49 entry survives this current R10 predecessor")


def validate_candidate(candidate, *, retained, staged, transport, read_pinned):
    """Read the actual manifests; source-only fields confer no case credit.

    The caller remains obligated to run the unchanged complete validate_plan.
    This additional reader makes a stale R6 package, unrelated package, or a
    caller's adoption boolean insufficient to pass this disposition gate.
    """
    keys = ("package", "source_package", "shared_materials", "artifacts", "policy_adoption", "live_policy_sha256")
    exact(candidate, keys, "exact current candidate tuple")
    expected = {"package": "/runtime/MANIFEST.json", "source_package": "/root-chain/SOURCE-MANIFEST.json",
                "shared_materials": "/shared/SHARED-MATERIALS.json", "artifacts": "/ARTIFACTS.json"}
    for key, suffix in expected.items():
        need(candidate[key]["path"] == CURRENT_ROOT + suffix, "one explicit R10 source target: " + key)
    values = {key: document(candidate[key], read_pinned) for key in keys if key != "live_policy_sha256"}
    manifest, root = values["package"], values["source_package"]
    need(same(manifest.get("retained_preaccept_binding"), retained["retained_preaccept_binding"])
         and same(root.get("retained_preaccept_binding"), retained["retained_preaccept_binding"]),
         "runtime and Root must retain the exact original failed R7 binding")
    need(same(manifest.get("retained_failed_staged_binding"), staged["retained_failed_staged_binding"])
         and same(root.get("retained_failed_staged_binding"), staged["retained_failed_staged_binding"]),
         "runtime and Root must retain the exact original failed R8 binding")
    need(same(manifest.get("retained_failed_transport_binding"), transport["retained_failed_transport_binding"])
         and same(root.get("retained_failed_transport_binding"), transport["retained_failed_transport_binding"]),
         "runtime and Root must retain the exact original failed R9 binding")
    need(manifest.get("schema") == "hepta.native-guard.adapter-package.v1"
         and candidate["package"]["sha256"] != ORIGINAL["runtime_manifest_sha256"], "original R6 tuple cannot receive new credit")
    need(root.get("schema") == "hepta.native-guard.root-chain-source-package.v1", "exact Root source manifest")
    members = {"reference/actual_policy_adoption.py", "source/phone_chain_bridge.py", "source/run_component_root_once.py"}
    need(type(root.get("files")) is list and len(root["files"]) == 3 and {r["path"] for r in root["files"]} == members,
         "original three-member Root source census must remain unchanged")
    need(type(manifest.get("files")) is list and len(manifest["files"]) == 38 and manifest.get("runtime_file_count") == 38,
         "original 38-member runtime census must remain unchanged")
    combo = manifest.get("current_combination_sha256")
    need(type(combo) is str and re.fullmatch(r"[0-9a-f]{64}", combo), "exact current combination digest")
    need(manifest.get("selected_case_order") == ["NEG-01", "NEG-02"]
         and manifest.get("automatic_retry") is False and manifest.get("source_parent_qualification_is_current_tuple_credit") is False,
         "candidate progression and credit rules differ")
    need(type(candidate["live_policy_sha256"]) is str and candidate["live_policy_sha256"] == manifest.get("current_policy_sha256"),
         "current explicit policy does not match candidate")
    for row, directory in ((manifest, CURRENT_ROOT + "/runtime"), (root, CURRENT_ROOT + "/root-chain")):
        seen = set()
        for member in row["files"]:
            name = member["path"]
            rel = PurePosixPath(name)
            need(type(name) is str and not rel.is_absolute() and str(rel) == name and ".." not in rel.parts
                 and name not in seen, "canonical exact source member")
            seen.add(name)
            read({"path": directory + "/" + name, "bytes": member["bytes"], "sha256": member["sha256"]}, read_pinned)
    return manifest


def validate_current_predecessor(context, manifest, *, retained, staged, transport, read_pinned):
    """Accept initial source-parent entry or this exact combination's NEG01.

    No new scope is synthesized. Existing validate_current_prior performs the
    full historical reader chain unchanged; these checks preserve the actual
    files used by that chain and forbid borrowing final04 for NEG02.
    """
    previous = document(context["previous"], read_pinned)
    need(previous.get("schema") == "hepta.native-guard.closed-previous.v1"
         and previous.get("known_all_dispatched_tools_confirmed_terminal") is True
         and previous.get("component_qualified") is True and previous.get("terminal") == {"status": "completed"}
         and previous.get("automatic_replay") is False, "actual qualified completed predecessor still required")
    home = PurePosixPath(context["previous"]["path"]).parent
    need(str(home.parent) == BASE + "/native-guard-root-chains-r10-r1"
         and PurePosixPath(context["previous"]["path"]).name == "ACTUAL-PREVIOUS-INPUT.json", "standard actual predecessor namespace")
    need(previous["identity"]["session_id"] == context["session_id"]
         and previous["identity"]["profile_id"] == context["profile_id"], "actual predecessor session/profile differs")
    bound = document(context["prior_boundary_descriptor"], read_pinned)
    raw = read(context["prior_boundary_original"], read_pinned)
    need(context["prior_boundary_descriptor"]["path"] == str(home / "LATE-BOUNDARY-DESCRIPTOR.json")
         and context["prior_boundary_original"]["path"] == str(home / "LATE-BOUNDARY.original.json")
         and same(previous["late_boundary"], bound)
         and (bound["bytes"], bound["sha256"]) == (len(raw), sha(raw)), "actual same-home late boundary originals")
    boundary = strict(raw)
    need(boundary.get("schema") == "hepta.native-guard.late-boundary.v1" and boundary.get("boot_id") == context["boot_id"]
         and boundary.get("scope") == previous["identity"] and boundary.get("component_qualified") is True
         and boundary.get("native_status") == "completed", "actual current qualified boundary binding")
    closure_desc = previous["closed_component"]
    need(closure_desc["path"] == str(home / "CLOSURE.json"), "actual same-home closure")
    closed = document(closure_desc, read_pinned)
    need(closed.get("state") == "ORIGINAL_NATIVE_COMPONENT_CLOSED" and closed.get("component_qualified") is True
         and closed.get("native_status") == "completed" and closed.get("scope") == previous["identity"], "actual successful original component closure")
    inventory_desc = {"path": str(home / "INVENTORY.json"), "bytes": boundary["inventory"]["bytes"],
                      "sha256": boundary["inventory"]["sha256"]}
    inventory = document(inventory_desc, read_pinned)
    checked = validate_complete_inventory(inventory)
    need(checked["roots"] == boundary["roots"], "actual complete current cumulative inventory roots")
    if context["case_id"] == "NEG-01":
        need(context["previous"]["sha256"] == PREVIOUS_SHA and context["previous"]["bytes"] == 1426
             and inventory_desc["sha256"] == HISTORICAL_INVENTORY_PIN[1] and len(checked["roots"]) == 44,
             "new first case must enter through exact final04 source parent")
        records = manifest.get("source_parent_records")
        need(type(records) is list and len(records) == 1 and same(records[0]["closed_previous"], context["previous"])
             and same(records[0]["boundary"], bound), "candidate omitted its exact source parent")
        need(same(bound, retained["original_native_predecessor"])
             and len(set(checked["roots"]) | set(retained["private_roots"])) == 47
             and set(checked["roots"]) | set(retained["private_roots"]) == set(retained["inventory_value"]["roots"]),
             "native final04 stays 44 roots; separate actual retained R7 adds exactly three")
        need(same(bound, staged["original_native_predecessor"])
             and set(retained["inventory_value"]["roots"]).isdisjoint(staged["private_roots"])
             and set(checked["roots"]) | set(retained["private_roots"]) | set(staged["private_roots"])
                 == set(staged["inventory_value"]["roots"])
             and len(staged["inventory_value"]["roots"]) == 49,
             "native final04 stays44; independently retained R7three and R8two yield exact49")
        need(same(bound, transport["original_native_predecessor"])
             and transport["private_roots"] == [] and transport["component_role_identities"] == {}
             and same(validate_complete_inventory(transport["inventory_value"]),
                      validate_complete_inventory(staged["inventory_value"])),
             "actual failed R9 adds no root or role and preserves every original old49 entry")
        selected_inventory = transport["inventory"]
        kind = "exact_source_parent44_plus_retained_failed_r7_r8_r9_49"
    elif context["case_id"] == "NEG-02":
        need(context["previous"]["sha256"] != PREVIOUS_SHA and boundary.get("case_id") == "NEG-01"
             and boundary.get("package_sha256") == context["candidate"]["package"]["sha256"]
             and boundary.get("combination_sha256") == manifest["current_combination_sha256"]
             and home.name == CURRENT_LABELS["NEG-01"]
             and len(checked["roots"]) == 52, "NEG02 requires this exact R10 combination's completed NEG01 and its 52 roots")
        closers = [r for r in manifest["files"] if r["path"] == "source/close_component.py"]
        need(len(closers) == 1 and closed.get("closure_source_sha256") == closers[0]["sha256"], "actual current-generation closer origin")
        need(closed.get("nonce") == boundary.get("nonce") and closed.get("case_id") == "NEG-01", "current NEG01 closure identity")
        need(same(boundary.get("retained_preaccept_binding"), retained["retained_preaccept_binding"])
             and same(closed.get("retained_preaccept_binding"), retained["retained_preaccept_binding"]),
             "current NEG01 boundary and closure must retain the same failed R7 originals")
        need(same(boundary.get("retained_failed_staged_binding"), staged["retained_failed_staged_binding"])
             and same(closed.get("retained_failed_staged_binding"), staged["retained_failed_staged_binding"]),
             "current NEG01 boundary and closure must retain the same failed R8 originals")
        need(same(boundary.get("retained_failed_transport_binding"), transport["retained_failed_transport_binding"])
             and same(closed.get("retained_failed_transport_binding"), transport["retained_failed_transport_binding"]),
             "current NEG01 boundary and closure must retain the same failed R9 originals")
        RETAINED.validate_private_preservation(retained, inventory, inventory_reader=validate_complete_inventory)
        STAGED.validate_private_preservation(staged, inventory, inventory_reader=validate_complete_inventory)
        validate_retained_transport_preservation(transport, inventory)
        selected_inventory = boundary["inventory"]
        kind = "current_r10_native_head_with_separate_retained_failed_r7_r8_r9"
    else:
        raise Refused("unreviewed current case")
    return {"kind": kind, "previous": context["previous"], "boundary_sha256": sha(raw),
            "inventory": inventory_desc, "root_count": len(checked["roots"]),
            "effective_current_root_count": 49 if context["case_id"] == "NEG-01" else 52,
            "retained_preaccept_inventory": retained["inventory"],
            "retained_failed_staged_inventory": staged["inventory"],
            "retained_failed_transport_inventory": transport["inventory"],
            "selected_inventory": selected_inventory}


def verify_current_mac_fence(accepted, *, read_live_fence):
    """Every new mutation stage rereads the actual first original entry gate.

    Past complete producer reconciliation excludes already-past-entry actors.
    The immutable original program never removes the three P4 tombstones.
    All future delayed original controller entries must first mkdir this Mac
    name. This local O_NOFOLLOW read preserves preparer's network prohibition.
    """
    expected = next(r for r in fence_rows() if r["host"] == "mac")
    raw, metadata = read_live_fence(expected)
    need(type(raw) is bytes and raw == base64.b64decode(expected["payload_base64"], validate=True), "live original Mac tombstone differs")
    need(type(metadata) is dict and metadata.get("st_uid") == 501 and metadata.get("st_nlink") == 1
         and stat.S_ISREG(metadata.get("st_mode", 0)) and stat.S_IMODE(metadata["st_mode"]) == 0o600,
         "live original Mac fence owner/type/mode differs")
    version = ":".join(str(metadata[k]) for k in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))
    need(version == accepted["fences"][expected["fence_id"]]["version"], "live original Mac fence replaced/deleted/recreated")
    return {"path": expected["path"], "version": version, "sha256": sha(raw)}


def fresh_admission(plan_context, resolution_descriptor, fresh_observation_descriptor, *, retained_preaccept_descriptor, retained_failed_staged_descriptor, retained_failed_transport_descriptor, read_pinned, read_live_fence):
    """Additional disposition gate, subordinate to unchanged case protocol.

    Freshness is current context + current local durable fence + actual
    predecessor originals. The old complete phone inventory/roles/endpoints
    and sender selection/draft CAS run in their original execution positions.
    Reusing a dated phone observation is never called a fresh phone check.
    """
    context_keys = ("schema", "stage", "candidate", "case_id", "label", "nonce", "out", "request_directory",
                    "previous", "prior_boundary_descriptor", "prior_boundary_original", "request", "boot_id", "session_id", "profile_id")
    exact(plan_context, context_keys, "current execution context")
    need(plan_context["schema"] == CONTEXT_SCHEMA and plan_context["stage"] in FIXED_STAGES, "one actual guarded execution stage")
    require_retained_transport_binding()
    accepted = verify_disposition(resolution_descriptor, read_pinned=read_pinned)
    retained = verify_retained_preaccept(retained_preaccept_descriptor, read_pinned=read_pinned)
    staged = verify_retained_failed_staged(retained_failed_staged_descriptor, retained=retained, read_pinned=read_pinned)
    transport = verify_retained_failed_transport(retained_failed_transport_descriptor,
                                                retained=retained, staged=staged, read_pinned=read_pinned)
    retained_nonces = [retained["nonce"], staged["nonce"], transport["nonce"]]
    need(len(set(retained_nonces)) == 3
         and set(retained_nonces) == {"4808fbf1e81fd1542e7ffb60d7f57ca6", "aa06c3b8d035dcd0c0047105f620b3bf", "299483481a678cbd589aeba54ed8b68f"},
         "exact three distinct original retained nonces must be consumed before plan reservation")
    fresh = document(fresh_observation_descriptor, read_pinned)
    exact(fresh, ("schema", "original", "resolution_sha256", "retained_preaccept", "retained_failed_staged", "retained_failed_transport", "candidate", "case_id", "label", "previous", "prior_boundary_descriptor",
                  "prior_boundary_original", "boot_id", "session_id", "profile_id", "reservation"), "explicit fresh candidate admission input")
    need(fresh["schema"] == FRESH_SCHEMA and same(fresh["original"], ORIGINAL)
         and fresh["resolution_sha256"] == resolution_descriptor["sha256"]
         and same(fresh["retained_preaccept"], retained_preaccept_descriptor)
         and same(fresh["retained_failed_staged"], retained_failed_staged_descriptor)
         and same(fresh["retained_failed_transport"], retained_failed_transport_descriptor), "fresh four-family disposition binding")
    for key in ("candidate", "case_id", "label", "previous", "prior_boundary_descriptor", "prior_boundary_original", "boot_id", "session_id", "profile_id"):
        need(same(plan_context[key], fresh[key]), "fresh context differs: " + key)
    need(fresh["boot_id"] == BOOT and fresh["profile_id"] == "owner-open", "current reviewed boot/profile")
    live = verify_current_mac_fence(accepted, read_live_fence=read_live_fence)
    manifest = validate_candidate(plan_context["candidate"], retained=retained, staged=staged, transport=transport, read_pinned=read_pinned)
    predecessor = validate_current_predecessor(plan_context, manifest, retained=retained, staged=staged, transport=transport, read_pinned=read_pinned)
    need(CURRENT_LABELS.get(fresh["case_id"]) == fresh["label"], "one explicitly reviewed current case label")
    expected_out = BASE + "/native-guard-root-chains-r10-r1/" + fresh["label"]
    expected_inputs = BASE + "/native-guard-root-inputs-r10-r1/" + fresh["label"]
    need(plan_context["out"] == expected_out and plan_context["request_directory"] == expected_inputs, "fixed successor namespaces")
    reservation = fresh["reservation"]
    exact(reservation, ("label", "case_id", "request_directory", "out", "maximum_nonce_generations"), "one plan reservation")
    need(type(reservation["maximum_nonce_generations"]) is int and same(reservation,
         {"label": fresh["label"], "case_id": fresh["case_id"], "request_directory": expected_inputs,
          "out": expected_out, "maximum_nonce_generations": 1}), "exact one-nonce reservation")
    if plan_context["stage"] == "prepare-before-create":
        need(plan_context["nonce"] is None and plan_context["request"] is None, "prepare admission precedes nonce/request creation")
        action = "DISPOSITION_GATE_ACCEPTED_FOR_ONE_SPECIFIED_PLAN"
    else:
        nonce = plan_context["nonce"]
        consumed = {NONCE, BOUND01["nonce"], retained["nonce"], staged["nonce"], transport["nonce"]}
        def retain_nonces(value):
            if type(value) is dict:
                for key, child in value.items():
                    if key == "nonce" and type(child) is str:
                        consumed.add(child)
                    retain_nonces(child)
            elif type(value) is list:
                for child in value:
                    retain_nonces(child)
        retain_nonces(manifest)
        need(type(nonce) is str and re.fullmatch(r"[0-9a-f]{32}", nonce) and nonce not in consumed, "fresh runtime nonce required")
        req = read(plan_context["request"], read_pinned)
        need(plan_context["request"]["path"] == expected_inputs + "/REQUEST.txt" and 20 <= len(req) <= 16000
             and req.count(nonce.encode()) == 1 and NONCE.encode() not in req and BOUND01["nonce"].encode() not in req
             and retained["nonce"].encode() not in req and staged["nonce"].encode() not in req
             and transport["nonce"].encode() not in req,
             "actual new nonce-bound request bytes")
        action = "DISPOSITION_GATE_ACCEPTED_FOR_SPECIFIED_CURRENT_REQUEST"
    # A final second local read catches replacement while full originals were
    # validated. It uses no subprocess/socket and creates no output or nonce.
    need(same(live, verify_current_mac_fence(accepted, read_live_fence=read_live_fence)), "Mac fence changed across current admission")
    read(retained["original_root_namespace_anchor"], read_pinned)
    read(staged["original_root_namespace_anchor"], read_pinned)
    read(transport["original_root_namespace_anchor"], read_pinned)
    return {"schema": "hepta.r10.original-dispositions.fresh-admission.v1", "state": action, "stage": plan_context["stage"],
            "context_sha256": sha(canonical(plan_context)), "resolution_sha256": resolution_descriptor["sha256"],
            "observation_sha256": fresh_observation_descriptor["sha256"], "original_terminal": None,
            "original_effect_counts": {k: None for k in EFFECT_FIELDS}, "original_replay_allowed": False,
            "native_case_credit": False, "case_id": fresh["case_id"], "label": fresh["label"], "nonce": plan_context["nonce"],
            "predecessor": predecessor, "live_mac_fence": live, "standalone_execution_authorized": False,
            "retained_preaccept_descriptor": retained_preaccept_descriptor,
            "retained_preaccept_binding": retained["retained_preaccept_binding"],
            "retained_failed_staged_descriptor": retained_failed_staged_descriptor,
            "retained_failed_staged_binding": staged["retained_failed_staged_binding"],
            "retained_failed_transport_descriptor": retained_failed_transport_descriptor,
            "retained_failed_transport_binding": transport["retained_failed_transport_binding"],
            "retained_failed_transport_native_terminal": transport["native_terminal"],
            "retained_failed_transport_global_unknown_effect_count": transport["global_unknown_effect_count"],
            "retained_failed_transport_first_launch_receipt_gap": transport["first_launch_receipt_gap"],
            "consumed_native_nonces": retained_nonces,
            "retained_failed_staged_native_terminal": staged["native_terminal"],
            "retained_failed_staged_global_unknown_effect_count": staged["global_unknown_effect_count"],
            "retained_original_native_terminal": retained["native_terminal"],
            "retained_original_global_effect_count": retained["global_unknown_effect_count"],
            "existing_checks_still_required": ["complete_validate_plan_and_validate_current_prior", "late_verify_current_before_phone_stage_and_launch",
                                               "selected_identity_and_protected_draft_CAS", "existing_one_shot_output_and_nonce_reservation"]}
