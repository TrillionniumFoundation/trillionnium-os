"""Build the fixed bound02 namespace-cut plan; never performs a remote write.

Every name is derived from the already-issued R6 request.  This module neither
creates a successor nonce nor labels a namespace cut a process retirement.
"""
from pathlib import Path
import base64
import hashlib
import json

BASE = "/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1"
LABEL = "root-r10-neg01-fc33-r6-bound02"
NONCE = "731dc46ccaad6e5717306d0c5f029a82"
ORIGINAL = {
    "host": "mac", "job_id": "1a1b3420986-fc05-8183",
    "label": LABEL, "nonce": NONCE, "case_id": "NEG-01",
    "plan_sha256": "0fbfd5aa0ed86e0bad846f2e541c3117ee1c7a46c98af7000c96f2e7d25a4bfa",
    "request_sha256": "b25d5c139aebdec8a222ca4298e91cd57500b0836c0c9f1629cb4ce769ad6d3f",
    "runtime_manifest_sha256": "270357b7649af61414d31580b3c1eaddc47174bd1bac3c8adfc02934a92c8cf5",
    "combination_sha256": "7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411",
    "root_source_sha256": "53c2e7c26c960d76ac5d3201420d33f13fb06c241d30d40fc7b2b7577e690257",
}
ROOT_OUT = BASE + "/native-guard-root-chains-r10-r1/" + LABEL
P4_ROOT = "/home/alex/codex-native-guard-chain-r10-r1/" + NONCE
SENDER_OUT = "/home/alex/codex-hepta-natural-" + LABEL + "-root-v150"
FIXTURE_ROOT = "/home/alex/codex-hepta-native-guard-fixtures-r10-r1/" + NONCE
PHONE_BASE = "/home/alex/razr60-local-model-v150"
PHASES = ("setup", "before-guard", "after-guard")


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                       allow_nan=False) + "\n").encode("utf-8")


def phone_tags():
    tags = ["push-material", "copy-material", "push-stage-source", "copy-stage-source", "stage", "launch"]
    for phase in PHASES:
        tags.extend(["plan-" + phase, "push-witness-" + phase, "copy-witness-" + phase, "publish-" + phase])
    tags.extend(["role-end", "snapshot"])
    tags.extend("chunk-" + str(i) for i in range(128))
    tags.extend(["push-closed-closure", "copy-closed-closure", "push-closed-inventory", "copy-closed-inventory", "late-publish", "boundary-read"])
    assert len(tags) == 154 and len(set(tags)) == 154
    return tuple(tags)


def tombstone(fence_id, host, path):
    return {
        "schema": "hepta.r6.bound02.namespace-tombstone.v1",
        "fence_id": fence_id, "host": host, "path": path,
        "original": ORIGINAL,
        "purpose": "PERMANENT_EXCLUSIVE_DIRECTORY_NAME_RESERVATION",
        "original_terminal": "UNKNOWN", "historical_effect_count": None,
        "original_replay_allowed": False, "native_case_credit": False,
        "producer_retirement_proven_by_this_file": False,
    }


def fence_rows():
    rows = [
        ("mac-root-out", "mac", ROOT_OUT, ["Chain.__init__:485", "execute_process:608-670"],
         "Root must exclusively mkdir its output; every later child dispatch first creates an output subdirectory."),
        ("p4-chain-root", "pocket4", P4_ROOT, ["remote_files:842-849", "remote_program:859-864", "phone:868-879"],
         "Initial material stage and each remote child create the directory or a descendant before Popen."),
        ("p4-sender-out", "pocket4", SENDER_OUT, ["send_new_native_guard_task_r10_r4.py:80"],
         "Sender must exclusively mkdir before UI preparation, prompt replacement, Send or draft restore; baseline route reads occur earlier."),
        ("p4-fixture-root", "pocket4", FIXTURE_ROOT,
         ["run_component_root_once.py:965-976", "run_root_fixture_phase.py:prepare_parent_directory", "root_fixture_once.py:run"],
         "All three direct-transport fixture phases require a directory ancestor and exclusively create their phase/actor outputs."),
    ]
    out = []
    for fence_id, host, path, locations, consequence in rows:
        raw = canonical(tombstone(fence_id, host, path))
        out.append({"fence_id": fence_id, "host": host, "path": path,
                    "required_file_type": "regular", "expected_version": "absent",
                    "payload_bytes": len(raw), "payload_sha256": hashlib.sha256(raw).hexdigest(),
                    "payload_base64": base64.b64encode(raw).decode(),
                    "source_locations": locations, "source_consequence": consequence,
                    "if_existing_directory": "STOP_PRESERVE_ORIGINALS_NO_REPLACE_NO_RENAME_NO_DELETE",
                    "already_passed_entry": "REQUIRES_INDEPENDENT_EXACT_OWNER_RETIREMENT_AND_TRANSPORT_DRAIN"})
    return out


def build_plan():
    phone = []
    for tag in phone_tags():
        label = "ng-" + NONCE + "-" + tag
        phone.append({"tag": tag, "label": label,
                      "request_claim": PHONE_BASE + "/requests/" + label + ".json",
                      "operation_directory": PHONE_BASE + "/operations/" + label,
                      "root_child_directory": P4_ROOT + "/phone-" + tag})
    return {
        "schema": "hepta.r6.bound02.namespace-fence-plan.v1",
        "status": "SOURCE_ONLY_NOT_EXECUTED", "original": ORIGINAL,
        "fences": fence_rows(), "phone_once_operation_count": len(phone), "phone_once_operations": phone,
        "sender_additional_exclusive_claims": [BASE + "/" + LABEL + suffix for suffix in (".actor.py", ".local-once.json")],
        "fixture_direct_transport_paths": [{"phase": phase, "parent_out": FIXTURE_ROOT + "/" + phase,
                                              "actor_out": FIXTURE_ROOT + "/" + phase + "/actor"} for phase in PHASES],
        "write_protocol": [
            "Root may create a regular-file payload only with h_binary_write expected_version=absent at the exact path.",
            "An existing path, symlink, directory, uncertain write or changed readback is a stop, never a deletion or replacement request.",
            "Preserve the exact write response and independent h_file_info/read bytes and version after publication.",
            "Maintain all fences through producer accounting and fresh admission; recheck exact bytes/version/type before creating a new nonce.",
        ],
        "producer_retirement_minimum": [
            "Complete Mac and Pocket4 process/child/session census with boot identity, PID start identities, ownership selectors for exact original argv/path/nonce, and a complete pagination/snapshot boundary.",
            "For every producer already beyond a namespace entry, retain exact owner binding plus actual wait/terminal or identity-checked signal followed by two complete absence observations; signal receipt alone is insufficient.",
            "Account for reparented/detached children, the direct fixture actors, phone_once children and sender finally/draft cleanup, not only the coordinator or runtime job PID.",
            "Account for in-flight ADB sockets and phone commands/native role processes under the existing owner/inventory readers. Killing a host actor alone does not prove an issued phone command ended.",
            "Full phone native-role/lease/stage/action census and current UI/draft evidence; preserve original effect counts as unknown if historical evidence remains incomplete.",
            "If a complete before/after census cannot identify all relevant descendants, retain the block or use an independently proven boot epoch change plus persistent namespace fences and postboot phone state reconciliation.",
        ],
        "not_retirement_evidence": ["missing worker/output directory", "elapsed lease/plan age",
            "cancel timeout", "zero matching provider starts in a bounded read",
            "signal delivery without termination", "changed ADB server PID with reusable cached route",
            "caller boolean", "different nonce or bound01 recovery"],
        "source_pins": {
            "run_component_root_once.py": {"bytes": 78567, "sha256": ORIGINAL["root_source_sha256"]},
            "send_new_native_guard_task_r10_r4.py": {"bytes": 41745, "sha256": "de6c90187ad15995cbd85c662fb7d0a0ee40809bc54d9c1a51c46e164d75b354"},
            "phone_once.py": {"bytes": 5652, "sha256": "179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22"},
        },
        "original_terminal": "UNKNOWN", "historical_effect_count": None,
        "native_case_credit": False, "fresh_execution_eligible": False,
    }


if __name__ == "__main__":
    target = Path(__file__).with_name("BOUND02-FENCE-PLAN.json")
    target.write_bytes(canonical(build_plan()))
    print(json.dumps({"path": str(target), "bytes": target.stat().st_size,
                      "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                      "phone_once_operations": 154, "remote_actions": 0}))
