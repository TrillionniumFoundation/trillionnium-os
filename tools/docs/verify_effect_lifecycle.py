#!/usr/bin/env python3
"""Fail-closed verifier and finite model checker for the effect lifecycle.

This verifies only the checked-in source model.  Success is L1 evidence and
cannot establish installed-target, physical-device, destructive-fault,
signing, deployment, OTA, or public-release facts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
from collections import Counter, deque
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
AUTHORITY = ROOT / "docs" / "machine" / "effect-lifecycle.v1.json"

EXPECTED_STATES = [
    "RECEIVED",
    "VALIDATED",
    "CAPACITY_RESERVED",
    "ACCEPTED_DURABLE",
    "EFFECT_ATTEMPTING",
    "EFFECT_STARTED_OBSERVED",
    "TERMINAL_OBSERVED",
    "TERMINAL_DURABLE",
    "DELIVERY_PENDING",
    "DELIVERED",
    "ACKNOWLEDGED",
    "REJECTED_BEFORE_EFFECT",
    "UNKNOWN_RECONCILIATION_REQUIRED",
    "FENCED",
    "CLOSED",
]
EXPECTED_TRANSITION_IDS = [f"TR-{index:02d}" for index in range(1, 28)]
EXPECTED_CUT_IDS = [f"CUT-{index:02d}" for index in range(1, 14)]
EXPECTED_STATE_SEMANTICS = {
    "RECEIVED": ("ingress", False, False, "none", False),
    "VALIDATED": ("admission", False, False, "none", False),
    "CAPACITY_RESERVED": ("admission", False, False, "none", False),
    "ACCEPTED_DURABLE": ("admission", False, True, "none", True),
    "EFFECT_ATTEMPTING": ("effect", True, False, "none", False),
    "EFFECT_STARTED_OBSERVED": ("effect", True, False, "none", False),
    "TERMINAL_OBSERVED": ("terminal", True, False, "definitive", False),
    "TERMINAL_DURABLE": ("terminal", True, True, "definitive", False),
    "DELIVERY_PENDING": ("delivery", True, True, "definitive", False),
    "DELIVERED": ("delivery", True, True, "definitive", False),
    "ACKNOWLEDGED": ("delivery", True, True, "definitive", False),
    "REJECTED_BEFORE_EFFECT": ("terminal", False, False, "definitive", False),
    "UNKNOWN_RECONCILIATION_REQUIRED": ("uncertainty", True, False, "uncertain", False),
    "FENCED": ("uncertainty", True, False, "uncertain", False),
    "CLOSED": ("closed", True, True, "closed", False),
}
EXPECTED_CRASH_RECOVERIES = {
    "CUT-01": ("RECEIVED", ("RECEIVED", "REJECTED_BEFORE_EFFECT")),
    "CUT-02": ("VALIDATED", ("RECEIVED", "VALIDATED", "REJECTED_BEFORE_EFFECT")),
    "CUT-03": ("CAPACITY_RESERVED", ("REJECTED_BEFORE_EFFECT", "FENCED")),
    "CUT-04": ("ACCEPTED_DURABLE", ("ACCEPTED_DURABLE", "FENCED")),
    "CUT-05": ("EFFECT_ATTEMPTING", ("UNKNOWN_RECONCILIATION_REQUIRED", "FENCED")),
    "CUT-06": ("EFFECT_STARTED_OBSERVED", ("UNKNOWN_RECONCILIATION_REQUIRED", "FENCED")),
    "CUT-07": ("TERMINAL_OBSERVED", ("TERMINAL_DURABLE", "UNKNOWN_RECONCILIATION_REQUIRED", "FENCED")),
    "CUT-08": ("TERMINAL_DURABLE", ("TERMINAL_DURABLE", "DELIVERY_PENDING")),
    "CUT-09": ("DELIVERY_PENDING", ("DELIVERY_PENDING", "DELIVERED")),
    "CUT-10": ("DELIVERED", ("DELIVERY_PENDING", "DELIVERED", "ACKNOWLEDGED")),
    "CUT-11": ("ACKNOWLEDGED", ("ACKNOWLEDGED", "CLOSED")),
    "CUT-12": ("UNKNOWN_RECONCILIATION_REQUIRED", ("UNKNOWN_RECONCILIATION_REQUIRED", "FENCED")),
    "CUT-13": ("FENCED", ("FENCED", "CLOSED")),
}
EXPECTED_BINDING_FIELDS = [
    "operation_digest",
    "request_digest",
    "session_id",
    "turn_id",
    "call_id",
    "job_id",
    "ordering_key",
    "host_epoch",
    "provider_epoch",
    "writer_epoch",
    "fencing_token",
    "durable_sequence",
    "monotonic_timestamp_ns",
]
EXPECTED_CHECKERS = [
    "effect_requires_durable_acceptance",
    "ambiguous_observation_requires_unknown",
    "terminal_delivery_order_is_strict",
    "duplicate_policy_is_closed",
    "race_policy_has_one_linearization_point",
    "fenced_states_have_no_effect_path",
    "cleanup_preserves_primary_outcome",
    "crash_cuts_forbid_false_no_start",
    "automatic_redispatch_is_globally_false",
    "implementation_mapping_is_total",
]
EXPECTED_TLC_VERSION = "1.7.4"
EXPECTED_TLC_URL = "https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar"
EXPECTED_TLC_SHA1 = "bee4a54f3ee3d4afc347c3240ec2d9e93b075104"
EXPECTED_TLC_SHA256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
EXPECTED_CFG_INVARIANTS = {
    "TypeOK",
    "NoAutomaticRedispatch",
    "EffectRequiresDurableAcceptance",
    "DeliveryRequiresDurableTerminal",
    "AcknowledgementRequiresDelivery",
    "NoEffectReadmissionAfterUncertainRecovery",
}
EXPECTED_CFG_LINES = [
    "SPECIFICATION Spec",
    "INVARIANT TypeOK",
    "INVARIANT NoAutomaticRedispatch",
    "INVARIANT EffectRequiresDurableAcceptance",
    "INVARIANT DeliveryRequiresDurableTerminal",
    "INVARIANT AcknowledgementRequiresDelivery",
    "INVARIANT NoEffectReadmissionAfterUncertainRecovery",
    "CHECK_DEADLOCK FALSE",
]

TOP_KEYS = {
    "schema",
    "version",
    "program_revision",
    "status",
    "claim_ceiling",
    "automatic_redispatch",
    "binding_schema",
    "states",
    "transitions",
    "invariants",
    "duplicate_policy",
    "race_policy",
    "crash_cuts",
    "implementation_bindings",
    "verification",
}
BINDING_SCHEMA_KEYS = {
    "required_identity_fields",
    "nullable_when_not_applicable",
    "digest_algorithm",
    "monotonic_clock_required",
    "identity_conflict",
    "stale_epoch",
}
STATE_KEYS = {
    "id",
    "phase",
    "effect_may_have_started",
    "durable",
    "outcome",
    "permits_new_effect",
    "meaning",
}
TRANSITION_KEYS = {
    "id",
    "from",
    "to",
    "trigger",
    "effect_boundary",
    "requires_durable_acceptance",
    "preserves_effect_identity",
    "automatic_redispatch",
    "bindings",
    "notes",
}
INVARIANT_KEYS = {"id", "statement", "checker"}
DUPLICATE_KEYS = {
    "identity_fields",
    "exact_identity_equal_bytes",
    "exact_identity_changed_bytes",
    "unknown_effect_state",
    "implicit_defaults_change_identity",
    "field_aliases_change_identity",
    "automatic_redispatch",
}
RACE_KEYS = {
    "scope",
    "linearization_field",
    "clock_field",
    "cancel_before_effect",
    "effect_attempt_before_cancel",
    "terminal_before_cancel",
    "equal_time_tie_break",
    "cleanup_error_role",
    "stale_writer",
    "automatic_redispatch",
}
CUT_KEYS = {
    "id",
    "after",
    "legal_recovery",
    "forbidden_inference",
    "requires_same_effect_identity",
    "automatic_redispatch",
}
IMPLEMENTATION_KEYS = {"id", "modules", "source_path", "symbol", "transitions", "tests"}
VERIFICATION_KEYS = {
    "formal_model",
    "formal_config",
    "model_checker",
    "test_suite",
    "expected_state_count",
    "expected_transition_count",
    "exhaustive_ordered_pair_count",
    "legal_ordered_pair_count",
    "illegal_ordered_pair_count",
    "tlc_version",
    "tlc_url",
    "tlc_sha1",
    "tlc_sha256",
    "required_test_classes",
    "claim_ceiling",
}


class VerificationError(Exception):
    """Raised for a stable, fail-closed lifecycle verification failure."""


class DuplicateJsonMember(ValueError):
    """Raised when a JSON object repeats a member."""


def fail(message: str) -> None:
    raise VerificationError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonMember(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value}")


def load_authority(path: Path = AUTHORITY) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_pairs,
            parse_constant=_nonfinite,
        )
    except (OSError, ValueError) as error:
        fail(f"{path} is not strict JSON: {error}")
    require(isinstance(value, dict), "effect lifecycle root must be an object")
    return value


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    missing = expected - actual
    extra = actual - expected
    require(
        not missing and not extra,
        f"{label} keys drift; missing={sorted(missing)}, extra={sorted(extra)}",
    )


def string(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(value.strip()), f"{label} must be a non-empty string")
    require("\x00" not in value, f"{label} contains NUL")
    return value


def string_list(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    require(isinstance(value, list), f"{label} must be an array")
    if not allow_empty:
        require(bool(value), f"{label} must not be empty")
    result = [string(item, f"{label}[{index}]") for index, item in enumerate(value)]
    duplicates = sorted(item for item, count in Counter(result).items() if count > 1)
    require(not duplicates, f"{label} contains duplicates: {duplicates}")
    return result


def boolean(value: Any, label: str) -> bool:
    require(isinstance(value, bool), f"{label} must be boolean")
    return value


def positive_int(value: Any, label: str) -> int:
    require(isinstance(value, int) and not isinstance(value, bool) and value > 0, f"{label} must be a positive integer")
    return value


def _git_index_mode(root: Path, relative: str) -> str | None:
    try:
        top = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(root), "rev-parse", "--show-toplevel"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if top.returncode != 0:
        return None
    require(Path(top.stdout.strip()).resolve() == root.resolve(), "verification root is not the Git worktree root")
    indexed = subprocess.run(
        [
            "git",
            "--no-replace-objects",
            "-C",
            str(root),
            "ls-files",
            "--stage",
            "--error-unmatch",
            "--",
            relative,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    require(indexed.returncode == 0, f"repository path is not checked in: {relative}")
    rows = [line for line in indexed.stdout.splitlines() if line.strip()]
    require(len(rows) == 1, f"repository path has ambiguous Git index identity: {relative}")
    mode = rows[0].split(maxsplit=1)[0]
    require(mode in {"100644", "100755"}, f"repository path is not a regular Git file: {relative} ({mode})")
    return mode


def repository_relative_file(root: Path, raw: Any, label: str) -> Path:
    relative = string(raw, label)
    require("\\" not in relative, f"{label} must use normalized POSIX separators")
    path = Path(relative)
    require(not path.is_absolute(), f"{label} must be repository-relative")
    require(path.parts and all(part not in {"", ".", ".."} for part in path.parts), f"{label} is not normalized")

    root_resolved = root.resolve(strict=True)
    current = root_resolved
    for index, part in enumerate(path.parts):
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            fail(f"{label} does not name a regular checked-in file: {relative}: {error}")
        require(not stat.S_ISLNK(metadata.st_mode), f"{label} traverses a symbolic link: {relative}")
        if index + 1 < len(path.parts):
            require(stat.S_ISDIR(metadata.st_mode), f"{label} parent component is not a directory: {relative}")
        else:
            require(stat.S_ISREG(metadata.st_mode), f"{label} does not name a regular checked-in file: {relative}")

    resolved = current.resolve(strict=True)
    require(resolved.is_relative_to(root_resolved), f"{label} escapes the repository")
    _git_index_mode(root_resolved, path.as_posix())
    return resolved


def _parse_tla_set(text: str, name: str) -> set[str]:
    match = re.search(rf"^{re.escape(name)}\s*==\s*\{{(?P<body>.*?)^\}}$", text, re.DOTALL | re.MULTILINE)
    require(match is not None, f"formal model lacks {name} set")
    return set(re.findall(r'"([A-Z][A-Z0-9_]*)"', match.group("body")))


def _parse_tla_edges(text: str, name: str) -> set[tuple[str, str]]:
    match = re.search(rf"^{re.escape(name)}\s*==\s*\{{(?P<body>.*?)^\}}$", text, re.DOTALL | re.MULTILINE)
    require(match is not None, f"formal model lacks {name} set")
    return set(
        re.findall(
            r'<<\s*"([A-Z][A-Z0-9_]*)"\s*,\s*"([A-Z][A-Z0-9_]*)"\s*>>',
            match.group("body"),
        )
    )


def parse_tla_projection(text: str) -> tuple[set[str], set[tuple[str, str]], set[tuple[str, str]]]:
    return (
        _parse_tla_set(text, "States"),
        _parse_tla_edges(text, "Edges"),
        _parse_tla_edges(text, "RecoveryEdges"),
    )


def parse_tla_states_and_edges(text: str) -> tuple[set[str], set[tuple[str, str]]]:
    states, edges, _ = parse_tla_projection(text)
    return states, edges


def _render_tla_string_set(name: str, values: list[str]) -> list[str]:
    lines = [f"{name} == {{"]
    for index, value in enumerate(values):
        suffix = "," if index + 1 < len(values) else ""
        lines.append(f'  "{value}"{suffix}')
    lines.append("}")
    return lines


def _render_tla_edge_set(name: str, edges: list[tuple[str, str]]) -> list[str]:
    lines = [f"{name} == {{"]
    for index, (source, target) in enumerate(edges):
        suffix = "," if index + 1 < len(edges) else ""
        lines.append(f'  <<"{source}", "{target}">>{suffix}')
    lines.append("}")
    return lines


def render_tla_config() -> str:
    """Render the complete closed-world TLC configuration byte-for-byte."""

    return "\n".join(EXPECTED_CFG_LINES) + "\n"


def render_tla_model(
    states: list[dict[str, Any]],
    transitions: list[dict[str, Any]],
    crash_cuts: list[dict[str, Any]],
) -> str:
    state_ids = [state["id"] for state in states]
    edges = [(transition["from"], transition["to"]) for transition in transitions]
    recovery_edges = [
        (cut["after"], target)
        for cut in crash_cuts
        for target in cut["legal_recovery"]
    ]
    effect_possible = [state["id"] for state in states if state["effect_may_have_started"]]
    lines = [
        "---- MODULE EffectLifecycle ----",
        "EXTENDS Naturals, Sequences, FiniteSets",
        "",
        "(*",
        "GENERATED byte-for-byte from docs/machine/effect-lifecycle.v1.json.",
        "The Python verifier requires exact equality, explores the same ordinary and",
        "crash-recovery relations, and CI executes TLC on this checked-in projection.",
        "This remains L1 source evidence only; it is not target, device, fault, signing,",
        "deployment, OTA, or public-release evidence.",
        "*)",
        "",
    ]
    lines.extend(_render_tla_string_set("States", state_ids))
    lines.append("")
    lines.extend(_render_tla_edge_set("Edges", edges))
    lines.append("")
    lines.extend(_render_tla_edge_set("RecoveryEdges", recovery_edges))
    lines.append("")
    lines.extend(_render_tla_string_set("EffectPossibleStates", effect_possible))
    lines.extend(
        [
            "",
            "EffectAdmissionStates == {\"ACCEPTED_DURABLE\", \"EFFECT_ATTEMPTING\", \"EFFECT_STARTED_OBSERVED\"}",
            "DeliveryStates == {\"DELIVERY_PENDING\", \"DELIVERED\", \"ACKNOWLEDGED\"}",
            "",
            "VARIABLES state, accepted, attempted, terminalDurable, delivered, acknowledged,",
            "          recoveryLocked, automaticRedispatch",
            "",
            "vars == <<state, accepted, attempted, terminalDurable, delivered, acknowledged,",
            "          recoveryLocked, automaticRedispatch>>",
            "",
            "Init ==",
            "  /\\ state = \"RECEIVED\"",
            "  /\\ accepted = FALSE",
            "  /\\ attempted = FALSE",
            "  /\\ terminalDurable = FALSE",
            "  /\\ delivered = FALSE",
            "  /\\ acknowledged = FALSE",
            "  /\\ recoveryLocked = FALSE",
            "  /\\ automaticRedispatch = FALSE",
            "",
            "OrdinaryNext ==",
            "  \\E edge \\in Edges:",
            "    /\\ edge[1] = state",
            "    /\\ state' = edge[2]",
            "    /\\ accepted' = (accepted \\/ edge[2] = \"ACCEPTED_DURABLE\")",
            "    /\\ attempted' = (attempted \\/ edge = <<\"ACCEPTED_DURABLE\", \"EFFECT_ATTEMPTING\">>)",
            "    /\\ terminalDurable' = (terminalDurable \\/ edge[2] = \"TERMINAL_DURABLE\")",
            "    /\\ delivered' = (delivered \\/ edge[2] = \"DELIVERED\")",
            "    /\\ acknowledged' = (acknowledged \\/ edge[2] = \"ACKNOWLEDGED\")",
            "    /\\ recoveryLocked' = recoveryLocked",
            "    /\\ automaticRedispatch' = FALSE",
            "",
            "RecoveryNext ==",
            "  \\E edge \\in RecoveryEdges:",
            "    /\\ edge[1] = state",
            "    /\\ state' = edge[2]",
            "    /\\ accepted' = (accepted \\/ edge[2] = \"ACCEPTED_DURABLE\")",
            "    /\\ attempted' = attempted",
            "    /\\ terminalDurable' = (terminalDurable \\/ edge[2] = \"TERMINAL_DURABLE\")",
            "    /\\ delivered' = (delivered \\/ edge[2] = \"DELIVERED\")",
            "    /\\ acknowledged' = (acknowledged \\/ edge[2] = \"ACKNOWLEDGED\")",
            "    /\\ recoveryLocked' = (recoveryLocked \\/ edge[1] \\in EffectPossibleStates \\/ edge[2] \\in {\"UNKNOWN_RECONCILIATION_REQUIRED\", \"FENCED\"})",
            "    /\\ automaticRedispatch' = FALSE",
            "",
            "Next == OrdinaryNext \\/ RecoveryNext",
            "",
            "TypeOK ==",
            "  /\\ state \\in States",
            "  /\\ accepted \\in BOOLEAN",
            "  /\\ attempted \\in BOOLEAN",
            "  /\\ terminalDurable \\in BOOLEAN",
            "  /\\ delivered \\in BOOLEAN",
            "  /\\ acknowledged \\in BOOLEAN",
            "  /\\ recoveryLocked \\in BOOLEAN",
            "  /\\ automaticRedispatch \\in BOOLEAN",
            "",
            "NoAutomaticRedispatch == automaticRedispatch = FALSE",
            "",
            "EffectRequiresDurableAcceptance ==",
            "  (state \\in {\"EFFECT_ATTEMPTING\", \"EFFECT_STARTED_OBSERVED\"}) => accepted",
            "",
            "DeliveryRequiresDurableTerminal ==",
            "  (state \\in DeliveryStates) => terminalDurable",
            "",
            "AcknowledgementRequiresDelivery ==",
            "  (state = \"ACKNOWLEDGED\") => delivered",
            "",
            "NoEffectReadmissionAfterUncertainRecovery ==",
            "  recoveryLocked => state \\notin EffectAdmissionStates",
            "",
            "Spec == Init /\\ [][Next]_vars",
            "",
            "====",
            "",
        ]
    )
    return "\n".join(lines)

def _verify_state_graph(
    states: list[dict[str, Any]],
    transitions: list[dict[str, Any]],
    crash_cuts: list[dict[str, Any]],
) -> dict[str, int]:
    state_ids = [state["id"] for state in states]
    state_by_id = {state["id"]: state for state in states}
    edges = [(transition["from"], transition["to"]) for transition in transitions]
    recovery_edges = [
        (cut["after"], target)
        for cut in crash_cuts
        for target in cut["legal_recovery"]
    ]
    require(len(set(edges)) == len(edges), "lifecycle has duplicate ordered transition pairs")
    require(len(set(recovery_edges)) == len(recovery_edges), "lifecycle has duplicate crash-recovery pairs")

    outgoing: dict[str, list[str]] = {state_id: [] for state_id in state_ids}
    recoveries: dict[str, list[str]] = {state_id: [] for state_id in state_ids}
    for source, target in edges:
        outgoing[source].append(target)
    for source, target in recovery_edges:
        recoveries[source].append(target)

    reached = {"RECEIVED"}
    queue = deque(["RECEIVED"])
    while queue:
        source = queue.popleft()
        for target in outgoing[source]:
            if target not in reached:
                reached.add(target)
                queue.append(target)
    require(reached == set(state_ids), f"unreachable lifecycle states: {sorted(set(state_ids) - reached)}")

    initial = ("RECEIVED", False, False, False, False, False, False, False)
    product_reached = {initial}
    product_queue = deque([initial])
    ordinary_successors = 0
    recovery_successors = 0
    blocked = {"ACCEPTED_DURABLE", "EFFECT_ATTEMPTING", "EFFECT_STARTED_OBSERVED"}
    while product_queue:
        state, accepted, attempted, terminal_durable, delivered, acknowledged, recovery_locked, redispatch = product_queue.popleft()
        require(not redispatch, "finite model reached automatic redispatch")
        if state in {"EFFECT_ATTEMPTING", "EFFECT_STARTED_OBSERVED"}:
            require(accepted, f"{state} is reachable without durable acceptance")
        if state in {"DELIVERY_PENDING", "DELIVERED", "ACKNOWLEDGED"}:
            require(terminal_durable, f"{state} is reachable before terminal durability")
        if state == "ACKNOWLEDGED":
            require(delivered, "acknowledgement is reachable before delivery")
        if recovery_locked:
            require(state not in blocked, f"uncertain recovery re-entered effect admission at {state}")

        for target in outgoing[state]:
            edge = (state, target)
            successor = (
                target,
                accepted or target == "ACCEPTED_DURABLE",
                attempted or edge == ("ACCEPTED_DURABLE", "EFFECT_ATTEMPTING"),
                terminal_durable or target == "TERMINAL_DURABLE",
                delivered or target == "DELIVERED",
                acknowledged or target == "ACKNOWLEDGED",
                recovery_locked,
                False,
            )
            ordinary_successors += 1
            if successor not in product_reached:
                product_reached.add(successor)
                product_queue.append(successor)

        for target in recoveries[state]:
            successor_locked = (
                recovery_locked
                or bool(state_by_id[state]["effect_may_have_started"])
                or target in {"UNKNOWN_RECONCILIATION_REQUIRED", "FENCED"}
            )
            successor = (
                target,
                accepted or target == "ACCEPTED_DURABLE",
                attempted,
                terminal_durable or target == "TERMINAL_DURABLE",
                delivered or target == "DELIVERED",
                acknowledged or target == "ACKNOWLEDGED",
                successor_locked,
                False,
            )
            recovery_successors += 1
            if successor not in product_reached:
                product_reached.add(successor)
                product_queue.append(successor)

    effect_boundary = [transition for transition in transitions if transition["effect_boundary"]]
    require(len(effect_boundary) == 1, "there must be exactly one effect-boundary transition")
    require(
        (effect_boundary[0]["from"], effect_boundary[0]["to"])
        == ("ACCEPTED_DURABLE", "EFFECT_ATTEMPTING"),
        "the effect boundary must be ACCEPTED_DURABLE -> EFFECT_ATTEMPTING",
    )
    require(effect_boundary[0]["requires_durable_acceptance"] is True, "effect boundary does not require durable acceptance")

    effect_targets = {"EFFECT_ATTEMPTING", "EFFECT_STARTED_OBSERVED"}
    for transition in transitions:
        if transition["to"] in effect_targets:
            require(
                transition["requires_durable_acceptance"] is True,
                f"{transition['id']} enters an effect state without requiring durable acceptance",
            )
        if transition["from"] in {"UNKNOWN_RECONCILIATION_REQUIRED", "FENCED", "CLOSED"}:
            require(
                transition["to"] not in effect_targets,
                f"{transition['id']} permits a new effect from a fenced/uncertain/closed state",
            )

    for source, target in recovery_edges:
        if state_by_id[source]["effect_may_have_started"]:
            require(
                target not in blocked and not state_by_id[target]["permits_new_effect"],
                f"crash recovery from {source} re-enters effect admission at {target}",
            )

    exhaustive = len(state_ids) * len(state_ids)
    legal = len(edges)
    return {
        "reachable_state_count": len(reached),
        "reachable_product_state_count": len(product_reached),
        "ordinary_product_successor_count": ordinary_successors,
        "recovery_product_successor_count": recovery_successors,
        "legal_recovery_edge_count": len(recovery_edges),
        "exhaustive_ordered_pair_count": exhaustive,
        "legal_ordered_pair_count": legal,
        "illegal_ordered_pair_count": exhaustive - legal,
    }

def run_tlc_model(tlc_jar: Path, model_path: Path, config_path: Path) -> dict[str, Any]:
    try:
        metadata = tlc_jar.lstat()
    except OSError as error:
        fail(f"TLC JAR is unavailable: {error}")
    require(stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode), "TLC JAR must be a non-symlink regular file")
    raw = tlc_jar.read_bytes()
    require(hashlib.sha1(raw).hexdigest() == EXPECTED_TLC_SHA1, "TLC JAR official SHA-1 differs")
    require(hashlib.sha256(raw).hexdigest() == EXPECTED_TLC_SHA256, "TLC JAR SHA-256 differs")
    try:
        completed = subprocess.run(
            [
                "java",
                "-XX:+UseParallelGC",
                "-cp",
                str(tlc_jar.resolve()),
                "tlc2.TLC",
                "-workers",
                "1",
                "-config",
                config_path.name,
                model_path.name,
            ],
            cwd=model_path.parent,
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except (OSError, subprocess.SubprocessError) as error:
        fail(f"TLC execution failed: {error}")
    output = completed.stdout + "\n" + completed.stderr
    require(completed.returncode == 0, f"TLC rejected the effect lifecycle: {output[-4000:]}")
    require("Model checking completed. No error has been found." in output, "TLC did not report a clean terminal result")
    distinct = re.search(r"(\d+) distinct states found", output)
    return {
        "tlc_executed": True,
        "tlc_version": EXPECTED_TLC_VERSION,
        "tlc_distinct_state_count": int(distinct.group(1)) if distinct else None,
    }


def verify_authority(
    data: dict[str, Any],
    *,
    root: Path = ROOT,
    formal_text: str | None = None,
    config_text: str | None = None,
    model_check: bool = True,
    tlc_jar: Path | None = None,
) -> dict[str, Any]:
    exact_keys(data, TOP_KEYS, "effect lifecycle")
    require(data["schema"] == "org.trillionnium.effect-lifecycle.v1", "unsupported lifecycle schema")
    require(data["version"] == "1", "unsupported lifecycle version")
    string(data["program_revision"], "program_revision")
    require(data["status"] == "SOURCE_MODEL_PENDING_TARGET_EVIDENCE", "lifecycle status overclaims source evidence")
    claim = string(data["claim_ceiling"], "claim_ceiling")
    require("L1" in claim and ("NO_" in claim or "NOT_" in claim), "lifecycle claim ceiling must remain L1 source-only")
    require(boolean(data["automatic_redispatch"], "automatic_redispatch") is False, "global automatic redispatch must be false")

    binding_schema = data["binding_schema"]
    require(isinstance(binding_schema, dict), "binding_schema must be an object")
    exact_keys(binding_schema, BINDING_SCHEMA_KEYS, "binding_schema")
    required_fields = string_list(binding_schema["required_identity_fields"], "binding_schema.required_identity_fields")
    require(required_fields == EXPECTED_BINDING_FIELDS, "required lifecycle binding fields drifted")
    nullable = string_list(binding_schema["nullable_when_not_applicable"], "binding_schema.nullable_when_not_applicable", allow_empty=True)
    require(set(nullable) <= set(required_fields), "nullable binding field is not required")
    require(nullable == ["call_id", "job_id", "provider_epoch"], "nullable binding policy drifted")
    require(binding_schema["digest_algorithm"] == "sha256", "effect identity digest must be sha256")
    require(boolean(binding_schema["monotonic_clock_required"], "monotonic_clock_required") is True, "monotonic clock must be required")
    require(binding_schema["identity_conflict"] == "reject_before_effect", "identity conflict must reject before effect")
    require(binding_schema["stale_epoch"] == "fence_before_effect", "stale epoch must fence before effect")

    states_value = data["states"]
    require(isinstance(states_value, list), "states must be an array")
    states: list[dict[str, Any]] = []
    for index, item in enumerate(states_value):
        require(isinstance(item, dict), f"states[{index}] must be an object")
        exact_keys(item, STATE_KEYS, f"states[{index}]")
        state_id = string(item["id"], f"states[{index}].id")
        require(item["phase"] in {"ingress", "admission", "effect", "terminal", "delivery", "uncertainty", "closed"}, f"{state_id} has invalid phase")
        boolean(item["effect_may_have_started"], f"{state_id}.effect_may_have_started")
        boolean(item["durable"], f"{state_id}.durable")
        require(item["outcome"] in {"none", "definitive", "uncertain", "closed"}, f"{state_id} has invalid outcome")
        boolean(item["permits_new_effect"], f"{state_id}.permits_new_effect")
        string(item["meaning"], f"{state_id}.meaning")
        states.append(item)
    state_ids = [state["id"] for state in states]
    require(state_ids == EXPECTED_STATES, f"state order/set drifted: {state_ids}")
    require(sum(bool(state["permits_new_effect"]) for state in states) == 1, "exactly one state may permit a new effect")
    require(next(state for state in states if state["permits_new_effect"])["id"] == "ACCEPTED_DURABLE", "only ACCEPTED_DURABLE may permit a new effect")
    for state in states:
        observed = (
            state["phase"],
            state["effect_may_have_started"],
            state["durable"],
            state["outcome"],
            state["permits_new_effect"],
        )
        require(
            observed == EXPECTED_STATE_SEMANTICS[state["id"]],
            f"{state['id']} state attributes drifted; observed={observed}, expected={EXPECTED_STATE_SEMANTICS[state['id']]}",
        )

    transitions_value = data["transitions"]
    require(isinstance(transitions_value, list), "transitions must be an array")
    transitions: list[dict[str, Any]] = []
    for index, item in enumerate(transitions_value):
        require(isinstance(item, dict), f"transitions[{index}] must be an object")
        exact_keys(item, TRANSITION_KEYS, f"transitions[{index}]")
        transition_id = string(item["id"], f"transitions[{index}].id")
        require(item["from"] in state_ids, f"{transition_id} has unknown source state")
        require(item["to"] in state_ids, f"{transition_id} has unknown target state")
        string(item["trigger"], f"{transition_id}.trigger")
        boolean(item["effect_boundary"], f"{transition_id}.effect_boundary")
        boolean(item["requires_durable_acceptance"], f"{transition_id}.requires_durable_acceptance")
        require(boolean(item["preserves_effect_identity"], f"{transition_id}.preserves_effect_identity") is True, f"{transition_id} does not preserve effect identity")
        require(boolean(item["automatic_redispatch"], f"{transition_id}.automatic_redispatch") is False, f"{transition_id} enables automatic redispatch")
        bindings = string_list(item["bindings"], f"{transition_id}.bindings")
        require(bindings == required_fields, f"{transition_id} binding set/order is incomplete")
        require(isinstance(item["notes"], str) and "\x00" not in item["notes"], f"{transition_id}.notes must be text")
        transitions.append(item)
    transition_ids = [transition["id"] for transition in transitions]
    require(transition_ids == EXPECTED_TRANSITION_IDS, f"transition IDs drifted: {transition_ids}")

    graph_report: dict[str, int]

    invariants_value = data["invariants"]
    require(isinstance(invariants_value, list), "invariants must be an array")
    invariant_ids: list[str] = []
    checkers: list[str] = []
    for index, item in enumerate(invariants_value):
        require(isinstance(item, dict), f"invariants[{index}] must be an object")
        exact_keys(item, INVARIANT_KEYS, f"invariants[{index}]")
        invariant_ids.append(string(item["id"], f"invariants[{index}].id"))
        string(item["statement"], f"invariants[{index}].statement")
        checkers.append(string(item["checker"], f"invariants[{index}].checker"))
    require(invariant_ids == [f"INV-{index:02d}" for index in range(1, 11)], "invariant IDs drifted")
    require(checkers == EXPECTED_CHECKERS, "required lifecycle checker set/order drifted")

    duplicate = data["duplicate_policy"]
    require(isinstance(duplicate, dict), "duplicate_policy must be an object")
    exact_keys(duplicate, DUPLICATE_KEYS, "duplicate_policy")
    duplicate_identity = string_list(duplicate["identity_fields"], "duplicate_policy.identity_fields")
    require(duplicate_identity == EXPECTED_BINDING_FIELDS[:11], "duplicate effect identity fields drifted")
    require(duplicate["exact_identity_equal_bytes"] == "ATTACH_OR_REPLAY_KNOWN_STATE", "equal-byte duplicate policy must attach/replay")
    require(duplicate["exact_identity_changed_bytes"] == "CONFLICT_BEFORE_EFFECT", "changed-byte duplicate must conflict before effect")
    require(duplicate["unknown_effect_state"] == "RECONCILE_WITHOUT_AUTOMATIC_REDISPATCH", "unknown duplicate state must reconcile without redispatch")
    require(boolean(duplicate["implicit_defaults_change_identity"], "duplicate_policy.implicit_defaults_change_identity") is True, "implicit defaults must change effect identity")
    require(boolean(duplicate["field_aliases_change_identity"], "duplicate_policy.field_aliases_change_identity") is True, "field aliases must change effect identity")
    require(boolean(duplicate["automatic_redispatch"], "duplicate_policy.automatic_redispatch") is False, "duplicate policy enables redispatch")

    race = data["race_policy"]
    require(isinstance(race, dict), "race_policy must be an object")
    exact_keys(race, RACE_KEYS, "race_policy")
    require(race["scope"] == "one_ordering_key", "cancel/terminal race scope must be one ordering key")
    require(race["linearization_field"] == "durable_sequence", "cancel/terminal race must linearize on durable_sequence")
    require(race["clock_field"] == "monotonic_timestamp_ns", "race observation clock must be monotonic")
    require(race["cancel_before_effect"] == "TERMINAL_OBSERVED", "cancel-before-effect policy drifted")
    require("UNKNOWN_RECONCILIATION_REQUIRED" in race["effect_attempt_before_cancel"], "post-attempt cancel must retain uncertainty or terminal proof")
    require(race["terminal_before_cancel"] == "PRESERVE_TERMINAL", "terminal must win after linearization")
    require("DURABLE_SEQUENCE" in race["equal_time_tie_break"], "race tie-break must use durable sequence")
    require(race["cleanup_error_role"] == "SECONDARY_OBSERVATION_NEVER_PRIMARY_OUTCOME", "cleanup may not overwrite the primary outcome")
    require(race["stale_writer"] == "FENCED", "stale writer must be fenced")
    require(boolean(race["automatic_redispatch"], "race_policy.automatic_redispatch") is False, "race policy enables redispatch")

    cuts_value = data["crash_cuts"]
    require(isinstance(cuts_value, list), "crash_cuts must be an array")
    cuts: list[dict[str, Any]] = []
    for index, item in enumerate(cuts_value):
        require(isinstance(item, dict), f"crash_cuts[{index}] must be an object")
        exact_keys(item, CUT_KEYS, f"crash_cuts[{index}]")
        cut_id = string(item["id"], f"crash_cuts[{index}].id")
        require(item["after"] in state_ids, f"{cut_id} references unknown state")
        recoveries = string_list(item["legal_recovery"], f"{cut_id}.legal_recovery")
        require(set(recoveries) <= set(state_ids), f"{cut_id} has unknown recovery state")
        forbidden = string_list(item["forbidden_inference"], f"{cut_id}.forbidden_inference")
        require(boolean(item["requires_same_effect_identity"], f"{cut_id}.requires_same_effect_identity") is True, f"{cut_id} permits identity drift")
        require(boolean(item["automatic_redispatch"], f"{cut_id}.automatic_redispatch") is False, f"{cut_id} enables automatic redispatch")
        if item["after"] in {"ACCEPTED_DURABLE", "EFFECT_ATTEMPTING", "EFFECT_STARTED_OBSERVED", "UNKNOWN_RECONCILIATION_REQUIRED", "FENCED"}:
            joined = " ".join(forbidden).lower()
            require("safe" in joined or "not_started" in joined, f"{cut_id} does not forbid false safe/not-started inference")
        expected_after, expected_recoveries = EXPECTED_CRASH_RECOVERIES[cut_id]
        require(item["after"] == expected_after, f"{cut_id} crash state drifted")
        require(tuple(recoveries) == expected_recoveries, f"{cut_id} legal recovery relation drifted")
        cuts.append(item)
    require([cut["id"] for cut in cuts] == EXPECTED_CUT_IDS, "crash-cut IDs drifted")
    require({cut["after"] for cut in cuts} >= {"ACCEPTED_DURABLE", "EFFECT_ATTEMPTING", "EFFECT_STARTED_OBSERVED", "TERMINAL_OBSERVED", "TERMINAL_DURABLE", "DELIVERY_PENDING", "DELIVERED", "ACKNOWLEDGED", "UNKNOWN_RECONCILIATION_REQUIRED", "FENCED"}, "crash-cut coverage is incomplete")

    graph_report = _verify_state_graph(states, transitions, cuts) if model_check else {
        "reachable_state_count": 0,
        "reachable_product_state_count": 0,
        "ordinary_product_successor_count": 0,
        "recovery_product_successor_count": 0,
        "legal_recovery_edge_count": sum(len(cut["legal_recovery"]) for cut in cuts),
        "exhaustive_ordered_pair_count": len(states) ** 2,
        "legal_ordered_pair_count": len(transitions),
        "illegal_ordered_pair_count": len(states) ** 2 - len(transitions),
    }

    module_catalog = json.loads((root / "docs/machine/module-catalog.v1.json").read_text(encoding="utf-8"))
    known_modules = {module["id"] for module in module_catalog["modules"]}
    bindings_value = data["implementation_bindings"]
    require(isinstance(bindings_value, list), "implementation_bindings must be an array")
    covered: set[str] = set()
    binding_ids: list[str] = []
    for index, item in enumerate(bindings_value):
        require(isinstance(item, dict), f"implementation_bindings[{index}] must be an object")
        exact_keys(item, IMPLEMENTATION_KEYS, f"implementation_bindings[{index}]")
        binding_id = string(item["id"], f"implementation_bindings[{index}].id")
        binding_ids.append(binding_id)
        modules = string_list(item["modules"], f"{binding_id}.modules")
        require(set(modules) <= known_modules, f"{binding_id} references unknown modules")
        source = repository_relative_file(root, item["source_path"], f"{binding_id}.source_path")
        symbol = string(item["symbol"], f"{binding_id}.symbol")
        require(symbol in source.read_text(encoding="utf-8"), f"{binding_id} symbol not found in {item['source_path']}")
        mapped = string_list(item["transitions"], f"{binding_id}.transitions")
        require(set(mapped) <= set(transition_ids), f"{binding_id} references unknown transitions")
        covered.update(mapped)
        tests = string_list(item["tests"], f"{binding_id}.tests")
        for test_index, test_path in enumerate(tests):
            repository_relative_file(root, test_path, f"{binding_id}.tests[{test_index}]")
    require(len(binding_ids) == len(set(binding_ids)), "duplicate implementation binding ID")
    require(covered == set(transition_ids), f"implementation mapping is not total; missing={sorted(set(transition_ids) - covered)}")

    verification = data["verification"]
    require(isinstance(verification, dict), "verification must be an object")
    exact_keys(verification, VERIFICATION_KEYS, "verification")
    model_path = repository_relative_file(root, verification["formal_model"], "verification.formal_model")
    config_path = repository_relative_file(root, verification["formal_config"], "verification.formal_config")
    checker_path = repository_relative_file(root, verification["model_checker"], "verification.model_checker")
    test_path = repository_relative_file(root, verification["test_suite"], "verification.test_suite")
    require(checker_path.resolve() == Path(__file__).resolve(), "verification.model_checker does not bind this executable")
    require(test_path.name == "test_effect_lifecycle.py", "verification.test_suite does not bind lifecycle tests")
    require(positive_int(verification["expected_state_count"], "verification.expected_state_count") == len(states), "expected state count drifted")
    require(positive_int(verification["expected_transition_count"], "verification.expected_transition_count") == len(transitions), "expected transition count drifted")
    for field in ("exhaustive_ordered_pair_count", "legal_ordered_pair_count", "illegal_ordered_pair_count"):
        require(positive_int(verification[field], f"verification.{field}") == graph_report[field], f"verification.{field} drifted")
    required_classes = string_list(verification["required_test_classes"], "verification.required_test_classes")
    require(required_classes == [
        "legal_and_illegal_transition_exhaustion",
        "duplicate_and_conflict_mutation",
        "cancel_terminal_linearization",
        "crash_cut_recovery",
        "formal_projection_equivalence",
        "implementation_binding_totality",
        "source_path_custody",
    ], "required lifecycle test classes drifted")
    require(verification["tlc_version"] == EXPECTED_TLC_VERSION, "TLC version drifted")
    require(verification["tlc_url"] == EXPECTED_TLC_URL, "TLC download URL drifted")
    require(verification["tlc_sha1"] == EXPECTED_TLC_SHA1, "TLC official SHA-1 drifted")
    require(verification["tlc_sha256"] == EXPECTED_TLC_SHA256, "TLC content SHA-256 drifted")
    verification_claim = string(verification["claim_ceiling"], "verification.claim_ceiling")
    require("L1" in verification_claim and "NOT_INSTALLED_TARGET" in verification_claim, "verification claim ceiling overstates evidence")

    model_source = formal_text if formal_text is not None else model_path.read_text(encoding="utf-8")
    config_source = config_text if config_text is not None else config_path.read_text(encoding="utf-8")
    tla_states, tla_edges, tla_recovery_edges = parse_tla_projection(model_source)
    json_edges = {(transition["from"], transition["to"]) for transition in transitions}
    json_recovery_edges = {(cut["after"], target) for cut in cuts for target in cut["legal_recovery"]}
    require(tla_states == set(state_ids), f"formal state projection drift; missing={sorted(set(state_ids)-tla_states)}, extra={sorted(tla_states-set(state_ids))}")
    require(tla_edges == json_edges, f"formal edge projection drift; missing={sorted(json_edges-tla_edges)}, extra={sorted(tla_edges-json_edges)}")
    require(tla_recovery_edges == json_recovery_edges, f"formal recovery projection drift; missing={sorted(json_recovery_edges-tla_recovery_edges)}, extra={sorted(tla_recovery_edges-json_recovery_edges)}")
    canonical_model = render_tla_model(states, transitions, cuts)
    require(model_source == canonical_model, "formal model differs from the canonical executable projection")
    cfg_invariants = set(re.findall(r"^INVARIANT\s+([A-Za-z][A-Za-z0-9_]*)\s*$", config_source, re.MULTILINE))
    require(cfg_invariants == EXPECTED_CFG_INVARIANTS, f"formal config invariants drifted: {sorted(cfg_invariants)}")
    canonical_config = render_tla_config()
    require(
        config_source == canonical_config,
        "formal config differs from the canonical executable configuration",
    )
    for definition in EXPECTED_CFG_INVARIANTS | {"Spec", "Init", "Next", "OrdinaryNext", "RecoveryNext"}:
        require(re.search(rf"^{re.escape(definition)}\s*==", model_source, re.MULTILINE) is not None, f"formal model lacks definition {definition}")

    tlc_report: dict[str, Any] = {"tlc_executed": False, "tlc_version": EXPECTED_TLC_VERSION, "tlc_distinct_state_count": None}
    if tlc_jar is not None:
        require(formal_text is None and config_text is None, "TLC execution requires checked-in formal files")
        tlc_report = run_tlc_model(tlc_jar, model_path, config_path)

    report = {
        "schema": data["schema"],
        "version": data["version"],
        "program_revision": data["program_revision"],
        "status": "PASS",
        "claim_ceiling": verification_claim,
        "automatic_redispatch": False,
        "state_count": len(states),
        "transition_count": len(transitions),
        "crash_cut_count": len(cuts),
        "implementation_binding_count": len(bindings_value),
        "implementation_transition_coverage": len(covered),
        "formal_state_count": len(tla_states),
        "formal_edge_count": len(tla_edges),
        "formal_recovery_edge_count": len(tla_recovery_edges),
        "formal_model_sha256": hashlib.sha256(model_source.encode("utf-8")).hexdigest(),
        "formal_config_sha256": hashlib.sha256(config_source.encode("utf-8")).hexdigest(),
        **tlc_report,
        **graph_report,
        "installed_target_evidence": False,
        "device_evidence": False,
        "destructive_fault_evidence": False,
        "signing_or_release_evidence": False,
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authority", type=Path, default=AUTHORITY)
    parser.add_argument("--model-check", action="store_true")
    parser.add_argument("--tlc-jar", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        report = verify_authority(
            load_authority(args.authority),
            root=ROOT,
            model_check=args.model_check,
            tlc_jar=args.tlc_jar,
        )
    except VerificationError as error:
        if args.json:
            print(json.dumps({"status": "FAIL", "error": str(error)}, sort_keys=True))
        else:
            print(f"effect lifecycle verification failed: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print("effect lifecycle verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
