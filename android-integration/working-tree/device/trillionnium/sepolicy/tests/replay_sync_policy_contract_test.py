#!/usr/bin/env python3
"""Static contract for the inert, adapter-separated replay-sync policy."""

from __future__ import annotations

import os
from pathlib import Path
import re
import sys
import unittest


HERE = Path(__file__).resolve().parent
RELATIVE_FILES = {
    "Android.bp": "Android.bp",
    "README.md": "README.md",
    "file.te": "common/private/file.te",
    "file_contexts": "common/private/file_contexts",
    "port_contexts": "common/private/port_contexts",
    "system_server.te": "common/private/system_server.te",
    "trillionnium_agent_accessibility.te": (
        "common/private/trillionnium_agent_accessibility.te"
    ),
    "trillionnium_agent_direct_tools.te": (
        "common/private/trillionnium_agent_direct_tools.te"
    ),
    "trillionnium_agent_replay_sync.te": (
        "common/private/trillionnium_agent_replay_sync.te"
    ),
    "trillionnium_agentd.te": "common/private/trillionnium_agentd.te",
    "trillionnium_codex_agent.te": (
        "common/private/trillionnium_codex_agent.te"
    ),
    "users": "common/private/users",
}

PUBLICATION_DOMAIN = "trillionnium_agent_system_api_replay_sync"
SYSTEM_DOMAIN = "trillionnium_agent_system_api_operation_replay_sync"
ACCESSIBILITY_DOMAIN = (
    "trillionnium_agent_accessibility_operation_replay_sync"
)
CODEX_AGENT_DOMAIN = "trillionnium_codex_agent"
PUBLICATION_EXEC = f"{PUBLICATION_DOMAIN}_exec"
SYSTEM_EXEC = f"{SYSTEM_DOMAIN}_exec"
ACCESSIBILITY_EXEC = f"{ACCESSIBILITY_DOMAIN}_exec"
HELPER_DOMAINS = {
    PUBLICATION_DOMAIN,
    SYSTEM_DOMAIN,
    ACCESSIBILITY_DOMAIN,
}
GENERATED_POLICY_ENV = {
    "plat_sepolicy.cil": "TRILLIONNIUM_PLAT_SEPOLICY_CIL",
    "system_ext_sepolicy.cil": "TRILLIONNIUM_SYSTEM_EXT_SEPOLICY_CIL",
}


def source_root() -> Path | None:
    candidate = HERE.parent
    if (candidate / RELATIVE_FILES["file_contexts"]).is_file():
        return candidate.resolve()
    return None


def contract_file(leaf: str) -> Path:
    root = source_root()
    if root is not None:
        return root / RELATIVE_FILES[leaf]

    # Soong installs only this module's closed data set beside its launcher.
    program_dir = Path(sys.argv[0]).resolve().parent
    matches = sorted(
        path
        for path in program_dir.rglob(leaf)
        if path.is_file() and not path.is_symlink()
    )
    if len(matches) != 1:
        raise AssertionError(
            f"expected exactly one packaged replay-sync input {leaf}: {matches}"
        )
    return matches[0]


def read(leaf: str) -> str:
    return contract_file(leaf).read_text(encoding="utf-8")


def active_policy_text_files() -> list[Path]:
    root = source_root()
    search_root = root if root is not None else Path(sys.argv[0]).resolve().parent
    files = []
    for path in search_root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".cil"}:
            continue
        try:
            path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        files.append(path)
    return sorted(files)


def exact_existing_file(candidates: list[Path], description: str) -> Path:
    existing = {
        candidate.resolve()
        for candidate in candidates
        if candidate.is_file() and not candidate.is_symlink()
    }
    if len(existing) != 1:
        raise AssertionError(f"expected one {description}: {sorted(existing)}")
    return existing.pop()


def generated_policy_file(leaf: str) -> Path:
    configured = os.environ.get(GENERATED_POLICY_ENV[leaf])
    if configured:
        return exact_existing_file(
            [Path(configured)], f"configured generated {leaf}"
        )

    program_dir = Path(sys.argv[0]).resolve().parent
    return exact_existing_file(
        list(program_dir.rglob(leaf)), f"packaged generated {leaf}"
    )


def statements(kind: str, policy: str) -> list[str]:
    return [
        re.sub(r"\s+", " ", match.group(0)).strip()
        for match in re.finditer(
            rf"(?ms)^\s*{re.escape(kind)}\s+.*?;", policy
        )
    ]


class ReplaySyncPolicyContractTest(unittest.TestCase):
    def test_active_policy_tree_is_codex_only(self) -> None:
        retired_name = "open" + "claw"
        retired_markers = (
            retired_name,
            "trillionnium_" + retired_name,
            "59" + "02",
            "187" + "92",
        )
        for path in active_policy_text_files():
            content = path.read_text(encoding="utf-8").casefold()
            for marker in retired_markers:
                self.assertNotIn(marker, content, f"{marker} remains in {path}")

        file_types = read("file.te")
        contexts = read("file_contexts")
        ports = read("port_contexts")
        daemon = re.sub(r"\s+", " ", read("trillionnium_agentd.te"))
        codex = read("trillionnium_codex_agent.te")
        blueprint = read("Android.bp")

        self.assertEqual(
            codex.count("type trillionnium_codex_agent, domain, coredomain;"),
            1,
        )
        self.assertEqual(
            file_types.count(
                "type trillionnium_codex_agent_exec, exec_type, file_type, "
                "system_file_type;"
            ),
            1,
        )
        self.assertIn(
            "trillionnium-codex-agent-0\\.144\\.1 "
            "u:object_r:trillionnium_codex_agent_exec:s0",
            contexts,
        )
        self.assertEqual(
            ports.count(
                "portcon tcp 18791 "
                "u:object_r:trillionnium_codex_proxy_port:s0"
            ),
            1,
        )
        self.assertIn(
            "domain_auto_trans(trillionnium_agentd, "
            "trillionnium_codex_agent_exec, trillionnium_codex_agent)",
            daemon,
        )
        self.assertIn(
            '"common/private/trillionnium_codex_agent.te"', blueprint
        )

    def test_p0_userdebug_tool_call_transport_is_narrow_and_allocator_private(self) -> None:
        file_types = read("file.te")
        contexts = read("file_contexts")
        direct = read("trillionnium_agent_direct_tools.te")
        daemon = read("trillionnium_agentd.te")

        allocator_type = "trillionnium_direct_tool_call_allocator_file"
        self.assertEqual(
            file_types.count(
                f"type {allocator_type}, file_type, data_file_type, "
                "core_data_file_type;"
            ),
            1,
        )
        self.assertIn(
            "/data/trillionnium/agent-tools/"
            "direct-operation-tool-call-allocator-v1(/.*)? "
            f"u:object_r:{allocator_type}:s0",
            contexts,
        )
        self.assertIn(
            f"allow trillionnium_agentd {allocator_type}:dir rw_dir_perms;",
            daemon,
        )
        self.assertIn(
            f"allow trillionnium_agentd {allocator_type}:file create_file_perms;",
            daemon,
        )
        self.assertIn(
            "allow trillionnium_agent_system_api_tool "
            "trillionnium_agentd:unix_stream_socket",
            direct,
        )
        self.assertNotIn(
            "allow trillionnium_agent_accessibility_tool "
            "trillionnium_agentd:unix_stream_socket",
            direct,
        )
        allocator_denies = [
            item
            for item in statements("neverallow", direct)
            if allocator_type in item
        ]
        self.assertEqual(len(allocator_denies), 1)
        for domain in (
            "trillionnium_codex_agent",
            "trillionnium_agent_system_api_tool",
            "trillionnium_agent_accessibility_tool",
            "trillionnium_agent_adb_tool",
            "trillionnium_aiauthority",
            "trillionnium_aishell",
        ):
            self.assertIn(domain, allocator_denies[0])

    def test_domains_exec_types_and_future_paths_are_distinct(self) -> None:
        file_types = read("file.te")
        contexts = read("file_contexts")
        policy = read("trillionnium_agent_replay_sync.te")

        for domain in (PUBLICATION_DOMAIN, SYSTEM_DOMAIN, ACCESSIBILITY_DOMAIN):
            self.assertEqual(
                policy.count(f"type {domain}, domain, coredomain;"), 1
            )
        for exec_type in (PUBLICATION_EXEC, SYSTEM_EXEC, ACCESSIBILITY_EXEC):
            self.assertEqual(
                file_types.count(
                    f"type {exec_type}, exec_type, file_type, "
                    "system_file_type;"
                ),
                1,
            )

        expected_paths = {
            "/(system_ext|system/system_ext)/bin/"
            "trillionnium-system-api-replay-sync "
            f"u:object_r:{PUBLICATION_EXEC}:s0",
            "/(system_ext|system/system_ext)/bin/"
            "trillionnium-system-api-operation-replay-sync "
            f"u:object_r:{SYSTEM_EXEC}:s0",
            "/(system_ext|system/system_ext)/bin/"
            "trillionnium-accessibility-operation-replay-sync "
            f"u:object_r:{ACCESSIBILITY_EXEC}:s0",
        }
        for path in expected_paths:
            self.assertEqual(contexts.count(path), 1)
        self.assertEqual(
            len({PUBLICATION_DOMAIN, SYSTEM_DOMAIN, ACCESSIBILITY_DOMAIN}), 3
        )
        self.assertEqual(
            len({PUBLICATION_EXEC, SYSTEM_EXEC, ACCESSIBILITY_EXEC}), 3
        )
        self.assertNotIn(
            "trillionnium-accessibility-replay-sync ", contexts
        )

    def test_agentd_is_the_only_transition_and_execute_source(self) -> None:
        policy = read("trillionnium_agent_replay_sync.te")
        transitions = set(
            re.findall(
                r"domain_auto_trans\(\s*([a-zA-Z0-9_]+)\s*,\s*"
                r"([a-zA-Z0-9_]+)\s*,\s*([a-zA-Z0-9_]+)\s*\)",
                policy,
            )
        )
        self.assertEqual(
            transitions,
            {
                (
                    "trillionnium_agentd",
                    PUBLICATION_EXEC,
                    PUBLICATION_DOMAIN,
                ),
                ("trillionnium_agentd", SYSTEM_EXEC, SYSTEM_DOMAIN),
                (
                    "trillionnium_agentd",
                    ACCESSIBILITY_EXEC,
                    ACCESSIBILITY_DOMAIN,
                ),
            },
        )
        self.assertNotIn("domain_auto_trans(init", policy)
        self.assertNotIn("init_daemon_domain(", policy)
        self.assertNotIn("app_domain(", policy)
        self.assertNotIn("net_domain(", policy)

        for domain, exec_type in (
            (PUBLICATION_DOMAIN, PUBLICATION_EXEC),
            (SYSTEM_DOMAIN, SYSTEM_EXEC),
            (ACCESSIBILITY_DOMAIN, ACCESSIBILITY_EXEC),
        ):
            self.assertRegex(
                policy,
                rf"neverallow\s+\{{\s*domain\s+-trillionnium_agentd\s*\}}\s+"
                rf"{domain}:process\s+transition;",
            )
            self.assertRegex(
                policy,
                rf"neverallow\s+\{{\s*domain\s+-trillionnium_agentd\s+"
                rf"-{domain}\s+userdebug_or_eng\(`-overlay_remounter'\)\s*"
                rf"\}}\s+{exec_type}:file\s+execute;",
            )
            self.assertRegex(
                policy,
                rf"neverallow\s+\{{\s*domain\s+-{domain}\s*\}}\s+"
                rf"{exec_type}:file\s+entrypoint;",
            )
        self.assertRegex(
            policy,
            rf"neverallow\s+\{{\s*domain\s+"
            rf"userdebug_or_eng\(`-overlay_remounter'\)\s*\}}\s+"
            rf"\{{\s*{PUBLICATION_EXEC}\s+{SYSTEM_EXEC}\s+"
            rf"{ACCESSIBILITY_EXEC}\s*\}}:file\s+execute_no_trans;",
        )
        domains = (PUBLICATION_DOMAIN, SYSTEM_DOMAIN, ACCESSIBILITY_DOMAIN)
        for source in domains:
            for target in domains:
                if source != target:
                    self.assertIn(
                        f"neverallow {source} {target}:process *;", policy
                    )

    def test_measured_launcher_process_and_procfs_edges_are_exact(self) -> None:
        policy = read("trillionnium_agent_replay_sync.te")
        agentd = read("trillionnium_agentd.te")
        allows = statements("allow", policy)
        agentd_allows = statements("allow", agentd)

        self.assertIn(
            "allow trillionnium_agentd { "
            f"{SYSTEM_DOMAIN} {ACCESSIBILITY_DOMAIN} "
            "}:process { ptrace sigkill };",
            allows,
        )
        self.assertRegex(
            policy,
            rf"neverallow\s+trillionnium_agentd\s+{PUBLICATION_DOMAIN}:"
            r"process\s+~\{\s*transition\s+siginh\s+rlimitinh\s*\};",
        )
        self.assertRegex(
            policy,
            rf"neverallow\s+trillionnium_agentd\s+\{{\s*"
            rf"{SYSTEM_DOMAIN}\s+{ACCESSIBILITY_DOMAIN}\s*\}}:process\s+"
            r"~\{\s*transition\s+siginh\s+rlimitinh\s+ptrace\s+"
            r"sigkill\s*\};",
        )
        self.assertRegex(
            policy,
            rf"neverallow\s+\{{\s*{PUBLICATION_DOMAIN}\s+{SYSTEM_DOMAIN}\s+"
            rf"{ACCESSIBILITY_DOMAIN}\s*\}}\s+domain:process\s+ptrace;",
        )
        self.assertFalse(
            any(
                item.startswith(
                    f"allow trillionnium_agentd {PUBLICATION_DOMAIN}:process"
                )
                and ("ptrace" in item or "sigkill" in item)
                for item in allows
            ),
            allows,
        )

        self.assertIn(
            "allow trillionnium_agentd { "
            f"{SYSTEM_DOMAIN} {ACCESSIBILITY_DOMAIN} "
            "}:lnk_file { getattr read };",
            agentd_allows,
        )
        self.assertIn(
            f"neverallow trillionnium_agentd {PUBLICATION_DOMAIN}:"
            "lnk_file *;",
            re.sub(r"\s+", " ", agentd),
        )
        self.assertRegex(
            agentd,
            rf"neverallow\s+trillionnium_agentd\s+\{{\s*{SYSTEM_DOMAIN}\s+"
            rf"{ACCESSIBILITY_DOMAIN}\s*\}}:lnk_file\s+"
            r"~\{\s*getattr\s+read\s*\};",
        )
        self.assertRegex(
            agentd,
            rf"neverallow\s+trillionnium_agentd\s+\{{\s*domain\s+"
            rf"-trillionnium_agentd\s+-{SYSTEM_DOMAIN}\s+"
            rf"-{ACCESSIBILITY_DOMAIN}\s*\}}:process\s+ptrace;",
        )
        self.assertNotIn("allow trillionnium_agentd domain:lnk_file", agentd)

    def test_nnp_and_nosuid_transition_edges_are_exact(self) -> None:
        policy = read("trillionnium_agent_replay_sync.te")
        process2_allows = {
            item
            for item in statements("allow", policy)
            if ":process2" in item
        }
        self.assertEqual(
            process2_allows,
            {
                "allow trillionnium_agentd { "
                f"{SYSTEM_DOMAIN} {ACCESSIBILITY_DOMAIN} "
                "}:process2 { nnp_transition nosuid_transition };"
            },
        )
        normalized = re.sub(r"\s+", " ", policy)
        self.assertIn(
            f"neverallow trillionnium_agentd {PUBLICATION_DOMAIN}:"
            "process2 *;",
            normalized,
        )
        self.assertRegex(
            policy,
            rf"neverallow\s+\{{\s*domain\s+-trillionnium_agentd\s*\}}\s+"
            rf"\{{\s*{PUBLICATION_DOMAIN}\s+{SYSTEM_DOMAIN}\s+"
            rf"{ACCESSIBILITY_DOMAIN}\s*\}}:process2\s+\*;",
        )
        self.assertRegex(
            policy,
            rf"neverallow\s+trillionnium_agentd\s+\{{\s*domain\s+"
            rf"-{PUBLICATION_DOMAIN}\s+-{SYSTEM_DOMAIN}\s+"
            rf"-{ACCESSIBILITY_DOMAIN}\s+-{CODEX_AGENT_DOMAIN}\s+"
            rf"\}}:process2\s+\*;",
        )
        self.assertRegex(
            policy,
            rf"neverallow\s+\{{\s*{PUBLICATION_DOMAIN}\s+{SYSTEM_DOMAIN}\s+"
            rf"{ACCESSIBILITY_DOMAIN}\s*\}}\s+domain:process2\s+\*;",
        )

        plat_cil = generated_policy_file("plat_sepolicy.cil").read_text(
            encoding="utf-8"
        )
        self.assertEqual(plat_cil.count("(policycap nnp_nosuid_transition)"), 1)

        system_ext_cil = generated_policy_file(
            "system_ext_sepolicy.cil"
        ).read_text(encoding="utf-8")
        compiled_process2 = {
            (source, target, frozenset(perms.split()))
            for source, target, perms in re.findall(
                r"\(allow\s+(\S+)\s+(\S+)\s+\(process2\s+\(([^)]*)\)\)\)",
                system_ext_cil,
            )
            if source == "trillionnium_agentd"
            or source in HELPER_DOMAINS
            or target in HELPER_DOMAINS
        }
        self.assertEqual(
            compiled_process2,
            {
                (
                    "trillionnium_agentd",
                    SYSTEM_DOMAIN,
                    frozenset({"nnp_transition", "nosuid_transition"}),
                ),
                (
                    "trillionnium_agentd",
                    ACCESSIBILITY_DOMAIN,
                    frozenset({"nnp_transition", "nosuid_transition"}),
                ),
                (
                    "trillionnium_agentd",
                    CODEX_AGENT_DOMAIN,
                    frozenset({"nnp_transition", "nosuid_transition"}),
                ),
            },
        )

    def test_reply_fd_is_only_the_inherited_daemon_pipe(self) -> None:
        policy = read("trillionnium_agent_replay_sync.te")
        allows = statements("allow", policy)
        helper_allows = [
            item
            for item in allows
            if SYSTEM_DOMAIN in item or ACCESSIBILITY_DOMAIN in item
        ]
        self.assertIn(
            "allow { "
            f"{PUBLICATION_DOMAIN} {SYSTEM_DOMAIN} {ACCESSIBILITY_DOMAIN} "
            "} trillionnium_agentd:fd use;",
            helper_allows,
        )
        self.assertIn(
            "allow { "
            f"{PUBLICATION_DOMAIN} {SYSTEM_DOMAIN} {ACCESSIBILITY_DOMAIN} "
            "} trillionnium_agentd:fifo_file { getattr read write };",
            helper_allows,
        )
        self.assertFalse(
            any(":fd use" in item and "trillionnium_agentd:fd" not in item
                for item in helper_allows),
            helper_allows,
        )
        self.assertFalse(
            any(":sock_file" in item for item in helper_allows), helper_allows
        )

    def test_positive_storage_edges_are_adapter_local(self) -> None:
        policy = read("trillionnium_agent_replay_sync.te")
        allows = statements("allow", policy)
        system_allows = [item for item in allows if SYSTEM_DOMAIN in item]
        accessibility_allows = [
            item for item in allows if ACCESSIBILITY_DOMAIN in item
        ]
        publication_allows = [
            item for item in allows if PUBLICATION_DOMAIN in item
        ]

        for suffix in ("tool_state_file", "tool_inbox_file"):
            self.assertTrue(
                any(
                    f"trillionnium_codex_system_api_{suffix}" in item
                    for item in system_allows
                )
            )
            self.assertTrue(
                any(
                    f"trillionnium_codex_accessibility_{suffix}" in item
                    for item in accessibility_allows
                )
            )

        self.assertFalse(
            any("accessibility_tool_" in item for item in system_allows),
            system_allows,
        )
        self.assertFalse(
            any("system_api_tool_" in item for item in accessibility_allows),
            accessibility_allows,
        )
        self.assertFalse(
            any("adb_tool_state_file" in item for item in allows), allows
        )
        self.assertFalse(
            any(
                "tool_state_file" in item or "tool_inbox_file" in item
                for item in publication_allows
            ),
            publication_allows,
        )
        publication_custody_denials = [
            item
            for item in statements("neverallow", policy)
            if item.startswith(f"neverallow {PUBLICATION_DOMAIN} {{")
            and "tool_state_file" in item
            and "tool_inbox_file" in item
        ]
        self.assertEqual(len(publication_custody_denials), 1)

        for forbidden in (
            "trillionnium_rootlinux_receipt_file",
            "trillionnium_agent_egress_evidence_file",
            "trillionnium_system_api_replay_file",
            "trillionnium_agentd_state_file",
            "trillionnium_codex_data_file",
        ):
            self.assertFalse(
                any(forbidden in item for item in allows),
                f"positive helper allow reaches {forbidden}: {allows}",
            )

        direct = read("trillionnium_agent_direct_tools.te")
        self.assertIsNotNone(
            re.search(
                r"neverallow\s+trillionnium_agentd\s+\{.*?"
                r"trillionnium_codex_system_api_tool_state_file.*?"
                r"trillionnium_codex_accessibility_tool_state_file.*?"
                r"\}:\{\s*dir\s+file\s+lnk_file\s+sock_file\s*\}\s+\*;",
                direct,
                flags=re.DOTALL,
            )
        )

    def test_only_matching_backend_process_has_connectto(self) -> None:
        policy = read("trillionnium_agent_replay_sync.te")
        endpoint_allows = {
            item
            for item in statements("allow", policy)
            if "unix_stream_socket" in item
        }
        self.assertEqual(
            endpoint_allows,
            {
                f"allow {PUBLICATION_DOMAIN} "
                "system_server:unix_stream_socket connectto;",
                f"allow {SYSTEM_DOMAIN} system_server:unix_stream_socket "
                "connectto;",
                f"allow {ACCESSIBILITY_DOMAIN} "
                "trillionnium_agent_accessibility:unix_stream_socket "
                "connectto;",
            },
        )
        self.assertNotRegex(
            policy,
            rf"allow\s+(system_server|trillionnium_agent_accessibility)\s+"
            rf"({PUBLICATION_DOMAIN}|{SYSTEM_DOMAIN}|{ACCESSIBILITY_DOMAIN}):"
            r"(unix_stream_socket|fd)",
        )
        self.assertIn(
            f"neverallow {PUBLICATION_DOMAIN} "
            "trillionnium_agent_accessibility:"
            "unix_stream_socket connectto;",
            policy,
        )
        self.assertIn(
            f"neverallow {SYSTEM_DOMAIN} trillionnium_agent_accessibility:"
            "unix_stream_socket connectto;",
            policy,
        )
        self.assertIn(
            f"neverallow {ACCESSIBILITY_DOMAIN} system_server:"
            "unix_stream_socket connectto;",
            policy,
        )

        system_server = read("system_server.te")
        accessibility = read("trillionnium_agent_accessibility.te")
        self.assertIn(ACCESSIBILITY_DOMAIN, system_server)
        self.assertIn(
            "allow trillionnium_agent_accessibility activity_service:service_manager find;",
            accessibility,
        )
        self.assertNotIn(
            "allow trillionnium_agent_accessibility activity_service:service_manager {",
            accessibility,
        )
        for domain in (PUBLICATION_DOMAIN, SYSTEM_DOMAIN):
            self.assertIn(domain, accessibility)
        replay_file_denies = [
            item
            for item in statements("neverallow", system_server)
            if "trillionnium_system_api_replay_file" in item
        ]
        self.assertEqual(len(replay_file_denies), 2)
        for domain in (PUBLICATION_DOMAIN, SYSTEM_DOMAIN, ACCESSIBILITY_DOMAIN):
            self.assertTrue(
                all(domain in item for item in replay_file_denies),
                replay_file_denies,
            )

    def test_denials_cover_privileged_routes_network_and_data(self) -> None:
        policy = read("trillionnium_agent_replay_sync.te")
        for marker in (
            "trillionnium_aiauthority",
            "trillionnium_aishell",
            "trillionnium_capability_lease_issuer",
            "trillionnium_codex_agent",
            "trillionnium_agent_system_api_tool",
            "trillionnium_agent_accessibility_tool",
            "trillionnium_agent_adb_tool",
            "trillionnium_rootlinux",
            "trillionnium_agent_egress_guard",
            "trillionnium_agent_egress_probe",
            "trillionnium_rootlinux_receipt_file",
            "trillionnium_agent_egress_evidence_file",
            ":binder *",
            ":service_manager *",
            "hwservice_manager_type:hwservice_manager *",
            "port_type:tcp_socket name_connect",
            "tcp_socket",
            "udp_socket",
            "netlink_socket",
            "netlink_route_socket",
            "netlink_generic_socket",
            "data_file_type",
            "shell_exec",
            "toolbox_exec",
        ):
            self.assertIn(marker, policy)

        allows = statements("allow", policy)
        for item in allows:
            if (
                PUBLICATION_DOMAIN not in item
                and SYSTEM_DOMAIN not in item
                and ACCESSIBILITY_DOMAIN not in item
            ):
                continue
            for forbidden in (
                ":binder",
                ":service_manager",
                ":hwservice_manager",
                ":tcp_socket",
                ":udp_socket",
                ":netlink",
                "shell_exec:file",
                "toolbox_exec:file",
                ":capability",
            ):
                self.assertNotIn(forbidden, item, item)

        users = read("users")
        self.assertIsNotNone(
            re.search(
                rf"constrain\s+file\s+\{{\s*execute\s+execute_no_trans\s*\}}.*?"
                rf"{PUBLICATION_DOMAIN}.*?{SYSTEM_DOMAIN}.*?"
                rf"{ACCESSIBILITY_DOMAIN}.*?"
                r"or\s+t2\s*!=\s*\{\s*shell_exec\s+toolbox_exec\s*\}",
                users,
                flags=re.DOTALL,
            )
        )
        for constraint in (
            "constrain binder { impersonate call set_context_mgr transfer }",
            "constrain service_manager { add find list }",
            "constrain hwservice_manager { add find list }",
        ):
            self.assertIn(constraint, users)
        for domain in (PUBLICATION_DOMAIN, SYSTEM_DOMAIN, ACCESSIBILITY_DOMAIN):
            self.assertGreaterEqual(users.count(domain), 5)

    def test_source_and_packaged_contracts_remain_hold(self) -> None:
        blueprint = read("Android.bp")
        policy_path = '"common/private/trillionnium_agent_replay_sync.te"'
        self.assertEqual(blueprint.count(policy_path), 3)
        self.assertEqual(
            blueprint.count(
                'name: "TrillionniumAgentReplaySyncPolicyContractTest"'
            ),
            1,
        )
        self.assertNotIn("cc_binary", blueprint)
        self.assertNotIn("cc_prebuilt_binary", blueprint)
        self.assertNotIn("prebuilt_etc", blueprint)
        self.assertNotIn("init_rc", blueprint)
        self.assertNotIn("PRODUCT_PACKAGES", blueprint)
        self.assertNotIn("product_packages", blueprint)

        readme = re.sub(r"\s+", " ", read("README.md"))
        for marker in (
            "inert source boundary",
            "does not install any reserved binary",
            "no per-name SELinux type",
            "/proc/self/attr/exec",
            "`ptrace` and `sigkill` only",
            "`PR_SET_NO_NEW_PRIVS` before `execveat`",
            "`process2 nnp_transition`",
            "`nosuid_transition`",
            "5901",
            "source-only and unwired",
            "remain **HOLD**",
        ):
            self.assertIn(marker, readme)


if __name__ == "__main__":
    unittest.main()
