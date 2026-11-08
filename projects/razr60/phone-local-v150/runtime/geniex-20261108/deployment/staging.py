#!/usr/bin/env python3
"""Render the dedicated inverse staging bind, without performing it.

The data directory lives under the existing state bind, so the unchanged GNU
root exposes it as an ordinary directory. A new Android alias is bind-mounted
to it in init's real mount namespace. No /run write or executable noexec bypass
is used. The renderer never installs policy, mounts, starts, or resumes a task.
"""
from __future__ import annotations
import re
import shlex

STATE = "/data/trillionnium/owner-open/state"
GNU_STATE = "/var/lib/trillionnium/owner-open"
STAGE_TYPE = "trillionnium_owner_open_geniex_stage_file"
STAGE_CONTEXT = "u:object_r:" + STAGE_TYPE + ":s0"
STOP_SHA = "ff6401f96ef8d2206e61e9fdf6d75d1dd11fe25f5696d7f6996b6647023fdb07"
CLAIMS_SHA = "7feecc970e6499cd1735e5b0bf2c68386c669462a89a76d84f5bfc8b2225dd8c"


def need(value, message):
    if not value:
        raise ValueError(message)


def paths(instance):
    need(isinstance(instance, str) and re.fullmatch("[0-9a-f]{32}", instance), "fresh instance must be 32 lowercase hex digits")
    native = STATE + "/phone-local-v150/geniex-candidate-" + instance
    return {"native": native, "gnu": GNU_STATE + "/phone-local-v150/geniex-candidate-" + instance,
            "source": native + "/stage", "alias": "/data/local/tmp/hepta-geniex-stage-" + instance,
            "service": "hepta_geniex_provider_" + instance[:16]}


def hash_guard(path, digest):
    need(re.fullmatch("[0-9a-f]{64}", digest), "SHA256 required")
    return '[ "$(/system/bin/sha256sum ' + shlex.quote(path) + ' | /system/bin/cut -d\' \' -f1)" = ' + shlex.quote(digest) + ' ]'


def stopped_guards():
    return ['[ "$(/system/bin/getenforce)" = Enforcing ]', '[ "$(/system/bin/id -u)" = 0 ]',
            '[ "$(/system/bin/getprop init.svc.trillionnium_owner_open_bootstrap)" = stopped ]',
            hash_guard(STATE + "/emergency-stop", STOP_SHA),
            hash_guard(STATE + "/phone-local-v150/retained-claims.json", CLAIMS_SHA)]


def provision_script(instance):
    """Only new empty directories; keeps stop, original permissions and ledger."""
    p = paths(instance)
    lines = ["#!/system/bin/sh", "set -eu", "umask 077", *stopped_guards(),
             '[ "$(/system/bin/stat -c %u:%g:%a ' + STATE + ')" = 0:0:700 ]',
             '[ "$(/system/bin/readlink /proc/self/ns/mnt)" = "$(/system/bin/readlink /proc/1/ns/mnt)" ]']
    for path in (p["native"], p["alias"]):
        lines += ['[ ! -e ' + shlex.quote(path) + ' ]', '[ ! -L ' + shlex.quote(path) + ' ]']
    # mkdir is the first exclusive phone-side claim. Any partial failure remains
    # at this same identity and must be reconciled, never removed and repeated.
    lines += ['/system/bin/mkdir ' + shlex.quote(p["native"]),
              '/system/bin/chmod 0700 ' + shlex.quote(p["native"])]
    for name in ("stage", "startup-evidence", "model-evidence"):
        lines += ['/system/bin/mkdir ' + shlex.quote(p["native"] + "/" + name),
                  '/system/bin/chmod 0700 ' + shlex.quote(p["native"] + "/" + name)]
    lines += ['/system/bin/chown 2000:2000 ' + shlex.quote(p["source"]),
              '/system/bin/mkdir ' + shlex.quote(p["alias"]),
              '/system/bin/chown 2000:2000 ' + shlex.quote(p["alias"]),
              '/system/bin/chmod 0700 ' + shlex.quote(p["alias"]), '/system/bin/sync',
              *stopped_guards()]
    for label, path in (("CANDIDATE", p["native"]), ("SOURCE", p["source"]), ("ALIAS", p["alias"])):
        lines += ["/system/bin/stat -c '" + label + " %d:%i:%u:%g:%a' " + shlex.quote(path)]
    lines += ["printf 'MOUNT_NAMESPACE '", "/system/bin/readlink /proc/self/ns/mnt",
              "/system/bin/ls -ldZ " + shlex.join([p["native"], p["source"], p["alias"]])]
    return "\n".join(lines) + "\n"


def observation_contract(value):
    need(isinstance(value, dict) and set(value) == {"schema", "instance", "candidate", "source", "alias",
         "mount_namespace", "stage_mounted", "old_state_permissions_changed", "stop_sha256", "retained_claims_sha256"},
         "staging observation fields differ")
    need(value["schema"] == "hepta.geniex-inverse-stage-provision.v1", "staging observation schema differs")
    p = paths(value["instance"])
    for key, uid in (("candidate", 0), ("source", 2000), ("alias", 2000)):
        row = value[key]
        need(isinstance(row, dict) and set(row) == {"st_dev", "st_ino", "uid", "gid", "mode"}
             and all(type(row[field]) is int for field in row), "staging identity must use exact integers")
        need(row["st_dev"] >= 0 and row["st_ino"] > 0 and row["uid"] == row["gid"] == uid
             and row["mode"] == 0o700, "staging owner/mode differs")
    need((value["source"]["st_dev"], value["source"]["st_ino"]) !=
         (value["alias"]["st_dev"], value["alias"]["st_ino"]), "unmounted alias must be a separate directory")
    need(isinstance(value["mount_namespace"], str) and re.fullmatch(r"mnt:\[[0-9]+\]", value["mount_namespace"])
         and value["stage_mounted"] is False and value["old_state_permissions_changed"] is False
         and value["stop_sha256"] == STOP_SHA and value["retained_claims_sha256"] == CLAIMS_SHA,
         "staging preservation/mount observation differs")
    return p


def parse_provision_output(instance, raw):
    text = raw.decode("utf-8", errors="strict")
    result = {"schema": "hepta.geniex-inverse-stage-provision.v1", "instance": instance,
              "stage_mounted": False, "old_state_permissions_changed": False,
              "stop_sha256": STOP_SHA, "retained_claims_sha256": CLAIMS_SHA}
    for key in ("candidate", "source", "alias"):
        matches = re.findall("^" + key.upper() + r" ([0-9]+):([0-9]+):([0-9]+):([0-9]+):([0-7]+)$", text, re.M)
        need(len(matches) == 1, "one actual staging stat row required")
        row = matches[0]
        result[key] = dict(zip(("st_dev", "st_ino", "uid", "gid", "mode"),
                              [int(x) for x in row[:4]] + [int(row[4], 8)]))
    ns = re.findall(r"^MOUNT_NAMESPACE (mnt:\[[0-9]+\])$", text, re.M)
    need(len(ns) == 1, "actual mount namespace missing")
    result["mount_namespace"] = ns[0]
    observation_contract(result)
    return result


def _stat_guard(path, row):
    expected = f'{row["st_dev"]}:{row["st_ino"]}:{row["uid"]}:{row["gid"]}:{row["mode"]:o}'
    return '[ "$(/system/bin/stat -c %d:%i:%u:%g:%a ' + shlex.quote(path) + ')" = ' + shlex.quote(expected) + ' ]'


def bind_script(value):
    """Per-boot, create-only bind. Intended for the reviewed new module only."""
    p = observation_contract(value)
    lines = ["#!/system/bin/sh", "set -eu", "umask 077", '[ "$(/system/bin/id -u)" = 0 ]',
             '[ "$(/system/bin/getenforce)" = Enforcing ]',
             # Original post-fs-data restorecon runs before the existing GNU
             # bootstrap becomes ready. A standalone premature invocation must
             # fail, otherwise later restorecon could undo the new stage type.
             '[ "$(/system/bin/getprop init.svc.trillionnium_owner_open_bootstrap)" = running ]',
             '[ "$(/system/bin/getprop trillionnium.owner_open.ready)" = 1 ]',
             '[ "$(/system/bin/getprop trillionnium.owner_open.mount_ready)" = 1 ]',
             '[ "$(/system/bin/readlink /proc/self/ns/mnt)" = "$(/system/bin/readlink /proc/1/ns/mnt)" ]',
             _stat_guard(p["native"], value["candidate"]), _stat_guard(p["source"], value["source"]),
             _stat_guard(p["alias"], value["alias"]), hash_guard(STATE + "/phone-local-v150/retained-claims.json", CLAIMS_SHA),
             'if /data/adb/magisk/busybox mountpoint -q ' + shlex.quote(p["alias"]) + '; then exit 70; fi',
             'boot_id=$(/system/bin/cat /proc/sys/kernel/random/boot_id)',
             'printf \'%s\\n\' "$boot_id" | /system/bin/grep -Eq \'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$\'',
             'claim=' + shlex.quote(p["native"] + '/startup-evidence/bind-') + '"$boot_id"',
             '/system/bin/mkdir "$claim"', 'printf \'bind_intent_no_automatic_retry\\n\' > "$claim/intent.txt"',
             '/system/bin/sync']
    # Type changes apply only to the two newly allocated empty staging roots.
    # Their fixed inodes were measured before this new type is installed.
    for target in (p["source"], p["alias"]):
        lines += ['/system/bin/chcon ' + STAGE_CONTEXT + ' ' + shlex.quote(target)]
    lines += ['/data/adb/magisk/busybox mount --bind ' + shlex.quote(p["source"]) + ' ' + shlex.quote(p["alias"]),
              '/data/adb/magisk/busybox mount -o remount,bind,nosuid,nodev,noexec ' + shlex.quote(p["alias"]),
              _stat_guard(p["alias"], value["source"]),
              '/data/adb/magisk/busybox mountpoint -q ' + shlex.quote(p["alias"]),
              'line=$(/system/bin/awk -v p=' + shlex.quote(p["alias"]) + ' \'$5==p{print $6}\' /proc/self/mountinfo)',
              'case ",$line," in *,rw,*) ;; *) exit 70 ;; esac',
              'for flag in nosuid nodev noexec; do case ",$line," in *,"$flag",*) ;; *) exit 70 ;; esac; done',
              '[ "$(/system/bin/getprop init.svc.trillionnium_owner_open_bootstrap)" = running ]',
              '[ "$(/system/bin/getprop trillionnium.owner_open.ready)" = 1 ]',
              '[ "$(/system/bin/getprop trillionnium.owner_open.mount_ready)" = 1 ]',
              'set -C', 'printf \'bind_inode_and_flags_verified_provider_not_started\\n\' > "$claim/result.txt"',
              '/system/bin/sync']
    return "\n".join(lines) + "\n"


def unbind_script(value):
    p = observation_contract(value)
    return "\n".join(["#!/system/bin/sh", "set -eu", "umask 077", '[ "$(/system/bin/id -u)" = 0 ]',
        '[ "$(/system/bin/getprop init.svc.' + p["service"] + ')" = stopped ]',
        '[ "$(/system/bin/getprop init.svc.trillionnium_owner_open_bootstrap)" = stopped ]',
        '[ "$(/system/bin/readlink /proc/self/ns/mnt)" = "$(/system/bin/readlink /proc/1/ns/mnt)" ]',
        _stat_guard(p["source"], value["source"]), _stat_guard(p["alias"], value["source"]),
        '[ -z "$(/system/bin/find ' + shlex.quote(p["source"]) + ' -mindepth 1 -maxdepth 1 -print)" ]',
        '/data/adb/magisk/busybox mountpoint -q ' + shlex.quote(p["alias"]),
        '/system/bin/umount ' + shlex.quote(p["alias"]), _stat_guard(p["alias"], value["alias"]),
        '# Retain every original claim, request directory, startup intent and source file.']) + "\n"


def policy_fragment():
    lines = ["# New staging data only; no DSP/GPU grant and no execution permission.",
             "type " + STAGE_TYPE + " file_type",
             "typeattribute " + STAGE_TYPE + " data_file_type",
             "allow trillionnium_owner_open_bootstrap trillionnium_owner_open_bootstrap capability { chown dac_override }"]
    for domain in ("trillionnium_owner_open_bootstrap", "trillionnium_owner_open_phone_worker"):
        lines += [f"allow {domain} {STAGE_TYPE} dir {{ getattr open read search write add_name remove_name create rmdir setattr }}",
                  # Frozen counter and worker publish with linkat+unlinkat so
                  # an existing result can never be replaced. SELinux link is
                  # required independently of create/add_name permissions.
                  f"allow {domain} {STAGE_TYPE} file {{ getattr open read write create setattr link unlink }}",
                  f"type_transition {domain} {STAGE_TYPE} dir {STAGE_TYPE}",
                  f"type_transition {domain} {STAGE_TYPE} file {STAGE_TYPE}"]
    return "\n".join(lines) + "\n"


def artifact_policy_fragment():
    """Exact new read-only model/library/entry types; no shared-shell file grant."""
    worker = "trillionnium_owner_open_phone_worker"
    names = {"dir": "trillionnium_owner_open_geniex_artifact_dir",
             "data": "trillionnium_owner_open_geniex_data_file",
             "lib": "trillionnium_owner_open_geniex_library_file",
             "exec": "trillionnium_owner_open_geniex_runtime_exec"}
    lines = ["# Relabel only newly created, pinned candidate artifact trees."]
    for kind, name in names.items():
        lines += ["type " + name + " file_type",
                  "typeattribute " + name + " " + ("exec_type" if kind == "exec" else "data_file_type")]
    lines += [f"allow {worker} {names['dir']} dir {{ getattr search open read }}",
              f"allow {worker} {names['data']} file {{ getattr open read map }}",
              f"allow {worker} {names['lib']} file {{ getattr open read map execute }}",
              f"allow {worker} {names['exec']} file {{ getattr open read map execute execute_no_trans }}"]
    return "\n".join(lines) + "\n"


def service_rc(instance, plan_sha256):
    p = paths(instance)
    need(isinstance(plan_sha256, str) and re.fullmatch("[0-9a-f]{64}", plan_sha256), "complete entry plan SHA required")
    return ("# Additional service only; preserve every original ramdisk member.\n"
            "# No automatic start: selected operator sequence must validate the original native endpoint.\n"
            f"service {p['service']} /system_ext/bin/trillionnium-hepta-geniex-provider-entry --plan {p['native']}/startup/entry-plan.json --sha256 {plan_sha256}\n"
            "    class late_start\n    user root\n    group root\n    disabled\n    oneshot\n    namespace mnt\n"
            "    seclabel u:r:trillionnium_owner_open_bootstrap:s0\n"
            "    capabilities CHOWN DAC_OVERRIDE KILL SYS_CHROOT\n    gentle_kill\n\n"
            f"on property:sys.trillionnium.owner_open.stop=1\n    stop {p['service']}\n\n"
            f"on property:init.svc.trillionnium_owner_open_bootstrap=stopped\n    stop {p['service']}\n")
