#!/usr/bin/env python3
"""Freeze one reviewed r10 integration and bind it to the actual r9-r2 retirement.

Host-only builder: never contacts the phone, changes a policy, starts services,
or submits tasks. It refuses changed input pins and existing output paths.
"""
import argparse
import ast
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import tarfile

BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
ORIGINAL_RELEASE_POLICY='bfe7acc92ba8c5b7a3a1c2360d6faf53f804a19c3e25e20aad336e3220fa0e38'
PARENT_POLICY='f8219f9c3ad2e1d16a95fda8d5f0bc7612a31e00c0a661e53bf9a6e921c49d70'
PARENT_POLICY_SOURCE='30f3963d10aa4c4eea70c31c8f80278490be3c16986fb029853b5bc217a4b6f8'
BOUNDARY_CONSUMER_SHA256 = '41cc001cd5a4c74aea3e9f8b7604c74c49561ba20c29eb9cf7d5b3a78689cce0'
READINESS_SOURCE_SHA256 = 'c74b473092f284b4a43ae474cb2f00648cf0c66d00fbde04f28442be8776cf54'
COMPONENT_FRAGMENT_SHA256 = 'fadaa15600705c67d0c92031b810d8dca235f762bec53d9f5d9393c3b60dc022'
FORMAL_PARENT = {"bytes":28873,"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r9-diag-v3-f821-a1055-r1/CURRENT-FINAL-INTEGRATION-INPUTS.json","sha256":"4c186c37ea803daf46d079d9daf81d42192e6284d38b36a6a3254d1bf75f4dbd"}
FORMAL_CURRENT_READINESS_PATH = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-release-reader-reconstruction-a1055-r4/source/collect_r10_readiness.py'
NATIVE_SERVER='dbca8b3c6d024c414d018146e73df996cae51b18c8cf5d3bdab6b776318a348c'
A='/data/trillionnium/owner-open/state/phone-local-v150'
G='/var/lib/trillionnium/owner-open/phone-local-v150'
MODULE='/data/adb/modules/trillionnium_hepta_phone_local_v150_r10_r1'
MODEL='/data/local/tmp/hepta-phone-local-v150-r10-r1'
HELPER='/data/local/tmp/hepta-phone-executor-v150-r9-r1'
HISTORY='/data/adb/trillionnium-hepta-phone-local-v150-r10-r1'
OLD_ROLES={'supervisor': [12797, 12797, 12797, 12578704], 'model': [13191, 13191, 13191, 12579079], 'sidecar': [14188, 14188, 14188, 12579627], 'provider': [15160, 15160, 15160, 12579905]}
# These six unchanged, exact r7-r3 dependencies retain full startup verification.
# Rehashing both 1.55 GB weights for every role admission exceeds the existing
# five-second post-exec observation budget. No new release file is excluded.
STARTUP_ONLY_INPUTS={
    '/data/app/~~37uG3_vg0pSLDbVkrSFp8g==/org.trillionnium.hepta.controlprobe-lZ6MT7lwcqikAinn1huN0A==/base.apk':
        (24780,'4548c7da2c7aa39e6bf99ea3d93c6e4355fdfefd2355957c0851c7bb4478a405'),
    '/data/local/tmp/hepta-phone-local-v150-r1/models/GUI-Owl-1.5-2B-Instruct.Q4_K_M.gguf':
        (1107410432,'5fd2c77781a14a91128928b5bd313252aab076b44682396af4bb2c99667f5ef5'),
    '/data/local/tmp/hepta-phone-local-v150-r1/models/GUI-Owl-1.5-2B-Instruct.mmproj-Q8_0.gguf':
        (445053216,'16748786911f630d0c14869ac28999f77715053a62b2a00d2327021bd6d2afb7'),
    '/product/preinstall/PrcCalculator/PrcCalculator.apk':
        (5609102,'82b3399dcc5aa3c6c54f8eac65221a61a1aadb9420031bf2cd90a7523541e1e8'),
    '/system_ext/app/TrillionniumOwnerOpenShell/TrillionniumOwnerOpenShell.apk':
        (189950,'56c4e302cbe7448dffc9a0d8cfa8db2c2cb019fcb055fab36b815105dd55592f'),
    '/system_ext/priv-app/SettingsMoto/SettingsMoto.apk':
        (50521506,'0e5f1d1a545212640499dc2f266f3e7ecb50603a00fd75f0f99f951dbb61f1f8'),
}


def need(value,reason):
    if not value:raise ValueError(reason)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def enc(value):return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()


def read(row):
    path=Path(row['path']);info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1,'regular source required: '+str(path))
    raw=path.read_bytes()
    need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'source pin differs: '+str(path))
    return raw


def once(text,old,new):
    need(text.count(old)==1,'unique source integration anchor missing: '+old[:100])
    return text.replace(old,new)


def put(path,raw,mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())


def startup_prefix():
    return '''#!/system/bin/sh
set -eu
umask 077
BB=/data/adb/magisk/busybox
SYS=/system/bin
boot_id=$("$SYS/cat" /proc/sys/kernel/random/boot_id)
printf '%s\\n' "$boot_id" | "$BB" grep -Eq '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
NATIVE_RUN=/data/trillionnium/owner-open/state/phone-local-v150/model-runtime-r10-r1/$boot_id
GNU_RUN=/var/lib/trillionnium/owner-open/phone-local-v150/model-runtime-r10-r1/$boot_id
[ -d "$NATIVE_RUN" ] && [ ! -L "$NATIVE_RUN" ]
[ "$("$SYS/readlink" -f "$NATIVE_RUN")" = "$NATIVE_RUN" ]
[ "$("$SYS/stat" -c '%u:%g:%a' "$NATIVE_RUN")" = 0:0:700 ]
'''


OWNER_FINALIZER_INPUTS = json.loads('{"helper":{"bytes":32701,"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/fivefault-source-reconstruction-a1055-r2/source/resident_owner_terminal_candidate05.py","sha256":"958d796590cbd4f1d8440f76fdd95a1b273237c3c78aa1db8696728a697ad55a"},"observer":{"bytes":28570,"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/fivefault-source-reconstruction-a1055-r2/source/observe_resident_regular_outputs_UNBOUND08.py","sha256":"e48a4e1cd905643a7de060b49536d508aa31ba4535ea0a71708e6ccb71abd9bf"},"parent_service":{"bytes":11975,"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-r10-preparation-01/module-base-02/module-root/service.sh","sha256":"2dde5460ad8ea2e33075634f62ff67c7cae34e39d5e07a2329c20365803c7114"},"service":{"bytes":17999,"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/fivefault-source-reconstruction-a1055-r2/source/service_owner_finalizer_candidate04.sh","sha256":"f7104166cf935940832cca67e98c218a4cee2cece4a35148b3a6a8aaa07b0a24"}}')
OWNER_SERVICE_TRANSFORMS = json.loads('[{"after":"STOPPING=0\\n# Preserve original child PID/identity/hash in this real parent, not just files.\\nOWNED_MODEL_PID=\\nOWNED_MODEL_ID=\\nOWNED_MODEL_BINDING=\\nOWNED_SIDECAR_PID=\\nOWNED_SIDECAR_ID=\\nOWNED_SIDECAR_BINDING=\\nOWNED_PROVIDER_PID=\\nOWNED_PROVIDER_ID=\\nOWNED_PROVIDER_BINDING=\\n","before":"STOPPING=0\\n","count":1},{"after":"# Helpers are bounded foreground children, not new resident roles. The shell\\n# preserves each actual foreground return; only it waits its three original jobs.\\nowner_evidence() {\\n    owner_tag=$1\\n    shift\\n    case \\"$owner_tag\\" in\\n        bind-model|bind-sidecar|bind-provider|probe-model|probe-sidecar|probe-provider|wait-model|wait-sidecar|wait-provider|supervisor-terminal) ;;\\n        *) return 4 ;;\\n    esac\\n    owner_helper=$MODDIR/resident_owner_terminal.py\\n    [ -f \\"$owner_helper\\" ] && [ ! -L \\"$owner_helper\\" ] || return 4\\n    [ \\"$(\\"$SYS/stat\\" -c \'%u:%g:%a:%h:%s\' \\"$owner_helper\\")\\" = 0:0:600:1:25592 ] || return 4\\n    [ \\"$(\\"$SYS/sha256sum\\" \\"$owner_helper\\")\\" = \\"0c04cd67d063de444f51bebff2255c8175af784d7f2c4b0c733d28f7356f6667  $owner_helper\\" ] || return 4\\n    if \\"$BB\\" env -i PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 \\\\\\n        LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu \\\\\\n        PYTHONDONTWRITEBYTECODE=1 \\\\\\n        \\"$BB\\" chroot \\"$ROOT\\" /usr/bin/python3 -I -B \\\\\\n        \\"/proc/1/root$MODDIR/resident_owner_terminal.py\\" \\"$@\\"; then\\n        owner_rc=0\\n    else\\n        owner_rc=$?\\n    fi\\n    write_once \\"owner-$owner_tag.helper-return\\" \\"$owner_rc\\" || return 4\\n    return \\"$owner_rc\\"\\n}\\nowner_wait_role() {\\n    final_role=$1\\n    case \\"$final_role\\" in\\n        model) final_pid=$OWNED_MODEL_PID; final_id=$OWNED_MODEL_ID; final_binding=$OWNED_MODEL_BINDING ;;\\n        sidecar) final_pid=$OWNED_SIDECAR_PID; final_id=$OWNED_SIDECAR_ID; final_binding=$OWNED_SIDECAR_BINDING ;;\\n        provider) final_pid=$OWNED_PROVIDER_PID; final_id=$OWNED_PROVIDER_ID; final_binding=$OWNED_PROVIDER_BINDING ;;\\n        *) return 4 ;;\\n    esac\\n    [ -n \\"$final_pid\\" ] || return 0\\n    if [ -z \\"$final_id\\" ] || [ -z \\"$final_binding\\" ]; then\\n        write_once \\"owner-$final_role.wait-unknown\\" \'original memory binding incomplete; no wait or retry\' || :\\n        return 4\\n    fi\\n    # A positive generation-terminal probe makes this original builtin wait\\n    # nonblocking. Unknown, EACCES and a still-live child do not permit wait.\\n    if owner_evidence \\"probe-$final_role\\" probe --parent-identity \\"$PARENT_ID\\" \\\\\\n        --role \\"$final_role\\" --pid \\"$final_pid\\" --identity \\"$final_id\\" \\\\\\n        --binding-sha256 \\"$final_binding\\"; then\\n        if wait \\"$final_pid\\"; then\\n            final_rc=0\\n        else\\n            final_rc=$?\\n        fi\\n        # Preserve the actual result before diagnostics. 127 is kept ambiguous.\\n        write_once \\"owner-$final_role.wait-status\\" \\"$final_pid:$final_rc\\" || return 4\\n        owner_evidence \\"wait-$final_role\\" record-wait --parent-identity \\"$PARENT_ID\\" \\\\\\n            --role \\"$final_role\\" --pid \\"$final_pid\\" --identity \\"$final_id\\" \\\\\\n            --binding-sha256 \\"$final_binding\\" --wait-status \\"$final_rc\\"\\n    else\\n        write_once \\"owner-$final_role.wait-unknown\\" \'positive terminal probe unavailable; no wait or retry\' || :\\n        return 4\\n    fi\\n}\\nowner_terminal() {\\n    owner_finish_status=$1\\n    owner_memories=\\"model,$OWNED_MODEL_PID,$OWNED_MODEL_ID,$OWNED_MODEL_BINDING;sidecar,$OWNED_SIDECAR_PID,$OWNED_SIDECAR_ID,$OWNED_SIDECAR_BINDING;provider,$OWNED_PROVIDER_PID,$OWNED_PROVIDER_ID,$OWNED_PROVIDER_BINDING\\"\\n    owner_evidence supervisor-terminal terminal --parent-identity \\"$PARENT_ID\\" \\\\\\n        --memories \\"$owner_memories\\" --exit-status \\"$owner_finish_status\\"\\n}\\nstop_owned() {\\n","before":"stop_owned() {\\n","count":1},{"after":"    for role in provider sidecar model; do terminate_role \\"$role\\" || :; done\\n    for owner_role in provider sidecar model; do owner_wait_role \\"$owner_role\\" || :; done\\n","before":"    for role in provider sidecar model; do terminate_role \\"$role\\" || :; done\\n","count":1},{"after":"    write_once terminal-scope \'startup supervisor terminal only; no business success or full effect-quiescence claim\' || :\\n    owner_terminal \\"$result\\" || :\\n","before":"    write_once terminal-scope \'startup supervisor terminal only; no business success or full effect-quiescence claim\' || :\\n","count":1},{"after":"    role_pid=$!\\n    case \\"$role\\" in\\n        model) OWNED_MODEL_PID=$role_pid ;;\\n        sidecar) OWNED_SIDECAR_PID=$role_pid ;;\\n        provider) OWNED_PROVIDER_PID=$role_pid ;;\\n    esac\\n","before":"    role_pid=$!\\n","count":1},{"after":"    case \\"$role\\" in\\n        model) OWNED_MODEL_ID=$captured ;;\\n        sidecar) OWNED_SIDECAR_ID=$captured ;;\\n        provider) OWNED_PROVIDER_ID=$captured ;;\\n    esac\\n    owner_evidence \\"bind-$role\\" bind --parent-identity \\"$PARENT_ID\\" \\\\\\n        --role \\"$role\\" --pid \\"$role_pid\\" --identity \\"$captured\\" || return 1\\n    owner_binding=$(\\"$SYS/sha256sum\\" \\"$CLAIM/owner-$role.bind.json\\") || return 1\\n    owner_binding=${owner_binding%% *}\\n    printf \'%s\\\\n\' \\"$owner_binding\\" | \\"$BB\\" grep -Eq \'^[0-9a-f]{64}$\' || return 1\\n    case \\"$role\\" in\\n        model) OWNED_MODEL_BINDING=$owner_binding ;;\\n        sidecar) OWNED_SIDECAR_BINDING=$owner_binding ;;\\n        provider) OWNED_PROVIDER_BINDING=$owner_binding ;;\\n    esac\\n    # Only this exact, already-recorded group can cross the exec barrier.\\n","before":"    # Only this exact, already-recorded group can cross the exec barrier.\\n","count":1},{"after":"CLAIM=\\nPARENT_ID=\\nSTOPPING=0\\nOWNER_STOP_DEADLINE=\\n","before":"CLAIM=\\nSTOPPING=0\\n","count":1},{"after":"owner_stop_clock() {\\n    # /proc/uptime shares CLOCK_BOOTTIME with the bounded helper. Rounding down\\n    # makes the new 36-second observation window shorter, never longer.\\n    owner_uptime=\\n    owner_idle=\\n    read -r owner_uptime owner_idle < /proc/uptime || return 4\\n    owner_seconds=${owner_uptime%%.*}\\n    case \\"$owner_seconds\\" in \'\'|*[!0-9]*) return 4 ;; esac\\n    [ \\"${#owner_seconds}\\" -le 12 ] || return 4\\n}\\nowner_window_remaining() {\\n    [ -n \\"$OWNER_STOP_DEADLINE\\" ] || return 4\\n    owner_stop_clock || return 4\\n    [ \\"$owner_seconds\\" -lt \\"$OWNER_STOP_DEADLINE\\" ] || return 4\\n}\\nowner_evidence() {","before":"owner_evidence() {","count":1},{"after":"    case \\"$owner_tag\\" in\\n        bind-*) ;;\\n        *) owner_window_remaining || return 4\\n           set -- \\"$@\\" --stop-deadline \\"$OWNER_STOP_DEADLINE\\" ;;\\n    esac\\n    owner_helper=$MODDIR/resident_owner_terminal.py\\n","before":"    owner_helper=$MODDIR/resident_owner_terminal.py\\n","count":1},{"after":"0:0:600:1:27603","before":"0:0:600:1:25592","count":1},{"after":"74fced3a00ce8d507d3762951aee1a321fdbcef4900677fa987b6853a16e3a53","before":"0c04cd67d063de444f51bebff2255c8175af784d7f2c4b0c733d28f7356f6667","count":1},{"after":"    if [ -z \\"$PARENT_ID\\" ] || [ -z \\"$final_id\\" ] || [ -z \\"$final_binding\\" ]; then","before":"    if [ -z \\"$final_id\\" ] || [ -z \\"$final_binding\\" ]; then","count":1},{"after":"        if ! owner_window_remaining; then\\n            write_once \\"owner-$final_role.wait-unknown\\" \'observer window exhausted after probe; no wait or retry\' || :\\n            return 4\\n        fi\\n        if wait \\"$final_pid\\"; then\\n","before":"        if wait \\"$final_pid\\"; then\\n","count":1},{"after":"    owner_finish_status=$1\\n    [ -n \\"$PARENT_ID\\" ] || return 4\\n    owner_window_remaining || return 4\\n    owner_memories=","before":"    owner_finish_status=$1\\n    owner_memories=","count":1},{"after":"    STOPPING=1\\n    # This limits only new evidence helpers and newly authorized builtin waits.\\n    # Original TERM/KILL cleanup below always runs, including clock failure.\\n    if owner_stop_clock; then\\n        OWNER_STOP_DEADLINE=$((owner_seconds + 36))\\n        write_once owner-stop-window \\"$owner_seconds:$OWNER_STOP_DEADLINE\\" || :\\n    fi\\n    # Stop admission","before":"    STOPPING=1\\n    # Stop admission","count":1},{"after":"0:0:600:1:27599","before":"0:0:600:1:27603","count":1},{"after":"2ebce277e5037e90a973526bd6dd6fed63fbdb12b6855ba193f01a3c5bf865f1","before":"74fced3a00ce8d507d3762951aee1a321fdbcef4900677fa987b6853a16e3a53","count":1},{"after":"0:0:600:1:32701","before":"0:0:600:1:27599","count":1},{"after":"958d796590cbd4f1d8440f76fdd95a1b273237c3c78aa1db8696728a697ad55a","before":"2ebce277e5037e90a973526bd6dd6fed63fbdb12b6855ba193f01a3c5bf865f1","count":1}]')
OWNER_FINALIZER_PROVENANCE = json.loads('{"additional_resident_roles":0,"child_wait_owner":"ORIGINAL_SERVICE_SHELL_MEMORY","cleanup_audit2_outside_component_inventory_required":true,"exact_eight_stream_caller_required":true,"fixed19_credit":0,"formal_build_qualification_from_this_record":false,"helper_phase_total_seconds":2,"helper_source":{"bytes":32701,"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/fivefault-source-reconstruction-a1055-r2/source/resident_owner_terminal_candidate05.py","sha256":"958d796590cbd4f1d8440f76fdd95a1b273237c3c78aa1db8696728a697ad55a"},"installer_initial_stream_identity_proven":false,"new_stop_observation_window_seconds":36,"new_window_limits_only_observation_and_wait_qualification":true,"observer_deployed_as_module_member":false,"original_terminate_role_bytes_preserved":true,"original_three_role_stop_calls_always_attempted":true,"parent_builder":{"bytes":45121,"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-release-reader-reconstruction-a1055-r4/source/build_release_r10.py","sha256":"26bbd6dafa353badc6ef6be5e4e43a25ae1fecc48def321e883caafe7b48ddb0"},"parent_formal_inputs_sha256":"8443393552d1b322b0bf3f86d9e91474ece860e1efd708c80ad15ba8c539df9f","parent_module_service":{"bytes":11975,"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/root-r10-preparation-01/module-base-02/module-root/service.sh","sha256":"2dde5460ad8ea2e33075634f62ff67c7cae34e39d5e07a2329c20365803c7114"},"parent_stream_origin":"ACTUAL_OPEN_PARENT_FD_AT_CHILD_BIND_ONLY","phone_execution":false,"prewire_service":{"bytes":17999,"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/fivefault-source-reconstruction-a1055-r2/source/service_owner_finalizer_candidate04.sh","sha256":"f7104166cf935940832cca67e98c218a4cee2cece4a35148b3a6a8aaa07b0a24"},"regular_file_pipe_eof_claimed":false,"regular_output_observer_candidate":{"bytes":28570,"path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/fivefault-source-reconstruction-a1055-r2/source/observe_resident_regular_outputs_UNBOUND08.py","sha256":"e48a4e1cd905643a7de060b49536d508aa31ba4535ea0a71708e6ccb71abd9bf"},"resident_roles":["supervisor","model","sidecar","provider"],"schema":"hepta.module-r10-r1.resident-owner-finalizer.v1","service_lifetime_foreground_helper_invocations_maximum":10,"service_transform_count":19,"service_transforms_sha256":"e41a1392d2003c0c8e8879dcd4a6393adade6c5bdcdada0b57be0d9a0754fa47","status_127":"AMBIGUOUS_UNQUALIFIED","supervisor_original_parent_wait":"NOT_RETAINED","supervisor_terminal_type":"SELF_TERMINAL_PLUS_REQUIRED_INDEPENDENT_ABSENCE","task_endpoint_lock_latest_family_closure_separate":true}')
OWNER_WIRING_CONFIGURATION_SHA256 = '5ff00467e8432d7119ba72a700ce07cb20f16555d3dc0c90de7cbfc388103f48'
OWNER_SOURCE_META = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')

def read_owner_finalizer_source(row):
    path = Path(row['path'])
    need(path.is_absolute() and str(path) == row['path'] and '..' not in path.parts,
         'owner finalizer source must be canonical absolute')
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
         and before.st_size == row['bytes'] <= 262144, 'bounded owner finalizer source required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        first = os.fstat(fd)
        need(tuple(getattr(first,k) for k in OWNER_SOURCE_META) ==
             tuple(getattr(before,k) for k in OWNER_SOURCE_META), 'owner source open identity differs')
        pieces=[];total=0
        while True:
            part=os.read(fd,min(65536,row['bytes']+1-total))
            if not part:break
            pieces.append(part);total+=len(part)
            need(total<=row['bytes'],'owner source grew')
        raw=b''.join(pieces)
        last=os.fstat(fd);after=path.lstat()
        need(tuple(getattr(first,k) for k in OWNER_SOURCE_META) ==
             tuple(getattr(last,k) for k in OWNER_SOURCE_META) ==
             tuple(getattr(after,k) for k in OWNER_SOURCE_META),
             'owner source changed during original read')
    finally:os.close(fd)
    need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'owner finalizer source pin differs')
    return raw

def bind_owner_finalizer_module_inputs(module):
    need('resident_owner_terminal.py' not in module and 'RESIDENT-OWNER-FINALIZER.json' not in module,
         'owner module names must be create-only additions')
    parent=read_owner_finalizer_source(OWNER_FINALIZER_INPUTS['parent_service'])
    selected=read_owner_finalizer_source(OWNER_FINALIZER_INPUTS['service'])
    helper=read_owner_finalizer_source(OWNER_FINALIZER_INPUTS['helper'])
    observer=read_owner_finalizer_source(OWNER_FINALIZER_INPUTS['observer'])
    need(module['service.sh']==parent,'formal module row was replaced outside the typed wire transform')
    text=parent.decode()
    for change in OWNER_SERVICE_TRANSFORMS:
        need(change['count']==1 and text.count(change['before'])==1,'owner service exact transform anchor')
        text=text.replace(change['before'],change['after'],1)
    need(text.encode()==selected,'owner service whole derivation differs')
    inverse=selected.decode()
    for change in reversed(OWNER_SERVICE_TRANSFORMS):
        need(inverse.count(change['after'])==1,'owner service inverse anchor')
        inverse=inverse.replace(change['after'],change['before'],1)
    need(inverse.encode()==parent,'owner service full original inverse differs')
    compile(helper,'<exact-resident-owner-terminal>','exec')
    compile(observer,'<exact-regular-output-observer-candidate>','exec')
    module['service.sh']=selected
    module['resident_owner_terminal.py']=helper
    return copy.deepcopy(OWNER_FINALIZER_PROVENANCE)


def wire_module(module,config_sha):
    need(config_sha==OWNER_WIRING_CONFIGURATION_SHA256,'owner module requires the exact shared configuration')
    owner_binding=bind_owner_finalizer_module_inputs(module)
    # The reviewed r9-r2 base already has its exact new namespace. In particular,
    # its predecessor registry must retain r9-r1, never rename it to this release.
    need(sha(module['sepolicy.rule'])==PARENT_POLICY_SOURCE,'policy source changed')
    gate=module['activation_gate.sh'].decode()
    gate=once(gate,'for f in activation-inputs.tsv activation-artifacts.sha256 retired-groups.tsv; do',
              'for f in module-inputs.sha256 activation-inputs.tsv activation-artifacts.sha256 retired-groups.tsv; do')
    gate=once(gate,'(cd "$MODDIR" && "$SYS/sha256sum" -c activation-artifacts.sha256)',
              '(cd "$MODDIR" && "$SYS/sha256sum" -c module-inputs.sha256 && "$SYS/sha256sum" -c activation-artifacts.sha256)')
    module['activation_gate.sh']=gate.encode()
    text=module['launch-model.sh'].decode()
    line=next(line for line in text.splitlines() if line.startswith('exec '))
    line=once(line,"'TMPDIR=/data/local/tmp/hepta-phone-local-v150-r1'",
              "'TMPDIR=/data/local/tmp/hepta-phone-local-v150-r1' 'LLAMA_HEPTA_CPU_CANCEL_SAFEPOINT=1' \"LLAMA_HEPTA_RECEIPT_DIR=$NATIVE_RUN/receipts\"")
    line=once(line,"'/data/local/tmp/hepta-phone-local-v150-r1/bin/llama-server'",shlex.quote(MODEL+'/bin/llama-server'))
    module['launch-model.sh']=(startup_prefix()+'''[ -d "$NATIVE_RUN/receipts" ] && [ ! -L "$NATIVE_RUN/receipts" ]
[ "$("$SYS/stat" -c '%u:%g:%a' "$NATIVE_RUN/receipts")" = 0:0:700 ]
'''+line+'\n').encode()
    text=module['launch-provider.sh'].decode()
    line=next(line for line in text.splitlines() if line.startswith('exec '))
    line=once(line,'/provider-r8/source/daily_phone_local.py','/provider-r10-r1/source/daily_phone_local.py')
    line=once(line,'/local-config-r8.json','/local-config-r10-r1.json')
    line += ' --slot-cleanup-binding "$GNU_RUN/bindings/slot-cleanup-$boot_id-$model_pid-$model_ticks.json"'
    module['launch-provider.sh']=(startup_prefix()+'''for file in model.identity READY-BOUND.json; do
    [ -f "$NATIVE_RUN/$file" ] && [ ! -L "$NATIVE_RUN/$file" ]
    [ "$("$SYS/stat" -c '%u:%g:%a:%h' "$NATIVE_RUN/$file")" = 0:0:600:1 ]
done
model_identity=$("$SYS/cat" "$NATIVE_RUN/model.identity")
printf '%s\\n' "$model_identity" | "$BB" grep -Eq '^[1-9][0-9]*(:[1-9][0-9]*){3}$'
IFS=: read -r model_pid model_pgid model_sid model_ticks <<EOF
$model_identity
EOF
[ "$model_pid" = "$model_pgid" ] && [ "$model_pid" = "$model_sid" ]
'''+line+'\n').encode()
    text=module['role-expectations.tsv'].decode()
    text=once(text,'/data/local/tmp/hepta-phone-local-v150-r1/bin/llama-server\t7e8ea2c601bc3415f8698cca00fbe4737a2093873ba0705d749ae8d6908b3176',MODEL+'/bin/llama-server\t'+NATIVE_SERVER)
    module['role-expectations.tsv']=text.encode()
    text=module['service.sh'].decode()
    trampoline='''# Magisk may invoke this hook in its own session. Admit one private supervisor
# session before any claim, listener or service is created. Manual root startup
# already owns its session and therefore does not re-exec or fork here.
case "$#:${1-}" in 0:|1:--hepta-r9-owned-session) ;; *) exit 78 ;; esac
supervisor_stat=$("$SYS/cat" "/proc/$$/stat")
supervisor_tail=${supervisor_stat##*) }
supervisor_owned=$(printf '%s\\n' "$supervisor_tail" | "$BB" awk -v p="$$" '{if ($1=="Z") exit 1; if ($3==p && $4==p) print "yes"; else print "no"}')
if [ "$supervisor_owned" != yes ]; then
    [ "$#" = 0 ] || exit 78
    exec "$BB" setsid "$BB" sh "$MODDIR/service.sh" --hepta-r9-owned-session
fi
'''
    text=once(text,'SYS=/system/bin\n','SYS=/system/bin\n'+trampoline)
    insertion='''# Per-boot private model receipt/claim namespace; old epochs remain untouched.
MODEL_RUNTIME_ROOT=/data/trillionnium/owner-open/state/phone-local-v150/model-runtime-r10-r1
MODEL_RUN=$MODEL_RUNTIME_ROOT/$boot_id
GNU_MODEL_RUN=/var/lib/trillionnium/owner-open/phone-local-v150/model-runtime-r10-r1/$boot_id
prepare_model_runtime() {
    [ -d "$MODEL_RUNTIME_ROOT" ] && [ ! -L "$MODEL_RUNTIME_ROOT" ]
    [ "$("$SYS/readlink" -f "$MODEL_RUNTIME_ROOT")" = "$MODEL_RUNTIME_ROOT" ]
    [ "$("$SYS/stat" -c '%u:%g:%a' "$MODEL_RUNTIME_ROOT")" = 0:0:700 ]
    "$SYS/mkdir" -m 700 "$MODEL_RUN"
    "$SYS/mkdir" -m 700 "$MODEL_RUN/receipts" "$MODEL_RUN/bindings"
    for path in "$MODEL_RUN" "$MODEL_RUN/receipts" "$MODEL_RUN/bindings"; do
        [ "$("$SYS/stat" -c '%u:%g:%a' "$path")" = 0:0:700 ]
    done
    write_once model-runtime-directory "$MODEL_RUN"
}
bind_model_runtime() {
    identity_live model
    original=$("$SYS/cat" "$CLAIM/model.identity")
    ( set -C; printf '%s\\n' "$original" > "$MODEL_RUN/model.identity" )
    "$SYS/cmp" "$CLAIM/model.identity" "$MODEL_RUN/model.identity"
    model_claim_hash=$("$SYS/sha256sum" "$MODEL_RUN/model.identity")
    model_claim_hash=${model_claim_hash%% *}
    write_once model-binding-intent 'read-only bounded readiness and one actual binding; no inference, no model restart'
    "$BB" env -i PATH=/usr/bin:/bin:/usr/libexec/trillionnium \\
        PYTHONPATH=/usr/libexec/trillionnium/owner-open PYTHONHOME=/usr PYTHONDONTWRITEBYTECODE=1 \\
        LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu \\
        LANG=C.UTF-8 LC_ALL=C.UTF-8 NO_COLOR=1 TERM=dumb TMPDIR=/var/lib/trillionnium/owner-open/tmp \\
        "$BB" chroot "$ROOT" /usr/bin/python3 -B \\
        /var/lib/trillionnium/owner-open/phone-local-v150/provider-r10-r1/wait_and_bind_model.py \\
        --config /var/lib/trillionnium/owner-open/phone-local-v150/local-config-r10-r1.json \\
        --config-sha256 '''+config_sha+''' \\
        --server-sha256 '''+NATIVE_SERVER+''' \\
        --model-claim-sha256 "$model_claim_hash" --runtime-dir "$GNU_MODEL_RUN" \\
        >"$CLAIM/model-binding.stdout" 2>"$CLAIM/model-binding.stderr"
    identity_live model
    "$SYS/cmp" "$CLAIM/model.identity" "$MODEL_RUN/model.identity"
    [ -f "$MODEL_RUN/READY-BOUND.json" ] && [ ! -L "$MODEL_RUN/READY-BOUND.json" ]
    write_once model-binding-complete 'actual current boot/process/binary, one idle slot, CPU text and image abort callbacks'
}
'''
    text=once(text,'# Services may become listeners at different times; no health prompt is auto-issued.\n',
              insertion+'# Services may become listeners at different times; no health prompt is auto-issued.\n')
    text=once(text,'prepare_executor_logs\nstart_role model\nstart_role sidecar\nstart_role provider\n',
              'prepare_executor_logs\nprepare_model_runtime\nstart_role model\nbind_model_runtime\nstart_role sidecar\nstart_role provider\n')
    module['service.sh']=text.encode()
    owner_binding['wired_service']={'bytes':len(module['service.sh']),'sha256':sha(module['service.sh'])}
    owner_binding['wired_configuration_sha256']=config_sha
    module['RESIDENT-OWNER-FINALIZER.json']=enc(owner_binding)
    for name,raw in module.items():
        if name.endswith('.sh'):
            need(b'v150-r8' not in raw and b'provider-r8' not in raw,'stale r8 executable path: '+name)
            result=subprocess.run(['/bin/sh','-n'],input=raw,capture_output=True)
            need(result.returncode==0,'shell syntax: '+name+': '+result.stderr.decode())
    return module


def boundary_sources():
    home=Path(__file__).resolve().parent
    def source(name,pin):
        path=home/name;raw=read(dict(path=str(path),bytes=path.stat().st_size,sha256=pin))
        compile(raw,name,'exec')
        return raw
    consumer_raw=source('release_boundaries.py',BOUNDARY_CONSUMER_SHA256)
    namespace={'__name__':'reviewed_release_boundaries','__file__':str(home/'release_boundaries.py')}
    exec(compile(consumer_raw,namespace['__file__'],'exec',optimize=0),namespace)
    return namespace,consumer_raw,source('collect_r10_readiness.py',READINESS_SOURCE_SHA256),source('component_activation_gate.fragment.py',COMPONENT_FRAGMENT_SHA256)


def component_activation(module,activation,state,fragment):
    gate=activation['boot_activation_gate.py'].decode()
    old="require(len(sys.argv) == 4 and sys.argv[1:3] == ['--check-and-chain', '--retirement-boot'],"
    new="require(len(sys.argv) == 6 and sys.argv[1:3] == ['--check-and-chain', '--retirement-boot']\n            and sys.argv[4] == '--activation-mode' and sys.argv[5] in ('startup', 'admission'),"
    gate=once(gate,old,new)
    gate=once(gate,'def main():',fragment.decode()+'\n\ndef main():')
    gate=once(gate,'    epoch, report = census(binding, ProcView())',
              "    epoch, report = census(binding, ProcView())\n    report['closed_component_activation'] = verify_closed_components(epoch, ProcView(), sys.argv[5])")
    compile(gate,'boot_activation_gate.py','exec')
    activation['boot_activation_gate.py']=gate.encode()
    activation['closed-component-activation.json']=enc(dict(
        schema='hepta.module-r10-r1.closed-component-activation.v4',retirement_boot_id=BOOT,
        component_boundary_sha256=state['component_boundary_sha256'],
        component_package_sha256=state['component_input']['component_package_manifest']['sha256'],
        role_generations=state['component_roles'],
        retained_preaccept_binding=state['retained_preaccept_binding'],
        retained_preaccept_role_generations=state['retained_preaccept_roles'],
        retained_failed_staged_binding=state['retained_failed_staged_binding'],
        retained_failed_staged_role_generations=state['retained_failed_staged_roles'],
        retained_failed_transport_binding=state['retained_failed_transport_binding'],
        retained_failed_transport_role_generations=state['retained_failed_transport_roles']))
    shell=module['activation_gate.sh'].decode()
    shell=once(shell,'--check-and-chain --retirement-boot "$expected_boot"',
               '--check-and-chain --retirement-boot "$expected_boot" --activation-mode "$MODE"')
    need(subprocess.run(['/bin/sh','-n'],input=shell.encode(),capture_output=True).returncode==0,
         'derived activation shell syntax differs')
    module['activation_gate.sh']=shell.encode()


REVIEWED_SOURCE_BINDING = {'formal_parent': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-release-owner-finalizer-a1055-r1/contracts/FINAL-INTEGRATION-INPUTS.json', 'bytes': 28873, 'sha256': '8443393552d1b322b0bf3f86d9e91474ece860e1efd708c80ad15ba8c539df9f'}, 'formal': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-release-source-chain-r10-derived01/contracts/FINAL-INTEGRATION-INPUTS.json', 'bytes': 28953, 'sha256': '12d594168a91b964fbea17ce4669f6ed517ce1632479c5177fc8eaccf1979dbf'}, 'readiness': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-release-source-chain-r10-derived01/source/collect_r10_readiness.py', 'bytes': 16407, 'sha256': 'c74b473092f284b4a43ae474cb2f00648cf0c66d00fbde04f28442be8776cf54'}, 'production_replacements': {'daily_phone_local.py': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-20261106-fc33-shared-material-v3-01/shared/provider/source/daily_phone_local.py', 'bytes': 22059, 'sha256': 'a16be75d5a47a86a7c0d222dc95e8b2373017b3291ce644864e2dd3b763447b8'}, 'phone_local_tools.py': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-20261106-fc33-shared-material-v3-01/shared/provider/source/phone_local_tools.py', 'bytes': 13927, 'sha256': '2d0c9cc8f1ff0c643aab3daeef07c12e84541f1c2f0bfd13c8043c5c8fa58930'}, 'phone_observation_tools.py': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-20261106-fc33-shared-material-v3-01/shared/provider/source/phone_observation_tools.py', 'bytes': 55981, 'sha256': '4f95178996a2d7a604ae56eecd0f7725657222783f5cab5a7ff868f85a8cd086'}, 'provider_codex_host.py': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-20261106-fc33-shared-material-v3-01/shared/provider/source/provider_codex_host.py', 'bytes': 41618, 'sha256': '0ea72f9e38307055ead790aa5828143c4ba431ae33c8e44e19c5893073ade5fa'}, 'provider_phone_local.py': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-20261106-fc33-shared-material-v3-01/shared/provider/source/provider_phone_local.py', 'bytes': 70303, 'sha256': '0c04bbd0f2d8f88a0795776a23a6cb34bf5f9a88aabc09e8aa3c3ff34c534bee'}}, 'configuration': {'bytes': 1493, 'sha256': '5ff00467e8432d7119ba72a700ce07cb20f16555d3dc0c90de7cbfc388103f48'}, 'service': {'bytes': 10654, 'sha256': '273db17098e5de6c67ded208e120e3910531ab1c7a778faa76824d453ddddd58'}, 'material_parent_configuration_sha256': '22f57380a8bf92d88f0a0d7eda700adc7c711464975d7184b0dce48b3bdd5d3e', 'material_parent_service_sha256': 'e0522c5d743fd9bdc30343d93200a894d58016f935f564284bb6b0d924ba898a', 'material_source_input': {'bytes': 2730, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-20261106-fc33-shared-material-v3-01/SOURCE-INPUTS.json', 'sha256': 'f02822b6ae8393738e563f61b73a646ddf0ccdf799d94e662fb5a88a43f16bcc'}}

def verify_current_formal_parent(raw, value, readiness_raw):
    """Exact five reviewed production rows and this derived readiness row only."""
    binding=REVIEWED_SOURCE_BINDING
    need(type(binding)is dict,'UNBOUND_REVIEWED_SOURCE_BINDING_NO_IO')
    previous_raw=read(binding['formal_parent']);previous=json.loads(previous_raw)
    need(enc(previous)==previous_raw and enc(value)==raw,'exact canonical formal input bytes')
    expected=copy.deepcopy(previous)
    selected=binding['production_replacements']
    need(set(selected)=={'daily_phone_local.py','phone_local_tools.py','phone_observation_tools.py',
                         'provider_codex_host.py','provider_phone_local.py'},'exact reviewed five-source family')
    for row in expected['production_sources']:
        if row['name']in selected:
            name=row['name'];row.clear();row.update(name=name,**selected[name])
    rows=[row for row in expected['provider_helpers']if row['name']=='collect_r10_readiness.py']
    need(len(rows)==1 and len(readiness_raw)==binding['readiness']['bytes']
         and sha(readiness_raw)==binding['readiness']['sha256'],'exact derived readiness source')
    rows[0].clear();rows[0].update(name='collect_r10_readiness.py',**binding['readiness'])
    need(enc(expected)==raw and len(raw)==binding['formal']['bytes']
         and sha(raw)==binding['formal']['sha256'],'formal input changed beyond five production rows and readiness')
    material_input_raw=read(binding['material_source_input'])
    need(json.loads(material_input_raw)['changed_sources']==sorted(selected),
         'shared source derivation must select these same five reviewed sources')
    return sha(material_input_raw)


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--inputs',type=Path,required=True)
    p.add_argument('--inputs-sha256',required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--retirement-inputs',type=Path)
    p.add_argument('--retirement-inputs-sha256')
    p.add_argument('--component-boundary-inputs',type=Path)
    p.add_argument('--component-boundary-inputs-sha256')
    p.add_argument('--policy-adoption-inputs',type=Path)
    p.add_argument('--policy-adoption-inputs-sha256')
    p.add_argument('--material-only',action='store_true')
    p.add_argument('--shared-materials',type=Path)
    p.add_argument('--shared-materials-sha256')
    args=p.parse_args();os.umask(0o077)
    supplied=[args.component_boundary_inputs,args.component_boundary_inputs_sha256,
              args.policy_adoption_inputs,args.policy_adoption_inputs_sha256]
    need(all(x is None for x in supplied) or all(x is not None for x in supplied),
         'both explicit boundary inputs and both external SHA pins are required together')
    need(args.retirement_inputs is None or all(x is not None for x in supplied),
         'actual final sealing requires component boundary and explicit policy adoption')
    need((args.shared_materials is None)==(args.shared_materials_sha256 is None),
         'shared production materials require an explicit external SHA')
    need(args.retirement_inputs is None or args.shared_materials is not None,
         'actual final sealing requires the exact component/final shared production material')
    need(not args.material_only or (args.retirement_inputs is None
         and args.shared_materials is None and all(x is None for x in supplied)),
         'material-only has no retirement, component, adoption or seal input')
    consumer,consumer_raw,readiness_raw,fragment=boundary_sources()
    boundary_raw=None;boundary=None
    if args.component_boundary_inputs is not None:
        def input_row(path,pin):
            return dict(path=str(path.absolute()),bytes=path.stat().st_size,sha256=pin)
        boundary_raw,boundary=consumer['prepare_bundle'](
            input_row(args.component_boundary_inputs,args.component_boundary_inputs_sha256),
            input_row(args.policy_adoption_inputs,args.policy_adoption_inputs_sha256))
    runtime_policy=PARENT_POLICY if boundary is None else boundary['runtime_policy']['sha256']
    runtime_rule=PARENT_POLICY_SOURCE if boundary is None else sha(boundary['full_rule'])
    input_raw=args.inputs.read_bytes();need(sha(input_raw)==args.inputs_sha256,'integration inputs changed')
    v=json.loads(input_raw)
    need(v['schema']=='hepta.r10.reviewed-integration-inputs.v1','input schema')
    parent_formal_sha=verify_current_formal_parent(input_raw,v,readiness_raw)
    source={r['name']:read(r) for r in v['production_sources']}
    need(len(source)==15 and set(source)==set(Path(r['path']).name for r in v['production_sources']),
         'exact fifteen production sources required')
    # This is the one explicitly derived integration entry; all imported pins follow actual bytes.
    daily=source['daily_phone_local.py'].decode();tree=ast.parse(daily)
    node=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PARENTS' for t in n.targets))
    need(node.lineno==node.end_lineno,'PARENTS must be one explicit source line')
    parents={name:sha(raw) for name,raw in sorted(source.items()) if name!='daily_phone_local.py'}
    lines=daily.splitlines(keepends=True);lines[node.lineno-1]='PARENTS = '+repr(parents)+'\n'
    source['daily_phone_local.py']=''.join(lines).encode()
    need(sha(source['daily_phone_local.py'])==REVIEWED_SOURCE_BINDING['production_replacements']['daily_phone_local.py']['sha256'],
         'derived daily integration bytes differ from reviewed fifteen-source candidate')
    for name,raw in source.items():compile(raw,name,'exec')
    parent_config_raw=read(v['configuration']);config=json.loads(parent_config_raw)
    need(config['backend']=='phone_local' if 'backend' in config else True,'local backend required')
    activation={r['name']:read(r) for r in v['activation_sources']}
    helpers={r['name']:read(r) for r in v['provider_helpers']}
    if 'collect_r10_readiness.py' in helpers:
        need(sha(helpers['collect_r10_readiness.py']) in (
            'e123c352fc56976ff3c6987f42236cf5eb8d1fc63175e9dfd66bc66c7d9e636e',READINESS_SOURCE_SHA256),
            'reviewed parent readiness source differs')
    need('release_boundaries.py' not in helpers,'consumer source must come from this reviewed builder package')
    helpers['collect_r10_readiness.py']=readiness_raw
    helpers['release_boundaries.py']=consumer_raw
    need({'bind_slot_cleanup.py','wait_and_bind_model.py'}<=set(helpers),'startup helper sources missing')
    model_raw=read(v['server_binary']);need(sha(model_raw)==NATIVE_SERVER,'server binary differs')
    new_helper=read(v['focus_helper'])
    screen_row=v.get('screen_helper')
    need(screen_row=={"bytes":26156,"original_path":"/data/local/tmp/hepta-screen-codec-runtime-diag-a1055-v3-r1/original.jar","path":"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/codec-runtime-diagnostic-a1055-v3-candidate02/hepta-screen-codec-diagnostic-v3.jar","sha256":"54adf8e1434380b9b8414fac7ce1632a35ce8ebe97b5f1dc8b68af64fb6de60f","target":"/data/local/tmp/hepta-screen-codec-runtime-diag-a1055-v3-r1/codec.jar"},
         'exact new diagnostic screen helper provenance required')
    screen_raw=read(screen_row)
    need(len(screen_raw)==26156 and sha(screen_raw)=='54adf8e1434380b9b8414fac7ce1632a35ce8ebe97b5f1dc8b68af64fb6de60f',
         'new diagnostic screen helper bytes differ')
    need(v['focus_helper']['target'].startswith(HELPER+'/helpers/'),'helper target differs')
    parent_service_raw=read(v['parent_service_inputs'])
    need(sha(parent_service_raw)=='db89827f8068de55e35f577147de764cec66abee32bec63c424355d05204d2ff' and
         config['service_manifest_sha256']==sha(parent_service_raw),'parent service lineage differs')
    service=json.loads(parent_service_raw)
    need(service['schema']=='hepta.phone-local.service-inputs.v150.r9.1' and
         service['runtime']['server']['sha256']==NATIVE_SERVER,
         'parent runtime input differs')
    runtime_manifest_raw=read(v['runtime_source_manifest'])
    service['schema']='hepta.phone-local.service-inputs.v150.r10.1'
    service['scope']='Exact r9 runtime, model, executor/client, helpers and provider source bytes. Phone readiness, health, business and fault qualification remain separately evidenced.'
    service['parent_service_inputs_sha256']=REVIEWED_SOURCE_BINDING['material_parent_service_sha256']
    service['runtime']['server']=dict(path=MODEL+'/bin/llama-server',bytes=len(model_raw),sha256=sha(model_raw))
    service['runtime']['native_cancel_source_manifest_sha256']=sha(runtime_manifest_raw)
    service['runtime']['android_interpreter']='/system/bin/linker64'
    service['runtime']['needed_system_libraries']=['libm.so','libdl.so','libc.so']
    service['runtime']['cpu_text_and_image_cancel_required']=True
    service['runtime']['per_boot_receipts']=A+'/model-runtime-r10-r1/{boot_id}/receipts'
    service['runtime']['explicit_environment']={'LLAMA_HEPTA_CPU_CANCEL_SAFEPOINT':'1',
        'LLAMA_HEPTA_RECEIPT_DIR':A+'/model-runtime-r10-r1/{boot_id}/receipts'}
    # The already deployed strict helper is immutable, not appended twice.
    matching_helpers=[row for row in service['helpers'] if row['path']==v['focus_helper']['target']]
    need(len(matching_helpers)==1 and matching_helpers[0]['bytes']==len(new_helper)
         and matching_helpers[0]['sha256']==sha(new_helper)
         and sha(new_helper)=='c8ec62529d88a29872c313052cdd335dc7611b11089db87531008b35d926e855',
         'existing strict helper identity differs')
    old_screen=[row for row in service['helpers'] if row.get('path')=='/data/local/tmp/hepta-phone-executor-v150-r6/helpers/screen-codec-v148r1.jar']
    need(len(old_screen)==1 and old_screen[0]=={'byte_identical_copy_required': True, 'bytes': 16064, 'original_path': '/data/local/tmp/hepta-screen-v148-r1/codec.jar', 'path': '/data/local/tmp/hepta-phone-executor-v150-r6/helpers/screen-codec-v148r1.jar', 'sha256': 'bb1176b7707d1a2a67bcfd2bc9bd1b5db16036c3929f8eb1d8820b927ef62639'},
         'exact preserved old screen helper source row required')
    old_screen[0].clear();old_screen[0].update({'byte_identical_copy_required': True, 'bytes': 26156, 'original_path': '/data/local/tmp/hepta-screen-codec-runtime-diag-a1055-v3-r1/original.jar', 'path': '/data/local/tmp/hepta-screen-codec-runtime-diag-a1055-v3-r1/codec.jar', 'sha256': '54adf8e1434380b9b8414fac7ce1632a35ce8ebe97b5f1dc8b68af64fb6de60f'})
    service['provider_sources']=[dict(path='provider-r10-r1/source/'+name,bytes=len(raw),sha256=sha(raw))
                                 for name,raw in sorted(source.items())]
    service['approved_app_registry']=config['approved_apps']
    service['qualification_at_manifest_issue']=dict(actual_r10_startup='NOT_STARTED',
        native_new_helper='NOT_DEVICE_QUALIFIED',model_health='NEW_NONCE_REQUIRED',
        business_19='NOT_RUN_ON_THIS_COMBINATION',physical_faults='NOT_RUN',
        cold_boot='NOT_RUN',host_source_checks_do_not_grant_phone_qualification=True)
    service_raw=enc(service)
    config['service_manifest_sha256']=sha(service_raw)
    config_raw=enc(config);config_sha=sha(config_raw)
    need(dict(bytes=len(config_raw),sha256=sha(config_raw))==REVIEWED_SOURCE_BINDING['configuration']
         and dict(bytes=len(service_raw),sha256=sha(service_raw))==REVIEWED_SOURCE_BINDING['service'],
         'final release must retain the actual reviewed shared configuration and service bytes')
    # Both material-only and final release use these exact already-computed
    # bytes; no second config/service implementation or later guessed matching.
    shared_files=[dict(path='provider/source/'+name,bytes=len(raw),sha256=sha(raw))
                  for name,raw in sorted(source.items())]
    shared_files.extend([
        dict(path='local-config-r10-r1.json',bytes=len(config_raw),sha256=config_sha),
        dict(path='PHONE-SERVICE-INPUTS-v150-r10-r1.json',bytes=len(service_raw),sha256=sha(service_raw))])
    shared_files=sorted(shared_files,key=lambda row:row['path'])
    shared_value=dict(schema='hepta.r10.shared-production-materials.v1',
        state='HOST_SHARED_PRODUCTION_BYTES_NOT_INSTALLABLE',release_id='v150-r10-r1',
        source_input_sha256=sha(input_raw),parent_configuration_sha256=REVIEWED_SOURCE_BINDING['material_parent_configuration_sha256'],
        parent_service_inputs_sha256=REVIEWED_SOURCE_BINDING['material_parent_service_sha256'],files=shared_files,
        production_source_count=15,phone_calls=0,phone_qualification=False,
        policy_adoption_inferred=False)
    shared_raw=None
    if args.material_only:
        out=args.output;out.mkdir(mode=0o700)
        for name,raw in source.items():put(out/'provider/source'/name,raw)
        put(out/'local-config-r10-r1.json',config_raw)
        put(out/'PHONE-SERVICE-INPUTS-v150-r10-r1.json',service_raw)
        shared_raw=enc(shared_value);put(out/'SHARED-MATERIALS.json',shared_raw)
        result=dict(state=shared_value['state'],files=shared_files,
            shared_materials=dict(path=str(out/'SHARED-MATERIALS.json'),bytes=len(shared_raw),sha256=sha(shared_raw)),
            source_input_sha256=sha(input_raw),phone_calls=0,service_starts=0,
            module_generated=False,sealed_marker_created=False,archive_created=False)
        put(out/'MATERIAL-RESULT.json',enc(result));print(json.dumps(result,sort_keys=True));return
    if args.shared_materials is not None:
        shared_raw=args.shared_materials.read_bytes()
        need(sha(shared_raw)==args.shared_materials_sha256,'explicit shared material pin differs')
        original=json.loads(shared_raw)
        need(set(original)==set(shared_value)
             and original['source_input_sha256']==parent_formal_sha
             and all(original[key]==shared_value[key] for key in shared_value
                     if key!='source_input_sha256'),
             'component and final production source/config/service bytes differ')
    if boundary is not None:
        consumer['validate_shared_materials'](boundary,source,config_raw,service_raw)
    external_bindings=None if boundary is None else consumer['external_artifact_bindings'](boundary,source,service_raw)
    module=wire_module({r['name']:read(r) for r in v['module_sources']},config_sha)
    evidence={r['name']:read(r) for r in v['evidence']}
    if shared_raw is not None:
        need('SHARED-MATERIALS.json' not in evidence,'shared production evidence name is already used')
        evidence['SHARED-MATERIALS.json']=shared_raw
    if boundary is not None:
        need('RELEASE-BOUNDARIES.json' not in evidence,'boundary evidence name is already used')
        evidence['RELEASE-BOUNDARIES.json']=boundary_raw
        module['sepolicy.rule']=boundary['full_rule']
        component_activation(module,activation,boundary,fragment)
    parent_manifest_raw=read(v['parent_module_manifest'])
    parent_manifest=json.loads(parent_manifest_raw)
    need(sha(parent_manifest_raw)=='d7f276064d32ed6421a9b44e02db9c2374a637828434ec4373417d9235031c58'
         and parent_manifest['release_id']=='v150-r9-r2', 'current parent module identity differs')
    current_release_raw=read(v['current_release_manifest'])
    need(len(current_release_raw)==57152 and sha(current_release_raw)=='ec08482acbf8818631e2a9501eeb2b7ae277862967414d6e5b0ff14e832c66e6',
         'current original release raw bytes differ')
    current_release=json.loads(current_release_raw)
    need(current_release['release_id']=='v150-r9-r2' and current_release['migration_boot']==BOOT
         and current_release['policy_sha256']==ORIGINAL_RELEASE_POLICY
         and len(current_release['writes'])==90 and len(current_release['verify_existing'])==123,
         'current original release inventory differs')
    module_row=[row for row in current_release['writes']
        if row['target']=='/data/adb/modules/trillionnium_hepta_phone_local_v150_r9_r2/MODULE-MANIFEST-v150-r9-r2.json']
    need(len(module_row)==1 and module_row[0]['sha256']==sha(parent_manifest_raw)
         and module_row[0]['bytes']==len(parent_manifest_raw),'current release/module binding differs')
    retired=None;retirement_hash=None;failed_hash=None
    if args.retirement_inputs is not None:
        retirement_input_raw=args.retirement_inputs.read_bytes()
        need(args.retirement_inputs_sha256==sha(retirement_input_raw),'actual retirement input descriptor changed')
        r=json.loads(retirement_input_raw)
        retirement_raw=read(r['report']);operator_raw=read(r['operator'])
        retired=json.loads(retirement_raw);operator=json.loads(operator_raw);retirement_hash=sha(retirement_raw)
        need(retired['state']=='ORIGINAL_FOUR_GROUPS_ABSENT_STATE_PRESERVED'
             and retired['schema']=='hepta.r9-r2-retirement-observation.v1'
             and retired['boot_id']==BOOT and retired['original_role_identities']==OLD_ROLES
             and retired['original_effect_count']==len(retired['preserved_state']['executor_original_actions'])
             and retired['original_effect_count']>=10
             and retired['global_pending_clear'] is True and retired['server_lock_now_unheld'] is True,
             'actual current retirement is not complete')
        need(operator['state']=='R9_R2_RETIRED_ORIGINALS_PRESERVED'
             and operator['retirement_sha256']==retirement_hash and operator['live_policy_unchanged'] is True,
             'actual current retirement operator differs')
        for key in ('old_claims_deleted','old_task_terminal_rewritten','automatic_replay'):
            need(retired[key] is False,'retirement rewrote history')
        need(boundary is not None and boundary['retirement_sha256']==retirement_hash
             and boundary['component_input']['retirement']['probe']['sha256']==v['retirement_probe_sha256'],
             'final component boundary and generated retirement verifier differ')
        evidence['R9-R2-RETIREMENT.json']=retirement_raw
        evidence['R9-R2-RETIREMENT-OPERATOR.json']=operator_raw
        evidence['RETIREMENT-INPUTS.json']=retirement_input_raw
        ancestor_raw=read(r['ancestor_retirement'])
        need(sha(ancestor_raw)=='e22b4f20dfc82f634fe5fa0ac2be4578c2bbbffc67a617ebdf109bf485b3866d',
             'original r7-r3 retirement changed')
        evidence['R7-R3-RETIREMENT.json']=ancestor_raw
        failed_raw=read(r['failed_predecessor']);failed=json.loads(failed_raw);failed_hash=sha(failed_raw)
        need(failed_hash=='1bd4a67b7368466396612d2177d81831cc9fe6a9442a2e831159a4a263fdd89a'
             and failed['schema']=='hepta.r9-r1.preclaim-failure-closure.v1'
             and failed['state']=='ORIGINAL_PRECLAIM_FAILURE_CLOSED_MODULE_DISABLED'
             and failed['boot_id']==BOOT and failed['original_release']=='v150-r9-r1'
             and failed['retirement_sha256']==sha(ancestor_raw)
             and failed['prior_business_state_unchanged'] is True
             and failed['old_failures_preserved'] is True and failed['automatic_retry'] is False,
             'actual failed predecessor closure differs')
        evidence['R9-R1-FAILED-START-CLOSURE.json']=failed_raw
        for row in r.get('original_operation_evidence',[]):evidence[row['name']]=read(row)
    # All pinned source bytes are checked before any output is created.
    out=args.output;out.mkdir(mode=0o700)
    writes=[];blobs={}
    def add(target,raw,mode=0o600,label=None):
        need(target not in {x['target'] for x in writes},'duplicate integration write')
        member='payload/'+str(len(writes)).zfill(3)+'-'+Path(target).name
        row=dict(member=member,target=target,bytes=len(raw),sha256=sha(raw),mode=mode)
        if label:row['selinux']=label
        writes.append(row);blobs[member]=raw
    for name,raw in sorted(source.items()):add(A+'/provider-r10-r1/source/'+name,raw)
    for name,raw in sorted(helpers.items()):add(A+'/provider-r10-r1/'+name,raw)
    add(A+'/local-config-r10-r1.json',config_raw)
    add(A+'/PHONE-SERVICE-INPUTS-v150-r10-r1.json',service_raw)
    for name,raw in sorted(activation.items()):add(A+'/module-r10-activation-r1/'+name,raw)
    add(MODEL+'/bin/llama-server',model_raw,0o700,'u:object_r:shell_data_file:s0')
    # The exact strict helper already installed by r9-r1 is an immutable input.
    # No byte in the failed predecessor release is overwritten.
    source_seal=dict(schema='hepta.provider-r10.actual-integration-seal.v1',state='HOST_FROZEN_PHONE_NOT_STARTED',
        production_files=[dict(path='source/'+name,bytes=len(raw),sha256=sha(raw)) for name,raw in sorted(source.items())],
        configuration=dict(bytes=len(config_raw),sha256=config_sha),
        phone_service_inputs_sha256=sha(service_raw),model=config['model'],
        operator_helpers=[dict(path=name,bytes=len(raw),sha256=sha(raw)) for name,raw in sorted(helpers.items())],
        parent_configuration_sha256=sha(parent_config_raw),
        source_inputs_sha256=sha(input_raw),parent_sources_preserved=True,
        module_release='v150-r10-r1',phone_calls=0,model_requests=0,phone_business_qualified=False)
    source_seal_raw=enc(source_seal);add(A+'/provider-r10-r1/SOURCE-SEAL-v150-r10.json',source_seal_raw)
    # Every prior installed input and every original r9-r2 write stays pinned.
    existing=[dict(target=row['target'],bytes=row['bytes'],sha256=row['sha256'])
        for row in current_release['verify_existing']+current_release['writes']]
    need(len(existing)==213 and len({row['target'] for row in existing})==213,
         'current full original inventory is not unique')
    existing.extend(v.get('extra_existing_inputs',[]))
    if retired is not None:
        existing.extend([
            dict(target=A+'/module-retire-r9-r2-for-r10-r1-01/RETIREMENT.json',bytes=len(retirement_raw),sha256=retirement_hash),
            dict(target=A+'/module-retire-r9-r2-for-r10-r1-01/OPERATOR-RESULT.json',bytes=len(operator_raw),sha256=sha(operator_raw))])
    if boundary is not None:
        known={row['target']:row for row in existing}
        for original,_body in boundary['component_originals'].values():
            name=original['path']
            if name.startswith(G+'/'):target=A+name[len(G):]
            elif name.startswith('/proc/1/root/'):target=name[len('/proc/1/root'):]
            else:raise ValueError('component original is outside explicit GNU/Android mapping')
            row=dict(target=target,bytes=original['bytes'],sha256=original['sha256'])
            need(target not in known or known[target]==row,'component original conflicts with prior installed input')
            if target not in known:existing.append(row);known[target]=row
        for artifact in external_bindings:
            target=artifact['target']
            row=dict(target=target,bytes=artifact['bytes'],sha256=artifact['sha256'])
            need(target not in known or known[target]==row,
                 'component external dependency conflicts with prior installed input')
            need(target not in {entry['target'] for entry in writes},
                 'final release would overwrite a closed component dependency')
            if target not in known:existing.append(row);known[target]=row
        consumer['validate_external_inventory'](external_bindings,existing,path_key='target')
    need(len(existing)==len({r['target'] for r in existing})<=256,'duplicate/oversized existing input')
    source_targets=[dict(path=x['target'],bytes=x['bytes'],sha256=x['sha256']) for x in writes]
    payloads=sorted(source_targets+[dict(path=x['target'],bytes=x['bytes'],sha256=x['sha256']) for x in existing],key=lambda r:r['path'])
    module['activation-inputs.tsv']=(BOOT+'\t'+runtime_policy+'\n').encode()
    for name,raw in evidence.items():module['evidence/'+name]=raw
    module['evidence/INTEGRATION-INPUTS.json']=input_raw
    module['payload-inputs.sha256']=''.join(x['sha256']+'  '+x['path']+'\n' for x in payloads).encode()
    parent_by_path={row['path']:row for row in parent_manifest['payload_files']}
    payload_by_path={row['path']:row for row in payloads}
    new_targets={row['target'] for row in writes}
    for path,(size,pin) in STARTUP_ONLY_INPUTS.items():
        expected=dict(path=path,bytes=size,sha256=pin)
        need(parent_by_path.get(path)==expected and payload_by_path.get(path)==expected and path not in new_targets,
             'startup-only dependency differs or is a new release write: '+path)
    artifacts={x['path']:x['sha256'] for x in payloads if x['path'] not in STARTUP_ONLY_INPUTS}
    need(new_targets<=set(artifacts),'new release input omitted from role admission')
    artifacts.update({'evidence/'+name:sha(raw) for name,raw in evidence.items()})
    if retired is not None:
        artifacts[A+'/module-retire-r9-r2-for-r10-r1-01/RETIREMENT.json']=retirement_hash
        artifacts[A+'/module-retire-r9-r2-for-r10-r1-01/OPERATOR-RESULT.json']=sha(operator_raw)
    module['activation-artifacts.sha256']=''.join(pin+'  '+name+'\n' for name,pin in sorted(artifacts.items())).encode()
    binding=dict(schema='hepta.module-r10-r1.exact-integration.v1',release_id='v150-r10-r1',
        migration_boot=BOOT,policy_sha256=runtime_policy,policy_source_sha256=runtime_rule,
        parent_policy_sha256=PARENT_POLICY,shared_materials_sha256=None if shared_raw is None else sha(shared_raw),
        component_external_artifacts=external_bindings,
        component_boundary_inputs_sha256=None if boundary is None else boundary['component_input_sha256'],
        policy_adoption_inputs_sha256=None if boundary is None else boundary['policy_adoption_sha256'],
        component_boundary_sha256=None if boundary is None else boundary['component_boundary_sha256'],
        release_boundary_bundle_sha256=None if boundary is None else sha(boundary_raw),
        server_binary_sha256=NATIVE_SERVER,provider_source_seal_sha256=sha(source_seal_raw),
        configuration_sha256=config_sha,retirement_sha256=retirement_hash,
        failed_predecessor_sha256=failed_hash,failed_predecessor_sources_preserved=True,
        service_inputs_sha256=sha(service_raw),
        original_retirement_required=retired is None,old_effect_count=None if retired is None else retired['original_effect_count'],
        old_claims_and_actions_preserved=True,phone_installed=False,phone_ready=False,
        final_19_qualification=False,cold_boot_qualified=False,payloads=payloads)
    module['seal-binding.json']=enc(binding)
    module_manifest=dict(schema='hepta.module-r10-r1.file-manifest.v1',module_id=Path(MODULE).name,
        release_id='v150-r10-r1',binding_sha256=sha(module['seal-binding.json']),
        files=[dict(path=name,bytes=len(raw),sha256=sha(raw)) for name,raw in sorted(module.items())],
        payload_files=payloads,retirement_sha256=retirement_hash,phone_qualification=False)
    module['MODULE-MANIFEST-v150-r10-r1.json']=enc(module_manifest)
    module['module-inputs.sha256']=''.join(sha(raw)+'  '+name+'\n' for name,raw in sorted(module.items())).encode()
    # A source-only preparation cannot be mistaken for an installable seal.
    if retired is not None:module['SEALED']=b'HEPTA_PHONE_LOCAL_V150_R10_R1_REVIEWED_INPUTS_BOUND\n'
    for name,raw in sorted(module.items()):add(MODULE+'/'+name,raw,0o700 if name=='service.sh' else 0o600)
    release=dict(schema='hepta.phone-release.v1',release_id='v150-r10-r1',migration_boot=BOOT,
        policy_sha256=runtime_policy,parent_policy_sha256=PARENT_POLICY,module_dir=MODULE,runtime_dir=MODEL,provider_dir=A+'/provider-r10-r1',
        activation_dir=A+'/module-r10-activation-r1',helper_dir=HELPER,writes=writes,
        verify_existing=existing,retirement_probe_sha256=v['retirement_probe_sha256'],
        retirement_sha256=retirement_hash,failed_predecessor_sha256=failed_hash,runtime_directories=[
            dict(path=HISTORY),dict(path=A+'/model-runtime-r10-r1'),
            dict(path=A+'/executor-r6/module-history-r10-r1',selinux='u:object_r:trillionnium_owner_open_phone_executor_data_file:s0')])
    if boundary is not None:
        release.update(component_boundary_inputs_sha256=boundary['component_input_sha256'],
            policy_adoption_inputs_sha256=boundary['policy_adoption_sha256'],
            component_boundary_sha256=boundary['component_boundary_sha256'],
            component_external_artifacts=external_bindings,
            boundary_consumer_sha256=BOUNDARY_CONSUMER_SHA256,
            release_boundary_bundle=dict(target=MODULE+'/evidence/RELEASE-BOUNDARIES.json',
                bytes=len(boundary_raw),sha256=sha(boundary_raw)),
            retirement_probe_bytes=boundary['component_input']['retirement']['probe']['bytes'])
        consumer['validate_install_layout'](boundary,release)
    release['shared_materials_sha256']=None if shared_raw is None else sha(shared_raw)
    for name,raw in source.items():put(out/'provider/source'/name,raw)
    for name,raw in helpers.items():put(out/'provider'/name,raw)
    put(out/'provider/SOURCE-SEAL-v150-r10.json',source_seal_raw)
    for name,raw in module.items():put(out/'module'/name,raw,0o700 if name=='service.sh' else 0o600)
    for name,raw in activation.items():put(out/'activation'/name,raw)
    put(out/'local-config-r10-r1.json',config_raw)
    put(out/'PHONE-SERVICE-INPUTS-v150-r10-r1.json',service_raw)
    put(out/'release.json',enc(release))
    report=dict(schema='hepta.r10.integration-build.v1',state='SOURCE_ONLY_NOT_INSTALLABLE' if retired is None else 'SEALED_ACTUAL_RETIREMENT_BOUND',
        input_sha256=sha(input_raw),module_manifest_sha256=sha(module['MODULE-MANIFEST-v150-r10-r1.json']),
        source_seal_sha256=sha(source_seal_raw),production_source_count=len(source),
        configuration_sha256=config_sha,service_inputs_sha256=sha(service_raw),
        payload_write_count=len(writes),existing_input_count=len(existing),retirement_sha256=retirement_hash,
        failed_predecessor_sha256=failed_hash,
        phone_calls=0,model_requests=0,
        policy_sha256=runtime_policy,parent_policy_sha256=PARENT_POLICY,
        component_boundary_inputs_sha256=None if boundary is None else boundary['component_input_sha256'],
        policy_adoption_inputs_sha256=None if boundary is None else boundary['policy_adoption_sha256'],
        component_boundary_sha256=None if boundary is None else boundary['component_boundary_sha256'],
        release_boundary_bundle_sha256=None if boundary is None else sha(boundary_raw),
        shared_materials_sha256=None if shared_raw is None else sha(shared_raw))
    if retired is not None:
        archive=out/'phone-release-v150-r10-r1.tar.gz'
        with archive.open('xb') as stream, gzip.GzipFile(filename='',mode='wb',fileobj=stream,mtime=0) as gz, \
             tarfile.open(fileobj=gz,mode='w',format=tarfile.USTAR_FORMAT) as tar:
            allblobs={'release.json':enc(release),**blobs}
            for name,raw in sorted(allblobs.items()):
                member=tarfile.TarInfo(name);member.size=len(raw);member.mode=0o600
                member.uid=member.gid=0;member.mtime=0;tar.addfile(member,io.BytesIO(raw))
        raw=archive.read_bytes();report['archive']=dict(path=str(archive),bytes=len(raw),sha256=sha(raw))
    put(out/'BUILD-RESULT.json',enc(report))
    print(json.dumps(report,sort_keys=True))


if __name__=='__main__':main()
