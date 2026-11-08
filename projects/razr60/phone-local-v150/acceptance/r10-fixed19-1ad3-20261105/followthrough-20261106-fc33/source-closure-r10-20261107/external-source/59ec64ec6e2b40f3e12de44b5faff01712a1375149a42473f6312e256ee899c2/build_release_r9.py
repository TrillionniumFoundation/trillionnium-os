#!/usr/bin/env python3
"""Freeze one reviewed r9 integration and bind it to an actual r7-r3 retirement.

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
POLICY='bfe7acc92ba8c5b7a3a1c2360d6faf53f804a19c3e25e20aad336e3220fa0e38'
POLICY_SOURCE='30f3963d10aa4c4eea70c31c8f80278490be3c16986fb029853b5bc217a4b6f8'
NATIVE_SERVER='dbca8b3c6d024c414d018146e73df996cae51b18c8cf5d3bdab6b776318a348c'
A='/data/trillionnium/owner-open/state/phone-local-v150'
G='/var/lib/trillionnium/owner-open/phone-local-v150'
MODULE='/data/adb/modules/trillionnium_hepta_phone_local_v150_r9_r1'
MODEL='/data/local/tmp/hepta-phone-local-v150-r9-r1'
HELPER='/data/local/tmp/hepta-phone-executor-v150-r9-r1'
HISTORY='/data/adb/trillionnium-hepta-phone-local-v150-r9-r1'
OLD_ROLES={'supervisor':[571,571,571,10690877],'model':[707,707,707,10691094],
           'sidecar':[987,987,987,10691164],'provider':[1286,1286,1286,10691228]}
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
NATIVE_RUN=/data/trillionnium/owner-open/state/phone-local-v150/model-runtime-r9-r1/$boot_id
GNU_RUN=/var/lib/trillionnium/owner-open/phone-local-v150/model-runtime-r9-r1/$boot_id
[ -d "$NATIVE_RUN" ] && [ ! -L "$NATIVE_RUN" ]
[ "$("$SYS/readlink" -f "$NATIVE_RUN")" = "$NATIVE_RUN" ]
[ "$("$SYS/stat" -c '%u:%g:%a' "$NATIVE_RUN")" = 0:0:700 ]
'''


def wire_module(module,config_sha):
    need(sha(module['sepolicy.rule'])==POLICY_SOURCE,'policy source changed')
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
    line=once(line,'/provider-r8/source/daily_phone_local.py','/provider-r9/source/daily_phone_local.py')
    line=once(line,'/local-config-r8.json','/local-config-r9.json')
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
MODEL_RUNTIME_ROOT=/data/trillionnium/owner-open/state/phone-local-v150/model-runtime-r9-r1
MODEL_RUN=$MODEL_RUNTIME_ROOT/$boot_id
GNU_MODEL_RUN=/var/lib/trillionnium/owner-open/phone-local-v150/model-runtime-r9-r1/$boot_id
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
        /var/lib/trillionnium/owner-open/phone-local-v150/provider-r9/wait_and_bind_model.py \\
        --config /var/lib/trillionnium/owner-open/phone-local-v150/local-config-r9.json \\
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
    for name,raw in module.items():
        if name.endswith('.sh'):
            need(b'v150-r8' not in raw and b'provider-r8' not in raw,'stale r8 executable path: '+name)
            result=subprocess.run(['/bin/sh','-n'],input=raw,capture_output=True)
            need(result.returncode==0,'shell syntax: '+name+': '+result.stderr.decode())
    return module


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--inputs',type=Path,required=True)
    p.add_argument('--inputs-sha256',required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--retirement-inputs',type=Path)
    p.add_argument('--retirement-inputs-sha256')
    args=p.parse_args();os.umask(0o077)
    input_raw=args.inputs.read_bytes();need(sha(input_raw)==args.inputs_sha256,'integration inputs changed')
    v=json.loads(input_raw)
    need(v['schema']=='hepta.r9.reviewed-integration-inputs.v1','input schema')
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
    for name,raw in source.items():compile(raw,name,'exec')
    parent_config_raw=read(v['configuration']);config=json.loads(parent_config_raw)
    need(config['backend']=='phone_local' if 'backend' in config else True,'local backend required')
    activation={r['name']:read(r) for r in v['activation_sources']}
    helpers={r['name']:read(r) for r in v['provider_helpers']}
    need({'bind_slot_cleanup.py','wait_and_bind_model.py'}<=set(helpers),'startup helper sources missing')
    model_raw=read(v['server_binary']);need(sha(model_raw)==NATIVE_SERVER,'server binary differs')
    new_helper=read(v['focus_helper'])
    need(v['focus_helper']['target'].startswith(HELPER+'/helpers/'),'helper target differs')
    parent_service_raw=read(v['parent_service_inputs'])
    need(sha(parent_service_raw)=='ccb7cacf0dd9e4e12daba09515a56633363dd9f04607b44546df1e493d15bfd2' and
         config['service_manifest_sha256']==sha(parent_service_raw),'parent service lineage differs')
    service=json.loads(parent_service_raw)
    need(service['schema']=='hepta.phone-local.service-inputs.v150.3' and
         service['runtime']['server']['sha256']=='7e8ea2c601bc3415f8698cca00fbe4737a2093873ba0705d749ae8d6908b3176',
         'parent runtime input differs')
    runtime_manifest_raw=read(v['runtime_source_manifest'])
    service['schema']='hepta.phone-local.service-inputs.v150.r9.1'
    service['scope']='Exact r9 runtime, model, executor/client, helpers and provider source bytes. Phone readiness, health, business and fault qualification remain separately evidenced.'
    service['parent_service_inputs_sha256']=sha(parent_service_raw)
    service['runtime']['server']=dict(path=MODEL+'/bin/llama-server',bytes=len(model_raw),sha256=sha(model_raw))
    service['runtime']['native_cancel_source_manifest_sha256']=sha(runtime_manifest_raw)
    service['runtime']['android_interpreter']='/system/bin/linker64'
    service['runtime']['needed_system_libraries']=['libm.so','libdl.so','libc.so']
    service['runtime']['cpu_text_and_image_cancel_required']=True
    service['runtime']['per_boot_receipts']=A+'/model-runtime-r9-r1/{boot_id}/receipts'
    service['runtime']['explicit_environment']={'LLAMA_HEPTA_CPU_CANCEL_SAFEPOINT':'1',
        'LLAMA_HEPTA_RECEIPT_DIR':A+'/model-runtime-r9-r1/{boot_id}/receipts'}
    service['helpers'].append(dict(path=v['focus_helper']['target'],bytes=len(new_helper),sha256=sha(new_helper),
        typed_operation='phone.focus_input_text',legacy_input_contract_unchanged=True))
    service['provider_sources']=[dict(path='provider-r9/source/'+name,bytes=len(raw),sha256=sha(raw))
                                 for name,raw in sorted(source.items())]
    service['approved_app_registry']=config['approved_apps']
    service['qualification_at_manifest_issue']=dict(actual_r9_startup='NOT_STARTED',
        native_new_helper='NOT_DEVICE_QUALIFIED',model_health='NEW_NONCE_REQUIRED',
        business_19='NOT_RUN_ON_THIS_COMBINATION',physical_faults='NOT_RUN',
        cold_boot='NOT_RUN',host_source_checks_do_not_grant_phone_qualification=True)
    service_raw=enc(service)
    config['service_manifest_sha256']=sha(service_raw)
    config_raw=enc(config);config_sha=sha(config_raw)
    module=wire_module({r['name']:read(r) for r in v['module_sources']},config_sha)
    evidence={r['name']:read(r) for r in v['evidence']}
    parent_manifest=json.loads(read(v['parent_module_manifest']))
    need(parent_manifest['module_attempt']=='v150-r7-r3' and parent_manifest['live_policy_sha256']==POLICY,
         'parent module identity differs')
    retired=None;retirement_hash=None
    if args.retirement_inputs is not None:
        retirement_input_raw=args.retirement_inputs.read_bytes()
        need(args.retirement_inputs_sha256==sha(retirement_input_raw),'actual retirement input descriptor changed')
        r=json.loads(retirement_input_raw)
        retirement_raw=read(r['report']);operator_raw=read(r['operator'])
        retired=json.loads(retirement_raw);operator=json.loads(operator_raw);retirement_hash=sha(retirement_raw)
        need(retired['state']=='ORIGINAL_FOUR_GROUPS_ABSENT_STATE_PRESERVED' and
             retired['schema']=='hepta.r7-r3-retirement-observation.v1' and retired['boot_id']==BOOT and
             retired['original_role_identities']==OLD_ROLES and retired['original_effect_count']==6 and
             retired['global_pending_clear'] is True and retired['server_lock_now_unheld'] is True,
             'actual retirement is not complete')
        need(operator['state']=='R7_R3_RETIRED_ORIGINALS_PRESERVED' and
             operator['retirement_sha256']==retirement_hash and operator['live_policy_unchanged'] is True,
             'actual retirement operator differs')
        for key in ('old_claims_deleted','old_task_terminal_rewritten','automatic_replay'):
            need(retired[key] is False,'retirement rewrote history')
        evidence['R7-R3-RETIREMENT.json']=retirement_raw
        evidence['R7-R3-RETIREMENT-OPERATOR.json']=operator_raw
        evidence['RETIREMENT-INPUTS.json']=retirement_input_raw
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
    for name,raw in sorted(source.items()):add(A+'/provider-r9/source/'+name,raw)
    for name,raw in sorted(helpers.items()):add(A+'/provider-r9/'+name,raw)
    add(A+'/local-config-r9.json',config_raw)
    add(A+'/PHONE-SERVICE-INPUTS-v150-r9.json',service_raw)
    for name,raw in sorted(activation.items()):add(A+'/module-r9-activation-r1/'+name,raw)
    add(MODEL+'/bin/llama-server',model_raw,0o700,'u:object_r:shell_data_file:s0')
    add(v['focus_helper']['target'],new_helper,0o644,'u:object_r:trillionnium_owner_open_phone_helper_file:s0')
    source_seal=dict(schema='hepta.provider-r9.actual-integration-seal.v1',state='HOST_FROZEN_PHONE_NOT_STARTED',
        production_files=[dict(path='source/'+name,bytes=len(raw),sha256=sha(raw)) for name,raw in sorted(source.items())],
        configuration=dict(bytes=len(config_raw),sha256=config_sha),
        phone_service_inputs_sha256=sha(service_raw),model=config['model'],
        operator_helpers=[dict(path=name,bytes=len(raw),sha256=sha(raw)) for name,raw in sorted(helpers.items())],
        parent_configuration_sha256=sha(parent_config_raw),
        source_inputs_sha256=sha(input_raw),parent_sources_preserved=True,
        module_release='v150-r9-r1',phone_calls=0,model_requests=0,phone_business_qualified=False)
    source_seal_raw=enc(source_seal);add(A+'/provider-r9/SOURCE-SEAL-v150-r9.json',source_seal_raw)
    existing=[dict(target=row['path'],bytes=row['bytes'],sha256=row['sha256']) for row in parent_manifest['payload_files']]
    # Existing code, original model, weights, apps, helpers and proofs remain verified dependencies.
    existing.extend(v.get('extra_existing_inputs',[]))
    need(len(existing)==len({r['target'] for r in existing}),'duplicate existing input')
    source_targets=[dict(path=x['target'],bytes=x['bytes'],sha256=x['sha256']) for x in writes]
    payloads=sorted(source_targets+[dict(path=x['target'],bytes=x['bytes'],sha256=x['sha256']) for x in existing],key=lambda r:r['path'])
    module['activation-inputs.tsv']=(BOOT+'\t'+POLICY+'\n').encode()
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
        artifacts[A+'/module-retire-r7-r3-for-r8-r1-01/RETIREMENT.json']=retirement_hash
        artifacts[A+'/module-retire-r7-r3-for-r8-r1-01/OPERATOR-RESULT.json']=sha(operator_raw)
    module['activation-artifacts.sha256']=''.join(pin+'  '+name+'\n' for name,pin in sorted(artifacts.items())).encode()
    binding=dict(schema='hepta.module-r9-r1.exact-integration.v1',release_id='v150-r9-r1',
        migration_boot=BOOT,policy_sha256=POLICY,policy_source_sha256=POLICY_SOURCE,
        server_binary_sha256=NATIVE_SERVER,provider_source_seal_sha256=sha(source_seal_raw),
        configuration_sha256=config_sha,retirement_sha256=retirement_hash,
        service_inputs_sha256=sha(service_raw),
        original_retirement_required=retired is None,old_effect_count=6,
        old_claims_and_actions_preserved=True,phone_installed=False,phone_ready=False,
        final_19_qualification=False,cold_boot_qualified=False,payloads=payloads)
    module['seal-binding.json']=enc(binding)
    module_manifest=dict(schema='hepta.module-r9-r1.file-manifest.v1',module_id=Path(MODULE).name,
        release_id='v150-r9-r1',binding_sha256=sha(module['seal-binding.json']),
        files=[dict(path=name,bytes=len(raw),sha256=sha(raw)) for name,raw in sorted(module.items())],
        payload_files=payloads,retirement_sha256=retirement_hash,phone_qualification=False)
    module['MODULE-MANIFEST-v150-r9-r1.json']=enc(module_manifest)
    module['module-inputs.sha256']=''.join(sha(raw)+'  '+name+'\n' for name,raw in sorted(module.items())).encode()
    # A source-only preparation cannot be mistaken for an installable seal.
    if retired is not None:module['SEALED']=b'HEPTA_PHONE_LOCAL_V150_R9_R1_REVIEWED_INPUTS_BOUND\n'
    for name,raw in sorted(module.items()):add(MODULE+'/'+name,raw,0o700 if name=='service.sh' else 0o600)
    for name,raw in source.items():put(out/'provider/source'/name,raw)
    for name,raw in helpers.items():put(out/'provider'/name,raw)
    put(out/'provider/SOURCE-SEAL-v150-r9.json',source_seal_raw)
    for name,raw in module.items():put(out/'module'/name,raw,0o700 if name=='service.sh' else 0o600)
    for name,raw in activation.items():put(out/'activation'/name,raw)
    put(out/'local-config-r9.json',config_raw)
    put(out/'PHONE-SERVICE-INPUTS-v150-r9.json',service_raw)
    release=dict(schema='hepta.phone-release.v1',release_id='v150-r9-r1',migration_boot=BOOT,
        policy_sha256=POLICY,module_dir=MODULE,runtime_dir=MODEL,provider_dir=A+'/provider-r9',
        activation_dir=A+'/module-r9-activation-r1',helper_dir=HELPER,writes=writes,
        verify_existing=existing,retirement_probe_sha256=v['retirement_probe_sha256'],
        retirement_sha256=retirement_hash,runtime_directories=[
            dict(path=HISTORY),dict(path=A+'/model-runtime-r9-r1'),
            dict(path=A+'/executor-r6/module-history-r9-r1',selinux='u:object_r:trillionnium_owner_open_phone_executor_data_file:s0')])
    put(out/'release.json',enc(release))
    report=dict(schema='hepta.r9.integration-build.v1',state='SOURCE_ONLY_NOT_INSTALLABLE' if retired is None else 'SEALED_ACTUAL_RETIREMENT_BOUND',
        input_sha256=sha(input_raw),module_manifest_sha256=sha(module['MODULE-MANIFEST-v150-r9-r1.json']),
        source_seal_sha256=sha(source_seal_raw),production_source_count=len(source),
        configuration_sha256=config_sha,service_inputs_sha256=sha(service_raw),
        payload_write_count=len(writes),existing_input_count=len(existing),retirement_sha256=retirement_hash,
        phone_calls=0,model_requests=0)
    if retired is not None:
        archive=out/'phone-release-v150-r9-r1.tar.gz'
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
