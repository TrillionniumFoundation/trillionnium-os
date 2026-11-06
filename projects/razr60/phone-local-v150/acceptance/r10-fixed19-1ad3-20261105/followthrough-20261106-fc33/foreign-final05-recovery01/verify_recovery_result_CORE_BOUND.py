#!/usr/bin/env python3
"""Verify one actual finite recovery result on Pocket4; no phone or signals.

The frozen descriptor is bound only after Root reviews the final recovery source.
Original phone output is retained unchanged. A separately labelled in-memory
preflight adapter reuses the exact earlier pure readonly validator; it is never
published as a phone original or as a claim that the recovery was readonly.
"""
from pathlib import Path
import argparse, ast, base64, copy, hashlib, json, lzma, os, shlex, stat, types, zlib

FROZEN = None
CORE_VALIDATOR_RAW = b'#!/usr/bin/env python3\n"""Read one existing durable result, preserve it, and verify the bounded packet.\n\nHost only: no phone actor, subprocess, signal, socket or native/model request.\n"""\nfrom pathlib import Path\nimport argparse,ast,base64,hashlib,json,os,shlex,stat,zlib\n\nSOURCE_SHA=\'70c4dc710368da58f609208879f1fb83af5e0b428b712cfd31b8bced1907bc44\'\nSOURCE_BYTES=63646\nLABEL=\'ng-fc33-final05-failed-scope-readonly01\'\ndef need(ok,why):\n    if not ok:raise ValueError(why)\ndef sha(raw):return hashlib.sha256(raw).hexdigest()\ndef enc(value):return (json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(\',\',\':\'),allow_nan=False)+\'\\n\').encode()\ndef strict(raw):\n    def pairs(rows):\n        d={}\n        for k,v in rows:\n            need(k not in d,\'duplicate JSON key\');d[k]=v\n        return d\n    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,\'nonfinite JSON\'))\ndef full9(s):return [getattr(s,k) for k in (\'st_dev\',\'st_ino\',\'st_mode\',\'st_uid\',\'st_gid\',\'st_nlink\',\'st_size\',\'st_mtime_ns\',\'st_ctime_ns\')]\ndef read_exact(path,size,digest):\n    need(path.resolve(strict=True)==path,\'canonical host original path\')\n    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)\n    try:\n        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==size,\'host original regular file size\')\n        with os.fdopen(fd,\'rb\',closefd=False) as stream:raw=stream.read(size+1)\n        need(len(raw)==size and sha(raw)==digest and full9(a)==full9(os.fstat(fd))==full9(path.lstat()),\'host original bytes/full9 changed\')\n        return raw,{\'path\':str(path),\'bytes\':size,\'sha256\':digest,\'metadata\':full9(a)}\n    finally:os.close(fd)\ndef decode_zlib(encoded_raw,expected_size,expected_sha,limit):\n    need(len(encoded_raw)<=limit,\'compressed input bound\')\n    z=zlib.decompressobj();raw=z.decompress(encoded_raw,expected_size+1)\n    need(z.eof and not z.unused_data and not z.unconsumed_tail and len(raw)==expected_size and sha(raw)==expected_sha,\'complete exact zlib stream\')\n    return raw\ndef write_new(root,name,raw):\n    p=root/name\n    need(p.parent==root or root in p.parents,\'host output namespace\')\n    p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)\n    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n    with os.fdopen(fd,\'wb\') as s:s.write(raw);s.flush();os.fsync(s.fileno())\n    return {\'path\':str(p),\'bytes\':len(raw),\'sha256\':sha(raw)}\ndef check_metadata_row(row):\n    m=row.get(\'metadata\')\n    need(type(m) is list and len(m)==9 and all(type(v) is int and v>=0 for v in m),\'actual full9 shape\')\ndef tree_complete(observed,blobs):\n    roots=observed[\'roots\'];rows=observed[\'entries\'];total=0\n    need(len(roots)==len(set(roots)) and type(rows) is dict,\'tree roots/rows\')\n    for path,row in rows.items():\n        need(row[\'path\']==path and sum(path==r or path.startswith(r+\'/\') for r in roots)==1,\'tree exact lexical root\')\n        if row[\'kind\']==\'absent\':\n            need(path in roots and row[\'absence\']==\'ENOENT\' and row[\'no_effect_inferred\'] is False,\'exact root absence only\')\n            continue\n        check_metadata_row(row)\n        if row[\'kind\']==\'directory\':\n            names=sorted(p.rsplit(\'/\',1)[-1] for p in rows if p.rsplit(\'/\',1)[0]==path)\n            need(row[\'names\']==names and len(names)==len(set(names)),\'complete directory children\')\n        else:\n            need(row[\'kind\']==\'file\' and row[\'metadata\'][6]==row[\'bytes\'],\'regular file size row\')\n            total+=row[\'bytes\']\n            if blobs is not None:\n                need(row[\'sha256\'] in blobs and len(blobs[row[\'sha256\']])==row[\'bytes\'],\'every private byte preserved\')\n    need(total==observed[\'file_bytes_hashed\'],\'tree byte accounting\')\n\ndef validate(value,g,blobs):\n    evidence=value[\'evidence\'];inputs=g[\'INPUTS\'];scope=value[\'scope\']\n    need(scope=={\'label\':g[\'LABEL\'],\'nonce\':g[\'NONCE\'],\'lease_sha256\':g[\'LEASE_SHA\'],\'runtime_sha256\':g[\'PACKAGE_SHA\'],\'boot_id\':g[\'BOOT\']},\'exact failed old scope\')\n    need(value[\'inputs_sha256\']==g[\'INPUTS_SHA\'],\'exact probe inputs\')\n    for key in (\'file_writes\',\'file_deletes\',\'nonzero_signals_to_other_processes\',\'ui_inputs\',\'model_requests\',\'native_dispatches\',\'endpoint_connections\',\'target_programs_imported_or_executed\'):\n        need(value[key]==0 and type(value[key]) is int,\'readonly count \'+key)\n    need(value[\'scope_closure\'] is False and value[\'qualified_source_parent\'] is False and value[\'deletion_authorized\'] is False,\'no qualification or cleanup claim\')\n    baseline_raw=blobs[inputs[\'baseline\'][\'sha256\']];need(len(baseline_raw)==inputs[\'baseline\'][\'bytes\'],\'old44 original length\')\n    baseline=strict(baseline_raw)\n    for which in (\'baseline_before\',\'baseline_after\'):\n        observed=evidence[which];tree_complete(observed,None);g[\'compare_baseline\'](observed,baseline)\n    need(g[\'stable_tree_projection\'](evidence[\'baseline_before\'])==g[\'stable_tree_projection\'](evidence[\'baseline_after\']),\'old44 exact fresh bookends\')\n    for which in (\'private_before\',\'private_after\'):tree_complete(evidence[which],blobs)\n    need(g[\'stable_tree_projection\'](evidence[\'private_before\'])==g[\'stable_tree_projection\'](evidence[\'private_after\']),\'private fresh bookends\')\n    g[\'STATE\']={\'blobs\':{h:{\'bytes\':len(b),\'base64\':base64.b64encode(b).decode()} for h,b in blobs.items()}}\n    g[\'require_known_originals\'](evidence[\'private_before\'])\n    archive_pin=next(r for r in inputs[\'transport\'] if r[\'path\']==inputs[\'archive_path\'])\n    files=g[\'archive_members\'](blobs[archive_pin[\'sha256\']])\n    stage=g[\'immutable_stage_members\'](files,evidence[\'private_before\'])\n    need(stage==evidence[\'stage_members\'],\'all61 complete actual byte checks\')\n    locks=evidence[\'locks\'];need(locks[\'alias_count\']==28 and locks[\'inode_group_count\']==15 and locks[\'old_inode_group_count\']==14,\'all15 existing lock groups\')\n    need(len(locks[\'aliases\'])==28 and len({tuple(r[\'metadata\'][:2]) for r in locks[\'aliases\']})==15,\'actual lock aliases grouped by inode\')\n    need(evidence[\'parents_before\']==evidence[\'parents_after\'] and evidence[\'home_aliases_before\']==evidence[\'home_aliases_after\'],\'actual parent/alias bookends\')\n    process=evidence[\'process_windows\'];need(len(process)==2 and [r[\'index\'] for r in process]==[0,1],\'two fresh process windows\')\n    for window in process:\n        need(window[\'original_identities\']==inputs[\'role_identities\'],\'original exact two roles\')\n        census=window[\'census\'];need(census[\'complete\'] is True and sorted(census[\'stat_originals\'],key=int)==census[\'names\'],\'complete proc enumeration\')\n        need(census[\'numeric_pid_count\']==len(census[\'names\'])<=4096,\'proc count bound\')\n        members=[];disappeared=[]\n        ids={tuple(v) for v in inputs[\'role_identities\'].values()};groups={v[1] for v in ids};sessions={v[2] for v in ids}\n        for pid,row in census[\'stat_originals\'].items():\n            if row[\'state\']==\'OBSERVED_ENOENT\':\n                need(row[\'errno\']==2,\'only disappearing PID ENOENT\');disappeared.append(int(pid));continue\n            raw=base64.b64decode(row[\'base64\'],validate=True)\n            need(len(raw)==row[\'bytes\']<=8192 and sha(raw)==row[\'sha256\'],\'complete proc original\')\n            parsed=g[\'stat_identity\'](raw,int(pid),census=True)\n            need(parsed==row[\'identity\'],\'independent proc stat parsing\')\n            if tuple(g[\'generation\'](parsed)) in ids or parsed[\'pgid\'] in groups or parsed[\'sid\'] in sessions:members.append(parsed)\n        need(not members and census[\'members\']==[] and sorted(disappeared)==sorted(census[\'disappeared_while_reading\']),\'no declared generation/group/session in complete census\')\n        q=window[\'kernel_group_queries\'];need(len(q)==2,\'two kernel queries per window\')\n        for row in q:\n            identity=inputs[\'role_identities\'][row[\'role\']]\n            need(row[\'identity\']==identity and row[\'pid_argument\']==-identity[1] and row[\'signal\']==0\n                 and row[\'syscall\']==\'kill\' and row[\'state\']==\'ESRCH\' and row[\'errno\']==3,\'exact signal-zero ESRCH query\')\n    rows=evidence[\'private_before\'][\'entries\'];home=str(g[\'SCOPE_HOME\']);journal=str(g[\'JOURNAL\']);fixture=str(g[\'FIXTURE\'])\n    present=[n for n in inputs[\'inspect_absence_names\'] if home+\'/\'+n in rows]\n    claims=rows[home+\'/claims\'];operator=rows[home+\'/operator\'];actions=rows.get(journal+\'/actions\')\n    return {\'original44_full_inventory_equal\':True,\'original44_roots\':len(baseline[\'roots\']),\n        \'original44_entries\':len(baseline[\'entries\']),\'original44_file_bytes_hashed_each_window\':baseline[\'file_bytes_hashed\'],\n        \'runtime37_and_stage61_exact\':True,\'private_entry_count\':len(rows),\'private_file_bytes_each_window\':evidence[\'private_before\'][\'file_bytes_hashed\'],\n        \'fresh_known_groups_absent_two_windows\':True,\'signal_zero_ESRCH_count\':4,\n        \'unexpected_expected_absence_records_present\':present,\'claims_names\':claims[\'names\'],\'operator_names\':operator[\'names\'],\n        \'actions_names\':None if actions is None else actions[\'names\'],\'fixture_kind\':rows[fixture][\'kind\'],\n        \'bounded_no_claim_or_action_records\':not present and claims[\'names\']==[] and operator[\'names\']==[] and actions is not None and actions[\'names\']==[] and rows[fixture][\'kind\']==\'absent\',\n        \'scope_closure\':False,\'cleanup_authorized\':False,\'historical_native_or_effect_count_inferred\':None}\n\ndef main():\n    p=argparse.ArgumentParser();p.add_argument(\'--result\',required=True);p.add_argument(\'--bytes\',required=True,type=int);p.add_argument(\'--sha256\',required=True);p.add_argument(\'--out\',required=True);a=p.parse_args()\n    path=Path(a.result);need(path==Path(\'/home/alex/razr60-local-model-v150/operations\')/LABEL/\'result.json\',\'one existing operation only\')\n    need(0<a.bytes<=12*1024*1024,\'durable result cap\')\n    raw,descriptor=read_exact(path,a.bytes,a.sha256);operation=strict(raw)\n    need(operation[\'label\']==LABEL and operation[\'status\']==\'command_exited\' and operation[\'model_decision\'] is False and operation[\'native_task_result\'] is False,\'actual one read-only operation\')\n    actor_path=Path(\'/home/alex/razr60-local-model-v150/ops/phone_once.py\')\n    actor_raw,actor_descriptor=read_exact(actor_path,5652,\'179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22\')\n    request_path=Path(\'/home/alex/razr60-local-model-v150/requests\')/(LABEL+\'.json\')\n    request_raw,request_descriptor=read_exact(request_path,24502,\'0f49925c1eee833bdfeeddef788bb1ce51b3336b824a6ea07ca5a7919c092342\')\n    request=strict(request_raw)\n    need(set(request)=={\'kind\',\'root\',\'timeout_seconds\',\'command\'} and request[\'kind\']==\'shell\'\n         and request[\'root\'] is True and request[\'timeout_seconds\']==70,\'exact actual published request\')\n    # Exact transformation from the fully reviewed, SHA-pinned phone_once.py:\n    # if req.get(\'root\'): command=\'/debug_ramdisk/su -c \'+shlex.quote(command)\n    command=operation[\'phone\'][\'command\']\n    need(command==\'/debug_ramdisk/su -c \'+shlex.quote(request[\'command\']),\'exact pinned actor root=true transformation\')\n    outer=shlex.split(request[\'command\']);need(len(outer)==3 and outer[:2]==[\'/debug_ramdisk/su\',\'-c\'],\'exact request-owned Root wrapper\')\n    inner=shlex.split(outer[2]);need(inner[-5:-1]==[\'/usr/bin/python3\',\'-I\',\'-B\',\'-c\'],\'original Python runner\')\n    operation_inputs={}\n    for filename in (\'intent.json\',\'baseline.json\'):\n        original_path=path.parent/filename\n        size=original_path.lstat().st_size\n        need(0<size<=1048576,\'bounded operation input original\')\n        # First read obtains a full digest; the pinned re-read then proves full9\n        # and byte equality independently before these originals are preserved.\n        fd=os.open(original_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)\n        try:\n            before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==size,\'operation input type/size\')\n            with os.fdopen(fd,\'rb\',closefd=False) as stream:body=stream.read(size+1)\n            need(len(body)==size and full9(before)==full9(os.fstat(fd))==full9(original_path.lstat()),\'operation input first read raced\')\n        finally:os.close(fd)\n        original_raw,original_descriptor=read_exact(original_path,size,sha(body))\n        operation_inputs[filename]=(original_raw,original_descriptor)\n    intent=strict(operation_inputs[\'intent.json\'][0]);baseline_operation=strict(operation_inputs[\'baseline.json\'][0])\n    need(intent[\'label\']==LABEL and intent[\'request\']==request and intent[\'request_sha256\']==sha(request_raw)\n         and intent[\'automatic_replay\'] is False,\'actual actor intent binds exact request\')\n    need(baseline_operation[\'rc\']==0 and baseline_operation[\'stdout\'].splitlines()==[\n        \'f8019f83-20a7-4f18-bea1-51c980621e4d\',\n        \'motorola/leap_cn/leap:16/W1VL36H.59-53-11/643c83-3ed541:user/release-keys\',\'adb\',\'Enforcing\',\'3021\'],\n        \'actual actor phone baseline original\')\n    loader=ast.parse(inner[-1]);node=next(n for n in loader.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==\'data\' for t in n.targets))\n    zipped=base64.b64decode(ast.literal_eval(node.value.args[0]),validate=True)\n    source=decode_zlib(zipped,SOURCE_BYTES,SOURCE_SHA,65535)\n    g={\'__name__\':\'host_result_verification_only\',\'__file__\':\'<pinned-readonly-probe-definition>\'}\n    exec(compile(source,g[\'__file__\'],\'exec\'),g)\n    envelope=strict(operation[\'phone\'][\'stdout\'].encode());need(envelope[\'schema\']==\'hepta.fc33.failed-scope-readonly.packet.v1\' and envelope[\'qualification_granted\'] is False,\'complete evidence envelope\')\n    frame=envelope[\'packet\'];compressed=base64.b64decode(frame[\'base64\'],validate=True)\n    need(len(compressed)==frame[\'compressed_bytes\'] and sha(compressed)==frame[\'compressed_sha256\'],\'compressed packet descriptor\')\n    packet_raw=decode_zlib(compressed,frame[\'bytes\'],frame[\'sha256\'],8*1024*1024);value=strict(packet_raw)\n    need(value[\'schema\']==\'hepta.fc33.failed-scope-readonly.v1\' and enc(value)==packet_raw,\'canonical full original packet\')\n    blobs={}\n    for digest,row in value[\'original_blobs\'].items():\n        b=base64.b64decode(row[\'base64\'],validate=True);need(len(b)==row[\'bytes\'] and sha(b)==digest,\'every preserved original blob descriptor\');blobs[digest]=b\n    out=Path(a.out);need(out.parent.resolve(strict=True)==out.parent and not out.exists(),\'new host output directory only\')\n    out.mkdir(mode=0o700)\n    outputs=[write_new(out,\'result.original.json\',raw),write_new(out,\'packet.original.json\',packet_raw),write_new(out,\'probe-source.original.py\',source),write_new(out,\'probe-inputs.original.json\',g[\'INPUTS_RAW\'])]\n    outputs.append(write_new(out,\'phone-actor.original.py\',actor_raw))\n    outputs.append(write_new(out,\'phone-request.original.json\',request_raw))\n    for filename,(body,_) in operation_inputs.items():outputs.append(write_new(out,filename+\'.original\',body))\n    for digest,b in blobs.items():outputs.append(write_new(out,\'originals/\'+digest+\'.bin\',b))\n    checks=None;error=None\n    try:\n        need(operation[\'phone\'][\'rc\']==0 and operation[\'phone\'][\'stderr\']==\'\' and value[\'state\']==\'COMPLETE_FRESH_READONLY_SCOPE_CAPTURE_NO_CLOSURE\' and value[\'terminal_error\'] is None and value[\'errors\']==[],\'probe was incomplete or failed\')\n        checks=validate(value,g,blobs)\n    except BaseException as exc:error={\'type\':type(exc).__name__,\'detail\':str(exc)[:2048]}\n    report={\'schema\':\'hepta.fc33.failed-scope-readonly-host-verification.v1\',\'state\':\'FULL_FRESH_CAPTURE_VERIFIED_NO_CLOSURE\' if error is None else \'ORIGINALS_PRESERVED_PROBE_OR_VALIDATION_INCOMPLETE\',\n        \'actual_result\':descriptor,\'actual_actor\':actor_descriptor,\'actual_request\':request_descriptor,\n        \'actual_operation_inputs\':{name:pin for name,(_,pin) in operation_inputs.items()},\n        \'phone_rc\':operation[\'phone\'][\'rc\'],\'probe_state\':value[\'state\'],\'probe_error\':value[\'terminal_error\'],\n        \'host_validation_error\':error,\'checks\':checks,\'preserved_unique_originals\':len(blobs),\'preserved_original_bytes\':sum(map(len,blobs.values())),\n        \'output_descriptors\':outputs,\'phone_calls_by_host_verifier\':0,\'scope_closure\':False,\'deletion_authorized\':False}\n    report_raw=enc(report);report_pin=write_new(out,\'HOST-VERIFICATION.json\',report_raw)\n    print(json.dumps({\'state\':report[\'state\'],\'report\':report_pin,\'phone_rc\':report[\'phone_rc\'],\'probe_error\':report[\'probe_error\'],\'host_validation_error\':error,\'checks\':checks},sort_keys=True))\n    return 0 if error is None else 1\nif __name__==\'__main__\':raise SystemExit(main())\n'
CORE_VALIDATOR_PIN = (16500, '29520d5dcfa5f9eaeac033689869cea08cbc620b5eb16e5b5a2a91c1879286df')
BASE = Path('/home/alex/razr60-local-model-v150')
ACTOR = BASE/'ops/phone_once.py'
ACTOR_PIN = (5652, '179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22')
PROBE_PIN = (63646, '70c4dc710368da58f609208879f1fb83af5e0b428b712cfd31b8bced1907bc44')
EXPECTED_COMMAND_PREFIX = ['/data/adb/magisk/busybox','env','-i',
    'PATH=/usr/bin:/bin:/usr/libexec/trillionnium','PYTHONHOME=/usr','PYTHONDONTWRITEBYTECODE=1',
    'LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu',
    'LANG=C.UTF-8','LC_ALL=C.UTF-8','TMPDIR=/var/lib/trillionnium/owner-open/tmp','NO_COLOR=1','TERM=dumb',
    '/data/adb/magisk/busybox','chroot','/data/trillionnium/owner-open/root','/usr/bin/python3','-I','-B','-c']

def need(ok, why):
    if not ok: raise ValueError(why)

def sha(raw): return hashlib.sha256(raw).hexdigest()

def enc(value):
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()

def strict(raw):
    def pairs(rows):
        out={}
        for k,v in rows:
            need(k not in out,'duplicate JSON key');out[k]=v
        return out
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))

def full9(s):
    return [getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]

def metadata(m):
    need(type(m)is list and len(m)==9 and all(type(v)is int and 0<=v<(1<<63) for v in m),'exact bounded full9')

def read_exact(path, size, digest, expected_metadata=None):
    path=Path(path)
    need(path.is_absolute() and str(path)==str(path.resolve(strict=True)) and type(size)is int and 0<=size<=32*1024*1024,'canonical bounded host original')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==size,'regular single-link original length')
        with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(size+1)
        m=full9(a)
        need(len(raw)==size and sha(raw)==digest and m==full9(os.fstat(fd))==full9(path.lstat()) and path.resolve(strict=True)==path,'original bytes/full9/canonical bookends')
        if expected_metadata is not None: need(m==expected_metadata,'original preserved host identity changed')
        return raw,{'path':str(path),'bytes':size,'sha256':digest,'metadata':m}
    finally:os.close(fd)

def read_row(row):
    return read_exact(row['path'],row['bytes'],row['sha256'],row.get('metadata'))

def observe_input(path):
    path=Path(path);need(path.resolve(strict=True)==path,'canonical operation input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=1048576,'operation input size/type')
        with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(before.st_size+1)
        need(len(raw)==before.st_size and full9(before)==full9(os.fstat(fd))==full9(path.lstat()),'operation input first full read')
    finally:os.close(fd)
    return read_exact(path,len(raw),sha(raw),full9(before))

def write_new(root, name, raw):
    need('/' not in name and name not in ('.','..'),'finite output basename')
    path=root/name
    need(root.resolve(strict=True)==root,'canonical private output directory')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())
    _,row=read_exact(path,len(raw),sha(raw));return row

def load_module(raw, name):
    module=types.ModuleType(name);module.__file__='<reviewed-host-definition/'+name+'>'
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    return module

def decompress_frame(frame, limit):
    need(frame['encoding']=='zlib-base64' and type(frame['bytes'])is int and 0<frame['bytes']<=limit,'bounded preflight frame')
    compressed=base64.b64decode(frame['base64'],validate=True)
    need(len(compressed)==frame['compressed_bytes'] and sha(compressed)==frame['compressed_sha256'] and len(compressed)<=8*1024*1024,'complete compressed frame')
    d=zlib.decompressobj();raw=d.decompress(compressed,frame['bytes']+1)
    need(d.eof and not d.unused_data and not d.unconsumed_tail and len(raw)==frame['bytes'] and sha(raw)==frame['sha256'],'exact whole preflight stream')
    return raw

def extract_source(request):
    words=shlex.split(request['command'])
    need(words[:-1]==EXPECTED_COMMAND_PREFIX and len(request['command'].encode())<=65535,'exact reviewed GNU command prefix and wire bound')
    tree=ast.parse(words[-1]);nodes=[n for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='c']
    need(len(nodes)==1 and isinstance(nodes[0].value,ast.Call),'one explicit compressed source literal')
    call=nodes[0].value
    need(ast.unparse(call.func)=='base64.b64decode' and len(call.args)==1,'reviewed single base64 source expression')
    compressed=base64.b64decode(ast.literal_eval(call.args[0]),validate=True)
    need(len(compressed)<=65535,'bounded compressed source')
    d=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=32*1024*1024)
    source=d.decompress(compressed,max_length=FROZEN['source']['bytes']+1)
    need(d.eof and not d.unused_data and len(source)==FROZEN['source']['bytes'] and sha(source)==FROZEN['source']['sha256'],'whole reviewed recovery source from actual request')
    return source

def check_roles(value, expected, tag):
    need(set(value)=={'tag','rows','historical_wait_invented','nonzero_signals'} and value['tag']==tag and value['historical_wait_invented'] is False and type(value['nonzero_signals'])is int and value['nonzero_signals']==0,'exact known-role check boundary')
    need(len(value['rows'])==2 and [r['role'] for r in value['rows']]==sorted(expected),'complete two-role result')
    for row in value['rows']:
        identity=expected[row['role']]
        need(set(row)=={'role','identity','proc_state','kernel_state','pid_argument','signal','proc_errno','kernel_errno'},'exact known-role fields')
        need(row['identity']==identity and row['proc_state']=='ENOENT' and row['kernel_state']=='ESRCH'
             and type(row['proc_errno'])is int and row['proc_errno']==2 and type(row['kernel_errno'])is int and row['kernel_errno']==3
             and type(row['signal'])is int and row['signal']==0 and row['pid_argument']==-identity[1],'fresh actual known PID/group absence')

def validate_recovery(value, pre, module, blobs):
    C=module.C;targets=module.TARGETS;authority=module.AUTHORITY
    need(value['schema']=='hepta.fc33.final05.exact-owned-recovery.v1' and value['operation_label']==FROZEN['operation_label']
         and value['scope_label']==C.LABEL and value['nonce']==C.NONCE and value['boot_id']==C.BOOT
         and value['targets_sha256']==module.TARGETS_SHA and enc(value['authority'])==enc(authority),'exact recovery identity and authority')
    need(value['state']=='EXACT_OWNED_SCOPE_REMOVED_ORIGINAL44_UNCHANGED_NO_CASE_CREDIT' and value['phase']=='complete' and value['preflight_complete'] is True and value['terminal_error'] is None,'actual complete recovery terminal')
    for key in ('scope_closure','component_qualified','business_qualified','qualified_source_parent','automatic_retry','historical_supervisor_wait_invented'):
        need(value[key] is False,'historical or qualification flag must remain false: '+key)
    for key in ('ui_calls','model_requests','native_dispatches','nonzero_signals_to_other_processes'):
        need(type(value[key])is int and value[key]==0,'no unrelated operation: '+key)
    need(value['host_private_originals_untouched'] is True,'original private archives retained')
    files,dirs,parents=module.finite_plan()
    additional=C.BASELINE_FILE_BYTES+sum(r['bytes'] for r in files.values())+sum(C.INPUTS[k]['bytes'] for k in ('baseline','boundary'))+128*1024
    need(type(value['additional_read_allowance'])is int and value['additional_read_allowance']==additional,'exact additional finite read allowance including final input rereads')
    need(value['output_reservation']==module.reserve_output(value['preflight'],files,dirs,parents),'same complete output budget reserved before effects')
    need(pre['schema']=='hepta.fc33.exact-recovery-preflight.v1' and pre['targets_sha256']==module.TARGETS_SHA and enc(pre['authority'])==enc(authority),'complete preflight identity')
    expected_blobs=[{'sha256':h,'bytes':len(b)} for h,b in sorted(blobs.items())]
    need(pre['actual_complete_originals']==expected_blobs and len(expected_blobs)==88 and pre['all_original_bytes_preserved_by_host_authority'] is True and pre['private_body_blobs_omitted_because_already_exactly_preserved'] is True,'all actual88 original hashes match previously preserved full bytes')
    need((len(CORE_VALIDATOR_RAW),sha(CORE_VALIDATOR_RAW))==tuple(CORE_VALIDATOR_PIN),'exact reviewed pure preflight validator')
    verifier=load_module(CORE_VALIDATOR_RAW,'fc33_recovery_preflight_pure_validator')
    adapter={'evidence':pre['evidence'],'scope':{'label':C.LABEL,'nonce':C.NONCE,'lease_sha256':C.LEASE_SHA,'runtime_sha256':C.PACKAGE_SHA,'boot_id':C.BOOT},
        'inputs_sha256':C.INPUTS_SHA,'scope_closure':False,'qualified_source_parent':False,'deletion_authorized':False}
    for key in ('file_writes','file_deletes','nonzero_signals_to_other_processes','ui_inputs','model_requests','native_dispatches','endpoint_connections','target_programs_imported_or_executed'):adapter[key]=0
    # This is an explicit phase adapter for the unchanged C.capture function,
    # not a new original and not a statement about the later unlink/rmdir phase.
    prechecks=verifier.validate(adapter,C.__dict__,blobs)
    need(prechecks['bounded_no_claim_or_action_records'] is True,'no unaccounted provider/claim/action/fixture before recovery')
    evidence=pre['evidence']
    need(C.stable_tree_projection(evidence['private_before'])==C.stable_tree_projection(targets['prior_private_tree'])
         and C.stable_tree_projection(evidence['private_after'])==C.stable_tree_projection(targets['prior_private_tree']),'same fully preserved private scope before effects')
    need(evidence['parents_before']==evidence['parents_after']==[parents[p] for p in C.INPUTS['parent_paths']]
         and evidence['home_aliases_before']==evidence['home_aliases_after']==targets['prior_home_aliases'],'exact preserved parent and home aliases')
    check_roles(value['pre_mutation_roles'],C.INPUTS['role_identities'],'immediately_before_first_mutation')
    groups={};directory_map={}
    for path,row in (dirs|parents).items():
        metadata(row['metadata']);key=tuple(row['metadata'][:2]);fields={k:copy.deepcopy(row[k]) for k in ('metadata','names','selinux_raw_b64')}
        if key in groups:need(groups[key]['fields']==fields,'initial directory aliases identical')
        else:groups[key]={'fields':fields,'removed':False}
        directory_map[path]=groups[key]
    order=[('file',p) for p in sorted(files,key=lambda p:(p.endswith('/executor/server.lock'),p))]
    order += [('directory',p) for p in sorted(dirs,key=lambda p:(-p.count('/'),p))]
    operations=value['operations'];need(len(operations)==len(order)==107,'exact finite107 removal events')
    for i,(row,(kind,path)) in enumerate(zip(operations,order)):
        need(set(row)=={'index','kind','path','before_metadata','parent_before_metadata','effect_attempted','syscall_returned','verified_absent','after_metadata','parent_after_metadata','parent_fsynced'},'exact complete removal event shape')
        need(type(row['index'])is int and row['index']==i and (row['kind'],row['path'])==(kind,path),'one deterministic event for each owned target')
        need(all(row[k] is True for k in ('effect_attempted','syscall_returned','verified_absent','parent_fsynced')),'every actual effect returned and was checked/fsynced')
        before=row['before_metadata'];after=row['after_metadata'];pm=row['parent_after_metadata']
        for m in (before,after,row['parent_before_metadata'],pm):metadata(m)
        parent=directory_map[str(Path(path).parent)]
        need(not parent['removed'] and row['parent_before_metadata']==parent['fields']['metadata'],'held parent exact chained full9')
        if kind=='file':
            need(before==files[path]['metadata'] and after[:5]==before[:5] and after[5]==0 and after[6:8]==before[6:8],'exact original file inode lost its only link')
        else:
            current=directory_map[path]
            need(not current['removed'] and current['fields']['names']==[] and before==current['fields']['metadata'] and before[5]==2,'only emptied original directory removed')
            need(after[:5]==before[:5] and after[5]==0,'exact directory inode lost links');current['removed']=True
        old=parent['fields']['metadata'];name=Path(path).name
        need(name in parent['fields']['names'] and pm[:5]==old[:5] and pm[5]==old[5]-(1 if kind=='directory' else 0),'only declared parent entry/link delta')
        parent['fields']['names'].remove(name);parent['fields']['metadata']=pm
    need(all(directory_map[p]['removed'] for p in dirs),'all10 owned directory identities removed')
    after=value['after'];expected_parents=[{'path':r['path'],**directory_map[r['path']]['fields']} for r in targets['surviving_parents']]
    need(after['parents']==expected_parents,'complete actual after parent names/full9/labels match all107 changes')
    need(C.LABEL not in expected_parents[0]['names'] and len(expected_parents[0]['names'])==16 and expected_parents[0]['metadata'][5]==18,'original shared parent membership restored')
    expected_absences=[str(C.SCOPE_HOME),str(C.ANDROID_HOME),str(C.FIXTURE)]+[p for p in sorted(files) if not p.startswith(str(C.SCOPE_HOME)+'/')]
    need(len(expected_absences)==18 and [r['path'] for r in after['absences']]==expected_absences,'complete18 exact final absence paths')
    for row in after['absences']:
        need(set(row)=={'kind','path','absence','parent_metadata','parent_selinux_raw_b64','observed_monotonic_ns','no_effect_inferred'},'exact final absence fields')
        parent=directory_map[str(Path(row['path']).parent)]['fields']
        need(row['kind']=='absent' and row['absence']=='ENOENT' and row['no_effect_inferred'] is False and type(row['observed_monotonic_ns'])is int and row['observed_monotonic_ns']>0
             and row['parent_metadata']==parent['metadata'] and row['parent_selinux_raw_b64']==parent['selinux_raw_b64'],'held/reopened exact final absence with surviving parent identity')
    before=evidence['baseline_after']
    projection={'roots':before['roots'],'entries':C.legacy_projection(before),'file_bytes_hashed':before['file_bytes_hashed']};projection_raw=C.encoded(projection)
    expected_projection={'complete_roots':44,'complete_entries':3823,'complete_file_bytes_hashed':C.BASELINE_FILE_BYTES,
        'canonical_projection_bytes':len(projection_raw),'canonical_projection_sha256':sha(projection_raw),'equal_to_complete_preflight_projection':True,
        'all_present_labels_exact':True,'absent_fixture_parents_match_actual_surviving_parent':True}
    need(after['original44']==expected_projection,'actual complete post-read projection exactly matches original44')
    check_roles(after['known_roles'],C.INPUTS['role_identities'],'after_exact_scope_removal')
    resource=value['resources']
    need(resource['close_errors']==[] and resource['initial_fd_names']==resource['final_fd_names'] and resource['closed_file_descriptors']==97
         and resource['closed_directory_descriptors']==len(groups) and resource['closed_lock_descriptors']==15,'all owned files/directories/locks closed to measured FD baseline')
    need(all(type(n)is str and n.isdigit() for n in resource['initial_fd_names']) and len(resource['initial_fd_names'])==len(set(resource['initial_fd_names'])),'exact measured FD name baseline')
    need(value['files_removed_verified']==97 and value['directories_removed_verified']==10 and value['effect_attempt_count']==107,'exact independent removal accounting')
    need(type(value['read_bytes'])is int and value['read_bytes']>=pre['read_bytes'] and value['read_bytes']<=160*1024*1024+additional,'bounded actual read accounting')
    need(type(value['elapsed_seconds'])in (int,float) and 0<=value['elapsed_seconds']<=80,'bounded actual elapsed result')
    return {'exact_files_removed':97,'exact_directories_removed':10,'ordered_operations_checked':107,'exact_final_absences':18,
        'original44_roots':44,'original44_entries':3823,'original44_bytes_read_per_complete_window':C.BASELINE_FILE_BYTES,
        'after_projection':expected_projection,'after_inventory_representation':'Complete post-read projection hash verified against the complete preflight original graph; a separate raw after-inventory was not emitted.',
        'preflight_checks':prechecks,'preflight_adapter_is_original':False,'whole_operation_was_readonly':False,
        'current_role_absence_checks_before_and_after':True,'all15_original_locks_held_during_effects':True,'measured_fd_baseline_restored':True,
        'historical_supervisor_wait_proven':False,'producer_scope_closure_flag':False,'business_or_component_credit':False,
        'owned_recovery_closed':True,'fresh_component_admission_required':True}

def main():
    need(type(FROZEN)is dict and CORE_VALIDATOR_RAW is not None and CORE_VALIDATOR_PIN is not None,'UNBOUND_NO_IO')
    parser=argparse.ArgumentParser();parser.add_argument('--result',required=True);parser.add_argument('--bytes',required=True,type=int);parser.add_argument('--sha256',required=True);parser.add_argument('--out',required=True);a=parser.parse_args()
    label=FROZEN['operation_label'];path=Path(a.result)
    need(path==BASE/'operations'/label/'result.json' and 0<a.bytes<=16*1024*1024,'one bounded actual recovery result only')
    result_raw,result_pin=read_exact(path,a.bytes,a.sha256)
    actor_raw,actor_pin=read_exact(ACTOR,*ACTOR_PIN);request_raw,request_pin=read_row(FROZEN['request'])
    out=Path(a.out);need(out.parent==BASE and out.name==label.removeprefix('ng-')+'-import01' and out.parent.resolve(strict=True)==out.parent and not out.exists(),'fresh exact private import namespace')
    out.mkdir(mode=0o700)
    outputs=[write_new(out,'result.original.json',result_raw),write_new(out,'actor.original.py',actor_raw),write_new(out,'request.original.json',request_raw)]
    checks=None;error=None;inputs={};preserved=[];phone_rc=None
    try:
        operation=strict(result_raw);request=strict(request_raw)
        need(operation['label']==label and operation['status']=='command_exited' and operation['model_decision'] is False and operation['native_task_result'] is False,'actual original recovery actor result')
        need(set(request)=={'kind','root','timeout_seconds','command'} and request['kind']=='shell' and request['root'] is True and request['timeout_seconds']==80,'exact reviewed recovery request')
        need(operation['phone']['command']=='/debug_ramdisk/su -c '+shlex.quote(request['command']),'exact pinned actor root=true transformation')
        for filename in ('intent.json','baseline.json'):
            body,row=observe_input(path.parent/filename);inputs[filename]=(body,row);outputs.append(write_new(out,filename+'.original',body))
        intent=strict(inputs['intent.json'][0]);baseline=strict(inputs['baseline.json'][0])
        need(intent['label']==label and enc(intent['request'])==enc(request) and intent['request_sha256']==sha(request_raw) and intent['automatic_replay'] is False,'original one-use actor intent')
        need(baseline['rc']==0 and baseline['stdout'].splitlines()==['f8019f83-20a7-4f18-bea1-51c980621e4d','motorola/leap_cn/leap:16/W1VL36H.59-53-11/643c83-3ed541:user/release-keys','adb','Enforcing','3021'],'exact actual boot/build/route baseline')
        source=extract_source(request);outputs.append(write_new(out,'recovery-source.original.py',source));module=load_module(source,'fc33_reviewed_recovery_definitions')
        need((len(module.CAP_SOURCE_RAW),sha(module.CAP_SOURCE_RAW))==PROBE_PIN and module.OPERATION_LABEL==label,'unchanged reviewed capture definitions')
        targets_raw,targets_pin=read_row(FROZEN['targets']);authority_raw=module.AUTHORITY_RAW
        need(targets_raw==module.TARGETS_RAW and len(authority_raw)==FROZEN['authority']['bytes'] and sha(authority_raw)==FROZEN['authority']['sha256'],'complete actual targets and reviewed authority literal equal executed source')
        outputs.extend([write_new(out,'targets.original.json',targets_raw),write_new(out,'authority.original.json',authority_raw),write_new(out,'preflight-validator.original.py',CORE_VALIDATOR_RAW)])
        blobs={}
        for row in module.TARGETS['preserved_blob_descriptors']:
            raw,pin=read_exact(row['preserved_path'],row['bytes'],row['sha256']);need(row['sha256'] not in blobs,'unique original blob descriptor')
            blobs[row['sha256']]=raw;preserved.append(pin)
        phone_rc=operation['phone']['rc'];wire=operation['phone']['stdout'].encode();need(len(wire)<=8*1024*1024,'original8MiB phone stdout cap')
        value=strict(wire);need(enc(value)==wire,'canonical unchanged actual recovery stdout')
        outputs.append(write_new(out,'recovery-packet.original.json',wire))
        pre_raw=decompress_frame(value['preflight'],32*1024*1024);pre=strict(pre_raw);need(enc(pre)==pre_raw,'canonical complete preflight bytes')
        outputs.append(write_new(out,'preflight.original.json',pre_raw))
        need(phone_rc==0 and operation['phone']['stderr']=='','actual successful complete phone recovery')
        checks=validate_recovery(value,pre,module,blobs)
    except BaseException as exc:error={'type':type(exc).__name__,'detail':str(exc)[:2048]}
    report={'schema':'hepta.fc33.final05.exact-recovery-host-verification.v1',
        'state':'EXACT_OWNED_RECOVERY_INDEPENDENTLY_VERIFIED_NO_CASE_CREDIT' if error is None else 'ORIGINALS_PRESERVED_RECOVERY_INCOMPLETE_OR_UNKNOWN',
        'actual_result':result_pin,'actual_actor':actor_pin,'actual_request':request_pin,
        'actual_operation_inputs':{name:row for name,(_,row) in inputs.items()},'phone_rc':phone_rc,'host_validation_error':error,'checks':checks,
        'rechecked_preserved_originals':preserved,'output_descriptors':outputs,'phone_calls_by_host_verifier':0,
        'owned_recovery_closed':error is None,'original_failed_case_qualification':False,'historical_unknowns_upgraded':False,'private_bodies_in_public_report':False}
    report_pin=write_new(out,'HOST-VERIFICATION.PUBLIC.json',enc(report))
    print(json.dumps({'state':report['state'],'report':report_pin,'phone_rc':phone_rc,'host_validation_error':error,'owned_recovery_closed':error is None},sort_keys=True))
    return 0 if error is None else 1

if __name__=='__main__':raise SystemExit(main())
