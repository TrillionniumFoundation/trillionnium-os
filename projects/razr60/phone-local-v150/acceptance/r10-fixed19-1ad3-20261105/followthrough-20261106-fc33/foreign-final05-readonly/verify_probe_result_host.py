#!/usr/bin/env python3
"""Read one existing durable result, preserve it, and verify the bounded packet.

Host only: no phone actor, subprocess, signal, socket or native/model request.
"""
from pathlib import Path
import argparse,ast,base64,hashlib,json,os,shlex,stat,zlib

SOURCE_SHA='70c4dc710368da58f609208879f1fb83af5e0b428b712cfd31b8bced1907bc44'
SOURCE_BYTES=63646
LABEL='ng-fc33-final05-failed-scope-readonly01'
def need(ok,why):
    if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def enc(value):return (json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
def strict(raw):
    def pairs(rows):
        d={}
        for k,v in rows:
            need(k not in d,'duplicate JSON key');d[k]=v
        return d
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def full9(s):return [getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def read_exact(path,size,digest):
    need(path.resolve(strict=True)==path,'canonical host original path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==size,'host original regular file size')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(size+1)
        need(len(raw)==size and sha(raw)==digest and full9(a)==full9(os.fstat(fd))==full9(path.lstat()),'host original bytes/full9 changed')
        return raw,{'path':str(path),'bytes':size,'sha256':digest,'metadata':full9(a)}
    finally:os.close(fd)
def decode_zlib(encoded_raw,expected_size,expected_sha,limit):
    need(len(encoded_raw)<=limit,'compressed input bound')
    z=zlib.decompressobj();raw=z.decompress(encoded_raw,expected_size+1)
    need(z.eof and not z.unused_data and not z.unconsumed_tail and len(raw)==expected_size and sha(raw)==expected_sha,'complete exact zlib stream')
    return raw
def write_new(root,name,raw):
    p=root/name
    need(p.parent==root or root in p.parents,'host output namespace')
    p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as s:s.write(raw);s.flush();os.fsync(s.fileno())
    return {'path':str(p),'bytes':len(raw),'sha256':sha(raw)}
def check_metadata_row(row):
    m=row.get('metadata')
    need(type(m) is list and len(m)==9 and all(type(v) is int and v>=0 for v in m),'actual full9 shape')
def tree_complete(observed,blobs):
    roots=observed['roots'];rows=observed['entries'];total=0
    need(len(roots)==len(set(roots)) and type(rows) is dict,'tree roots/rows')
    for path,row in rows.items():
        need(row['path']==path and sum(path==r or path.startswith(r+'/') for r in roots)==1,'tree exact lexical root')
        if row['kind']=='absent':
            need(path in roots and row['absence']=='ENOENT' and row['no_effect_inferred'] is False,'exact root absence only')
            continue
        check_metadata_row(row)
        if row['kind']=='directory':
            names=sorted(p.rsplit('/',1)[-1] for p in rows if p.rsplit('/',1)[0]==path)
            need(row['names']==names and len(names)==len(set(names)),'complete directory children')
        else:
            need(row['kind']=='file' and row['metadata'][6]==row['bytes'],'regular file size row')
            total+=row['bytes']
            if blobs is not None:
                need(row['sha256'] in blobs and len(blobs[row['sha256']])==row['bytes'],'every private byte preserved')
    need(total==observed['file_bytes_hashed'],'tree byte accounting')

def validate(value,g,blobs):
    evidence=value['evidence'];inputs=g['INPUTS'];scope=value['scope']
    need(scope=={'label':g['LABEL'],'nonce':g['NONCE'],'lease_sha256':g['LEASE_SHA'],'runtime_sha256':g['PACKAGE_SHA'],'boot_id':g['BOOT']},'exact failed old scope')
    need(value['inputs_sha256']==g['INPUTS_SHA'],'exact probe inputs')
    for key in ('file_writes','file_deletes','nonzero_signals_to_other_processes','ui_inputs','model_requests','native_dispatches','endpoint_connections','target_programs_imported_or_executed'):
        need(value[key]==0 and type(value[key]) is int,'readonly count '+key)
    need(value['scope_closure'] is False and value['qualified_source_parent'] is False and value['deletion_authorized'] is False,'no qualification or cleanup claim')
    baseline_raw=blobs[inputs['baseline']['sha256']];need(len(baseline_raw)==inputs['baseline']['bytes'],'old44 original length')
    baseline=strict(baseline_raw)
    for which in ('baseline_before','baseline_after'):
        observed=evidence[which];tree_complete(observed,None);g['compare_baseline'](observed,baseline)
    need(g['stable_tree_projection'](evidence['baseline_before'])==g['stable_tree_projection'](evidence['baseline_after']),'old44 exact fresh bookends')
    for which in ('private_before','private_after'):tree_complete(evidence[which],blobs)
    need(g['stable_tree_projection'](evidence['private_before'])==g['stable_tree_projection'](evidence['private_after']),'private fresh bookends')
    g['STATE']={'blobs':{h:{'bytes':len(b),'base64':base64.b64encode(b).decode()} for h,b in blobs.items()}}
    g['require_known_originals'](evidence['private_before'])
    archive_pin=next(r for r in inputs['transport'] if r['path']==inputs['archive_path'])
    files=g['archive_members'](blobs[archive_pin['sha256']])
    stage=g['immutable_stage_members'](files,evidence['private_before'])
    need(stage==evidence['stage_members'],'all61 complete actual byte checks')
    locks=evidence['locks'];need(locks['alias_count']==28 and locks['inode_group_count']==15 and locks['old_inode_group_count']==14,'all15 existing lock groups')
    need(len(locks['aliases'])==28 and len({tuple(r['metadata'][:2]) for r in locks['aliases']})==15,'actual lock aliases grouped by inode')
    need(evidence['parents_before']==evidence['parents_after'] and evidence['home_aliases_before']==evidence['home_aliases_after'],'actual parent/alias bookends')
    process=evidence['process_windows'];need(len(process)==2 and [r['index'] for r in process]==[0,1],'two fresh process windows')
    for window in process:
        need(window['original_identities']==inputs['role_identities'],'original exact two roles')
        census=window['census'];need(census['complete'] is True and sorted(census['stat_originals'],key=int)==census['names'],'complete proc enumeration')
        need(census['numeric_pid_count']==len(census['names'])<=4096,'proc count bound')
        members=[];disappeared=[]
        ids={tuple(v) for v in inputs['role_identities'].values()};groups={v[1] for v in ids};sessions={v[2] for v in ids}
        for pid,row in census['stat_originals'].items():
            if row['state']=='OBSERVED_ENOENT':
                need(row['errno']==2,'only disappearing PID ENOENT');disappeared.append(int(pid));continue
            raw=base64.b64decode(row['base64'],validate=True)
            need(len(raw)==row['bytes']<=8192 and sha(raw)==row['sha256'],'complete proc original')
            parsed=g['stat_identity'](raw,int(pid),census=True)
            need(parsed==row['identity'],'independent proc stat parsing')
            if tuple(g['generation'](parsed)) in ids or parsed['pgid'] in groups or parsed['sid'] in sessions:members.append(parsed)
        need(not members and census['members']==[] and sorted(disappeared)==sorted(census['disappeared_while_reading']),'no declared generation/group/session in complete census')
        q=window['kernel_group_queries'];need(len(q)==2,'two kernel queries per window')
        for row in q:
            identity=inputs['role_identities'][row['role']]
            need(row['identity']==identity and row['pid_argument']==-identity[1] and row['signal']==0
                 and row['syscall']=='kill' and row['state']=='ESRCH' and row['errno']==3,'exact signal-zero ESRCH query')
    rows=evidence['private_before']['entries'];home=str(g['SCOPE_HOME']);journal=str(g['JOURNAL']);fixture=str(g['FIXTURE'])
    present=[n for n in inputs['inspect_absence_names'] if home+'/'+n in rows]
    claims=rows[home+'/claims'];operator=rows[home+'/operator'];actions=rows.get(journal+'/actions')
    return {'original44_full_inventory_equal':True,'original44_roots':len(baseline['roots']),
        'original44_entries':len(baseline['entries']),'original44_file_bytes_hashed_each_window':baseline['file_bytes_hashed'],
        'runtime37_and_stage61_exact':True,'private_entry_count':len(rows),'private_file_bytes_each_window':evidence['private_before']['file_bytes_hashed'],
        'fresh_known_groups_absent_two_windows':True,'signal_zero_ESRCH_count':4,
        'unexpected_expected_absence_records_present':present,'claims_names':claims['names'],'operator_names':operator['names'],
        'actions_names':None if actions is None else actions['names'],'fixture_kind':rows[fixture]['kind'],
        'bounded_no_claim_or_action_records':not present and claims['names']==[] and operator['names']==[] and actions is not None and actions['names']==[] and rows[fixture]['kind']=='absent',
        'scope_closure':False,'cleanup_authorized':False,'historical_native_or_effect_count_inferred':None}

def main():
    p=argparse.ArgumentParser();p.add_argument('--result',required=True);p.add_argument('--bytes',required=True,type=int);p.add_argument('--sha256',required=True);p.add_argument('--out',required=True);a=p.parse_args()
    path=Path(a.result);need(path==Path('/home/alex/razr60-local-model-v150/operations')/LABEL/'result.json','one existing operation only')
    need(0<a.bytes<=12*1024*1024,'durable result cap')
    raw,descriptor=read_exact(path,a.bytes,a.sha256);operation=strict(raw)
    need(operation['label']==LABEL and operation['status']=='command_exited' and operation['model_decision'] is False and operation['native_task_result'] is False,'actual one read-only operation')
    command=operation['phone']['command'];outer=shlex.split(command);need(outer[:2]==['/debug_ramdisk/su','-c'],'original Root transport')
    inner=shlex.split(outer[2]);need(inner[-5:-1]==['/usr/bin/python3','-I','-B','-c'],'original Python runner')
    loader=ast.parse(inner[-1]);node=next(n for n in loader.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='data' for t in n.targets))
    zipped=base64.b64decode(ast.literal_eval(node.value.args[0]),validate=True)
    source=decode_zlib(zipped,SOURCE_BYTES,SOURCE_SHA,65535)
    g={'__name__':'host_result_verification_only','__file__':'<pinned-readonly-probe-definition>'}
    exec(compile(source,g['__file__'],'exec'),g)
    envelope=strict(operation['phone']['stdout'].encode());need(envelope['schema']=='hepta.fc33.failed-scope-readonly.packet.v1' and envelope['qualification_granted'] is False,'complete evidence envelope')
    frame=envelope['packet'];compressed=base64.b64decode(frame['base64'],validate=True)
    need(len(compressed)==frame['compressed_bytes'] and sha(compressed)==frame['compressed_sha256'],'compressed packet descriptor')
    packet_raw=decode_zlib(compressed,frame['bytes'],frame['sha256'],8*1024*1024);value=strict(packet_raw)
    need(value['schema']=='hepta.fc33.failed-scope-readonly.v1' and enc(value)==packet_raw,'canonical full original packet')
    blobs={}
    for digest,row in value['original_blobs'].items():
        b=base64.b64decode(row['base64'],validate=True);need(len(b)==row['bytes'] and sha(b)==digest,'every preserved original blob descriptor');blobs[digest]=b
    out=Path(a.out);need(out.parent.resolve(strict=True)==out.parent and not out.exists(),'new host output directory only')
    out.mkdir(mode=0o700)
    outputs=[write_new(out,'result.original.json',raw),write_new(out,'packet.original.json',packet_raw),write_new(out,'probe-source.original.py',source),write_new(out,'probe-inputs.original.json',g['INPUTS_RAW'])]
    for digest,b in blobs.items():outputs.append(write_new(out,'originals/'+digest+'.bin',b))
    checks=None;error=None
    try:
        need(operation['phone']['rc']==0 and operation['phone']['stderr']=='' and value['state']=='COMPLETE_FRESH_READONLY_SCOPE_CAPTURE_NO_CLOSURE' and value['terminal_error'] is None and value['errors']==[],'probe was incomplete or failed')
        checks=validate(value,g,blobs)
    except BaseException as exc:error={'type':type(exc).__name__,'detail':str(exc)[:2048]}
    report={'schema':'hepta.fc33.failed-scope-readonly-host-verification.v1','state':'FULL_FRESH_CAPTURE_VERIFIED_NO_CLOSURE' if error is None else 'ORIGINALS_PRESERVED_PROBE_OR_VALIDATION_INCOMPLETE',
        'actual_result':descriptor,'phone_rc':operation['phone']['rc'],'probe_state':value['state'],'probe_error':value['terminal_error'],
        'host_validation_error':error,'checks':checks,'preserved_unique_originals':len(blobs),'preserved_original_bytes':sum(map(len,blobs.values())),
        'output_descriptors':outputs,'phone_calls_by_host_verifier':0,'scope_closure':False,'deletion_authorized':False}
    report_raw=enc(report);report_pin=write_new(out,'HOST-VERIFICATION.json',report_raw)
    print(json.dumps({'state':report['state'],'report':report_pin,'phone_rc':report['phone_rc'],'probe_error':report['probe_error'],'host_validation_error':error,'checks':checks},sort_keys=True))
    return 0 if error is None else 1
if __name__=='__main__':raise SystemExit(main())
