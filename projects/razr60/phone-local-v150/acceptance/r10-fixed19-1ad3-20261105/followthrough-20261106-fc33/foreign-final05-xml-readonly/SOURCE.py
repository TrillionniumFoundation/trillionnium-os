#!/usr/bin/env python3
"""Read the eleven exact sender-owned XML paths, never create/dump/UI/clean them."""
import base64,errno,hashlib,json,os,signal,stat,sys,time,zlib
from pathlib import Path
INPUTS_RAW=b'{"rows":[{"command_source":{"bytes":11023,"metadata":[66306,35783728,33152,1000,1000,1,11023,1793981694554755996,1793981694554755996],"path":"/home/alex/codex-hepta-natural-root-r10-neg02-a1055-final05-root-v150/INITIAL.json","sha256":"0b66aa135959f8f3bf7217defbf9bf7f5f28f7b0889bb1517a0d89e81bf26ad3"},"expected_bytes":9630,"expected_sha256":"e14c0e88c04509d8c8407e398f07f1fda5d1df516fc70ab0a8555d37bca40129","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","root_path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg02-a1055-final05-v150-1.xml","sequence":1},{"command_source":{"bytes":7598,"metadata":[66306,35783735,33152,1000,1000,1,7598,1793981697099709821,1793981697099709821],"path":"/home/alex/codex-hepta-natural-root-r10-neg02-a1055-final05-root-v150/DRAFT.json","sha256":"c365fa89c1dbbc1383057dac083a611e09cd2703cedd60d850c03dd8710fac94"},"expected_bytes":6547,"expected_sha256":"9055cd6feed26e6dd09505a4bf93627fd4f62e68d59e27899a754e01bb1d9895","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","root_path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg02-a1055-final05-v150-2.xml","sequence":2},{"command_source":{"bytes":22737,"metadata":[66306,35783732,33152,1000,1000,1,22737,1793981699352753442,1793981699352753442],"path":"/home/alex/codex-hepta-natural-root-r10-neg02-a1055-final05-root-v150/CONNECT-MENU.json","sha256":"3ab8cbef5673e1019a674f9ad508a48cecf424577213981a5748d2b6386affa4"},"expected_bytes":20280,"expected_sha256":"af100e2502584c375063ef1bbb0d3f3c120a01730b20b5221b927022bb68e303","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","root_path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg02-a1055-final05-v150-3.xml","sequence":3},{"command_source":{"bytes":10138,"metadata":[66306,35783742,33152,1000,1000,1,10138,1793981702055893667,1793981702055893667],"path":"/home/alex/codex-hepta-natural-root-r10-neg02-a1055-final05-root-v150/CURRENT-CONNECTION.json","sha256":"f95bbe02d29b441b7bb7a0863f47e1d39c833af89a847fa3859512d1ecbec249"},"expected_bytes":8859,"expected_sha256":"7aa29310a6e76dc4e473f63460f1f1ae390fa356be24e42cb5953608388e274e","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","root_path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg02-a1055-final05-v150-4.xml","sequence":4},{"command_source":{"bytes":12258,"metadata":[66306,35783747,33152,1000,1000,1,12258,1793981704290398002,1793981704290398002],"path":"/home/alex/codex-hepta-natural-root-r10-neg02-a1055-final05-root-v150/TASK-CONTROLS.json","sha256":"160235b9bdd8c3b05ed54d1b67d90e9d114e2527effa32a6a9711f70c0c9d776"},"expected_bytes":10751,"expected_sha256":"35cc404b028aa402c94061bdf997bd89c7ad47baf7579aac67ee5ee9dc74974d","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","root_path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg02-a1055-final05-v150-5.xml","sequence":5},{"command_source":{"bytes":14319,"metadata":[66306,35783751,33152,1000,1000,1,14319,1793981707834423710,1793981707834423710],"path":"/home/alex/codex-hepta-natural-root-r10-neg02-a1055-final05-root-v150/READBACK.json","sha256":"7d693427dcee9da65630dcd9bc1c788d5cfa9af32e1ce1b38948b07318c0032a"},"expected_bytes":12929,"expected_sha256":"33fc859e08ed6d4d708bfa1dbdf86b8b74a282a5a4d19522b0900a3e4ab3cfbe","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","root_path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg02-a1055-final05-v150-6.xml","sequence":6},{"command_source":{"bytes":22737,"metadata":[66306,35783760,33152,1000,1000,1,22737,1793981710049116646,1793981710049116646],"path":"/home/alex/codex-hepta-natural-root-r10-neg02-a1055-final05-root-v150/DETAILS-MENU.json","sha256":"f207a7ebcfd0aed107db0ef91c5bfdf9c2347fa1c5a393542ee885c1a171fa5e"},"expected_bytes":20280,"expected_sha256":"af100e2502584c375063ef1bbb0d3f3c120a01730b20b5221b927022bb68e303","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","root_path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg02-a1055-final05-v150-7.xml","sequence":7},{"command_source":{"bytes":106071,"metadata":[66306,35783762,33152,1000,1000,1,106071,1793981712568304456,1793981712568304456],"path":"/home/alex/codex-hepta-natural-root-r10-neg02-a1055-final05-root-v150/RAW-DETAILS.json","sha256":"b3123bb8ef065cf40e4ee86237c9f3e44c2c06025d98d63316005c98dea67d5d"},"expected_bytes":104139,"expected_sha256":"e8646bae1d9cdb53f928754d4777b19c3398eaafee5c2ce2fda664cb844dc323","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","root_path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg02-a1055-final05-v150-8.xml","sequence":8},{"command_source":{"bytes":11394,"metadata":[66306,35783772,33152,1000,1000,1,11394,1793981715176714241,1793981715176714241],"path":"/home/alex/codex-hepta-natural-root-r10-neg02-a1055-final05-root-v150/DETAILS-ACTIVITY-RETURN-UI.json","sha256":"fa1d25238c85665a315d176a6e76c4c773e7043b8e47ed4cefd7848b947abbd2"},"expected_bytes":10001,"expected_sha256":"f21f980f4870b0ef5d522ba677ad3742a504a14b9910fb23ee1946cabe466bdb","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","root_path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg02-a1055-final05-v150-9.xml","sequence":9},{"command_source":{"bytes":11398,"metadata":[66306,35783782,33152,1000,1000,1,11398,1793981718056938283,1793981718056938283],"path":"/home/alex/codex-hepta-natural-root-r10-neg02-a1055-final05-root-v150/FINAL-PRE-SEND-UI.json","sha256":"e837da8b43e33cfb7e46f928764eba19eb8f970355e6f7a417c71fe11c891409"},"expected_bytes":10001,"expected_sha256":"f21f980f4870b0ef5d522ba677ad3742a504a14b9910fb23ee1946cabe466bdb","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","root_path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg02-a1055-final05-v150-10.xml","sequence":10},{"command_source":{"bytes":11398,"metadata":[66306,35784480,33152,1000,1000,1,11398,1793981796026199357,1793981796026199357],"path":"/home/alex/codex-hepta-natural-root-r10-neg02-a1055-final05-root-v150/RESTORE-INITIAL.json","sha256":"80301832211fe81c10fd64523c9cd6f792bf6339a996424ecb309da770fb9c78"},"expected_bytes":10001,"expected_sha256":"f21f980f4870b0ef5d522ba677ad3742a504a14b9910fb23ee1946cabe466bdb","pin_basis":"exact UTF-8 recorded stdout suffix after one XML declaration","root_path":"/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg02-a1055-final05-v150-11.xml","sequence":11}],"schema":"hepta.fc33.final05.xml-readonly-inputs.v1","sender_private_originals":{"bytes":1784864,"path":"/home/alex/razr60-local-model-v150/fc33-final05-failed-scope-readonly01-import02/recovery-scope-derivation01/SENDER-ORIGINALS.PRIVATE.json.gz","sha256":"dd4c1bdc3a64be1874353d2dc5c1e9edc14c48aa9175ca68451998ae57e25c5a"},"source_public_manifest":{"bytes":11024,"sha256":"1fbd5617faca1b85a47318a87b30578fe18111bb9db4129d85740aa3848de0cf"}}\n'
INPUTS_SHA='e60399fc51486e454aad6d751e728ec1f8b001ce0e72be73d5eda52f4409e855'
INPUTS=json.loads(INPUTS_RAW)
assert hashlib.sha256(INPUTS_RAW).hexdigest()==INPUTS_SHA
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
LABEL='root-r10-neg02-a1055-final05'
NONCE='9b37081161d7bcbc3adf76d2e6ec7841'
PARENT='/proc/1/root/data/local/tmp'
EXPECTED_PATHS={r['root_path'] for r in INPUTS['rows']}
assert len(EXPECTED_PATHS)==11
MAX_FILE=262144
MAX_READ=8*1024*1024
STATE=None

def need(ok,why):
    if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
def metadata(s):return [getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def check_time():need(time.monotonic()<STATE['deadline'],'XML read-only deadline')
def parent_fd(path):
    p=Path(path);need(p.parts[:4]==('/','proc','1','root') and '..' not in p.parts and len(p.parts)<=16,'exact Android anchor path')
    fd=os.open('/proc/1/root',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for part in p.parts[4:-1]:
            new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=new
        return fd,p.name
    except BaseException:os.close(fd);raise
def directory():
    parent,name=parent_fd(PARENT)
    fd=None
    try:
        fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        a=os.fstat(fd);label=os.getxattr(fd,'security.selinux');names=sorted(os.listdir(fd))
        need(len(names)<=20000 and metadata(a)==metadata(os.fstat(fd))==metadata(os.stat(name,dir_fd=parent,follow_symlinks=False))
             and os.getxattr(fd,'security.selinux')==label,'XML parent listing changed')
        return {'path':PARENT,'metadata':metadata(a),'names':names,'selinux_raw_b64':base64.b64encode(label).decode()}
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)
def read_one(expected):
    check_time();path=expected['root_path'];need(path in EXPECTED_PATHS,'exact finite XML read set')
    parent,name=parent_fd(path);fd=None
    try:
        try:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        except OSError as error:
            need(error.errno==errno.ENOENT,'XML open unknown I/O')
            before=metadata(os.fstat(parent));label=os.getxattr(parent,'security.selinux')
            try:os.stat(name,dir_fd=parent,follow_symlinks=False)
            except OSError as second:need(second.errno==errno.ENOENT,'XML absence unknown')
            else:need(False,'XML appeared after open ENOENT')
            again,leaf=parent_fd(path)
            try:
                need(leaf==name and metadata(os.fstat(again))==before,'XML absence parent changed')
                try:os.stat(leaf,dir_fd=again,follow_symlinks=False)
                except OSError as second:need(second.errno==errno.ENOENT,'XML canonical absence unknown')
                else:need(False,'XML canonical absence changed')
            finally:os.close(again)
            need(metadata(os.fstat(parent))==before and os.getxattr(parent,'security.selinux')==label,'XML absence parent bookend')
            return {'path':path,'state':'OBSERVED_ENOENT','errno':2,'parent_metadata':before,
                    'parent_selinux_raw_b64':base64.b64encode(label).decode(),'no_effect_inferred':False}
        a=os.fstat(fd);label=os.getxattr(fd,'security.selinux')
        need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=MAX_FILE,'XML regular/single-link/size bound')
        parts=[];count=0
        while True:
            check_time();part=os.read(fd,min(65536,MAX_FILE+1-count))
            if not part:break
            parts.append(part);count+=len(part);STATE['read_bytes']+=len(part)
            need(count<=MAX_FILE and STATE['read_bytes']<=MAX_READ,'XML cumulative complete read bound')
        raw=b''.join(parts);after=os.fstat(fd)
        need(len(raw)==a.st_size and metadata(a)==metadata(after)==metadata(os.stat(name,dir_fd=parent,follow_symlinks=False))
             and os.getxattr(fd,'security.selinux')==label,'XML complete read bookend changed')
        again,leaf=parent_fd(path)
        try:need(leaf==name and metadata(os.stat(leaf,dir_fd=again,follow_symlinks=False))==metadata(a),'XML canonical path changed')
        finally:os.close(again)
        digest=sha(raw)
        if digest not in STATE['blobs']:STATE['blobs'][digest]={'bytes':len(raw),'base64':base64.b64encode(raw).decode()}
        same=(len(raw)==expected['expected_bytes'] and digest==expected['expected_sha256'])
        identity=(a.st_uid==a.st_gid==2000 and stat.S_IMODE(a.st_mode) & 0o7111==0)
        row={'path':path,'state':'COMPLETE_ORIGINAL_READ','metadata':metadata(a),'bytes':len(raw),'sha256':digest,
             'selinux_raw_b64':base64.b64encode(label).decode(),'matches_recorded_original_xml':same,
             'ordinary_shell_owned_non_executable_file':identity,'raw_preserved_privately':True}
        if not same or not identity:STATE['errors'].append({'path':path,'error':'ORIGINAL_XML_BYTES_OR_CURRENT_OWNERSHIP_DIFFER'})
        return row
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)
def anchored_identity():
    need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'Root read-only credentials')
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();domain=Path('/proc/self/attr/current').read_bytes()
    need(boot==BOOT and domain.rstrip(b'\0\n')==b'u:r:magisk:s0','same boot and native Root domain')
    raw=Path('/proc/1/stat').read_bytes();head,tail=raw.rsplit(b') ',1);parts=tail.split()
    need(head.startswith(b'1 (') and len(parts)>=20 and int(parts[19])==0,'original native init identity')
    g=os.stat('/');a=os.stat('/proc/1/root');need((g.st_dev,g.st_ino)!=(a.st_dev,a.st_ino),'distinct GNU/Android root anchors')
    return {'boot_id':boot,'domain_raw_b64':base64.b64encode(domain).decode(),'pid':os.getpid(),
            'gnu_root_metadata':metadata(g),'android_root_metadata':metadata(a),
            'init_stat_original':{'bytes':len(raw),'sha256':sha(raw),'base64':base64.b64encode(raw).decode()}}
def main():
    global STATE
    STATE={'deadline':time.monotonic()+20,'read_bytes':0,'blobs':{},'errors':[]}
    old=signal.getsignal(signal.SIGALRM);need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'existing timer may not be replaced')
    def expired(_s,_f):raise TimeoutError('20-second XML read-only deadline')
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,20)
    result={'schema':'hepta.fc33.final05.xml-readonly.v1','state':'PARTIAL_XML_OBSERVATION_UNKNOWN_REMAINS','scope_label':LABEL,
        'nonce':NONCE,'public_inputs_sha256':INPUTS_SHA,'windows':[],'parent_profiles':[],
        'xml_created':0,'file_writes':0,'file_deletes':0,'ui_calls':0,'model_requests':0,'native_dispatches':0,
        'signals_to_other_processes':0,'deletion_authorized':False,'scope_closure':False,
        'existing_scope_liveness_reproven_by_this_xml_probe':False,'historical_absence_inferred':False,
        'stdout_contains_private_xml_originals_do_not_publish':True,'automatic_retry':False}
    error=None;rc=0;output_started=False
    try:
        try:
            result['collector_identity']=anchored_identity();result['parent_profiles'].append(directory())
            for window in (0,1):
                rows=[];result['windows'].append({'index':window,'rows':rows})
                for expected in INPUTS['rows']:rows.append(read_one(expected))
                result['parent_profiles'].append(directory())
            need(result['windows'][0]['rows']==result['windows'][1]['rows'],'XML complete two-window bytes/full9/label differ')
            need(result['parent_profiles'][0]==result['parent_profiles'][1]==result['parent_profiles'][2],'XML common parent bookends changed')
            need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==BOOT,'boot changed')
            need(not STATE['errors'],'XML bytes/current ownership not exact')
            result['state']='COMPLETE_FRESH_XML_OBSERVATIONS_NO_CLOSURE'
        except BaseException as exc:
            error={'type':type(exc).__name__,'detail':str(exc)[:1024]};rc=1
        result.update(terminal_error=error,errors=STATE['errors'],original_blobs=STATE['blobs'],read_bytes=STATE['read_bytes'])
        raw=encoded(result);need(len(raw)<=8*1024*1024,'complete private XML packet raw bound')
        zipped=zlib.compress(raw,9)
        envelope=encoded({'schema':'hepta.fc33.final05.xml-readonly.packet.v1','private_originals':True,
            'packet':{'encoding':'zlib-base64','bytes':len(raw),'sha256':sha(raw),'compressed_bytes':len(zipped),
                      'compressed_sha256':sha(zipped),'base64':base64.b64encode(zipped).decode()},'qualification_granted':False})
        need(len(envelope)<=8*1024*1024,'unchanged8MiB complete wire cap');check_time();output_started=True
        sys.stdout.buffer.write(envelope);sys.stdout.buffer.flush()
    except BaseException as exc:
        rc=1;small=encoded({'schema':'hepta.fc33.final05.xml-readonly.output-failure.v1','state':'FULL_PRIVATE_PACKET_UNKNOWN',
            'error':type(exc).__name__+':'+str(exc)[:512],'qualification_granted':False,'automatic_retry':False})
        stream=sys.stderr.buffer if output_started else sys.stdout.buffer;stream.write(small);stream.flush()
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,old)
    return rc
if __name__=='__main__':raise SystemExit(main())
