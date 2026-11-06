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
