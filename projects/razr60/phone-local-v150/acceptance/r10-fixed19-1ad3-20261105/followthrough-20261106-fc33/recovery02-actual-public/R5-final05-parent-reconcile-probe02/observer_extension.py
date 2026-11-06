"""Fresh finite parent/XML/foreign-audit observation. No recovery authority."""
STATE=None
MAX_SECONDS=30
MAX_FOREIGN_FILE=4*1024*1024

def require(v,s):
    if not v:raise ValueError(s)

def root_identity():
    require(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'actual Root observer credentials')
    boot=C.proc_bytes('/proc/sys/kernel/random/boot_id',128).decode().strip();domain=C.proc_bytes('/proc/self/attr/current',4096)
    require(boot==C.BOOT and domain.rstrip(b'\0\n')==b'u:r:magisk:s0','same boot and Root domain')
    raw=C.proc_bytes('/proc/1/stat',8192);identity=C.stat_identity(raw,1,census=True)
    gnu=os.stat('/');android=os.stat(C.ANDROID)
    require(identity['pid']==1 and identity['start_ticks']==0 and (gnu.st_dev,gnu.st_ino)!=(android.st_dev,android.st_ino),'actual native init and distinct root anchors')
    return {'boot_id':boot,'domain_raw_b64':base64.b64encode(domain).decode(),'init':identity,'init_stat_original':C.blob(raw),
            'gnu_root_metadata':C.metadata(gnu),'android_root_metadata':C.metadata(android),'collector_pid':os.getpid()}

def parents():
    rows=[]
    for reference in INPUTS['parent_identity_references']:
        row=C.project_directory(C.directory(reference['path']))
        require(row['metadata'][:5]==reference['metadata'][:5] and row['selinux_raw_b64']==reference['selinux_raw_b64'],'known surviving parent identity/owner/mode/label changed')
        rows.append(row)
    require(len(rows)==5 and rows[0]['metadata']==rows[1]['metadata'] and rows[0]['names']==rows[1]['names'] and rows[0]['selinux_raw_b64']==rows[1]['selinux_raw_b64'],'complete GNU/Android common parent aliases')
    return rows

def window(index,first=None):
    value={'index':index,'parents_before':parents(),'xml':[],'foreign_audit_originals':[],'fixture_absence':None}
    STATE['windows'].append(value)
    for pin in INPUTS['xml_files']:
        row,_=C.original(pin['path'],262144,expected=pin,owner=(2000,2000,(stat.S_IMODE(pin['metadata'][2]),)),preserve=True)
        value['xml'].append(row)
    for i,path in enumerate(INPUTS['foreign_audit_paths']):
        pin=None if first is None else first['foreign_audit_originals'][i]
        # Unknown foreign records are data only. Their actual owner/mode are
        # retained; neither existence nor content grants deletion authority.
        row,_=C.original(path,MAX_FOREIGN_FILE,expected=pin,owner=None,preserve=True)
        value['foreign_audit_originals'].append(row)
    value['fixture_absence']=C.exact_absence(INPUTS['fixture_path'])
    value['parents_after']=parents()
    require(value['parents_before']==value['parents_after'],'complete parent bookends changed during observation')
    parent=value['parents_after'][-1];absence=value['fixture_absence']
    require(absence['parent_metadata']==parent['metadata'] and absence['parent_selinux_raw_b64']==parent['selinux_raw_b64'],'fresh fixture absence tied to same complete XML parent profile')
    if first is not None:
        require(first['parents_before']==value['parents_before'] and first['xml']==value['xml'] and first['foreign_audit_originals']==value['foreign_audit_originals'],'complete two-window parent/XML/audit originals differ')
        a={k:v for k,v in first['fixture_absence'].items() if k!='observed_monotonic_ns'}
        b={k:v for k,v in absence.items() if k!='observed_monotonic_ns'}
        require(a==b,'complete two-window exact fixture absence differs')
    return value

def observe():
    STATE['collector_identity']=root_identity()
    row,raw=C.original(C.INPUTS['baseline']['path'],C.MAX_FILE,expected=C.INPUTS['baseline'],owner=(0,0,(0o600,)),preserve=False)
    baseline=C.strict(raw)
    require(baseline['schema']=='hepta.native-guard.complete-inventory.v1' and baseline['roots']==C.INPUTS['baseline_roots'] and len(baseline['roots'])==44 and len(baseline['entries'])==3823,'exact existing lock-source inventory')
    STATE['lock_inventory_original']=row;STATE['locks']=C.acquire_locks(baseline)
    require(len(C.STATE['lock_fds'])==15 and STATE['locks']['alias_count']==28,'all15 declared existing locks held')
    first=window(0);window(1,first)
    reread,_=C.original(C.INPUTS['baseline']['path'],C.MAX_FILE,expected=C.INPUTS['baseline'],owner=(0,0,(0o600,)),preserve=False)
    require(row==reread and C.proc_bytes('/proc/sys/kernel/random/boot_id',128).decode().strip()==C.BOOT,'lock source and boot bookends')
    require(not C.STATE['errors'],'unknown read observation retained')

def observer_main():
    global STATE
    started=time.monotonic();initial_fds=sorted(os.listdir('/proc/self/fd'))
    C.STATE={'deadline':started+MAX_SECONDS,'read_bytes':0,'complete_file_reads':0,'errors':[],
             'evidence':{},'blobs':{},'blob_bytes':0,'lock_fds':[],'last_complete_read':None}
    STATE={'schema':'hepta.fc33.final05.parent-reconciliation-observation.v1','state':'PARTIAL_READONLY_OBSERVATION_UNKNOWN',
        'scope_label':C.LABEL,'nonce':C.NONCE,'boot_id':C.BOOT,'inputs_sha256':INPUTS_SHA,'reference_failure':INPUTS['reference_failure'],
        'reference_failure_preflight':INPUTS['reference_failure_preflight'],'windows':[],'terminal_error':None,
        'file_writes':0,'file_deletes':0,'ui_calls':0,'model_requests':0,'native_dispatches':0,'signals_to_other_processes':0,
        'foreign_originals_read_only':True,'foreign_cleanup_success_inferred':False,'all44_files_refreshed':False,
        'private82_or_transport4_refreshed':False,'known_process_liveness_refreshed':False,'all97_current_originals_proven':False,
        'scope_closure':False,'deletion_authorized':False,'business_qualified':False,'component_qualified':False,'automatic_retry':False,
        'private_xml_and_foreign_original_bodies_do_not_publish':True}
    prior=signal.getsignal(signal.SIGALRM);require(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'existing timer cannot be replaced')
    def expired(_s,_f):raise TimeoutError('30-second finite read-only observer deadline')
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,MAX_SECONDS)
    rc=0
    try:
        try:observe();STATE['state']='COMPLETE_FRESH_PARENT_XML_AND_FOREIGN_AUDIT_OBSERVATIONS_NO_CLOSURE'
        except BaseException as exc:rc=1;STATE['terminal_error']={'type':type(exc).__name__,'detail':str(exc)[:1024]}
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,prior)
        errors=[]
        for fd in reversed(C.STATE['lock_fds']):
            try:os.close(fd)
            except OSError as exc:errors.append({'errno':exc.errno})
        STATE['resources']={'initial_fd_names':initial_fds,'final_fd_names':sorted(os.listdir('/proc/self/fd')),'closed_lock_descriptors':len(C.STATE['lock_fds']),'close_errors':errors}
        if errors or STATE['resources']['initial_fd_names']!=STATE['resources']['final_fd_names']:
            rc=1;STATE['state']='READONLY_RESOURCE_FINALIZATION_UNKNOWN'
    STATE['original_blobs']=C.STATE['blobs'];STATE['read_bytes']=C.STATE['read_bytes'];STATE['errors']=C.STATE['errors'];STATE['elapsed_seconds']=time.monotonic()-started
    try:
        raw=C.encoded(STATE);require(len(raw)<=32*1024*1024,'full private observation raw packet bound')
        compressed=zlib.compress(raw,9)
        wire=C.encoded({'schema':'hepta.fc33.final05.parent-reconciliation.packet.v1','private_originals':True,'qualification_granted':False,
            'packet':{'encoding':'zlib-base64','bytes':len(raw),'sha256':C.sha(raw),'compressed_bytes':len(compressed),'compressed_sha256':C.sha(compressed),'base64':base64.b64encode(compressed).decode()}})
        require(len(wire)<=8*1024*1024,'unchanged complete8MiB stdout cap');sys.stdout.buffer.write(wire);sys.stdout.buffer.flush()
    except BaseException as exc:
        rc=1;small=C.encoded({'schema':'hepta.fc33.parent-observation.output-unknown.v1','state':'FULL_ORIGINALS_OUTPUT_UNKNOWN','error':type(exc).__name__+':'+str(exc)[:512],'automatic_retry':False,'qualification_granted':False})
        sys.stderr.buffer.write(small);sys.stderr.buffer.flush()
    return rc
