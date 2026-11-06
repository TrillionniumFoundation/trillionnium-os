"""Exactly one previously staged, never launched scope. Read only, no closure."""
PROBE_STATE=None

def acquire_unstarted_locks(baseline):
    aliases={p:r for p,r in baseline['entries'].items() if r['kind']=='file' and (p.rsplit('/',1)[-1]=='lock' or p.endswith('.lock'))}
    need(len(aliases)==26 and len({tuple(r['metadata'][:2]) for r in aliases.values()})==14,'original44 exact26 aliases/14 inode groups')
    groups={};acquired=[];observations=[]
    try:
        for path,expected in sorted(aliases.items(),key=lambda x:(x[1]['metadata'][0],x[1]['metadata'][1],x[0])):
            row,_=original(path,65536,expected=expected,owner=(0,0,(0o600,)),preserve=False)
            parent,name=parent_fd(path)
            try:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            finally:os.close(parent)
            try:
                need(metadata(os.fstat(fd))==row['metadata'] and base64.b64encode(os.getxattr(fd,'security.selinux')).decode()==row['selinux_raw_b64'],'lock descriptor changed')
                key=tuple(row['metadata'][:2])
                if key not in groups:
                    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);groups[key]=fd;acquired.append(fd);fd=None
                else:need(metadata(os.fstat(groups[key]))==row['metadata'],'lock aliases differ')
                observations.append(row)
            finally:
                if fd is not None:os.close(fd)
        need(len(groups)==14 and len(observations)==26,'exact original14 lock set, no new scope lock exists')
        STATE['lock_fds']=acquired
        return {'alias_count':26,'inode_group_count':14,'lock_mode':'LOCK_EX|LOCK_NB on existing O_RDONLY descriptors','aliases':observations,'lock_files_created':0,'held_through_both_windows':True}
    except BaseException:
        for fd in reversed(acquired):os.close(fd)
        raise

def root_identity():
    need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'actual Root read-only collector credentials')
    boot=proc_bytes('/proc/sys/kernel/random/boot_id',128).decode().strip();domain=proc_bytes('/proc/self/attr/current',4096)
    need(boot==BOOT and domain.rstrip(b'\0\n')==b'u:r:magisk:s0','same boot and Root domain')
    raw=proc_bytes('/proc/1/stat',8192);init=stat_identity(raw,1,census=True);gnu=os.stat('/');android=os.stat(ANDROID)
    need(init['pid']==1 and init['start_ticks']==0 and (gnu.st_dev,gnu.st_ino)!=(android.st_dev,android.st_ino),'actual native init and distinct GNU/Android anchors')
    return {'boot_id':boot,'domain_raw_b64':base64.b64encode(domain).decode(),'init':init,'init_stat_original':blob(raw),'gnu_root_metadata':metadata(gnu),'android_root_metadata':metadata(android),'collector_pid':os.getpid()}

def canonical_private(path):
    a=str(ANDROID_HOME);g=str(SCOPE_HOME)
    return g+path[len(a):] if path==a or path.startswith(a+'/') else path

def parents():
    rows=[project_directory(directory(p)) for p in INPUTS['parent_paths']]
    need(len(rows)==5 and {k:rows[0][k] for k in ('metadata','names','selinux_raw_b64')}=={k:rows[1][k] for k in ('metadata','names','selinux_raw_b64')},'complete shared GNU/Android parent aliases')
    need(LABEL in rows[0]['names'] and rows[0]['metadata'][3:5]==[0,0] and stat.S_IMODE(rows[0]['metadata'][2])==0o700,'exact staged home in actual private shared parent')
    return rows

def home_aliases():
    rows=[project_directory(directory(p)) for p in (str(SCOPE_HOME),str(ANDROID_HOME))]
    need({k:rows[0][k] for k in ('metadata','names','selinux_raw_b64')}=={k:rows[1][k] for k in ('metadata','names','selinux_raw_b64')},'complete staged home aliases')
    return rows

def exact_archive(raw):
    files=archive_members(raw)
    need(len(files)==62 and [{'relative_path':n,'bytes':len(b),'sha256':sha(b)} for n,b in sorted(files.items())]==INPUTS['archive_members'],'all62 immutable original members')
    lease_raw=files['LEASE.json'];manifest_raw=files['package/MANIFEST.json'];lease=strict(lease_raw);manifest=strict(manifest_raw)
    need(sha(lease_raw)==LEASE_SHA and lease==INPUTS['lease'] and sha(manifest_raw)==PACKAGE_SHA and manifest['files']==INPUTS['runtime_files'] and len(manifest['files'])==38,'exact original lease and runtime38')
    expected={'LEASE.json','owner-request.txt','sender-contract.json','package/MANIFEST.json','inputs/COMBINATION.json','inputs/SOURCE-SEAL.original.json','inputs/configuration.original.json','inputs/service-inputs.original.json','inputs/PRIOR-BOUNDARY.original.json'}
    expected.update('package/'+r['path'] for r in manifest['files']);reviewed=strict(files['package/reference/REVIEWED-PRODUCTION-PINS.json'])
    need(len(reviewed)==15,'exact original reviewed15 production members');expected.update('inputs/production/'+n for n in reviewed)
    need(set(files)==expected,'complete declared stage archive namespace')
    for r in manifest['files']:need(len(files['package/'+r['path']])==r['bytes'] and sha(files['package/'+r['path']])==r['sha256'],'each runtime byte pin')
    for name,h in reviewed.items():need('/' not in name and name.endswith('.py') and sha(files['inputs/production/'+name])==h,'each production source byte pin')
    need(lease['label']==LABEL and lease['nonce']==NONCE and lease['boot_id']==BOOT and lease['package_sha256']==PACKAGE_SHA and lease['prior_boundary']==INPUTS['boundary'],'exact original unstarted scope')
    return files

def private_shape(observed,files):
    rows=observed['entries'];canonical={};aliases={}
    for path,row in rows.items():
        if path==str(FIXTURE):continue
        p=canonical_private(path);need(p==str(SCOPE_HOME) or p.startswith(str(SCOPE_HOME)+'/'),'only exact owned scope in private tree')
        value={k:v for k,v in row.items() if k!='path'}
        if p in canonical:need(canonical[p]==value,'all private alias content/full9/label fields agree')
        canonical[p]=value;aliases.setdefault(p,[]).append(path)
    expected_files={str(SCOPE_HOME/n) for n in files}|{str(SCOPE_HOME/'STAGE-COMPLETE.json')}
    actual_files={p for p,r in canonical.items() if r['kind']=='file'};actual_dirs={p for p,r in canonical.items() if r['kind']=='directory'}
    need(actual_files==expected_files and len(actual_files)==63 and actual_dirs==set(INPUTS['expected_directories']) and len(actual_dirs)==9,'complete current tree is exact63 files and9 unique directories')
    members=[]
    for name,raw in sorted(files.items()):
        path=str(SCOPE_HOME/name);row=rows[path]
        need(row['kind']=='file' and row['bytes']==len(raw) and row['sha256']==sha(raw) and base64.b64decode(STATE['blobs'][row['sha256']]['base64'],validate=True)==raw,'full current stage original differs '+name)
        members.append({'relative_path':name,'path':path,'bytes':len(raw),'sha256':sha(raw),'metadata':row['metadata']})
    stage_row=rows[str(SCOPE_HOME/'STAGE-COMPLETE.json')]
    need(all(stage_row[k]==INPUTS['stage_complete'][k] for k in ('bytes','sha256')),'actual successful STAGE-COMPLETE original')
    stage=strict(base64.b64decode(STATE['blobs'][stage_row['sha256']]['base64'],validate=True))
    need(stage['state']=='PRIVATE_COMPONENT_INPUTS_STAGED_NO_ROLES' and stage['members']==62 and stage['lease_sha256']==LEASE_SHA and stage['package_sha256']==PACKAGE_SHA and stage['archive_sha256']==INPUTS['transport'][0]['sha256'] and stage['service_launches']==stage['model_requests']==stage['native_tasks']==0,'original stage no-role result exact scope')
    need(stage['created_directories']==INPUTS['stage_directory_identity'],'same original created-directory identities')
    for created in stage['created_directories']:
        path=canonical_private(created['path']);row=canonical[path]
        need(row['metadata'][:5]==created['metadata'][:5],'exact originally created directory identity/mode/owner')
        if created['selinux'] is not None:need(base64.b64decode(row['selinux_raw_b64'],validate=True).rstrip(b'\0').decode()==created['selinux'],'original explicit directory label')
    for name in ('claims','operator','executor'):
        need(rows[str(SCOPE_HOME/name)]['names']==[],'unstarted scope requires empty '+name)
    fixture=rows[str(FIXTURE)];need(fixture['kind']=='absent' and fixture['absence']=='ENOENT','exact never-created fixture currently absent')
    need(type(INPUTS['lease']['expires_unix_ms']) is int and 0<INPUTS['lease']['expires_unix_ms']<time.time_ns()//1000000,'original scope lease expired, no extension')
    return {'archive_member_count':62,'runtime_file_count':38,'current_home_file_count':63,'unique_private_directory_count':9,'all_current_archive_bytes_exact':True,'all_runtime_bytes_exact':True,'members':members,'canonical_aliases':aliases,'claims_operator_executor_empty':True,'original_lease_expired':True,'process_liveness_measured':False,'role_generation_invented':False}

def capture_window(index,baseline,first=None):
    window={'index':index,'started_monotonic_ns':time.monotonic_ns(),'parents_before':parents(),'home_aliases_before':home_aliases(),'transport':[],'xml':[],'private':None,'baseline':None,'stage_members':None,'pinned_input_bookends':[]}
    PROBE_STATE['windows'].append(window)
    archive_raw=None
    for i,pin in enumerate(INPUTS['transport']):
        owner=pin['owner'];expected=pin if first is None else first['transport'][i]
        row,raw=original(pin['path'],MAX_FILE,expected=expected,owner=(owner[0],owner[1],tuple(owner[2])))
        need(row['bytes']==pin['bytes'] and row['sha256']==pin['sha256'],'same original transport bytes');window['transport'].append(row)
        if pin['path']==INPUTS['archive_path']:archive_raw=raw
    need(archive_raw is not None,'exact GNU archive original');files=exact_archive(archive_raw)
    for i,pin in enumerate(INPUTS['sender_xml']):
        expected=pin if first is None else first['xml'][i]
        row,_=original(pin['path'],262144,expected=expected,owner=(2000,2000,(0o666,)))
        need(row['bytes']==pin['bytes'] and row['sha256']==pin['sha256'],'exact original sender XML bytes');window['xml'].append(row)
    private=tree([str(SCOPE_HOME),str(JOURNAL),str(FIXTURE)],preserve=True,absent_fixtures=[str(FIXTURE)])
    window['private']=private;window['stage_members']=private_shape(private,files)
    fixtures=[p for p in baseline['roots'] if p.startswith('/proc/1/root/data/local/tmp/hepta-native-guard-')]
    current=tree(baseline['roots'],preserve=False,absent_fixtures=fixtures);compare_baseline(current,baseline);window['baseline']=current
    window['parents_after']=parents();window['home_aliases_after']=home_aliases()
    need(window['parents_before']==window['parents_after'] and window['home_aliases_before']==window['home_aliases_after'],'complete parent/home alias bookends')
    absence=private['entries'][str(FIXTURE)];tmp=window['parents_after'][-1]
    need(absence['parent_metadata']==tmp['metadata'] and absence['parent_selinux_raw_b64']==tmp['selinux_raw_b64'],'same current complete tmp parent for fixture absence and XML')
    for pin in (INPUTS['baseline'],INPUTS['boundary']):
        row,_=original(pin['path'],MAX_FILE,expected=pin,owner=(0,0,(0o600,)))
        window['pinned_input_bookends'].append(row)
    if first is not None:
        for field in ('parents_before','parents_after','home_aliases_before','home_aliases_after','transport','xml','stage_members','pinned_input_bookends'):need(first[field]==window[field],'complete two-window field differs '+field)
        need(stable_tree_projection(first['private'])==stable_tree_projection(private),'private complete byte/full9/label tree differs between windows')
        need(stable_tree_projection(first['baseline'])==stable_tree_projection(current),'original44 complete byte/full9/label tree differs between windows')
    window['finished_monotonic_ns']=time.monotonic_ns()
    return window

def capture_bound02():
    PROBE_STATE['collector_identity']=root_identity()
    row,raw=original(INPUTS['baseline']['path'],MAX_FILE,expected=INPUTS['baseline'],owner=(0,0,(0o600,)))
    baseline=strict(raw);need(baseline['schema']=='hepta.native-guard.complete-inventory.v1' and baseline['roots']==INPUTS['baseline_roots'] and len(baseline['roots'])==44 and len(baseline['entries'])==3823 and baseline['file_bytes_hashed']==BASELINE_FILE_BYTES,'exact original44 complete inventory')
    PROBE_STATE['baseline_original']=row
    row,_=original(INPUTS['boundary']['path'],MAX_FILE,expected=INPUTS['boundary'],owner=(0,0,(0o600,)));PROBE_STATE['boundary_original']=row
    PROBE_STATE['locks']=acquire_unstarted_locks(baseline)
    first=capture_window(0,baseline);capture_window(1,baseline,first)
    need(not STATE['errors'] and proc_bytes('/proc/sys/kernel/random/boot_id',128).decode().strip()==BOOT,'same boot and no unknown observations')

def probe_main():
    global STATE,PROBE_STATE
    started=time.monotonic();initial_fds=sorted(os.listdir('/proc/self/fd'))
    STATE={'deadline':started+MAX_SECONDS,'read_bytes':0,'complete_file_reads':0,'errors':[],'evidence':{},'blobs':{},'blob_bytes':0,'lock_fds':[],'last_complete_read':None}
    PROBE_STATE={'schema':'hepta.fc33.bound02.unstarted-readonly.v1','state':'PARTIAL_READONLY_CAPTURE_UNKNOWN_REMAINS','scope':{'label':LABEL,'nonce':NONCE,'lease_sha256':LEASE_SHA,'runtime_sha256':PACKAGE_SHA,'boot_id':BOOT},'inputs_sha256':INPUTS_SHA,'windows':[],'terminal_error':None,'file_writes':0,'file_deletes':0,'signals_to_other_processes':0,'ui_calls':0,'model_requests':0,'native_dispatches':0,'endpoint_connections':0,'target_programs_imported_or_executed':0,'process_liveness_measured':False,'role_generation_invented':False,'scope_closure':False,'deletion_authorized':False,'component_qualified':False,'business_qualified':False,'automatic_retry':False,'historical_native_effect_count_inferred':None,'private_request_and_XML_original_bodies_do_not_publish':True}
    previous=signal.getsignal(signal.SIGALRM);need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'existing timer cannot be replaced')
    def expired(_s,_f):raise TimeoutError('bounded unstarted-scope read-only deadline')
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,MAX_SECONDS);rc=0
    try:
        try:capture_bound02();PROBE_STATE['state']='COMPLETE_FRESH_UNSTARTED_SCOPE_CAPTURE_NO_CLOSURE'
        except BaseException as exc:rc=1;PROBE_STATE['terminal_error']={'type':type(exc).__name__,'detail':str(exc)[:1024]}
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous);errors=[]
        for fd in reversed(STATE['lock_fds']):
            try:os.close(fd)
            except OSError as exc:errors.append({'errno':exc.errno})
        PROBE_STATE['resources']={'initial_fd_names':initial_fds,'final_fd_names':sorted(os.listdir('/proc/self/fd')),'closed_lock_descriptors':len(STATE['lock_fds']),'close_errors':errors}
        if errors or PROBE_STATE['resources']['initial_fd_names']!=PROBE_STATE['resources']['final_fd_names']:
            rc=1;PROBE_STATE['state']='READONLY_RESOURCE_FINALIZATION_UNKNOWN'
    PROBE_STATE.update(original_blobs=STATE['blobs'],read_bytes=STATE['read_bytes'],complete_file_reads=STATE['complete_file_reads'],preserved_unique_original_bytes=STATE['blob_bytes'],errors=STATE['errors'],last_complete_read=STATE['last_complete_read'],elapsed_seconds=time.monotonic()-started)
    try:
        raw=encoded(PROBE_STATE);need(len(raw)<=MAX_PACKET,'complete private evidence packet bound');compressed=zlib.compress(raw,9)
        wire=encoded({'schema':'hepta.fc33.bound02.unstarted-readonly.packet.v1','private_originals':True,'qualification_granted':False,'packet':{'encoding':'zlib-base64','bytes':len(raw),'sha256':sha(raw),'compressed_bytes':len(compressed),'compressed_sha256':sha(compressed),'base64':base64.b64encode(compressed).decode()}})
        need(len(wire)<=MAX_OUTPUT,'complete8MiB output bound');sys.stdout.buffer.write(wire);sys.stdout.buffer.flush()
    except BaseException as exc:
        rc=1;sys.stderr.buffer.write(encoded({'schema':'hepta.fc33.bound02.readonly-output-unknown.v1','state':'FULL_ORIGINALS_OUTPUT_UNKNOWN','error':type(exc).__name__+':'+str(exc)[:512],'automatic_retry':False,'qualification_granted':False}));sys.stderr.buffer.flush()
    return rc
