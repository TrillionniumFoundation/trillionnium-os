"""One finite unstarted bound02 recovery. Root is the only dispatcher.

The original readonly C and exact TARGETS are immutable. The same current
parent profiles govern the fixture absence and every held directory handle.
No role PID, historical wait, case qualification, or successful task is inferred.
"""
MAX_OUTPUT=8*1024*1024
MAX_INTEGER=(1<<63)-1
RECOVERY_SECONDS=55
RECOVERY=None

def finite_plan():
    require(TARGETS['schema']=='hepta.fc33.bound02.readonly-exact-target-observation.v1' and TARGETS['phone_label']==C.LABEL and TARGETS['nonce']==C.NONCE and TARGETS['source_lease_sha256']==C.LEASE_SHA and TARGETS['source_package_sha256']==C.PACKAGE_SHA,'exact actual unstarted scope original')
    files={r['path']:r for r in TARGETS['files']};dirs={r['path']:r for r in TARGETS['directories']};parents={r['path']:r for r in TARGETS['surviving_parents']}
    home=str(C.SCOPE_HOME);private={home+'/'+r['relative_path'] for r in C.INPUTS['archive_members']}|{home+'/STAGE-COMPLETE.json'}
    transport={r['path'] for r in C.INPUTS['transport']};xml={r['path'] for r in C.INPUTS['sender_xml']}
    require(len(files)==len(TARGETS['files'])==78 and len(dirs)==len(TARGETS['directories'])==9 and len(private)==63 and len(transport)==4 and len(xml)==11 and set(files)==private|transport|xml and set(dirs)==set(C.INPUTS['expected_directories']),'finite exact63+4+11 files and9 directories')
    require(len(parents)==5 and list(parents)==C.INPUTS['parent_paths'],'same five complete surviving parents, no mixed snapshots')
    retained=TARGETS['preserved_unique_originals'];require(len(retained)==74,'actual74 complete private-preservation blobs')
    for path,row in files.items():
        bounded_metadata(row['metadata']);require(row['kind']=='file' and type(row['bytes']) is int and row['bytes']==row['metadata'][6] and row['sha256'] in retained and retained[row['sha256']]['bytes']==row['bytes'],'each78 target byte/hash has actual private preservation')
        require(str(Path(path))==path and '..' not in Path(path).parts and str(Path(path).parent) in dirs|parents and stat.S_ISREG(row['metadata'][2]) and row['metadata'][5]==1,'finite canonical single-link regular file')
        require(0<len(base64.b64decode(row['selinux_raw_b64'],validate=True))<=256,'bounded actual target label')
    for path,row in (dirs|parents).items():
        bounded_metadata(row['metadata']);require(stat.S_ISDIR(row['metadata'][2]),'actual directory type')
        require(row['names']==sorted(set(row['names'])) and len(row['names'])<=20000 and all(type(n) is str and n not in ('','.','..') and '/' not in n and '\0' not in n and len(n.encode())<=255 for n in row['names']),'complete finite directory child grammar')
        require(0<len(base64.b64decode(row['selinux_raw_b64'],validate=True))<=256,'bounded directory label')
    for path,row in dirs.items():
        require(row['metadata'][3:5]==[0,0] and stat.S_IMODE(row['metadata'][2])==0o700 and row['names']==sorted(Path(p).name for p in files|dirs if str(Path(p).parent)==path),'private directory exact owner/membership')
    require(AUTHORITY['sender_terminal_proof']==C.INPUTS['sender_terminal_proof'] and AUTHORITY['source_targets']['bytes']==len(TARGETS_RAW) and AUTHORITY['source_targets']['sha256']==TARGETS_SHA and AUTHORITY['scope_report']['sha256']=='8a2418d4ea274a508a5aa1e547b35a49fff782dabca81dafd2e763cfff83d454','actual complete target/host receiver/terminal proof pins')
    require(AUTHORITY['host_preservation_recheck_required'] is True and AUTHORITY['historical_scope_never_launched_by_original_coordinator'] is True and AUTHORITY['current_proc_liveness_measured'] is False and AUTHORITY['role_generation_invented'] is False,'precise original unstarted recovery authority')
    return files,dirs,parents

def expected_private_tree(files,dirs):
    home=str(C.SCOPE_HOME);entries={p:r for p,r in files.items() if p.startswith(home+'/')};entries.update(dirs)
    executor=entries[home+'/executor'];entries[str(C.JOURNAL)]=dict(executor,path=str(C.JOURNAL));entries[str(C.FIXTURE)]=TARGETS['fixture_absence']
    return {'roots':[home,str(C.JOURNAL),str(C.FIXTURE)],'entries':entries,'file_bytes_hashed':sum(r['bytes'] for p,r in files.items() if p.startswith(home+'/'))}

def check_capture(files,dirs,parents):
    evidence=C.PROBE_STATE;require(not C.STATE['errors'] and len(evidence['windows'])==2,'complete two-window source capture')
    expected=C.stable_tree_projection(expected_private_tree(files,dirs))
    for window in evidence['windows']:
        require(C.stable_tree_projection(window['private'])==expected,'private original complete bytes/full9/label/absence changed')
        require(window['parents_before']==window['parents_after']==TARGETS['surviving_parents'] and window['home_aliases_before']==window['home_aliases_after']==TARGETS['home_aliases'],'exact same complete current parent/home alias profiles')
        require(window['transport']==[files[r['path']] for r in C.INPUTS['transport']] and window['xml']==[files[r['path']] for r in C.INPUTS['sender_xml']],'exact all15 external original identities and bytes')
        require(window['stage_members']['claims_operator_executor_empty'] is True and window['stage_members']['original_lease_expired'] is True,'precise unstarted empty role/task scope and expired original lease')
    require(evidence['locks']['alias_count']==26 and evidence['locks']['inode_group_count']==14 and len(C.STATE['lock_fds'])==14,'all14 existing original lock groups held')
    require(C.INPUTS['lease']['expires_unix_ms']<time.time_ns()//1000000,'original unstarted lease remains expired')

def open_bound_handles(files,dirs,parents):
    groups={};paths={}
    for path,r in sorted((dirs|parents).items()):
        parent,name=C.parent_fd(path);fd=None
        try:
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            require(C.metadata(os.fstat(fd))==r['metadata'] and base64.b64encode(os.getxattr(fd,'security.selinux')).decode()==r['selinux_raw_b64'],'exact directory handle before mutation')
            key=tuple(r['metadata'][:2])
            if key not in groups:
                groups[key]={'fd':fd,'paths':[],'expected':directory_fields(r),'removed':False};RECOVERY['directory_fds'].append(fd);fd=None
            else:require(groups[key]['expected']==directory_fields(r),'directory alias full9/label/names differ')
            groups[key]['paths'].append(path);paths[path]=groups[key]
        finally:
            if fd is not None:os.close(fd)
            os.close(parent)
    for h in groups.values():exact_directory(h)
    handles={}
    for path,r in sorted(files.items()):
        owner=(r['metadata'][3],r['metadata'][4],(stat.S_IMODE(r['metadata'][2]),))
        actual,_=C.original(path,C.MAX_FILE,expected=r,owner=owner,preserve=True)
        parent=paths[str(Path(path).parent)];exact_directory(parent)
        fd=os.open(Path(path).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent['fd']);RECOVERY['file_fds'].append(fd)
        require(C.metadata(os.fstat(fd))==r['metadata'] and actual==r,'exact held original file descriptor')
        handles[path]={'fd':fd,'parent':parent,'original':r,'removed':False}
    retained={h:r['bytes'] for h,r in TARGETS['preserved_unique_originals'].items()}
    require({h:r['bytes'] for h,r in C.STATE['blobs'].items()}==retained,'all74 actual complete original blobs match private preservation')
    return handles,paths,groups

def preflight_value():
    value={'schema':'hepta.fc33.bound02.unstarted-recovery-preflight.v1','scope':{'label':C.LABEL,'nonce':C.NONCE,'lease_sha256':C.LEASE_SHA,'runtime_sha256':C.PACKAGE_SHA,'boot_id':C.BOOT},'inputs_sha256':C.INPUTS_SHA,
        'targets_sha256':TARGETS_SHA,'authority':AUTHORITY,'actual_complete_originals':[{'sha256':h,'bytes':r['bytes']} for h,r in sorted(C.STATE['blobs'].items())],
        'all_original_bytes_preserved_by_host_authority':True,'private_body_blobs_omitted_because_already_exactly_preserved':True,
        'read_bytes':C.STATE['read_bytes'],'preserved_unique_original_bytes':C.STATE['blob_bytes'],
        'file_writes':0,'file_deletes':0,'signals_to_other_processes':0,'ui_calls':0,'model_requests':0,'native_dispatches':0,'endpoint_connections':0,'target_programs_imported_or_executed':0,
        'process_liveness_measured':False,'role_generation_invented':False,'scope_closure':False,'deletion_authorized':False,'component_qualified':False,'business_qualified':False,'automatic_retry':False,'historical_native_effect_count_inferred':None,'private_request_and_XML_original_bodies_do_not_publish':True,
        'resources':{'held_lock_descriptors':len(C.STATE['lock_fds']),'closed_lock_descriptors':0,'held_file_descriptors':len(RECOVERY['file_fds']),'held_directory_descriptors':len(RECOVERY['directory_fds'])}}
    value.update(C.PROBE_STATE);return value

def compressed_preflight():
    raw=C.encoded(preflight_value());require(len(raw)<=C.MAX_PACKET,'bounded full preflight proof');z=zlib.compress(raw,9)
    return {'encoding':'zlib-base64','bytes':len(raw),'sha256':C.sha(raw),'compressed_bytes':len(z),'compressed_sha256':C.sha(z),'base64':base64.b64encode(z).decode()}

def reserve_output(frame,files,dirs,parents):
    paths=list(files)+list(dirs);op_bound=sum(len(C.encoded({'path':p}))+4*9*21+1024 for p in paths)
    parent_bound=sum(len(C.encoded(r))+9*21+512 for r in parents.values())
    absence_bound=18*(max(len(p.encode()) for p in paths)+9*21+256*2+512)
    other_bound=64*1024;future=op_bound+parent_bound+absence_bound+other_bound
    fixed=len(C.encoded(frame));require(fixed+future<=MAX_OUTPUT,'entire final audit reserved before first mutation')
    return {'fixed_preflight_json_bytes':fixed,'operations_max_bytes':op_bound,'parents_max_bytes':parent_bound,'absences_max_bytes':absence_bound,'other_max_bytes':other_bound,'future_max_bytes':future,'wire_max_bytes':fixed+future,'stdout_cap':MAX_OUTPUT}

def perform_recovery():
    files,dirs,parents=finite_plan();RECOVERY['phase']='complete_original_preflight'
    C.capture_bound02();check_capture(files,dirs,parents)
    handles,dir_paths,groups=open_bound_handles(files,dirs,parents)
    for h in groups.values():exact_directory(h)
    RECOVERY['unstarted_role_authority']={'original_sender_terminal_proof':AUTHORITY['sender_terminal_proof'],'original_root_failed_before_prepared_and_launch':True,'expired_original_lease':True,'current_complete_scope_has_only_stage_material':True,'current_proc_liveness_measured':False,'role_generation_invented':False,'no_signal_sent':True}
    RECOVERY['preflight']=compressed_preflight();RECOVERY['output_reservation']=reserve_output(RECOVERY['preflight'],files,dirs,parents)
    extra=C.BASELINE_FILE_BYTES+sum(r['bytes'] for r in files.values())+C.INPUTS['baseline']['bytes']+C.INPUTS['boundary']['bytes']+128*1024
    RECOVERY['additional_read_allowance']=extra;C.MAX_READ_BYTES+=extra
    require(C.proc_bytes('/proc/sys/kernel/random/boot_id',128).decode().strip()==C.BOOT and C.INPUTS['lease']['expires_unix_ms']<time.time_ns()//1000000,'same boot/expired original lease immediately before mutation')
    RECOVERY['preflight_complete']=True
    for path in sorted(files):remove_one_file(handles[path])
    for path in sorted(dirs,key=lambda p:(-p.count('/'),p)):remove_one_directory(path,dir_paths[path],dir_paths[str(Path(path).parent)])
    RECOVERY['phase']='fresh_after_recovery';after=[]
    for original in TARGETS['surviving_parents']:after.append({'path':original['path'],**exact_directory(dir_paths[original['path']])})
    RECOVERY['after']['parents']=after
    original=TARGETS['surviving_parents'][0];common=after[0]
    require(common['names']==[n for n in original['names'] if n!=C.LABEL] and len(common['names'])==16 and common['metadata'][5]==original['metadata'][5]-1==18,'only exact new scope removed from original shared parent')
    absent=[str(C.SCOPE_HOME),str(C.ANDROID_HOME),str(C.FIXTURE)]+[p for p in sorted(files) if not p.startswith(str(C.SCOPE_HOME)+'/')]
    require(len(absent)==18,'exact18 root/fixture/external absence list');RECOVERY['after']['absences']=[C.exact_absence(p) for p in absent]
    RECOVERY['after']['original44']=baseline_after(C.PROBE_STATE['windows'][1]['baseline'])
    for pin in (C.INPUTS['baseline'],C.INPUTS['boundary']):C.original(pin['path'],C.MAX_FILE,expected=pin,owner=(0,0,(0o600,)),preserve=False)
    for original in TARGETS['surviving_parents']:require(C.project_directory(C.directory(original['path']))==next(r for r in after if r['path']==original['path']),'complete final surviving parent bookend')
    require(C.proc_bytes('/proc/sys/kernel/random/boot_id',128).decode().strip()==C.BOOT,'same boot after recovery')
    require(len(RECOVERY['operations'])==87 and all(r['syscall_returned'] and r['verified_absent'] and r['parent_fsynced'] for r in RECOVERY['operations']) and not C.STATE['errors'],'all87 exact operations and original44 postcheck')
    RECOVERY['phase']='complete';RECOVERY['state']='EXACT_UNSTARTED_SCOPE_REMOVED_ORIGINAL44_UNCHANGED_NO_CASE_CREDIT'

def cleanup_main():
    global RECOVERY
    started=time.monotonic();start_fds=sorted(os.listdir('/proc/self/fd'))
    C.STATE={'deadline':started+RECOVERY_SECONDS,'read_bytes':0,'complete_file_reads':0,'errors':[],'evidence':{},'blobs':{},'blob_bytes':0,'lock_fds':[],'last_complete_read':None};C.PROBE_STATE={'windows':[]}
    RECOVERY={'schema':'hepta.fc33.bound02.exact-unstarted-recovery.v1','operation_label':OPERATION_LABEL,'scope_label':C.LABEL,'nonce':C.NONCE,'boot_id':C.BOOT,'targets_sha256':TARGETS_SHA,'authority':AUTHORITY,'state':'PRE_MUTATION_REJECTED','phase':'initial','preflight_complete':False,'preflight':None,'operations':[],'after':{},'terminal_error':None,'file_fds':[],'directory_fds':[],'automatic_retry':False,'scope_closure':False,'component_qualified':False,'business_qualified':False,'qualified_source_parent':False,'ui_calls':0,'model_requests':0,'native_dispatches':0,'signals_to_other_processes':0,'role_generation_invented':False,'historical_wait_invented':False,'host_private_originals_untouched':True}
    previous=signal.getsignal(signal.SIGALRM);require(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'existing timer cannot be replaced')
    def expired(_n,_f):raise TimeoutError('bounded exact unstarted recovery deadline')
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,RECOVERY_SECONDS);rc=0
    try:
        try:perform_recovery()
        except BaseException as exc:
            rc=1;RECOVERY['terminal_error']={'type':type(exc).__name__[:128],'detail':str(exc)[:1024]}
            if RECOVERY['operations']:RECOVERY['state']='PARTIAL_RECOVERY_OR_POSTCONDITION_UNKNOWN_NO_RETRY'
            if RECOVERY['preflight'] is None:
                try:RECOVERY['preflight']=compressed_preflight()
                except BaseException:RECOVERY['preflight_unavailable']=True
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous);errors=[]
        for key,values in [('file_fds',RECOVERY['file_fds']),('directory_fds',RECOVERY['directory_fds']),('lock_fds',C.STATE['lock_fds'])]:
            for fd in reversed(values):
                try:os.close(fd)
                except OSError as exc:errors.append({'kind':key,'errno':exc.errno})
        RECOVERY['resources']={'initial_fd_names':start_fds,'final_fd_names':sorted(os.listdir('/proc/self/fd')),'closed_file_descriptors':len(RECOVERY['file_fds']),'closed_directory_descriptors':len(RECOVERY['directory_fds']),'closed_lock_descriptors':len(C.STATE['lock_fds']),'close_errors':errors};del RECOVERY['file_fds'];del RECOVERY['directory_fds']
        if errors or RECOVERY['resources']['initial_fd_names']!=RECOVERY['resources']['final_fd_names']:rc=1;RECOVERY['state']='RESOURCE_FINALIZATION_UNKNOWN_NO_RETRY'
    RECOVERY['files_removed_verified']=sum(r['kind']=='file' and r['verified_absent'] for r in RECOVERY['operations']);RECOVERY['directories_removed_verified']=sum(r['kind']=='directory' and r['verified_absent'] for r in RECOVERY['operations']);RECOVERY['effect_attempt_count']=len(RECOVERY['operations']);RECOVERY['read_bytes']=C.STATE['read_bytes'];RECOVERY['elapsed_seconds']=time.monotonic()-started
    try:
        wire=C.encoded(RECOVERY);require(len(wire)<=MAX_OUTPUT,'complete final audit wire cap');sys.stdout.buffer.write(wire);sys.stdout.buffer.flush()
    except BaseException as exc:
        rc=1;sys.stderr.buffer.write(C.encoded({'schema':'hepta.fc33.bound02.recovery-output-unknown.v1','state':'AUDIT_OUTPUT_UNKNOWN_NO_RETRY','effect_attempt_count':len(RECOVERY['operations']),'error':type(exc).__name__+':'+str(exc)[:512],'component_qualified':False,'business_qualified':False,'automatic_retry':False}));sys.stderr.buffer.flush()
    return rc
