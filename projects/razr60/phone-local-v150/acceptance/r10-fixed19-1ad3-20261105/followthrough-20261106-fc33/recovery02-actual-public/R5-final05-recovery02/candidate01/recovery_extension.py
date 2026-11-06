"""Exact failed-scope recovery logic. C is the unchanged reviewed readonly module.

TARGETS and AUTHORITY are complete, byte-pinned host originals supplied by the
builder. This file is not a standalone dispatcher and contains no model/UI path.
"""

MAX_OUTPUT=8*1024*1024
MAX_INTEGER=(1<<63)-1
RECOVERY_SECONDS=55
OWNED_DIRECTORY_SUFFIXES=('', 'inputs','inputs/production','package','package/reference',
                          'package/source','claims','operator','executor','executor/actions')
RECOVERY=None

def require(v,s):
    if not v:raise ValueError(s)

def bounded_metadata(m):
    require(type(m) is list and len(m)==9 and all(type(v) is int and 0<=v<=MAX_INTEGER for v in m),'bounded exact full9')

def directory_fields(row):
    return {k:row[k] for k in ('metadata','names','selinux_raw_b64')}

def finite_plan():
    require(TARGETS['schema']=='hepta.fc33.final05.exact-recovery-targets.v1'
        and TARGETS['scope_label']==C.LABEL and TARGETS['nonce']==C.NONCE and TARGETS['boot_id']==C.BOOT,'exact failed scope binding')
    require(len(TARGETS['files'])==TARGETS['file_count']==97 and len(TARGETS['directories'])==TARGETS['directory_count']==10,'exact97 files and10 directories')
    files={r['path']:r for r in TARGETS['files']};dirs={r['path']:r for r in TARGETS['directories']}
    home=str(C.SCOPE_HOME);transport={r['path'] for r in C.INPUTS['transport']}
    xml={'/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg02-a1055-final05-v150-'+str(i)+'.xml' for i in range(1,12)}
    expected_dirs={home+('/'+n if n else '') for n in OWNED_DIRECTORY_SUFFIXES}
    private={p for p in files if p.startswith(home+'/')}
    require(len(files)==97 and len(private)==82 and len(transport)==4 and len(xml)==11
        and set(files)==private|transport|xml and set(dirs)==expected_dirs,'finite original scope has no other path')
    old=C.stable_tree_projection(TARGETS['prior_private_tree'])
    old_files={p:r for p,r in old['entries'].items() if r['kind']=='file' and p.startswith(home+'/')}
    require(set(old_files)==private,'all82 targets originate in complete private scope original')
    for p,r in old_files.items():
        require(files[p]=={k:r[k] for k in ('path','bytes','sha256','metadata','selinux_raw_b64')},'private target original descriptor changed')
    parents={r['path']:r for r in TARGETS['surviving_parents']}
    require(len(parents)==5 and set(parents)==set(C.INPUTS['parent_paths'])|{'/proc/1/root/data/local/tmp'},'exact five surviving aliases')
    retained={r['sha256']:r for r in TARGETS['preserved_blob_descriptors']}
    require(len(retained)==88,'exact private-preservation unique blob set')
    for p,r in files.items():
        bounded_metadata(r['metadata']);require(type(r['bytes']) is int and r['bytes']==r['metadata'][6]
            and r['sha256'] in retained and retained[r['sha256']]['bytes']==r['bytes'],'every97 file byte/hash is privately preserved')
        require(str(Path(p))==p and '..' not in Path(p).parts and str(Path(p).parent) in dirs|parents,'exact canonical target/direct parent')
        require(stat.S_ISREG(r['metadata'][2]) and r['metadata'][5]==1,'single-link regular target')
        label=base64.b64decode(r['selinux_raw_b64'],validate=True);require(0<len(label)<=256,'bounded original target label')
    for p,r in (dirs|parents).items():
        bounded_metadata(r['metadata']);require(stat.S_ISDIR(r['metadata'][2]),'directory target type')
        require(r['names']==sorted(set(r['names'])) and len(r['names'])<=20000,'complete unique directory names')
        require(all(type(n) is str and n not in ('.','..') and '/' not in n and '\0' not in n and len(n.encode())<=255 for n in r['names']),'bounded directory member grammar')
        require(0<len(base64.b64decode(r['selinux_raw_b64'],validate=True))<=256,'bounded directory label')
    for p,r in dirs.items():
        require(r['metadata'][3:5]==[0,0] and stat.S_IMODE(r['metadata'][2])==0o700,'private root directory ownership')
        require(r['names']==sorted(Path(q).name for q in set(files)|set(dirs) if str(Path(q).parent)==p),'private complete membership equals finite targets')
    require(AUTHORITY['sender_terminal_proof']['sha256']=='9f33402d6d3bf1b7911f0cf1d53cb47f0900c9cff1f39e4590dbc3b57bc5d5fe'
        and AUTHORITY['scope_report']['sha256']=='0e84d8aa6f2d49c479f6d1bf5fabd5bafc57ed505b342d7bfeec51bc7b232ddf'
        and AUTHORITY['xml_report']['sha256']=='d7bfcee9638946266de4be6af3c139e6323f98042f933387f873c7b408f3ee6a','complete sender and fresh original proof pins')
    return files,dirs,parents

def check_capture(files,dirs,parents):
    e=C.STATE['evidence'];require(not C.STATE['errors'],'unknown observation in exact preflight')
    require(C.stable_tree_projection(e['private_before'])==C.stable_tree_projection(TARGETS['prior_private_tree'])
        and C.stable_tree_projection(e['private_after'])==C.stable_tree_projection(TARGETS['prior_private_tree']), 'private byte/full9/label/tree changed since full preservation')
    require(e['home_aliases_before']==e['home_aliases_after']==TARGETS['prior_home_aliases'],'exact original two private aliases')
    require(e['parents_before']==e['parents_after']==[parents[p] for p in C.INPUTS['parent_paths']],'exact prior parent metadata/labels/names')
    presence=e['bounded_current_presence']
    require(all(v['state']=='ABSENT_FROM_COMPLETE_HOME_LISTING' for v in presence['home_records'].values())
        and presence['claims_directory']['names']==[] and presence['actions_directory']['names']==[]
        and e['private_after']['entries'][str(C.SCOPE_HOME/'operator')]['names']==[]
        and presence['fixture_root']['kind']=='absent','no provider/ready/accepted/claim/action/fixture record')
    require(C.project_directory(C.directory('/proc/1/root/data/local/tmp'))==parents['/proc/1/root/data/local/tmp'],'exact current XML parent original')
    require(e['locks']['alias_count']==28 and e['locks']['inode_group_count']==15 and len(C.STATE['lock_fds'])==15,'all15 required existing locks held')

def fd_directory(h):
    C.check_time();a=os.fstat(h['fd']);label=os.getxattr(h['fd'],'security.selinux');names=sorted(os.listdir(h['fd']))
    m=C.metadata(a);bounded_metadata(m)
    require(len(names)<=20000 and m==C.metadata(os.fstat(h['fd'])) and label==os.getxattr(h['fd'],'security.selinux'),'held directory full listing raced')
    for path in h['paths']:
        parent,leaf=C.parent_fd(path)
        try:require(C.metadata(os.stat(leaf,dir_fd=parent,follow_symlinks=False))==m,'held directory canonical alias changed')
        finally:os.close(parent)
    return {'metadata':m,'names':names,'selinux_raw_b64':base64.b64encode(label).decode()}

def exact_directory(h):
    observed=fd_directory(h);require(observed==h['expected'],'directory changed outside exact recorded operations');return observed

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
        fd=os.open(Path(path).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent['fd'])
        RECOVERY['file_fds'].append(fd)
        require(C.metadata(os.fstat(fd))==r['metadata'] and actual['sha256']==r['sha256'],'exact held file original')
        handles[path]={'fd':fd,'parent':parent,'original':r,'removed':False}
    retained={r['sha256']:r['bytes'] for r in TARGETS['preserved_blob_descriptors']}
    require({h:r['bytes'] for h,r in C.STATE['blobs'].items()}==retained,'all actual88 complete original bytes match private preservation')
    return handles,paths,groups

def exact_file(h):
    r=h['original'];parent=h['parent'];exact_directory(parent)
    a=os.fstat(h['fd']);label=os.getxattr(h['fd'],'security.selinux')
    require(C.metadata(a)==r['metadata'] and base64.b64encode(label).decode()==r['selinux_raw_b64'],'held file full9/label changed')
    os.lseek(h['fd'],0,os.SEEK_SET);raw=C.read_fd(h['fd'],r['bytes'])
    require(len(raw)==r['bytes'] and C.sha(raw)==r['sha256'] and C.metadata(os.fstat(h['fd']))==r['metadata']
        and os.getxattr(h['fd'],'security.selinux')==label,'immediate full target byte recheck')
    p,n=C.parent_fd(r['path'])
    try:
        require(C.metadata(os.fstat(p))==parent['expected']['metadata'] and C.metadata(os.stat(n,dir_fd=p,follow_symlinks=False))==r['metadata'],'immediate canonical target identity')
    finally:os.close(p)
    return raw

def exact_leaf_absent(parent,name):
    try:os.stat(name,dir_fd=parent['fd'],follow_symlinks=False)
    except OSError as exc:require(exc.errno==errno.ENOENT,'post-effect leaf absence unknown')
    else:require(False,'post-effect leaf remains or was replaced')

def advance_parent(h,name,is_directory):
    old=h['expected'];new=fd_directory(h)
    require(name in old['names'] and new['names']==[n for n in old['names'] if n!=name],'only exact owned leaf removed from parent')
    require(new['metadata'][:5]==old['metadata'][:5] and new['metadata'][5]==old['metadata'][5]-(1 if is_directory else 0)
        and new['selinux_raw_b64']==old['selinux_raw_b64'],'post-effect parent identity/label/nlink delta')
    h['expected']=new;exact_leaf_absent(h,name);return new

def remove_one_file(h):
    r=h['original'];parent=h['parent'];exact_file(h)
    row={'index':len(RECOVERY['operations']),'kind':'file','path':r['path'],'before_metadata':r['metadata'],
         'parent_before_metadata':parent['expected']['metadata'],'effect_attempted':True,'syscall_returned':False,'verified_absent':False}
    RECOVERY['operations'].append(row);RECOVERY['phase']='unlink_owned_file'
    os.unlink(Path(r['path']).name,dir_fd=parent['fd']);row['syscall_returned']=True;h['removed']=True
    after=C.metadata(os.fstat(h['fd']));bounded_metadata(after)
    require(after[:5]==r['metadata'][:5] and after[5]==0 and after[6:8]==r['metadata'][6:8]
        and base64.b64encode(os.getxattr(h['fd'],'security.selinux')).decode()==r['selinux_raw_b64'],'held unlinked file is exact original with zero links')
    row['after_metadata']=after;row['parent_after_metadata']=advance_parent(parent,Path(r['path']).name,False)['metadata']
    os.fsync(parent['fd']);row['parent_fsynced']=True;row['verified_absent']=True

def remove_one_directory(path,h,parent):
    current=exact_directory(h);exact_directory(parent)
    require(current['names']==[] and current['metadata'][5]==2,'owned directory is exactly empty with two links')
    row={'index':len(RECOVERY['operations']),'kind':'directory','path':path,'before_metadata':current['metadata'],
         'parent_before_metadata':parent['expected']['metadata'],'effect_attempted':True,'syscall_returned':False,'verified_absent':False}
    RECOVERY['operations'].append(row);RECOVERY['phase']='rmdir_owned_directory'
    os.rmdir(Path(path).name,dir_fd=parent['fd']);row['syscall_returned']=True;h['removed']=True
    after=C.metadata(os.fstat(h['fd']));bounded_metadata(after)
    require(after[:5]==current['metadata'][:5] and after[5]==0,'held removed directory remains exact inode with zero links')
    row['after_metadata']=after;row['parent_after_metadata']=advance_parent(parent,Path(path).name,True)['metadata']
    os.fsync(parent['fd']);row['parent_fsynced']=True;row['verified_absent']=True

def final_known_roles(tag):
    rows=[]
    for role,identity in sorted(C.INPUTS['role_identities'].items()):
        row={'role':role,'identity':identity,'proc_state':None,'kernel_state':None,'pid_argument':-identity[1],'signal':0};rows.append(row)
        try:raw=C.proc_bytes('/proc/%d/stat'%identity[0],8192)
        except OSError as exc:
            require(exc.errno==errno.ENOENT,'known-role proc absence unknown');row['proc_state']='ENOENT';row['proc_errno']=2
        else:
            row['proc_state']='PRESENT';row['actual_stat']=C.blob(raw);require(False,'known-role PID appeared; do not infer permission from reuse')
        try:os.kill(-identity[1],0)
        except OSError as exc:
            row['kernel_errno']=exc.errno;row['kernel_state']='ESRCH' if exc.errno==errno.ESRCH else 'UNKNOWN';require(exc.errno==errno.ESRCH,'known-role kernel group absence unknown')
        else:row['kernel_state']='PRESENT';require(False,'known-role process group appeared')
    return {'tag':tag,'rows':rows,'historical_wait_invented':False,'nonzero_signals':0}

def baseline_after(before):
    baseline=C.strict(base64.b64decode(C.STATE['blobs'][C.INPUTS['baseline']['sha256']]['base64'],validate=True))
    fixtures=[p for p in baseline['roots'] if p.startswith('/proc/1/root/data/local/tmp/hepta-native-guard-')]
    observed=C.tree(baseline['roots'],preserve=False,absent_fixtures=fixtures)
    C.compare_baseline(observed,baseline)
    for path,row in observed['entries'].items():
        if row['kind']!='absent':require(row==before['entries'][path],'present historical original full9/hash/label changed after cleanup')
        else:
            require(row['parent_metadata']==RECOVERY['after']['parents'][-1]['metadata']
                and row['parent_selinux_raw_b64']==RECOVERY['after']['parents'][-1]['selinux_raw_b64'],'absent historical fixture has exact modified XML parent')
    projection={'roots':observed['roots'],'entries':C.legacy_projection(observed),'file_bytes_hashed':observed['file_bytes_hashed']}
    raw=C.encoded(projection)
    expected=C.encoded({'roots':before['roots'],'entries':C.legacy_projection(before),'file_bytes_hashed':before['file_bytes_hashed']})
    require(raw==expected,'post inventory canonical old projection differs')
    return {'complete_roots':44,'complete_entries':3823,'complete_file_bytes_hashed':C.BASELINE_FILE_BYTES,
            'canonical_projection_bytes':len(raw),'canonical_projection_sha256':C.sha(raw),'equal_to_complete_preflight_projection':True,
            'all_present_labels_exact':True,'absent_fixture_parents_match_actual_surviving_parent':True}

def compressed_preflight():
    value={'schema':'hepta.fc33.exact-recovery-preflight.v1','evidence':C.STATE['evidence'],
           'actual_complete_originals':[{'sha256':h,'bytes':r['bytes']} for h,r in sorted(C.STATE['blobs'].items())],
           'all_original_bytes_preserved_by_host_authority':True,'read_bytes':C.STATE['read_bytes'],
           'targets_sha256':TARGETS_SHA,'reconciliation_sha256':RECONCILIATION_SHA,'derived_targets_sha256':DERIVED_TARGETS_SHA,'authority':AUTHORITY,'private_body_blobs_omitted_because_already_exactly_preserved':True}
    raw=C.encoded(value);require(len(raw)<=C.MAX_PACKET,'bounded full preflight proof');z=zlib.compress(raw,9)
    return {'encoding':'zlib-base64','bytes':len(raw),'sha256':C.sha(raw),'compressed_bytes':len(z),'compressed_sha256':C.sha(z),'base64':base64.b64encode(z).decode()}

def reserve_output(frame,files,dirs,parents):
    # Future output contains only these finite paths, fixed-shape metadata,
    # complete surviving parent names minus owned entries, and bounded errors.
    paths=list(files)+list(dirs)
    op_bound=sum(len(C.encoded({'path':p}))+4*9*21+1024 for p in paths)
    parent_bound=sum(len(C.encoded(r))+9*21+512 for r in parents.values())
    absence_bound=18*(max(len(p.encode()) for p in paths)+9*21+256*2+512)
    known_role_bound=2*(4*((8192+2)//3)+4096)
    other_bound=64*1024 # schemas, authority pins, fixed counters, errors <=1024 codepoints, summary
    future=op_bound+parent_bound+absence_bound+known_role_bound+other_bound
    fixed=len(C.encoded(frame));require(fixed+future<=MAX_OUTPUT,'full final audit output reserved before first mutation')
    return {'fixed_preflight_json_bytes':fixed,'operations_max_bytes':op_bound,'parents_max_bytes':parent_bound,
        'absences_max_bytes':absence_bound,'known_role_max_bytes':known_role_bound,'other_max_bytes':other_bound,
        'future_max_bytes':future,'wire_max_bytes':fixed+future,'stdout_cap':MAX_OUTPUT}

def perform_recovery():
    files,dirs,parents=finite_plan();RECOVERY['phase']='complete_original_preflight'
    C.capture();check_capture(files,dirs,parents)
    handles,dir_paths,groups=open_bound_handles(files,dirs,parents)
    RECOVERY['pre_mutation_roles']=final_known_roles('immediately_before_first_mutation')
    for h in groups.values():exact_directory(h)
    RECOVERY['preflight']=compressed_preflight();RECOVERY['output_reservation']=reserve_output(RECOVERY['preflight'],files,dirs,parents)
    # Original capture retains its160MiB limit. These additional reads are the
    # exact97 files, one complete44 inventory, both pinned input re-reads,
    # and bounded known-role/boot reads are reserved explicitly.
    extra=(C.BASELINE_FILE_BYTES+sum(r['bytes'] for r in files.values())
           +C.INPUTS['baseline']['bytes']+C.INPUTS['boundary']['bytes']+128*1024)
    RECOVERY['additional_read_allowance']=extra;C.MAX_READ_BYTES+=extra
    require(C.proc_bytes('/proc/sys/kernel/random/boot_id',128).decode().strip()==C.BOOT,'boot changed before mutation')
    RECOVERY['preflight_complete']=True
    order=sorted(files,key=lambda p:(p.endswith('/executor/server.lock'),p))
    for path in order:remove_one_file(handles[path])
    for path in sorted(dirs,key=lambda p:(-p.count('/'),p)):
        remove_one_directory(path,dir_paths[path],dir_paths[str(Path(path).parent)])
    RECOVERY['phase']='fresh_after_recovery'
    after_parents=[]
    for original in TARGETS['surviving_parents']:
        h=dir_paths[original['path']];actual=exact_directory(h)
        after_parents.append({'path':original['path'],**actual})
    RECOVERY['after']['parents']=after_parents
    common=after_parents[0]
    require(C.LABEL not in common['names'] and len(common['names'])==16 and common['metadata'][5]==18,'exact original16-home shared parent restored')
    absent=[str(C.SCOPE_HOME),str(C.ANDROID_HOME),str(C.FIXTURE)]
    absent.extend(p for p in sorted(files) if not p.startswith(str(C.SCOPE_HOME)+'/'))
    require(len(absent)==18,'exact root and external leaf absence list')
    RECOVERY['after']['absences']=[C.exact_absence(p) for p in absent]
    RECOVERY['after']['original44']=baseline_after(C.STATE['evidence']['baseline_after'])
    RECOVERY['after']['known_roles']=final_known_roles('after_exact_scope_removal')
    for pin in (C.INPUTS['baseline'],C.INPUTS['boundary']):C.original(pin['path'],C.MAX_FILE,expected=pin,owner=(0,0,(0o600,)),preserve=False)
    for original in TARGETS['surviving_parents']:
        require(C.project_directory(C.directory(original['path']))==next(r for r in after_parents if r['path']==original['path']),'final surviving parent bookend changed')
    require(C.proc_bytes('/proc/sys/kernel/random/boot_id',128).decode().strip()==C.BOOT,'boot changed after recovery')
    require(len(RECOVERY['operations'])==107 and all(r['syscall_returned'] and r['verified_absent'] and r['parent_fsynced'] for r in RECOVERY['operations']),'all exact finite operations verified')
    require(not C.STATE['errors'],'read error accumulated')
    RECOVERY['phase']='complete';RECOVERY['state']='EXACT_OWNED_SCOPE_REMOVED_ORIGINAL44_UNCHANGED_NO_CASE_CREDIT'

def cleanup_main():
    global RECOVERY
    started=time.monotonic();start_fds=sorted(os.listdir('/proc/self/fd'))
    C.STATE={'deadline':started+RECOVERY_SECONDS,'read_bytes':0,'complete_file_reads':0,'errors':[],
             'evidence':{},'blobs':{},'blob_bytes':0,'lock_fds':[],'last_complete_read':None}
    RECOVERY={'schema':'hepta.fc33.final05.exact-owned-recovery.v1','operation_label':OPERATION_LABEL,
        'scope_label':C.LABEL,'nonce':C.NONCE,'boot_id':C.BOOT,'targets_sha256':TARGETS_SHA,'reconciliation_sha256':RECONCILIATION_SHA,'derived_targets_sha256':DERIVED_TARGETS_SHA,'authority':AUTHORITY,
        'state':'PRE_MUTATION_REJECTED','phase':'initial','preflight_complete':False,'preflight':None,'operations':[],
        'after':{},'terminal_error':None,'file_fds':[],'directory_fds':[],'automatic_retry':False,
        'scope_closure':False,'component_qualified':False,'business_qualified':False,'qualified_source_parent':False,
        'ui_calls':0,'model_requests':0,'native_dispatches':0,'nonzero_signals_to_other_processes':0,
        'historical_supervisor_wait_invented':False,'host_private_originals_untouched':True}
    prior=signal.getsignal(signal.SIGALRM);require(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'existing timer cannot be replaced')
    def expired(_number,_frame):raise TimeoutError('bounded exact recovery deadline')
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,RECOVERY_SECONDS)
    rc=0
    try:
        try:perform_recovery()
        except BaseException as exc:
            rc=1;RECOVERY['terminal_error']={'type':type(exc).__name__[:128],'detail':str(exc)[:1024]}
            if RECOVERY['operations']:RECOVERY['state']='PARTIAL_RECOVERY_OR_POSTCONDITION_UNKNOWN_NO_RETRY'
            if RECOVERY['preflight'] is None:
                try:RECOVERY['preflight']=compressed_preflight()
                except BaseException:RECOVERY['preflight_unavailable']=True
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,prior)
        close_errors=[]
        for key,values in [('file_fds',RECOVERY['file_fds']),('directory_fds',RECOVERY['directory_fds']),('lock_fds',C.STATE['lock_fds'])]:
            for fd in reversed(values):
                try:os.close(fd)
                except OSError as exc:close_errors.append({'kind':key,'errno':exc.errno})
        RECOVERY['resources']={'initial_fd_names':start_fds,'final_fd_names':sorted(os.listdir('/proc/self/fd')),
            'closed_file_descriptors':len(RECOVERY['file_fds']),'closed_directory_descriptors':len(RECOVERY['directory_fds']),
            'closed_lock_descriptors':len(C.STATE['lock_fds']),'close_errors':close_errors}
        del RECOVERY['file_fds'];del RECOVERY['directory_fds']
        if close_errors or RECOVERY['resources']['initial_fd_names']!=RECOVERY['resources']['final_fd_names']:
            rc=1;RECOVERY['state']='RESOURCE_FINALIZATION_UNKNOWN_NO_RETRY'
    RECOVERY['files_removed_verified']=sum(r['kind']=='file' and r['verified_absent'] for r in RECOVERY['operations'])
    RECOVERY['directories_removed_verified']=sum(r['kind']=='directory' and r['verified_absent'] for r in RECOVERY['operations'])
    RECOVERY['effect_attempt_count']=len(RECOVERY['operations']);RECOVERY['read_bytes']=C.STATE['read_bytes']
    RECOVERY['elapsed_seconds']=time.monotonic()-started
    try:
        wire=C.encoded(RECOVERY);require(len(wire)<=MAX_OUTPUT,'final complete audit wire cap')
        sys.stdout.buffer.write(wire);sys.stdout.buffer.flush()
    except BaseException as exc:
        rc=1;small=C.encoded({'schema':'hepta.fc33.exact-recovery.output-unknown.v1','state':'AUDIT_OUTPUT_UNKNOWN_NO_RETRY',
            'effect_attempt_count':len(RECOVERY['operations']),'error':type(exc).__name__+':'+str(exc)[:512],
            'component_qualified':False,'business_qualified':False,'automatic_retry':False})
        sys.stderr.buffer.write(small);sys.stderr.buffer.flush()
    return rc
