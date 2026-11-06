def original(path, maximum, *, expected=None, owner=None, preserve=True):
    """One complete no-follow read; byte/full9/label bookends stay mandatory."""
    check_time()
    parent = fd = None
    path = str(path)
    started = time.monotonic_ns()
    try:
        parent, name = parent_fd(path)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= maximum <= MAX_FILE, 'bounded regular single-link original: '+path)
        if owner is not None:
            uid, gid, modes = owner
            need(before.st_uid == uid and before.st_gid == gid and stat.S_IMODE(before.st_mode) in modes,
                 'original ownership/mode: '+path)
        label = os.getxattr(fd, 'security.selinux')
        raw = read_fd(fd, maximum)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        need(len(raw) == before.st_size and metadata(before) == metadata(after) == metadata(named)
             and os.getxattr(fd, 'security.selinux') == label, 'original full read raced: '+path)
        second, leaf = parent_fd(path)
        try:
            need(leaf == name and metadata(os.stat(leaf, dir_fd=second, follow_symlinks=False)) == metadata(before),
                 'original canonical path changed: '+path)
        finally:
            os.close(second)
        row = {'kind':'file', 'path':path, 'metadata':metadata(before), 'bytes':len(raw), 'sha256':sha(raw),
               'selinux_raw_b64':base64.b64encode(label).decode()}
        if expected is not None:
            for key in ('bytes','sha256','metadata','selinux_raw_b64'):
                if key in expected:
                    need(row[key] == expected[key], 'pinned original differs '+key+': '+path)
        if preserve:
            add_blob(raw)
        STATE['complete_file_reads'] += 1
        STATE['last_complete_read'] = {'path':path, 'bytes':len(raw), 'sha256':sha(raw)}
        return row, raw
    finally:
        if fd is not None:
            os.close(fd)
        if parent is not None:
            os.close(parent)


def add_blob(raw):
    digest = sha(raw)
    previous = STATE['blobs'].get(digest)
    if previous is not None:
        need(previous['bytes'] == len(raw) and base64.b64decode(previous['base64'],validate=True) == raw,
             'original hash collision')
        return digest
    need(STATE['blob_bytes'] + len(raw) <= MAX_BLOB_BYTES, 'complete private original output budget')
    STATE['blobs'][digest] = {'bytes':len(raw), 'base64':base64.b64encode(raw).decode()}
    STATE['blob_bytes'] += len(raw)
    return digest


def project_directory(row):
    need(row['state'] == 'COMPLETE_DIRECTORY_LISTING', 'complete directory required: '+row['path'])
    return {k:row[k] for k in ('path','metadata','names','selinux_raw_b64')}


def exact_absence(path):
    """Fresh ENOENT using a held and independently reopened parent."""
    parent, name = parent_fd(path)
    try:
        before = os.fstat(parent)
        label = os.getxattr(parent, 'security.selinux')
        for _ in range(2):
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except OSError as error:
                need(error.errno == errno.ENOENT, 'absence is unknown: '+str(path))
            else:
                need(False, 'expected absent original is present: '+str(path))
        after = os.fstat(parent)
        need(metadata(before) == metadata(after) and os.getxattr(parent,'security.selinux') == label,
             'absence parent changed: '+str(path))
        second, leaf = parent_fd(path)
        try:
            need(leaf == name and metadata(os.fstat(second)) == metadata(before)
                 and os.getxattr(second,'security.selinux') == label, 'absence canonical parent changed')
            try:
                os.stat(leaf, dir_fd=second, follow_symlinks=False)
            except OSError as error:
                need(error.errno == errno.ENOENT, 'second absence is unknown')
            else:
                need(False, 'absent original appeared')
        finally:
            os.close(second)
        return {'kind':'absent','path':str(path),'absence':'ENOENT','parent_metadata':metadata(before),
                'parent_selinux_raw_b64':base64.b64encode(label).decode(),
                'observed_monotonic_ns':time.monotonic_ns(),'no_effect_inferred':False}
    finally:
        os.close(parent)


def tree(roots, *, preserve, absent_fixtures):
    """Complete recursive listing and bytes, never glob-based selective evidence."""
    result = {}
    byte_count = 0
    fixtures = set(absent_fixtures)
    for root in roots:
        need(root not in result, 'duplicate tree root')
        parent, name = parent_fd(root)
        try:
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except OSError as error:
                need(error.errno == errno.ENOENT and root in fixtures, 'tree root missing/unknown: '+root)
                result[root] = exact_absence(root)
                continue
        finally:
            os.close(parent)
        stack = [root]
        while stack:
            check_time()
            path = stack.pop()
            need(path not in result and len(result) < MAX_ENTRIES, 'tree entry duplicate/budget')
            parent, name = parent_fd(path)
            try:
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            finally:
                os.close(parent)
            fixture = any(path == p or path.startswith(p+'/') for p in fixtures)
            owner = (2000,2000,(0o700,0o600,0o400)) if fixture else (0,0,(0o700,0o600))
            if preserve:
                need(info.st_uid == owner[0] and info.st_gid == owner[1]
                     and stat.S_IMODE(info.st_mode) in owner[2], 'tree private ownership/mode: '+path)
            if stat.S_ISDIR(info.st_mode):
                row = project_directory(directory(path))
                need(metadata(info) == row['metadata'], 'tree directory identity raced')
                row['kind'] = 'directory'
                need(all(type(n) is str and n not in ('.','..') and '/' not in n and '\0' not in n
                         for n in row['names']), 'directory child grammar')
                stack.extend(path+'/'+n for n in reversed(row['names']))
            else:
                need(stat.S_ISREG(info.st_mode), 'special/link tree member: '+path)
                row, _raw = original(path, MAX_FILE, owner=owner if preserve else None, preserve=preserve)
                need(metadata(info) == row['metadata'], 'tree file identity raced')
                byte_count += row['bytes']
                need(byte_count <= (MAX_PRIVATE_TREE_BYTES if preserve else BASELINE_FILE_BYTES), 'tree byte budget')
            result[path] = row
        # Every directory is re-opened after its entire descendants have been read.
        for path,row in list(result.items()):
            if (path == root or path.startswith(root+'/')) and row['kind'] == 'directory':
                need(project_directory(directory(path)) == {k:row[k] for k in ('path','metadata','names','selinux_raw_b64')},
                     'directory bookend changed: '+path)
    return {'roots':list(roots),'entries':result,'file_bytes_hashed':byte_count}


def legacy_projection(observed):
    rows = {}
    for path,row in observed['entries'].items():
        if row['kind'] == 'absent':
            rows[path] = {'kind':'absent','absence':'ENOENT'}
        elif row['kind'] == 'directory':
            rows[path] = {k:row[k] for k in ('kind','metadata','names')}
        else:
            rows[path] = {k:row[k] for k in ('kind','metadata','bytes','sha256')}
    return rows


def stable_tree_projection(observed):
    # Only the measurement time of a proved ENOENT is excluded. Full parent
    # metadata, label and every present file/directory field remain exact.
    rows = {p:({k:v for k,v in r.items() if k != 'observed_monotonic_ns'}
               if r['kind'] == 'absent' else r) for p,r in observed['entries'].items()}
    return {'roots':observed['roots'],'entries':rows,'file_bytes_hashed':observed['file_bytes_hashed']}


def compare_baseline(observed, baseline):
    need(observed['roots'] == baseline['roots'] and legacy_projection(observed) == baseline['entries']
         and observed['file_bytes_hashed'] == baseline['file_bytes_hashed'], 'original44 full inventory differs')


def acquire_locks(baseline):
    aliases = {p:r for p,r in baseline['entries'].items()
               if r['kind'] == 'file' and (p.rsplit('/',1)[-1] == 'lock' or p.endswith('.lock'))}
    need(len(aliases) == 26 and len({tuple(r['metadata'][:2]) for r in aliases.values()}) == 14,
         'original44 exact lock alias/group count')
    for p in (str(SCOPE_HOME/'executor/server.lock'),str(JOURNAL/'server.lock')):
        need(p not in aliases, 'foreign lock overlaps original44')
        aliases[p] = INPUTS['foreign_server_lock']
    groups = {}
    acquired = []
    observations = []
    try:
        for path, expected in sorted(aliases.items(),key=lambda x:(x[1]['metadata'][0],x[1]['metadata'][1],x[0])):
            row, _ = original(path,65536,expected=expected,owner=(0,0,(0o600,)),preserve=False)
            parent, name = parent_fd(path)
            try:
                fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            finally:
                os.close(parent)
            try:
                need(metadata(os.fstat(fd)) == row['metadata']
                     and base64.b64encode(os.getxattr(fd,'security.selinux')).decode() == row['selinux_raw_b64'],
                     'lock descriptor changed')
                key = tuple(row['metadata'][:2])
                if key not in groups:
                    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    groups[key] = fd
                    acquired.append(fd)
                    fd = None
                else:
                    need(metadata(os.fstat(groups[key])) == row['metadata'], 'lock aliases differ')
                observations.append(row)
            finally:
                if fd is not None:
                    os.close(fd)
        need(len(groups) == 15 and len(observations) == 28, 'exact original14 plus foreign1 lock set')
        STATE['lock_fds'] = acquired
        return {'alias_count':28,'inode_group_count':15,'old_inode_group_count':14,
                'lock_mode':'LOCK_EX|LOCK_NB on existing O_RDONLY descriptors','aliases':observations,
                'lock_files_created':0,'held_through_both_windows':True}
    except BaseException:
        for fd in reversed(acquired):
            os.close(fd)
        raise


def archive_members(raw):
    """Exact original stage archive grammar, with no extraction or target execution."""
    need(0 < len(raw) <= 8*1024*1024, 'compressed archive size bound')
    decoder = zlib.decompressobj(31)
    plain = decoder.decompress(raw,16*1024*1024+1)
    need(len(plain) <= 16*1024*1024 and decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data,
         'gzip archive incomplete/oversized/concatenated')
    files = {}
    with tarfile.open(fileobj=io.BytesIO(plain),mode='r:') as archive:
        for row in archive:
            p = Path(row.name)
            need(len(files) < 80 and str(p) == row.name and not p.is_absolute() and '..' not in p.parts
                 and '\0' not in row.name and '\\' not in row.name and row.name not in files
                 and row.isreg() and not row.pax_headers and row.uid == row.gid == 0 and row.mode == 0o600
                 and row.mtime == 0 and 0 <= row.size <= 8*1024*1024, 'original archive member differs')
            stream = archive.extractfile(row)
            need(stream is not None, 'archive member absent')
            data = stream.read(row.size+1)
            need(len(data) == row.size, 'archive member incomplete')
            files[row.name] = data
    need(sum(map(len,files.values())) <= 8*1024*1024 and len(files) == 61, 'exact61 stage members required')
    canonical = io.BytesIO()
    with tarfile.open(fileobj=canonical,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for name,data in sorted(files.items()):
            row = tarfile.TarInfo(name)
            row.mode = 0o600; row.uid = row.gid = 0; row.mtime = 0; row.size = len(data)
            archive.addfile(row,io.BytesIO(data))
    need(plain == canonical.getvalue(), 'noncanonical archive metadata/order/trailing content')
    return files


def immutable_stage_members(files, observed):
    lease_raw = files['LEASE.json']; manifest_raw = files['package/MANIFEST.json']
    need(sha(lease_raw) == LEASE_SHA and sha(manifest_raw) == PACKAGE_SHA, 'stage lease/package pins')
    lease = strict(lease_raw); manifest = strict(manifest_raw)
    need(lease == INPUTS['lease'] and manifest['files'] == INPUTS['runtime_files'], 'exact old scope/37 file set')
    expected = {'LEASE.json','owner-request.txt','sender-contract.json','package/MANIFEST.json',
                'inputs/COMBINATION.json','inputs/SOURCE-SEAL.original.json','inputs/configuration.original.json',
                'inputs/service-inputs.original.json','inputs/PRIOR-BOUNDARY.original.json'}
    expected.update('package/'+r['path'] for r in manifest['files'])
    reviewed = strict(files['package/reference/REVIEWED-PRODUCTION-PINS.json'])
    need(len(reviewed) == 15, 'original production pin count')
    expected.update('inputs/production/'+name for name in reviewed)
    need(set(files) == expected and len(manifest['files']) == 37, 'stage61/runtime37 exact namespaces')
    for r in manifest['files']:
        b = files['package/'+r['path']]
        need(len(b) == r['bytes'] and sha(b) == r['sha256'], 'archived runtime file pin')
    for name,digest in reviewed.items():
        need('/' not in name and name.endswith('.py') and sha(files['inputs/production/'+name]) == digest,
             'archived production original differs')
    rows = []
    for name,raw in sorted(files.items()):
        path = str(SCOPE_HOME/name); row = observed['entries'].get(path)
        need(row is not None and row['kind'] == 'file' and row['bytes'] == len(raw)
             and row['sha256'] == sha(raw) and base64.b64decode(STATE['blobs'][row['sha256']]['base64'],validate=True) == raw,
             'current staged member no longer exact: '+name)
        rows.append({'relative_path':name,'path':path,'bytes':len(raw),'sha256':sha(raw),'metadata':row['metadata']})
    return {'archive_member_count':61,'runtime_file_count':37,'all61_current_bytes_equal_original_archive':True,
            'all37_current_bytes_equal_original_manifest':True,'members':rows}


def process_window(index):
    """Two known identities only; signal zero queries cannot terminate a process."""
    started = time.monotonic_ns()
    identities = INPUTS['role_identities']
    result = {'index':index,'started_monotonic_ns':started,'original_identities':identities,
              'process_observations':[], 'census':{}, 'kernel_group_queries':[]}
    STATE['evidence'].setdefault('process_windows',[]).append(result)
    for role,identity in sorted(identities.items()):
        item = inspect_pid(identity[0],[identity]); item['role'] = role
        result['process_observations'].append(item)
    names = sorted((n for n in os.listdir('/proc') if n.isdecimal()),key=int)
    need(len(names) <= MAX_PIDS, 'proc PID count budget')
    limit = min(STATE['deadline'],time.monotonic()+CENSUS_SECONDS)
    rows = {}; members = []; disappeared = []
    ids = {tuple(v) for v in identities.values()}
    groups = {v[1] for v in identities.values()}
    sessions = {v[2] for v in identities.values()}
    for name in names:
        check_time();need(time.monotonic() < limit, 'proc census deadline; absence unknown')
        pid = int(name)
        try:
            raw = proc_bytes('/proc/%d/stat'%pid,8192)
        except OSError as error:
            need(error.errno == errno.ENOENT, 'proc census unknown I/O')
            disappeared.append(pid)
            rows[name] = {'state':'OBSERVED_ENOENT','errno':errno.ENOENT}
            continue
        row = stat_identity(raw,pid,census=True)
        rows[name] = {'state':'COMPLETE_PROC_STAT','identity':row,**blob(raw)}
        if tuple(generation(row)) in ids or row['pgid'] in groups or row['sid'] in sessions:
            members.append(row)
    need(time.monotonic() < limit, 'proc census deadline; absence unknown')
    result['census'] = {'complete':True,'numeric_pid_count':len(names),'names':names,'stat_originals':rows,
                        'disappeared_while_reading':disappeared,'members':members}
    # Do not send any nonzero signal. A live/reused group or EPERM is UNKNOWN,
    # never a permission to kill or a successful absence observation.
    for role,identity in sorted(identities.items()):
        pgid = identity[1]
        need(identity[:3] == [identity[0]]*3 and all(type(v) is int and v > 1 for v in identity), 'exact session identity')
        row = {'role':role,'identity':identity,'syscall':'kill','pid_argument':-pgid,'signal':0,
               'observed_monotonic_ns':time.monotonic_ns()}
        try:
            os.kill(-pgid,0)
        except OSError as error:
            row['errno'] = error.errno
            row['state'] = 'ESRCH' if error.errno == errno.ESRCH else 'UNKNOWN_ERROR'
        else:
            row['errno'] = None;row['state'] = 'GROUP_EXISTS'
        result['kernel_group_queries'].append(row)
    result['finished_monotonic_ns'] = time.monotonic_ns()
    result['known_groups_absent_in_this_window'] = not members and all(r['state'] == 'ESRCH' for r in result['kernel_group_queries'])
    need(result['known_groups_absent_in_this_window'], 'original known process group absence not established')
    return result


def require_known_originals(observed):
    for path,pin in INPUTS['known_originals'].items():
        row = observed['entries'].get(path)
        need(row is not None and row['kind'] == 'file', 'known lifecycle original absent: '+path)
        for key in ('bytes','sha256','metadata','selinux_raw_b64'):
            need(row[key] == pin[key], 'known lifecycle original changed '+key+': '+path)


def capture():
    need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0, 'actual Root credentials')
    boot = proc_bytes('/proc/sys/kernel/random/boot_id',128).decode().strip()
    domain = proc_bytes('/proc/self/attr/current',4096)
    need(boot == BOOT and domain.rstrip(b'\0\n') == b'u:r:magisk:s0', 'same boot/native Root domain')
    init_raw = proc_bytes('/proc/1/stat',8192);init = stat_identity(init_raw,1,census=True)
    gnu_root = os.stat('/');android_root = os.stat(ANDROID)
    need(init['pid'] == 1 and init['start_ticks'] == 0
         and (gnu_root.st_dev,gnu_root.st_ino) != (android_root.st_dev,android_root.st_ino), 'native init/anchor binding')
    STATE['evidence']['collector_identity'] = {'pid':os.getpid(),'boot_id':boot,'domain_raw_b64':base64.b64encode(domain).decode(),
        'init':init,'init_stat_original':blob(init_raw),'gnu_root_metadata':metadata(gnu_root),'android_root_metadata':metadata(android_root)}
    baseline_row,baseline_raw = original(INPUTS['baseline']['path'],MAX_FILE,expected=INPUTS['baseline'],owner=(0,0,(0o600,)))
    baseline = strict(baseline_raw)
    need(baseline['schema'] == 'hepta.native-guard.complete-inventory.v1'
         and baseline['roots'] == INPUTS['baseline_roots'] and len(baseline['roots']) == 44
         and len(baseline['entries']) == 3823 and baseline['file_bytes_hashed'] == BASELINE_FILE_BYTES,
         'exact original44 inventory shape')
    boundary_row,_ = original(INPUTS['boundary']['path'],MAX_FILE,expected=INPUTS['boundary'],owner=(0,0,(0o600,)))
    STATE['evidence']['baseline_original'] = baseline_row;STATE['evidence']['boundary_original'] = boundary_row
    STATE['evidence']['locks'] = acquire_locks(baseline)
    # Known roles must already be absent before any bulk capture.
    process_window(0)
    parents_before = [project_directory(directory(p)) for p in INPUTS['parent_paths']]
    aliases_before = [project_directory(directory(p)) for p in (str(SCOPE_HOME),str(ANDROID_HOME))]
    need({k:aliases_before[0][k] for k in ('metadata','names','selinux_raw_b64')} ==
         {k:aliases_before[1][k] for k in ('metadata','names','selinux_raw_b64')}, 'GNU/Android private home aliases differ')
    transport_rows = []
    archive_raw = None
    for pin in INPUTS['transport']:
        owner = (pin['metadata'][3],pin['metadata'][4],(stat.S_IMODE(pin['metadata'][2]),))
        row,raw = original(pin['path'],MAX_FILE,expected=pin,owner=owner)
        transport_rows.append(row)
        if pin['path'] == INPUTS['archive_path']:
            archive_raw = raw
    need(archive_raw is not None, 'one exact GNU stage archive')
    files = archive_members(archive_raw)
    STATE['evidence']['transport'] = transport_rows
    fixtures = [p for p,r in baseline['entries'].items() if r['kind'] == 'absent']
    need(all(p in baseline['roots'] and p.startswith('/proc/1/root/data/local/tmp/hepta-native-guard-') for p in fixtures),
         'only exact historical fixture roots may be absent')
    # All fixture namespaces also need their original UID2000 file semantics.
    fixtures = [p for p in baseline['roots'] if p.startswith('/proc/1/root/data/local/tmp/hepta-native-guard-')]
    before = tree(baseline['roots'],preserve=False,absent_fixtures=fixtures)
    compare_baseline(before,baseline);STATE['evidence']['baseline_before'] = before
    private_before = tree([str(SCOPE_HOME),str(JOURNAL),str(FIXTURE)],preserve=True,absent_fixtures=[str(FIXTURE)])
    require_known_originals(private_before)
    STATE['evidence']['private_before'] = private_before
    STATE['evidence']['stage_members'] = immutable_stage_members(files,private_before)
    stage_row = private_before['entries'][str(SCOPE_HOME/'STAGE-COMPLETE.json')]
    need(stage_row['bytes'] == 36354 and stage_row['sha256'] == '409d65f2167f704fcc380bcd11c42536b141763e232210d2f039d12ab8e1adc0',
         'original successful stage record differs')
    # Repeat every private byte/full9 and every original44 hash under the same locks.
    private_after = tree([str(SCOPE_HOME),str(JOURNAL),str(FIXTURE)],preserve=True,absent_fixtures=[str(FIXTURE)])
    need(stable_tree_projection(private_after) == stable_tree_projection(private_before), 'private complete tree changed between windows')
    after = tree(baseline['roots'],preserve=False,absent_fixtures=fixtures)
    compare_baseline(after,baseline)
    need(stable_tree_projection(after) == stable_tree_projection(before), 'original44 complete tree changed between windows')
    STATE['evidence']['private_after'] = private_after;STATE['evidence']['baseline_after'] = after
    process_window(1)
    parents_after = [project_directory(directory(p)) for p in INPUTS['parent_paths']]
    aliases_after = [project_directory(directory(p)) for p in (str(SCOPE_HOME),str(ANDROID_HOME))]
    need(parents_before == parents_after and aliases_before == aliases_after, 'parent/private alias bookends changed')
    STATE['evidence']['parents_before'] = parents_before;STATE['evidence']['parents_after'] = parents_after
    STATE['evidence']['home_aliases_before'] = aliases_before;STATE['evidence']['home_aliases_after'] = aliases_after
    rereads = []
    for pin in [INPUTS['baseline'],INPUTS['boundary']]+INPUTS['transport']:
        owner = (pin['metadata'][3],pin['metadata'][4],(stat.S_IMODE(pin['metadata'][2]),))
        row,_ = original(pin['path'],MAX_FILE,expected=pin,owner=owner)
        rereads.append(row)
    STATE['evidence']['pinned_input_bookends'] = rereads
    need(proc_bytes('/proc/sys/kernel/random/boot_id',128).decode().strip() == BOOT, 'boot changed')
    # These are current observations, not a reconstructed historical native count.
    rows = private_before['entries'];presence = {}
    for name in INPUTS['inspect_absence_names']:
        path = str(SCOPE_HOME/name)
        if path in rows:
            presence[name] = {'state':'PRESENT','row':rows[path]}
        else:
            need('/' not in name, 'only directly enumerated home leaf absence')
            presence[name] = {'state':'ABSENT_FROM_COMPLETE_HOME_LISTING'}
    claims = rows[str(SCOPE_HOME/'claims')]
    actions = rows.get(str(JOURNAL/'actions'))
    STATE['evidence']['bounded_current_presence'] = {'home_records':presence,'claims_directory':claims,
        'actions_directory':actions,'fixture_root':rows[str(FIXTURE)],
        'historical_native_or_effect_count_inferred':None,'closure_granted':False}


def output_packet(value):
    raw = encoded(value)
    need(len(raw) <= MAX_PACKET, 'full raw evidence packet bound')
    compressed = zlib.compress(raw,9)
    wire = encoded({'schema':'hepta.fc33.failed-scope-readonly.packet.v1','qualification_granted':False,
        'packet':{'encoding':'zlib-base64','bytes':len(raw),'sha256':sha(raw),'compressed_bytes':len(compressed),
                  'compressed_sha256':sha(compressed),'base64':base64.b64encode(compressed).decode()}})
    need(len(wire) <= MAX_OUTPUT, 'complete packet exceeds unchanged8MiB output cap')
    return wire


def main():
    global STATE
    started = time.monotonic()
    STATE = {'deadline':started+MAX_SECONDS,'read_bytes':0,'complete_file_reads':0,'errors':[],
             'evidence':{},'blobs':{},'blob_bytes':0,'lock_fds':[],'last_complete_read':None}
    previous = signal.getsignal(signal.SIGALRM)
    need(signal.getitimer(signal.ITIMER_REAL) == (0.0,0.0), 'existing timer cannot be replaced')
    def expired(_signum,_frame):
        raise TimeoutError('fresh read-only scope deadline')
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,MAX_SECONDS)
    error = None;rc = 0;output_started = False
    try:
        try:
            capture()
            need(not STATE['errors'], 'one or more read observations unknown')
        except BaseException as exc:
            error = {'type':type(exc).__name__,'detail':str(exc)[:1024]};rc = 1
        value = {'schema':'hepta.fc33.failed-scope-readonly.v1',
            'state':'COMPLETE_FRESH_READONLY_SCOPE_CAPTURE_NO_CLOSURE' if error is None else 'PARTIAL_READONLY_CAPTURE_UNKNOWN_REMAINS',
            'scope':{'label':LABEL,'nonce':NONCE,'lease_sha256':LEASE_SHA,'runtime_sha256':PACKAGE_SHA,'boot_id':BOOT},
            'inputs_sha256':INPUTS_SHA,'evidence':STATE['evidence'],'original_blobs':STATE['blobs'],
            'errors':STATE['errors'],'terminal_error':error,'last_complete_read':STATE['last_complete_read'],
            'read_bytes':STATE['read_bytes'],'complete_file_reads':STATE['complete_file_reads'],
            'preserved_unique_original_bytes':STATE['blob_bytes'],'elapsed_before_output':time.monotonic()-started,
            'file_writes':0,'file_deletes':0,'nonzero_signals_to_other_processes':0,'ui_inputs':0,'model_requests':0,
            'native_dispatches':0,'endpoint_connections':0,'target_programs_imported_or_executed':0,
            'scope_closure':False,'qualified_source_parent':False,'deletion_authorized':False,
            'historical_failed_cmdline_reconstructed':False,'historical_scope_effect_count_inferred':None,
            'host_sender_or_draft_current_state_proven':False,'automatic_retry':False,
            'locks_release':'all existing descriptors closed in finally after output'}
        try:
            wire = output_packet(value);check_time();output_started = True
            sys.stdout.buffer.write(wire);sys.stdout.buffer.flush()
        except BaseException as exc:
            rc = 1
            fallback = encoded({'schema':'hepta.fc33.failed-scope-readonly.output-failure.v1',
                'state':'FULL_PACKET_NOT_PUBLISHED_OR_OUTPUT_UNKNOWN','error':type(exc).__name__+':'+str(exc)[:512],
                'label':LABEL,'qualification_granted':False,'retry_automatic':False})
            stream = sys.stderr.buffer if output_started else sys.stdout.buffer
            stream.write(fallback);stream.flush()
    finally:
        for fd in reversed(STATE['lock_fds']):
            os.close(fd)
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
    return rc


if __name__ == '__main__':
    raise SystemExit(main())
