"""Fresh complete host-preservation admission before the only phone actor exec."""
CACHE={};READ_BYTES=0

def read_original(pin,maximum=16*1024*1024):
    global READ_BYTES
    path=Path(pin['path']);need(path.resolve(strict=True)==path,'canonical exact host original path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==before.st_gid==1000 and 0<=before.st_size<=maximum,'actual host original private file type/size/owner')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(maximum+1)
        READ_BYTES+=len(raw);need(READ_BYTES<=64*1024*1024 and len(raw)==before.st_size and full9(before)==full9(os.fstat(fd))==full9(path.lstat()),'complete original byte/full9 budget and bookend')
        row={'path':str(path),'bytes':len(raw),'sha256':sha(raw),'metadata':full9(before)}
        for k in ('bytes','sha256','metadata'):
            if k in pin:need(row[k]==pin[k],'exact host original pin '+k)
        if str(path) in CACHE:need(CACHE[str(path)]['descriptor']==row and CACHE[str(path)]['raw']==raw,'repeated original full identity changed')
        CACHE[str(path)]={'descriptor':row,'raw':raw};return raw,row
    finally:os.close(fd)

def one_mcp(value):
    need(value.get('isError') is not True and len(value['content'])==1 and value['content'][0]['type']=='text','complete actual MCP original')
    return strict(value['content'][0]['text'])

def verify_controller(controller,request_raw,result_pin):
    publication=one_mcp(controller['request_publication']);start=one_mcp(controller['start']);status=one_mcp(controller['status']);read=one_mcp(controller['read'])
    need(publication['sha256']==sha(request_raw) and publication['written']==publication['size']==len(request_raw) and publication['mode']==0o600,'actual create-only request publication bytes')
    request=controller['request'];job=start['job'];need(request['host']=='pocket4' and request['executable']=='/usr/bin/python3' and request['args']==job['args'] and job['executable']==request['executable'] and job['host']==request['host'] and job['idempotency_key']==request['idempotency_key']=='fc33-neg01-bound02-unstarted-readonly01' and start['reused'] is False and job['launch_state']=='launched' and job['launch_error'] is None,'same unique actual controller start')
    need(job['id']==status['job_id']==read['job_id']=='1a1b2892c1a-fc05-7e7c' and status['exit_code']==0 and status['state']=='succeeded' and status['output_complete'] is True and status['output_durable'] is True and status['terminal_publication_confirmed'] is True and status['automatic_retry'] is False and status['timed_out'] is False and status['cancelled'] is False,'actual durable complete zero controller terminal')
    for name,n in (('stdout',296),('stderr',0)):
        stream=read[name];b=bytes.fromhex(stream['bytes_hex']);need(b==stream['text'].encode() and len(b)==n and stream['offset']==0 and stream['next_offset']==stream['size']==n and stream['eof'] is True and status['log_bytes'][name]=={'seen':n,'stored':n} and status['log_synced'][name] is True and status['log_truncated'][name] is False and status['log_errors'][name] is None,'whole original controller log/EOF '+name)
    summary=strict(read['stdout']['text']);need(summary['sha256']==result_pin['sha256'] and summary['run']==str(Path(result_pin['path']).parent) and summary['phone_rc']==0 and summary['status']=='command_exited' and summary['error'] is None,'actual controller binds exact successful readonly operation')
    return {'job_id':job['id'],'controller_original_sha256':sha(CONTROLLER_RAW),'exit_code':0,'both_eof':True,'phone_rc':0,'no_retry':True}

def verify():
    global HOST,FROZEN
    targets_raw,target_pin=read_original(BOUND['targets']);need(targets_raw==TARGETS_RAW,'actual TARGETS full bytes/full9')
    targets=strict(targets_raw);report_raw,report_pin=read_original(BOUND['report']);report=strict(report_raw)
    need(report['state']=='COMPLETE_UNSTARTED_SCOPE_PRIVATELY_PRESERVED_AND_INDEPENDENTLY_VERIFIED' and report['host_validation_error'] is None and report['phone_rc']==0 and report['checks']['exact_owned_file_count']==78 and report['checks']['unique_private_directories']==9,'actual independent full scope receiver result')
    inputs_raw,input_pin=read_original(BOUND['inputs']);inputs=strict(inputs_raw)
    blobs={}
    for digest,pin in sorted(targets['preserved_unique_originals'].items()):
        raw,_=read_original(pin);need(sha(raw)==digest,'every actual private blob full hash');blobs[digest]=raw
    need(len(blobs)==74 and all(r['sha256'] in blobs and len(blobs[r['sha256']])==r['bytes'] for r in targets['files']),'all78 originals actually retained by74 private blobs')
    for pin in inputs['preservation'].values():read_original(pin)
    for pin in report['output_descriptors'].values():
        if pin['path'] not in CACHE:read_original(pin,32*1024*1024)
    packet_raw=CACHE[targets['source_packet']['path']]['raw'];need(len(packet_raw)==targets['source_packet']['bytes'] and sha(packet_raw)==targets['source_packet']['sha256'],'actual complete private capture packet')
    packet=strict(packet_raw);need(packet['terminal_error'] is None and packet['errors']==[] and packet['state']=='COMPLETE_FRESH_UNSTARTED_SCOPE_CAPTURE_NO_CLOSURE','complete readonly original packet')
    for digest,row in packet['original_blobs'].items():need(base64.b64decode(row['base64'],validate=True)==blobs[digest] and row['bytes']==len(blobs[digest]),'every private packet original exactly retained')
    need(set(packet['original_blobs'])==set(blobs),'same complete retained blob namespace')
    result_raw,result_pin=read_original(targets['source_result'],12*1024*1024);original_request_raw=CACHE[report['output_descriptors']['request.original.json']['path']]['raw']
    original_operation=strict(result_raw);need(original_operation['phone']['rc']==0 and original_operation['phone']['stderr']=='','actual original phone readonly terminal')
    controller=verify_controller(strict(CONTROLLER_RAW),original_request_raw,result_pin)
    host_private_raw=CACHE[inputs['preservation']['HOST-ORIGINALS.PRIVATE.json']['path']]['raw'];HOST=strict(host_private_raw)
    FROZEN={'label':inputs['label'],'sender_root':'/home/alex/codex-hepta-natural-'+inputs['label']+'-root-v150','lease_sha256':inputs['lease_sha256'],'package_sha256':inputs['package_sha256']}
    terminal=terminal_proof();terminal_raw,_=read_original(inputs['sender_terminal_proof']);need(enc(terminal)==terminal_raw,'same full actual sender host wait and synchronous terminal proof')
    root_plan=strict(original('ROOT-PLAN.original.json'));root_manifest=strict(ROOT_SOURCE_MANIFEST_RAW)
    need(root_plan['source_package']['bytes']==len(ROOT_SOURCE_MANIFEST_RAW) and root_plan['source_package']['sha256']==sha(ROOT_SOURCE_MANIFEST_RAW),'actual original root source-package binding')
    root_row=next(r for r in root_manifest['files'] if r['path']=='source/run_component_root_once.py');root_source=original('run_component_root_once.py')
    need(root_row['bytes']==len(root_source) and root_row['sha256']==sha(root_source),'original failed root coordinator source exact manifest member')
    sender_zip=CACHE[inputs['preservation']['SENDER-ORIGINALS.PRIVATE.json.gz']['path']]['raw'];d=zlib.decompressobj(31);plain=d.decompress(sender_zip,8*1024*1024+1);need(d.eof and not d.unused_data and not d.unconsumed_tail and len(plain)<=8*1024*1024,'complete original sender private archive');sender=strict(plain)
    root=Path(sender['source_path']);need(str(root)==FROZEN['sender_root'] and root.resolve(strict=True)==root and full9(root.lstat())==sender['source_metadata'] and sorted(os.listdir(root))==sender['names'] and len(sender['files'])==23,'actual ended sender namespace exact23')
    for name,row in sorted(sender['files'].items()):
        raw,_=read_original(row['descriptor']);need(raw==base64.b64decode(row['base64'],validate=True) and row['descriptor']['path']==str(root/name),'same ended sender original complete bytes')
    need(full9(root.lstat())==sender['source_metadata'] and sorted(os.listdir(root))==sender['names'],'ended sender complete namespace bookend')
    need(not any(n.startswith('SEND.') or n in ('COMPONENT-PREPARED-NO-SEND.json','SEND-NATIVE-LATENCY.json') for n in sender['names']),'exact original sender stopped before prepared and Send')
    actor_raw,actor_pin=read_original(BOUND['actor'],65536)
    request_raw,request_pin=read_original(BOUND['request'],65536);request=strict(request_raw);need(request_pin['metadata'][3:5]==[1000,1000] and stat.S_IMODE(request_pin['metadata'][2])==0o600,'new exact private recovery request mode')
    parts=shlex.split(request['command']);need(request['kind']=='shell' and request['root'] is True and request['timeout_seconds']==80 and parts[-5:-1]==['/usr/bin/python3','-I','-B','-c'],'exact reviewed GNU recovery request route')
    loader=ast.parse(parts[-1]);n=next(n for n in loader.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='c' for t in n.targets));compressed=base64.b64decode(ast.literal_eval(n.value.args[0]),validate=True)
    decoder=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=128*1024*1024);source=decoder.decompress(compressed,max_length=BOUND['source']['bytes']+1)
    need(decoder.eof and not decoder.unused_data and len(source)==BOUND['source']['bytes'] and sha(source)==BOUND['source']['sha256'],'complete exact recovery source loader')
    namespace={'__name__':'host_exact_recovery_definition_review'};exec(compile(source,'<exact-reviewed-recovery>','exec'),namespace)
    need(namespace['RECOVERY'] is None and namespace['C'].STATE is None and namespace['C'].PROBE_STATE is None and namespace['TARGETS_RAW']==targets_raw and namespace['AUTHORITY_RAW']==AUTHORITY_RAW,'complete guarded source load and exact immutable inputs')
    files,dirs,parents=namespace['finite_plan']();expected=namespace['C'].stable_tree_projection(namespace['expected_private_tree'](files,dirs))
    for window in packet['windows']:
        need(namespace['C'].stable_tree_projection(window['private'])==expected and window['parents_before']==window['parents_after']==targets['surviving_parents'] and window['home_aliases_before']==window['home_aliases_after']==targets['home_aliases'],'actual archived packet exactly matches new whole private/parent expectation, no mixed snapshots')
        need(window['transport']==[files[r['path']] for r in inputs['transport']] and window['xml']==[files[r['path']] for r in inputs['sender_xml']],'new exact target descriptors match all15 observed external originals')
    for path,entry in CACHE.items():
        p=Path(path);need(p.resolve(strict=True)==p and full9(p.lstat())==entry['descriptor']['metadata'],'every retained original canonical full9 final bookend')
    need(root.resolve(strict=True)==root and full9(root.lstat())==sender['source_metadata'] and sorted(os.listdir(root))==sender['names'],'final actual sender namespace bookend')
    need(not Path(BOUND['operation']).exists(),'one recovery operation never started')
    return {'schema':'hepta.fc33.bound02.recovery-host-preservation-admission.v1','state':'ALL_EXACT_ORIGINALS_AND_SOURCE_RECHECKED_NO_PHONE_YET','source':BOUND['source'],'request':request_pin,'actor':actor_pin,'targets':target_pin,'scope_report':report_pin,'inputs':input_pin,'controller':controller,'host_originals_rechecked':len(CACHE),'host_bytes_read':READ_BYTES,'private_blobs':74,'sender_originals':23,'finite_files':78,'finite_directories':9,'same_actual_five_parent_profile':True,'historical_scope_never_launched_by_original_coordinator':True,'current_proc_liveness_measured':False,'role_generation_invented':False,'original_lease_not_extended':True,'scope_closure':False,'case_credit':False,'automatic_retry':False,'phone_calls':0}

def guard_main():
    parser=argparse.ArgumentParser();group=parser.add_mutually_exclusive_group(required=True);group.add_argument('--verify-only',action='store_true');group.add_argument('--execute-once',action='store_true');args=parser.parse_args()
    admission=verify()
    if args.verify_only:
        print(json.dumps({'state':admission['state'],'host_originals_rechecked':admission['host_originals_rechecked'],'host_bytes_read':admission['host_bytes_read'],'private_blobs':74,'sender_originals':23,'finite_files':78,'finite_directories':9,'same_actual_five_parent_profile':True,'phone_calls':0,'admission_written':False},sort_keys=True));return 0
    path=Path(BOUND['admission']);need(path.parent.resolve(strict=True)==path.parent,'exact host admission parent')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(enc(admission));stream.flush();os.fsync(stream.fileno())
    parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(parent)
    finally:os.close(parent)
    os.execv('/usr/bin/python3',['/usr/bin/python3','-I','-B',BOUND['actor']['path'],BOUND['label'],BOUND['request']['path']])
