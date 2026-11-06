"""Host-only reread of the one retained observation and known0 predecessor."""

def exact_source_from_request(request, expected_source):
    words=shlex.split(request['command'])
    need(words[-5:-1]==['/usr/bin/python3','-I','-B','-c'],'exact declared Python source transport')
    assigned={n.targets[0].id:n.value for n in ast.parse(words[-1]).body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
    zipped=base64.b64decode(ast.literal_eval(assigned['c'].args[0]),validate=True)
    d=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=32*1024*1024)
    raw=d.decompress(zipped,max_length=expected_source[0]+1)
    need(d.eof and not d.unused_data and (len(raw),sha(raw))==expected_source,'complete exact request-owned source')
    return raw

def verify_parent_reconciliation(source,assignments,authority,original_targets):
    raw,report_pin=descriptor(authority['parent_reconciliation']);report=strict(raw)
    need(raw==ast.literal_eval(assignments['RECONCILIATION_RAW'])
        and sha(raw)==ast.literal_eval(assignments['RECONCILIATION_SHA'])
        and (len(raw),sha(raw))==(72764,'3f07757cf054f697e2a81ad1ce0752c6e1aa5ca6a7b09488cb122363b76b038a'),
        'actual complete reconciliation report equals frozen source')
    need(report['host_validation_error'] is None and report['state']=='COMPLETE_FINITE_OBSERVATION_PRIVATELY_PRESERVED_NO_CLOSURE',
        'retained finite observation host success')
    need((len(RECONCILIATION_VALIDATOR_RAW),sha(RECONCILIATION_VALIDATOR_RAW))==(22485,'cebb4cbe8244826208c17011e1838a31c24349dc3dd3ce37cc3f2cae5c8c9d0d')
        and authority['reconciliation_host_verifier']=={'bytes':len(RECONCILIATION_VALIDATOR_RAW),'sha256':sha(RECONCILIATION_VALIDATOR_RAW)},
        'exact reviewed pure observation validator')
    v={'__name__':'host_finite_observer_validation_only'}
    exec(compile(RECONCILIATION_VALIDATOR_RAW,'<pinned-host-only-observer-validator>','exec'),v)
    output_root=BASE/'fc33-final05-surviving-parents-readonly02-import03';bodies={}
    need(len(report['output_descriptors'])==21,'exact complete finite-observer preservation output set')
    for row in report['output_descriptors']:
        path=Path(row['path']);need(path.parent==output_root or path.parent==output_root/'private-originals','fixed observation preservation namespace')
        relative=str(path.relative_to(output_root));need(relative not in bodies,'duplicate preserved observation name')
        bodies[relative]=descriptor(row)[0]
    required={'result.original.json','phone-actor.original.py','phone-request.original.json','observer-source.original.py','observer-inputs.original.json','targets.original.json','failure-reference.original.json','original44-lock-source.original.json','intent.json.original','baseline.json.original','packet.original.PRIVATE.json'}
    need(set(bodies)-{p for p in bodies if p.startswith('private-originals/')}==required,'all actual complete observation control originals')
    need(bodies['targets.original.json']==enc(original_targets),'observation retained the same historical ownership original')
    actual_result,_=descriptor(report['actual_result']);actual_request,_=descriptor(report['actual_request'])
    need(actual_result==bodies['result.original.json'] and actual_request==bodies['phone-request.original.json'],'actual and retained observer result/request equal')
    op=strict(actual_result);request=strict(actual_request)
    need(op['label']=='ng-fc33-final05-surviving-parents-readonly02' and op['status']=='command_exited'
        and op['model_decision'] is False and op['native_task_result'] is False and op['phone']['rc']==0 and op['phone']['stderr']=='',
        'one actual completed non-native read-only observer')
    need((len(actual_request),sha(actual_request))==(28145,'e7afd47d4f41b18fe5745de2c2c32eabb8d771b54f7354fd64e89ed54fa45fbf')
        and set(request)=={'kind','root','timeout_seconds','command'} and request['kind']=='shell'
        and request['root'] is True and request['timeout_seconds']==50
        and op['phone']['command']=='/debug_ramdisk/su -c '+shlex.quote(request['command']),
        'exact reviewed actor root transformation and original request')
    observer_source=exact_source_from_request(request,(91164,'0af051db4502e1655c5e3eb1580ff6cd981fae794dc6cb41a56e1704bd490acc'))
    need(observer_source==bodies['observer-source.original.py'] and (len(bodies['phone-actor.original.py']),sha(bodies['phone-actor.original.py']))==ACTOR_PIN,
        'actual observer source and actor privately retained')
    inp_assign=v['assignments'](observer_source);inputs_raw=ast.literal_eval(inp_assign['INPUTS_RAW'])
    need(inputs_raw==bodies['observer-inputs.original.json'],'actual observer complete embedded inputs')
    inputs=strict(inputs_raw);cap_raw=ast.literal_eval(inp_assign['CAP_SOURCE_RAW'])
    need((len(cap_raw),sha(cap_raw))==(63646,'70c4dc710368da58f609208879f1fb83af5e0b428b712cfd31b8bced1907bc44'),'same original read-only capture helpers')
    cap_inputs=strict(ast.literal_eval(v['assignments'](cap_raw)['INPUTS_RAW']))
    for name in ('intent.json','baseline.json'):
        actual,_=descriptor(report['actual_operation_inputs'][name]);need(actual==bodies[name+'.original'],'actual observer input and preserved original equal')
    intent=strict(bodies['intent.json.original']);baseline=strict(bodies['baseline.json.original'])
    need(intent['label']==op['label'] and intent['request']==request and intent['request_sha256']==sha(actual_request) and intent['automatic_replay'] is False,'actual one immutable observer intent')
    need(baseline['rc']==0 and baseline['stdout'].splitlines()==['f8019f83-20a7-4f18-bea1-51c980621e4d','motorola/leap_cn/leap:16/W1VL36H.59-53-11/643c83-3ed541:user/release-keys','adb','Enforcing','3021'],'actual observer boot/transport baseline')
    envelope=strict(op['phone']['stdout'].encode());frame=envelope['packet']
    need(envelope['schema']=='hepta.fc33.final05.parent-reconciliation.packet.v1' and envelope['private_originals'] is True and envelope['qualification_granted'] is False,'actual observer packet identity')
    z=base64.b64decode(frame['base64'],validate=True)
    need(frame['encoding']=='zlib-base64' and len(z)==frame['compressed_bytes'] and sha(z)==frame['compressed_sha256'],'actual complete packet transport')
    packet_raw=v['decode_zlib'](z,frame['bytes'],frame['sha256'])
    need(packet_raw==bodies['packet.original.PRIVATE.json'],'actual complete observation packet retained')
    packet=strict(packet_raw);need(enc(packet)==packet_raw,'canonical complete observation packet')
    blobs={}
    for h,row in packet['original_blobs'].items():
        b=base64.b64decode(row['base64'],validate=True)
        need(len(b)==row['bytes'] and sha(b)==h and b==bodies['private-originals/'+h+'.bin'],'every complete private XML/foreign original retained')
        blobs[h]=b
    need(len(blobs)==10 and {'private-originals/'+h+'.bin' for h in blobs}=={p for p in bodies if p.startswith('private-originals/')},'exact ten unique blobs for thirteen observed files')
    lock_source=bodies['original44-lock-source.original.json'];need((len(lock_source),sha(lock_source))==(cap_inputs['baseline']['bytes'],cap_inputs['baseline']['sha256']),'same exact original44 lock-source bytes')
    reference=bodies['failure-reference.original.json'];need((len(reference),sha(reference))==(12129,'5dd20c0bb2fbc049dea1b168cb83a730a3abc9916677be5e47ac81bbd7518427'),'retained precise failure profile reference')
    checks=v['validate'](packet,inputs,cap_inputs,strict(lock_source),blobs,original_targets,strict(reference))
    need(enc(checks)==enc(report['checks']),'actual complete private observer evidence independently reproduces public report')
    module={'__name__':'host_recovery02_pure_projection_only'}
    exec(compile(source,'<exact-reviewed-recovery02-definitions>','exec'),module)
    need(module['C'].STATE is None and module['RECOVERY'] is None,'no phone capture or cleanup during host projection')
    need(module['TARGETS_RAW']==enc(original_targets) and module['RECONCILIATION_RAW']==raw
        and module['DERIVED_TARGETS_SHA']==sha(enc(module['TARGETS']))==authority['derived_targets_sha256'],
        'one exact derived expectation, never substituted original target raw')
    files,dirs,parents=module['finite_plan']();need(len(files)==97 and len(dirs)==10 and len(parents)==5,'same finite recovery ownership')
    old_raw,old_pin=descriptor(authority['previous_rejected_recovery']);old=strict(old_raw)
    old_request_raw,_=descriptor(authority['previous_rejected_request']);old_request=strict(old_request_raw)
    exact_source_from_request(old_request,(275947,'30172f90d4cd2cb3042a6c998a3e501d0eaba1ba3bf83bf1198a6fa19821a622'))
    need(old['label']=='ng-fc33-final05-owned-scope-recovery01' and old['status']=='command_exited'
        and old['model_decision'] is False and old['native_task_result'] is False and old['phone']['rc']==1
        and old['phone']['stderr']=='' and old['phone']['command']=='/debug_ramdisk/su -c '+shlex.quote(old_request['command']),
        'exact previous rejected actor and reviewed source')
    failed=strict(old['phone']['stdout'].encode())
    need(failed['operation_label']==old['label'] and failed['state']=='PRE_MUTATION_REJECTED'
        and failed['phase']=='complete_original_preflight' and failed['preflight_complete'] is False
        and failed['operations']==[] and failed['effect_attempt_count']==failed['files_removed_verified']==failed['directories_removed_verified']==0
        and failed['terminal_error']=={'type':'ValueError','detail':'private byte/full9/label/tree changed since full preservation'},
        'previous unique recovery is positively known to reject before effects')
    resources=failed['resources']
    need(resources['closed_file_descriptors']==resources['closed_directory_descriptors']==0
        and resources['closed_lock_descriptors']==15 and resources['close_errors']==[]
        and resources['initial_fd_names']==resources['final_fd_names'],'previous rejection released all original locks')
    return {'actual_report':report_pin,'derived_targets_sha256':module['DERIVED_TARGETS_SHA'],
        'complete_current_parent_profiles_revalidated_from_private_packet':True,'private_observer_outputs_reread':len(bodies),
        'observer_unique_private_blobs':len(blobs),'observer_files':13,'observer_XML_files':11,'foreign_audit_originals_read_only':2,
        'previous_unique_recovery_known_pre_mutation_zero':old_pin,'previous_namespace_replayed':False,
        'new_scope_or_business_authority_granted':False}
