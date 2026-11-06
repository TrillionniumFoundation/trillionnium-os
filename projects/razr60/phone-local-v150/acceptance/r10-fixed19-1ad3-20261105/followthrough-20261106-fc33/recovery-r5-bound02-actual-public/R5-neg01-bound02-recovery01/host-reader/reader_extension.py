def literal(source, name):
    tree=ast.parse(source)
    nodes=[n for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1
           and isinstance(n.targets[0],ast.Name) and n.targets[0].id==name]
    need(len(nodes)==1,'exactly one reviewed source literal: '+name)
    return ast.literal_eval(nodes[0].value)


def source_context(source, targets_raw):
    """Inspect fixed bytes only; never import or execute the phone producer."""
    cap=literal(source,'CAP_RAW')
    need(type(cap)is bytes and (len(cap),sha(cap))==PROBE_PIN
         and literal(source,'CAP_SHA')==PROBE_PIN[1],'exact immutable readonly producer bytes')
    inputs_raw=literal(cap,'INPUTS_RAW')
    need(type(inputs_raw)is bytes and len(inputs_raw)==36390 and sha(inputs_raw)==INPUTS_SHA,
         'exact original source inputs literal')
    need(literal(source,'TARGETS_RAW')==targets_raw
         and literal(source,'TARGETS_SHA')==FROZEN['targets']['sha256'],
         'complete exact target literal equals preserved original')
    authority_raw=literal(source,'AUTHORITY_RAW')
    need(type(authority_raw)is bytes and len(authority_raw)==FROZEN['authority']['bytes']
         and sha(authority_raw)==FROZEN['authority']['sha256']
         and literal(source,'AUTHORITY_SHA')==sha(authority_raw)
         and literal(source,'OPERATION_LABEL')==FROZEN['operation_label']
         and literal(source,'RECOVERY_SECONDS')==55,'exact authority, operation and deadline literals')
    return strict(inputs_raw),strict(targets_raw),strict(authority_raw),inputs_raw,authority_raw,cap


def independent_targets(targets, inputs, authority):
    need(targets['schema']=='hepta.fc33.bound02.readonly-exact-target-observation.v1'
         and targets['phone_label']==inputs['label'] and targets['nonce']==inputs['nonce']
         and targets['source_lease_sha256']==inputs['lease_sha256']
         and targets['source_package_sha256']==inputs['package_sha256'],
         'same preserved exact unstarted scope')
    files={r['path']:r for r in targets['files']}
    dirs={r['path']:r for r in targets['directories']}
    parents={r['path']:r for r in targets['surviving_parents']}
    need(len(files)==len(targets['files'])==78 and len(dirs)==len(targets['directories'])==9
         and len(parents)==5 and list(parents)==inputs['parent_paths'],
         'exact finite78 files9 directories5 parents')
    home=inputs['phone_home']
    expected={home+'/'+r['relative_path'] for r in inputs['archive_members']}|{home+'/STAGE-COMPLETE.json'}
    expected|={r['path'] for r in inputs['transport']+inputs['sender_xml']}
    need(set(files)==expected and set(dirs)==set(inputs['expected_directories']),
         'exact complete declared file and directory namespace')
    for path,row in files.items():
        regular_row(row)
        need(str(Path(path))==path and str(Path(path).parent) in dirs|parents,
             'canonical target below held declared parent')
    for path,row in (dirs|parents).items():
        directory_row(row);metadata(row['metadata'])
        if path in dirs:
            need(row['metadata'][3:5]==[0,0] and stat.S_IMODE(row['metadata'][2])==0o700
                 and row['names']==sorted(Path(p).name for p in files|dirs if str(Path(p).parent)==path),
                 'private original directory exact owner/membership')
    fixture=targets['fixture_absence'];parent=parents[str(Path(inputs['fixture']).parent)]
    need(fixture['path']==inputs['fixture'] and fixture['kind']=='absent'
         and fixture['absence']=='ENOENT' and fixture['parent_metadata']==parent['metadata']
         and fixture['parent_selinux_raw_b64']==parent['selinux_raw_b64'],
         'single coherent complete parent profile, no mixed snapshots')
    need(authority['schema']=='hepta.fc33.bound02.unstarted-recovery-authority.v1'
         and authority['sender_terminal_proof']==inputs['sender_terminal_proof']
         and authority['source_targets']==FROZEN['targets']
         and authority['historical_scope_never_launched_by_original_coordinator'] is True
         and authority['host_preservation_recheck_required'] is True
         and authority['current_proc_liveness_measured'] is False
         and authority['role_generation_invented'] is False,
         'fixed actual unstarted authority; no invented process identity')
    return files,dirs,parents


def output_reservation(frame,files,dirs,parents):
    paths=list(files)+list(dirs)
    operations=sum(len(enc({'path':p}))+4*9*21+1024 for p in paths)
    parent_bytes=sum(len(enc(r))+9*21+512 for r in parents.values())
    absences=18*(max(len(p.encode()) for p in paths)+9*21+256*2+512)
    other=64*1024;future=operations+parent_bytes+absences+other;fixed=len(enc(frame))
    need(fixed+future<=8*1024*1024,'complete output reserved within unchanged8MiB cap')
    return {'fixed_preflight_json_bytes':fixed,'operations_max_bytes':operations,
        'parents_max_bytes':parent_bytes,'absences_max_bytes':absences,'other_max_bytes':other,
        'future_max_bytes':future,'wire_max_bytes':fixed+future,'stdout_cap':8*1024*1024}


def compare_preserved_observation(observed,targets):
    keys=('files','directories','surviving_parents','home_aliases','original44_baseline',
          'source_lease_sha256','source_package_sha256','phone_label','nonce','scope_closure','deletion_authorized')
    for key in keys:
        need(enc(observed[key])==enc(targets[key]),'complete current preflight equals preserved target: '+key)
    # Each window has its own actual monotonic observation time; every identity,
    # parent field, absence result and flag is still compared without relaxation.
    a={k:v for k,v in observed['fixture_absence'].items() if k!='observed_monotonic_ns'}
    b={k:v for k,v in targets['fixture_absence'].items() if k!='observed_monotonic_ns'}
    need(enc(a)==enc(b),'exact fixture absence and same complete current parent')


def validate_recovery(value,pre,inputs,targets,authority,blobs):
    files,dirs,parents=independent_targets(targets,inputs,authority)
    need(value['schema']=='hepta.fc33.bound02.exact-unstarted-recovery.v1'
         and value['operation_label']==FROZEN['operation_label']
         and value['scope_label']==inputs['label'] and value['nonce']==inputs['nonce']
         and value['boot_id']==inputs['lease']['boot_id']
         and value['targets_sha256']==FROZEN['targets']['sha256']
         and enc(value['authority'])==enc(authority),'exact actual recovery identity and authority')
    need(value['state']=='EXACT_UNSTARTED_SCOPE_REMOVED_ORIGINAL44_UNCHANGED_NO_CASE_CREDIT'
         and value['phase']=='complete' and value['preflight_complete'] is True
         and value['terminal_error'] is None,'complete successful recovery terminal')
    for key in ('scope_closure','component_qualified','business_qualified','qualified_source_parent',
                'automatic_retry','role_generation_invented','historical_wait_invented'):
        need(value[key] is False,'unrelated authority remains false: '+key)
    for key in ('ui_calls','model_requests','native_dispatches','signals_to_other_processes'):
        need(type(value[key])is int and value[key]==0,'no unrelated effects: '+key)
    need(value['host_private_originals_untouched'] is True,'private original archive retained')
    need(pre['schema']=='hepta.fc33.bound02.unstarted-recovery-preflight.v1'
         and pre['targets_sha256']==FROZEN['targets']['sha256']
         and enc(pre['authority'])==enc(authority),'exact actual held-preflight identity')
    expected_blobs=[{'sha256':h,'bytes':len(b)} for h,b in sorted(blobs.items())]
    need(len(expected_blobs)==74 and enc(pre['actual_complete_originals'])==enc(expected_blobs)
         and pre['all_original_bytes_preserved_by_host_authority'] is True
         and pre['private_body_blobs_omitted_because_already_exactly_preserved'] is True,
         'all74 whole private originals reread and hash checked')
    prechecks,observed=validate_bound02_held_preflight(pre,inputs,blobs)
    compare_preserved_observation(observed,targets)
    expected_role_authority={'original_sender_terminal_proof':authority['sender_terminal_proof'],
        'original_root_failed_before_prepared_and_launch':True,'expired_original_lease':True,
        'current_complete_scope_has_only_stage_material':True,'current_proc_liveness_measured':False,
        'role_generation_invented':False,'no_signal_sent':True}
    need(enc(value['unstarted_role_authority'])==enc(expected_role_authority),
         'precise original never-launched authority without current process claim')
    additional=44353573+sum(r['bytes'] for r in files.values())+sum(inputs[k]['bytes'] for k in ('baseline','boundary'))+128*1024
    need(type(value['additional_read_allowance'])is int and value['additional_read_allowance']==additional==51703579,
         'finite read allowance including full final baseline and boundary rereads')
    need(enc(value['output_reservation'])==enc(output_reservation(value['preflight'],files,dirs,parents)),
         'independent full pre-mutation output reservation')
    groups={};directory_map={}
    for path,row in (dirs|parents).items():
        metadata(row['metadata']);key=tuple(row['metadata'][:2])
        fields={k:copy.deepcopy(row[k]) for k in ('metadata','names','selinux_raw_b64')}
        if key in groups:need(enc(groups[key]['fields'])==enc(fields),'initial directory aliases identical')
        else:groups[key]={'fields':fields,'removed':False}
        directory_map[path]=groups[key]
    need(len(groups)==13,'exact13 held directory inode groups')
    order=[('file',p) for p in sorted(files)]
    order += [('directory',p) for p in sorted(dirs,key=lambda p:(-p.count('/'),p))]
    operations=value['operations'];need(len(operations)==len(order)==87,'exact finite87 removal events')
    for i,(row,(kind,path)) in enumerate(zip(operations,order)):
        need(set(row)=={'index','kind','path','before_metadata','parent_before_metadata','effect_attempted',
                       'syscall_returned','verified_absent','after_metadata','parent_after_metadata','parent_fsynced'},
             'exact complete removal event shape')
        need(type(row['index'])is int and row['index']==i and (row['kind'],row['path'])==(kind,path),
             'one deterministic event for each owned target')
        need(all(row[k] is True for k in ('effect_attempted','syscall_returned','verified_absent','parent_fsynced')),
             'every actual effect returned and was checked/fsynced')
        before=row['before_metadata'];after=row['after_metadata'];pm=row['parent_after_metadata']
        for m in (before,after,row['parent_before_metadata'],pm):metadata(m)
        parent=directory_map[str(Path(path).parent)]
        need(not parent['removed'] and row['parent_before_metadata']==parent['fields']['metadata'],
             'held parent exact chained full9')
        if kind=='file':
            need(before==files[path]['metadata'] and after[:5]==before[:5] and after[5]==0
                 and after[6:8]==before[6:8],'exact original file inode lost its only link')
        else:
            current=directory_map[path]
            need(not current['removed'] and current['fields']['names']==[]
                 and before==current['fields']['metadata'] and before[5]==2,
                 'only emptied original directory removed')
            need(after[:5]==before[:5] and after[5]==0,'exact directory inode lost links')
            current['removed']=True
        old=parent['fields']['metadata'];name=Path(path).name
        need(name in parent['fields']['names'] and pm[:5]==old[:5]
             and pm[5]==old[5]-(1 if kind=='directory' else 0),'only declared parent entry/link delta')
        parent['fields']['names'].remove(name);parent['fields']['metadata']=pm
    need(all(directory_map[p]['removed'] for p in dirs),'all9 original directory identities removed')
    after=value['after'];need(set(after)=={'parents','absences','original44'},'exact final postcondition fields')
    expected_parents=[{'path':r['path'],**directory_map[r['path']]['fields']} for r in targets['surviving_parents']]
    need(enc(after['parents'])==enc(expected_parents),'complete actual after parents match all87 chained changes')
    need(inputs['label'] not in expected_parents[0]['names'] and len(expected_parents[0]['names'])==16
         and expected_parents[0]['metadata'][5]==18,'shared parent original membership restored')
    home=inputs['phone_home']
    expected_absences=[home,inputs['android_home'],inputs['fixture']]+[p for p in sorted(files) if not p.startswith(home+'/')]
    need(len(expected_absences)==18 and [r['path'] for r in after['absences']]==expected_absences,
         'complete18 exact final absence paths')
    for row in after['absences']:
        need(set(row)=={'kind','path','absence','parent_metadata','parent_selinux_raw_b64',
                       'observed_monotonic_ns','no_effect_inferred'},'exact final absence fields')
        metadata(row['parent_metadata']);parent=directory_map[str(Path(row['path']).parent)]['fields']
        need(row['kind']=='absent' and row['absence']=='ENOENT' and row['no_effect_inferred'] is False
             and type(row['observed_monotonic_ns'])is int and row['observed_monotonic_ns']>0
             and row['parent_metadata']==parent['metadata']
             and row['parent_selinux_raw_b64']==parent['selinux_raw_b64'],
             'exact held/reopened final absence and surviving parent identity')
    before=pre['windows'][1]['baseline']
    projected={'roots':before['roots'],'entries':legacy_rows(before),'file_bytes_hashed':before['file_bytes_hashed']}
    projected_raw=enc(projected)
    expected_projection={'complete_roots':44,'complete_entries':3823,'complete_file_bytes_hashed':44353573,
        'canonical_projection_bytes':len(projected_raw),'canonical_projection_sha256':sha(projected_raw),
        'equal_to_complete_preflight_projection':True,'all_present_labels_exact':True,
        'absent_fixture_parents_match_actual_surviving_parent':True}
    need(enc(after['original44'])==enc(expected_projection),
         'actual complete post-read projection exactly matches original44')
    resource=value['resources']
    need(set(resource)=={'close_errors','initial_fd_names','final_fd_names','closed_file_descriptors',
                        'closed_directory_descriptors','closed_lock_descriptors'},'complete final resource fields')
    need(resource['close_errors']==[] and resource['initial_fd_names']==resource['final_fd_names']
         and type(resource['closed_file_descriptors'])is int and resource['closed_file_descriptors']==78
         and type(resource['closed_directory_descriptors'])is int and resource['closed_directory_descriptors']==13
         and type(resource['closed_lock_descriptors'])is int and resource['closed_lock_descriptors']==14,
         'all owned descriptors closed to actual measured FD baseline')
    need(all(type(n)is str and n.isdigit() for n in resource['initial_fd_names'])
         and len(resource['initial_fd_names'])==len(set(resource['initial_fd_names'])),'exact actual FD names')
    for key,number in (('files_removed_verified',78),('directories_removed_verified',9),('effect_attempt_count',87)):
        need(type(value[key])is int and value[key]==number,'independent exact removal count '+key)
    need(type(value['read_bytes'])is int and pre['read_bytes']<=value['read_bytes']<=160*1024*1024+additional,
         'bounded actual complete read accounting')
    need(type(value['elapsed_seconds'])in (int,float) and 0<=value['elapsed_seconds']<=80,
         'bounded actual elapsed result')
    return {'exact_files_removed':78,'exact_directories_removed':9,'ordered_operations_checked':87,
        'exact_final_absences':18,'original44_roots':44,'original44_entries':3823,
        'original44_bytes_read_per_complete_window':44353573,'after_projection':expected_projection,
        'after_inventory_representation':'Complete post-read projection hash matches the independently checked complete preflight graph; no separate raw after-inventory was emitted.',
        'preflight_checks':prechecks,'preflight_adapter_is_original':False,
        'preflight_adapter_changes_only_resource_phase_validation':True,
        'whole_operation_was_readonly':False,'all14_original_locks_held_during_effects':True,
        'actual_final_resource_observation':resource,'measured_fd_baseline_restored':True,
        'current_process_liveness_measured':False,'role_generation_invented':False,
        'historical_supervisor_wait_proven':False,'producer_source_executed_by_reader':False,
        'producer_scope_closure_flag':False,'business_or_component_credit':False,
        'owned_recovery_closed':True,'fresh_component_admission_required':True}


def main():
    need(type(FROZEN)is dict,'UNBOUND_NO_IO')
    parser=argparse.ArgumentParser()
    for name in ('result','sha256','version','out'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--bytes',required=True,type=int);a=parser.parse_args()
    label=FROZEN['operation_label'];path=Path(a.result)
    need(path==BASE/'operations'/label/'result.json' and 0<a.bytes<=16*1024*1024
         and re.fullmatch('[0-9a-f]{64}',a.sha256),'one bounded actual recovery result only')
    result_raw,result_pin=read_exact(path,a.bytes,a.sha256)
    m=result_pin['metadata']
    need(':'.join(str(m[i]) for i in (0,1,6,7,8))==a.version
         and m[3:6]==[1000,1000,1] and stat.S_IMODE(m[2])==0o600,
         'actual Root-observed immutable result version and owner')
    actor_raw,actor_pin=read_exact(ACTOR,*ACTOR_PIN)
    request_raw,request_pin=read_row(FROZEN['request'])
    out=Path(a.out)
    need(out.parent==BASE and out.name==label.removeprefix('ng-')+'-import01'
         and out.parent.resolve(strict=True)==out.parent and not os.path.lexists(out),
         'fresh exact private import namespace')
    out.mkdir(mode=0o700)
    outputs=[write_new(out,'result.original.json',result_raw),write_new(out,'actor.original.py',actor_raw),
             write_new(out,'request.original.json',request_raw)]
    checks=None;error=None;operation_inputs={};preserved=[];authority_originals=[];phone_rc=None
    try:
        operation=strict(result_raw);request=strict(request_raw)
        need(operation['schema']=='hepta.phone-local.operator-result.v150.1'
             and operation['label']==label and operation['status']=='command_exited'
             and operation['model_decision'] is False and operation['native_task_result'] is False,
             'actual original recovery actor terminal')
        need(set(request)=={'kind','root','timeout_seconds','command'} and request['kind']=='shell'
             and request['root'] is True and type(request['timeout_seconds'])is int
             and request['timeout_seconds']==80,'exact reviewed recovery request')
        need(operation['phone']['command']=='/debug_ramdisk/su -c '+shlex.quote(request['command']),
             'exact pinned actor single root wrapper')
        for filename in ('intent.json','baseline.json'):
            body,row=observe_input(path.parent/filename);operation_inputs[filename]=(body,row)
            outputs.append(write_new(out,filename+'.original',body))
        intent=strict(operation_inputs['intent.json'][0]);baseline=strict(operation_inputs['baseline.json'][0])
        need(intent['schema']=='hepta.phone-local.operator-intent.v150.1' and intent['label']==label
             and enc(intent['request'])==enc(request) and intent['request_sha256']==sha(request_raw)
             and intent['automatic_replay'] is False,'original one-use actor intent')
        need(type(baseline['rc'])is int and baseline['rc']==0
             and baseline['stdout'].splitlines()==['f8019f83-20a7-4f18-bea1-51c980621e4d',
                'motorola/leap_cn/leap:16/W1VL36H.59-53-11/643c83-3ed541:user/release-keys','adb','Enforcing','3021']
             and baseline['route']==operation['phone']['route']==[5037,'23'],
             'exact actual boot/build/route baseline')
        source=extract_source(request);outputs.append(write_new(out,'recovery-source.original.py',source))
        targets_raw,targets_pin=read_row(FROZEN['targets'])
        inputs,targets,authority,inputs_raw,authority_raw,cap=source_context(source,targets_raw)
        independent_targets(targets,inputs,authority)
        host_inputs,input_pin=read_row(authority['input_original'])
        need(host_inputs==inputs_raw,'actual preserved host/source input bytes equal')
        outputs.extend([write_new(out,'targets.original.json',targets_raw),
            write_new(out,'authority.original.json',authority_raw),write_new(out,'inputs.original.json',inputs_raw),
            write_new(out,'readonly-source.reference.py',cap)])
        for name,row in sorted(authority['host_original_preservation'].items()):
            _,pin=read_row(row);authority_originals.append({'name':name,'original':pin})
        for name in ('scope_report','sender_terminal_proof','source_sender_public','source_packet','source_result'):
            raw,pin=read_row(authority[name]);authority_originals.append({'name':name,'original':pin})
            if name=='scope_report':
                scope_report=strict(raw)
                need(scope_report['state']=='COMPLETE_UNSTARTED_SCOPE_PRIVATELY_PRESERVED_AND_INDEPENDENTLY_VERIFIED'
                     and scope_report['phone_rc']==0 and scope_report['host_validation_error'] is None
                     and scope_report['target_observation']['sha256']==sha(targets_raw),
                     'prior complete independent preservation proof')
        blobs={}
        for h,row in sorted(targets['preserved_unique_originals'].items()):
            need(set(row)=={'path','bytes','sha256'} and row['sha256']==h
                 and row['path']==str(Path(authority['source_targets']['path']).parent/'originals'/(h+'.bin')),
                 'only exact74 previously preserved private blob paths')
            raw,pin=read_row(row);need(h not in blobs,'unique preserved original digest')
            blobs[h]=raw;preserved.append(pin)
        phone_rc=operation['phone']['rc'];wire=operation['phone']['stdout'].encode()
        need(len(wire)<=8*1024*1024,'unchanged original8MiB phone stdout cap')
        outputs.append(write_new(out,'recovery-packet.original.json',wire))
        value=strict(wire);need(enc(value)==wire,'canonical unchanged recovery stdout')
        pre_raw=decompress_frame(value['preflight'],32*1024*1024);pre=strict(pre_raw)
        need(enc(pre)==pre_raw,'canonical complete held-preflight bytes')
        outputs.append(write_new(out,'preflight.original.json',pre_raw))
        need(type(phone_rc)is int and phone_rc==0 and operation['phone']['stderr']=='',
             'actual complete successful phone recovery')
        checks=validate_recovery(value,pre,inputs,targets,authority,blobs)
        # Re-read every exact authoritative host original after the full parser,
        # including private preserved blobs; no post-delete phone reads occur.
        for row in [result_pin,actor_pin,request_pin,targets_pin,input_pin]+preserved+[r['original'] for r in authority_originals]+[r[1] for r in operation_inputs.values()]:
            read_row(row)
    except BaseException as exc:
        error={'type':type(exc).__name__,'detail':str(exc)[:2048]}
    report={'schema':'hepta.fc33.bound02.exact-unstarted-recovery-host-verification.v1',
        'state':'EXACT_UNSTARTED_RECOVERY_INDEPENDENTLY_VERIFIED_NO_CASE_CREDIT' if error is None else 'ORIGINALS_PRESERVED_RECOVERY_INCOMPLETE_OR_UNKNOWN',
        'actual_result':result_pin,'actual_actor':actor_pin,'actual_request':request_pin,
        'actual_operation_inputs':{name:row for name,(_,row) in operation_inputs.items()},
        'phone_rc':phone_rc,'host_validation_error':error,'checks':checks,
        'rechecked_preserved_originals':preserved,'rechecked_authority_originals':authority_originals,
        'output_descriptors':outputs,'phone_calls_by_host_verifier':0,
        'producer_source_imported_or_executed':False,'owned_recovery_closed':error is None,
        'scope_closure':False,'current_proc_liveness_measured':False,
        'original_failed_case_qualification':False,'historical_unknowns_upgraded':False,
        'private_bodies_in_public_report':False}
    report_pin=write_new(out,'HOST-VERIFICATION.PUBLIC.json',enc(report))
    print(json.dumps({'state':report['state'],'report':report_pin,'phone_rc':phone_rc,
        'host_validation_error':error,'owned_recovery_closed':error is None},sort_keys=True))
    return 0 if error is None else 1


if __name__=='__main__':raise SystemExit(main())
