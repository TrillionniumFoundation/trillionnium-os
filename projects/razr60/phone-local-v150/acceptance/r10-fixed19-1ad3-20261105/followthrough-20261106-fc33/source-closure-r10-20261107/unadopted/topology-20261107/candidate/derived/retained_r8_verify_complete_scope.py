"""Unadopted derived pure function; bind new provenance before use.
Historical publisher and historical reader identities remain distinct.
No production selector or runtime admission is provided.
"""

def verify_complete_scope(capture_raw,source,stage_files,stage_complete_raw,prior,common,inventory_reader):
    need(pin(capture_raw)==CAPTURE and pin(source)==SOURCE,'complete actual capture and exact observer source')
    value=strict(capture_raw);need(enc(value)==capture_raw,'whole canonical original capture')
    need(value['schema']=='hepta.r8.staged-before-fork.scope-observation.v1'
         and value['state']=='COMPLETE_READ_ONLY_SCOPE_ORIGINALS_CAPTURED_NO_DISPOSITION'
         and value['label']==LABEL and value['nonce']==NONCE and value['boot_id']==BOOT
         and value['original_root_job']=='1a1b60cdf9b-12894-20e'
         and value['capture_source_sha256']==SOURCE['sha256']and 'error'not in value,'one complete error-free original scope capture')
    need(value['native_terminal']is None and value['global_unknown_effect_count']is None
         and all(value[k]is False for k in ('retirement_accepted','runtime_admission','original_failure_rewritten',
             'past_failure_offender_identified','automatic_retry'))
         and value['fixture_absence_is_not_zero_effect']is True,'observed absence cannot rewrite original unknowns or grant admission')
    need(all(type(value[k])is int and value[k]==0 for k in ('phone_file_writes','signals_including_signal_zero',
         'locks_acquired','sockets_opened','subprocesses_spawned','ui_actions','model_requests','native_submissions',
         'new_nonces','native_case_credit')),'original complete scope observation stayed read-only')
    need(value['limits']=={'shared_seconds':30,'shared_actual_read_bytes':201326592,'inventory_entries':30000,
         'inventory_unique_file_bytes':536870912,'inventory_file_bytes':67108864,'original_fixture_cap':14,
         'scope_entries':512,'scope_raw_bytes':16777216,'result_bytes':67108864,'compressed_bytes':8388608},
         'same original stricter shared observation budget')
    need(0<=value['elapsed_seconds']<30 and math.isfinite(value['elapsed_seconds'])
         and 0<value['ended']['monotonic_ns']-value['began']['monotonic_ns']<30_000_000_000
         and value['ended']['unix_ns']>=value['began']['unix_ns'],'complete actual capture stayed within original30 seconds')
    files=complete_private_files(value,stage_files,stage_complete_raw)
    manifest=strict(files[HOME+'/package/MANIFEST.json'])
    need(pin(files[HOME+'/package/MANIFEST.json'])==PACKAGE and len(manifest['files'])==38
         and len({row['path']for row in manifest['files']})==38,'same full actual package38')
    for row in manifest['files']:
        path=HOME+'/package/'+row['path']
        need(pin(files[path])=={k:row[k]for k in ('bytes','sha256')},'every actual frozen runtime member preserved')
    lease_raw=files[HOME+'/LEASE.json'];lease=strict(lease_raw)
    need(pin(lease_raw)==LEASE and value['lease']['descriptor']==LEASE and value['lease']['value']==lease
         and value['lease']['expired_at_observation']is True
         and value['began']['unix_ns']//1000000>lease['expires_unix_ms'],
         'same original lease remains expired, without extension')
    need((lease['label'],lease['nonce'],lease['boot_id'],lease['case_id'])==(LABEL,NONCE,BOOT,'NEG-01')
         and lease['package_sha256']==PACKAGE['sha256']and lease['owner_request_sha256']==OWNER
         and pin(files[HOME+'/owner-request.txt'])['sha256']==OWNER
         and files[HOME+'/owner-request.txt'].count(NONCE.encode())==1,'same exact consumed original identity')
    old=prior['inventory_value'];before=value['full_inventory_before'];after=value['full_inventory_after']
    need(pin(enc(old))==OLD==prior['inventory']==value['prior_inventory']
         and value['prior_retained_binding']==prior['retained_preaccept_binding']==manifest['retained_preaccept_binding'],
         'same independently verified accepted R7 old47 predecessor')
    need(inventory_reader(before)==inventory_reader(after)and pin(enc(before))==BEFORE and pin(enc(after))==AFTER,
         'both complete49 original inventories agree except original elapsed')
    need(value['prior_roots']==old['roots']and after['roots']==old['roots']+[HOME,JOURNAL]
         and value['actual_scope_roots']==[HOME,JOURNAL]and value['actual_root_count']==49
         and len(after['entries'])==3991 and after['file_bytes_hashed']==53016728,
         'actual49 roots and complete3991-entry inventory')
    need(all(after['entries'].get(path)==row for path,row in old['entries'].items()),'all3918 old47 original entries remain exact')
    _topology_old_root_parts=frozenset(Path(root).parts for root in old['roots'])
    _topology_old_root_depths=frozenset(len(parts) for parts in _topology_old_root_parts)
    for path in after['entries']:
        _topology_entry_parts=Path(path).parts
        if any(_topology_entry_parts[:depth] in _topology_old_root_parts
               for depth in _topology_old_root_depths if depth<=len(_topology_entry_parts)):
            need(path in old['entries'],'no new child added below any old retained root')
    fixtures=[root for root in after['roots']if re.fullmatch(r'/proc/1/root/data/local/tmp/hepta-native-guard-[0-9a-f]{32}',root)]
    need(len(fixtures)==value['actual_fixture_root_count']==13 and FIXTURE not in fixtures,'actual fixture root count remains13')
    need(all(value[k]is True for k in ('complete_old47_preserved','full_inventory_entries_equal',
        'all_scope_raw_files_match_both_complete_inventories')),'actual full-read bookends all completed')
    stage=strict(stage_complete_raw)
    need(stage['lease_sha256']==LEASE['sha256']and stage['package_sha256']==PACKAGE['sha256']
         and stage['state']=='PRIVATE_COMPONENT_INPUTS_STAGED_NO_ROLES','actual complete staging belongs to this failed runtime and lease')
    private=current_markers_and_parents(value,source,after,stage)
    for path in (HOME+'/claims',HOME+'/operator',HOME+'/executor',JOURNAL):
        need(after['entries'][path]['kind']=='directory'and after['entries'][path]['names']==[],'all current claims/operator/executor namespaces are empty')
    need(after['entries'][HOME+'/executor']==after['entries'][JOURNAL],'both executor aliases identify one unchanged empty directory')
    need(all(PurePosixPath(path).name!='lock'and not PurePosixPath(path).name.endswith('.lock')
         for path in value['original_files']),'no new scope lock inode appears')
    function_pins={}
    life=files[HOME+'/package/source/component_lifecycle.py'].decode()
    for name in ('fixture_absence','inventory'):
        function_pins[name]=pin((ast.get_source_segment(life,source_function(life,name))+'\n').encode())
    need(value['unchanged_original_inventory_functions']==function_pins,'complete inventory source functions remain the exact originals')
    endpoint_receipts=endpoints(value,common,files[HOME+'/package/source/component_snapshot.py'])
    proc_bytes=native_profile_originals(value,files)
    known=literal(source,'KNOWN_PHONE_ORIGINALS')
    need(len(known)==20 and all(value['readset'][row['path']]=={k:row[k]for k in ('path','bytes','sha256','metadata')}for row in known),
         'all20 earlier role-source originals persist with complete full9')
    # The source's two complete inventories hash aliases exactly as originally
    # counted; every other successful source read is accounted in this formula.
    read_bytes=PACKAGE['bytes']+sum(row['bytes']for row in manifest['files'])+2*sum(row['bytes']for row in known)
    read_bytes+=LEASE['bytes']+len(files[HOME+'/owner-request.txt'])+2*(3000200+413)
    read_bytes+=before['file_bytes_hashed']+after['file_bytes_hashed']+proc_bytes
    need(read_bytes==value['budgeted_actual_read_bytes']==119134962<=201326592,'shared actual read budget independently accounted')
    return value,lease,files,{'schema':'hepta.r8.complete-scope.pure-replay.v1','capture':CAPTURE,'observer_source':SOURCE,
        'inventory':AFTER,'root_count':49,'entry_count':3991,'file_bytes_hashed':53016728,'old47_entries_preserved':3918,
        'new_private_file_count':63,'new_private_bytes':3929058,'actual_fixture_root_count':13,
        'unchanged_inventory_functions':function_pins,'current_endpoints':endpoint_receipts,**private,
        'budgeted_actual_read_bytes':read_bytes,'retirement_accepted':False,'runtime_admission':False,
        'native_case_credit':0,'past_failure_offender_identified':False,'global_unknown_effect_count':None}
