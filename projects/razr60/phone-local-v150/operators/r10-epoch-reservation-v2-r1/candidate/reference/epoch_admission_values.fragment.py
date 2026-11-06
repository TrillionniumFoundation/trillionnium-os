def epoch_resource_reservation_value(value):
    c,_modules,_manifest,mf,_bodies=_est_modules();binding=_est_binding(c)
    c._ep_exact(value,{'schema','epoch_id','boot_id','case_id','generation','observation',
        'source_model','runtime_manifest','remaining_qualification_cases','measured','profiles',
        'copy_overhead','arithmetic','producer_limits','copy_ledger','native_calls_authorized',
        'component_qualified','business_qualified','automatic_retry'},
        'the complete source-bound preclaim resource reservation is required')
    c._ep_need(value['schema']=='hepta.native-guard.epoch-resource-reservation.v1'
        and value['epoch_id']==c.EPOCH_ID and value['boot_id']==binding['boot_id']
        and value['case_id'] in ('NEG-01','NEG-02') and value['case_id'] in value['remaining_qualification_cases']
        and type(value['native_calls_authorized']) is int and value['native_calls_authorized']==0
        and value['component_qualified'] is False and value['business_qualified'] is False
        and value['automatic_retry'] is False,'preclaim resource accounting cannot grant a native action')
    c._ep_pin(value['generation'],original=True)
    for key in ('observation','source_model','runtime_manifest'):
        c._ep_exact(value[key],{'bytes','sha256'},'complete canonical resource input byte identity required')
        c._ep_need(type(value[key]['bytes']) is int and 0<value[key]['bytes']<=16*1024*1024
            and type(value[key]['sha256']) is str and c.EPOCH_HASH.fullmatch(value[key]['sha256']),
            'resource input byte identity is not bounded')
    model=binding['resource_model'];epoch_resource_model_value(model)
    c._ep_need(value['source_model']==c._ep_bare(c._ep_encoded(model))
        and value['runtime_manifest']==c._ep_bare(mf)
        and c._ep_same(value['producer_limits'],model['producer_limits'])
        and c._ep_same(value['copy_ledger'],model['copy_ledger'])
        and c._ep_same(value['copy_overhead'],model['copy_overhead'])
        and c._ep_same(value['profiles'],[model['profiles'][case] for case in value['remaining_qualification_cases']]),
        'resource reservation changed an actual producer or complete copy bound')
    expected=c.epoch_resource_forecast(value['measured'],value['profiles'],
        additional_profile_copies=value['copy_overhead'],
        remaining_qualification_cases=value['remaining_qualification_cases'])
    c._ep_need(c._ep_same(expected,value['arithmetic']),'all shared resource arithmetic must be recomputed')
    return value


def epoch_resource_model_value(model):
    c,modules,_manifest,_mf,_bodies=_est_modules()
    c._ep_exact(model,{'schema','profiles','copy_overhead','producer_limits','copy_ledger',
        'historical_consumer_originals','historical_consumer_proof'},
        'complete fixed producer and copy accounting model required')
    c._ep_need(model['schema']=='hepta.native-guard.epoch-source-resource-model.v1',
        'resource source model schema differs')
    c._ep_exact(model['profiles'],{'NEG-01','NEG-02'},'both finite qualification producer profiles are mandatory')
    for profile in model['profiles'].values():
        c._ep_exact(profile,set(EPOCH_RESOURCE_KEYS)|{'producer_proof','copy_plan'},
            'complete source-frozen qualification profile required')
        for key in EPOCH_RESOURCE_KEYS:
            c._ep_need(type(profile[key]) is int and profile[key]>=0,'resource counts must be nonnegative integers')
        for key in ('producer_proof','copy_plan'):_est_host3(c,profile[key])
    c._ep_exact(model['copy_overhead'],EPOCH_RESOURCE_KEYS,'all repeated proof/copy domains must be charged')
    c._ep_need(all(type(n) is int and n>=0 for n in model['copy_overhead'].values()),
        'copy overhead must be explicitly bounded in every pool')
    c._ep_exact(model['producer_limits'],{'fixture','owned_role_output','native_output','snapshot',
        'closure_outputs','operation_transport','case_protocol'},'the complete final producer graph is required')
    limits=model['producer_limits'];lifecycle=modules['component_lifecycle']
    c._ep_need(type(limits['fixture']) is dict and limits['fixture']
        and type(limits['owned_role_output']) is dict and limits['owned_role_output'].get('per_stream_bytes')==lifecycle.OWNED_OUTPUT_LIMIT
        and limits['owned_role_output'].get('roles')==3 and limits['owned_role_output'].get('streams_per_role')==2
        and limits['native_output']=={'per_action_combined_bytes':600000,'maximum_actions_per_case':2},
        'actual finite fixture, six-role-stream and native producer limits are required')
    rows=model['copy_ledger'];c._ep_need(type(rows) is list and rows and len(rows)<=256,
        'finite complete per-producer copy graph is required')
    seen=set()
    for row in rows:
        c._ep_exact(row,{'name','producer','maximum_body_bytes','maximum_count','copies','pool'},
            'each source-fixed writer/copy domain must be explicit')
        c._ep_need(type(row['name']) is str and row['name'] not in seen
            and row['producer'] in limits and row['pool'] in (
                'physical_read','physical_write','inventory','snapshot','consumer','transport')
            and all(type(row[key]) is int and row[key]>=0 for key in ('maximum_body_bytes','maximum_count','copies')),
            'resource graph repeats, leaves a pool, or uses unbounded writer data')
        seen.add(row['name'])
    originals=model['historical_consumer_originals'];_est_host3(c,model['historical_consumer_proof'])
    c._ep_need(type(originals) is list and 1<=len(originals)<=8192,
        'actual historical consumer body union is mandatory')
    paths=set()
    for row in originals:
        _est_host3(c,row);c._ep_need(row['path'] not in paths,'historical physical callback path repeats');paths.add(row['path'])
    return model


def epoch_allocation_admission_value(value,*,identity,identity_pin,reservation,reservation_pin,
        initialization,index,originals):
    c,_modules,_manifest,_mf,_bodies=_est_modules()
    c._ep_exact(value,EPOCH_ALLOCATION_ADMISSION_FIELDS,'complete actual allocation admission required')
    c._ep_need(value['schema']=='hepta.native-guard.epoch-allocation-admission.v1'
        and value['state']=='PRECLAIM_OBSERVATION_AND_CAPACITY_BOUND_TO_EXCLUSIVE_IDENTITY'
        and value['epoch_id']==c.EPOCH_ID and type(value['ordinal']) is int
        and value['ordinal']==identity['ordinal']==reservation['ordinal']
        and value['boot_id']==identity['boot_id']
        and value['nonce_generated_after_exclusive_claim'] is True
        and value['native_scope_assigned'] is False and value['component_qualified'] is False
        and value['business_qualified'] is False and value['automatic_retry'] is False,
        'allocation admission cannot claim a scope, native action or qualification')
    c._ep_need(type(initialization) is dict and set(initialization)>= {'value','original'},
        'the independently verified actual initialization is required')
    expected={'anchor':initialization['value']['anchor'],'initialization':initialization['original'],
        'generation':reservation['generation'],'claim':reservation_pin,'identity':identity_pin,
        'predecessor_terminal':identity['predecessor_terminal'],'prior_boundary':identity['prior_boundary']}
    for key,pin in expected.items():
        c._ep_need(c._ep_same(value[key],pin),'allocation admission changed actual '+key)
        if pin is not None:c._ep_manifest_raw(pin,index,originals)
    c._ep_need({key:value['anchor'][key] for key in ('path','bytes','sha256')}==reservation['anchor'],
        'allocation changed the independent historical anchor identity')
    resource=epoch_resource_reservation_value(value['resource_reservation'])
    observation=value['preclaim_observation']
    c._ep_need(type(observation) is dict
        and observation.get('schema')=='hepta.native-guard.epoch-preclaim-observation.v1'
        and observation.get('epoch_id')==c.EPOCH_ID and observation.get('boot_id')==identity['boot_id']
        and c._ep_bare(c._ep_encoded(observation))==resource['observation']
        and c._ep_same(resource,reservation['resource_reservation'])
        and c._ep_same(resource['generation'],reservation['generation'])
        and c._ep_same(value['authorization_original'],reservation['authorization_request']['origin']),
        'complete actual preclaim observation or authorization/resource value differs')
    epoch_preclaim_observation_value(observation,resource,initialization=initialization,
        index=index,originals=originals)
    return value


def epoch_role_launch_intent_value(value,*,identity,identity_pin,lease_pin,generation,index,originals):
    c,_modules,_manifest,_mf,_bodies=_est_modules()
    c._ep_exact(value,{'schema','epoch_id','ordinal','identity','lease','generation','scope',
        'maximum_forks','automatic_retry','component_qualified','business_qualified'},
        'complete one-fork intent is required before lifecycle admission')
    c._ep_need(value['schema']=='hepta.native-guard.epoch-role-launch-intent.v1'
        and value['epoch_id']==c.EPOCH_ID and type(value['ordinal']) is int
        and value['ordinal']==identity['ordinal'] and c._ep_same(value['identity'],identity_pin)
        and c._ep_same(value['lease'],lease_pin) and c._ep_same(value['generation'],generation)
        and value['scope'] is None and type(value['maximum_forks']) is int and value['maximum_forks']==1
        and value['automatic_retry'] is False and value['component_qualified'] is False
        and value['business_qualified'] is False,'one-fork intent changed source, identity or admission semantics')
    for pin in (identity_pin,lease_pin,generation):c._ep_manifest_raw(pin,index,originals)
    return value
