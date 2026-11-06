class _EpochProtocolOriginalCollector:
 def __init__(self, common, binding, budget_check):
  common._ep_need(callable(budget_check), 'one enclosing budget callback required')
  self.c=common; self.binding=binding; self.check=budget_check
  self.files={}; self.raw={}; self.directories={}; self.total=0
  self.public={r['path']:r for r in binding['control_leaves']}
  self.fixed={r['path']:r for r in binding['fixed_inputs']}
  self.fixed.update(self.public)
  self.approved_saved=set()
  stage=common._epoch_stage_api()
  _c,modules,_mf,_raw,_bodies=stage._est_modules(budget_check=budget_check)
  self.installed={r['path']:r for r in modules['component_lifecycle'].EPOCH_INSTALLED_ARTIFACT_ALLOWANCE}
 def directory(self, path, *, private=False):
  c=self.c; self.check(); path=str(c._ep_path(path))
  row=c.epoch_read_directory(path); self.check()
  if private:
   c._ep_need(row['metadata'][3:5]==[0,0]
   and c._ep_stat.S_IMODE(row['metadata'][2])==0o700,
   'complete control directory must remain root-owned private')
  if path in self.directories:
   c._ep_need(c._ep_same(self.directories[path],row),
   'directory changed within the complete original collection')
  else:
   c._ep_need(path not in self.files and len(self.directories)<30000,
   'directory type conflict or metadata set exceeded')
   self.directories[path]=row
  return row
 def allowed_file(self,path):
  c=self.c; c._ep_path(path)
  return (path in self.fixed or path in self.installed or path in self.approved_saved
  or any(path.startswith(root+'/') for root in self.binding['control_roots']))
 def file(self,path,*,expected=None):
  c=self.c; self.check(); path=str(c._ep_path(path))
  c._ep_need(self.allowed_file(path),'original is outside fixed historical/control/saved scopes')
  if expected is not None:
   c._ep_pin(expected,original=True)
   c._ep_need(expected['path']==path,'expected original path differs')
  if path in self.files:
   if expected is not None:
    c._ep_need(c._ep_same(self.files[path],expected),
    'one original path has two byte/full9 identities')
   return self.files[path],self.raw[path]
  c._ep_need(len(self.files)<c.EPOCH_MAX_INPUT_FILES,
  'complete original file count exceeds the one capture input pool')
  self.directory(str(c._EpPath(path).parent))
  chain,name=c._ep_parent_chain(path); fd=None
  try:
   self.check()
   fd=c._ep_os.open(name,c._ep_os.O_RDONLY|c._ep_os.O_NONBLOCK
   |c._ep_os.O_NOFOLLOW|c._ep_os.O_CLOEXEC,dir_fd=chain[-1][0])
   before=c._ep_metadata(c._ep_os.fstat(fd))
   c._ep_need(c._ep_stat.S_ISREG(before[2]) and before[5]==1
   and type(before[6]) is int and 0<=before[6]
   and before[6]<=c.EPOCH_MAX_INPUT_FILE
   and before[6]<=c.EPOCH_MAX_INPUT_BYTES-self.total,
   'original type/size exceeds the single precharged retained-body pool')
   public=self.public.get(path)
   installed=self.installed.get(path)
   if installed is not None:
    c._ep_need(before[3:6]==[installed['uid'],installed['gid'],1]
    and c._ep_stat.S_IMODE(before[2])==installed['mode'] and before[6]==installed['bytes'],
    'actual installed source-fixed leaf ownership/mode/size differs')
   elif public is None:
    c._ep_need(before[3:6]==[0,0,1]
    and c._ep_stat.S_IMODE(before[2])==0o600,
    'original is not an exact root-owned private regular file')
   else:
    c._ep_need(before==public['metadata'] and before[6]==public['bytes'],
    'old shell-owned incoming file changed its individually fixed full9')
   if expected is not None:
    c._ep_need(before==expected['metadata'] and before[6]==expected['bytes'],
    'saved/fixed original differs before reading any content')
   parts=[];left=before[6]+1
   while left:
    self.check()
    part=c._ep_os.read(fd,min(65536,left))
    if not part:break
    parts.append(part);left-=len(part)
   body=b''.join(parts)
   c._ep_need(len(body)==before[6]
   and before==c._ep_metadata(c._ep_os.fstat(fd))
   ==c._ep_metadata(c._ep_os.stat(name,dir_fd=chain[-1][0],follow_symlinks=False))
   ==c._ep_metadata(c._EpPath(path).lstat()),
   'complete original changed its held/named/canonical file identity')
   row={'path':path,**c._ep_bare(body),'metadata':before}
   if installed is not None:c._epoch_stage_api().epoch_installed_original_value(row,body)
   if public is not None:c._ep_need(c._ep_same(row,public),'old incoming body changed')
   if expected is not None:c._ep_need(c._ep_same(row,expected),'saved/fixed bytes changed')
   c._ep_chain_check(chain);self.check()
   self.total+=len(body);self.files[path]=row;self.raw[path]=body
  finally:
   if fd is not None:c._ep_os.close(fd)
   for item in reversed(chain):c._ep_os.close(item[0])
  self.directory(str(c._EpPath(path).parent))
  return row,body
 def tree(self,root):
  c=self.c
  c._ep_need(root in self.binding['control_roots'],'only the two complete private control roots may be scanned')
  pending=[(root,0)]
  while pending:
   path,depth=pending.pop();self.check()
   c._ep_need(depth<=16,'control directory depth exceeds the fixed protocol')
   row=self.directory(path,private=True)
   for name in row['names']:
    self.check();child=path+'/'+name
    before=c._EpPath(child).lstat()
    if c._ep_stat.S_ISDIR(before.st_mode):pending.append((child,depth+1))
    else:
     c._ep_need(c._ep_stat.S_ISREG(before.st_mode),
     'control namespace contains a link, special file or unknown type')
     self.file(child)
   self.directory(path,private=True)
 def manifest(self):
  return {'schema':'hepta.native-guard.epoch-capture-inputs.v1',
  'files':[self.files[p] for p in sorted(self.files)],
  'directories':[self.directories[p] for p in sorted(self.directories)]}


# Existing RFO-member protocol collection helpers; no top-level I/O or imports.
# Whole32 admission precedes this ordinary explicitly loaded source member.


def _epoch_protocol_context(prepared,common,budget_check):
    import sys
    common._ep_need(callable(budget_check),'the same enclosing protocol clock is required')
    checked,modules,_mf,raw,bodies=common._epoch_stage_api()._est_modules(budget_check=budget_check)
    current=sys.modules.get('root_fixture_originals')
    common._ep_need(checked is common and modules['prepare_component'] is prepared
        and current is not None and current.__dict__ is globals()
        and common.epoch_actual_context(globals())==common.epoch_actual_context(prepared.__dict__)
        and globals().get('__reviewed_package_manifest_raw__')==raw
        and globals().get('__reviewed_package_sources__') is bodies
        and globals().get('__reviewed_source_sha256__')==common._ep_sha(bodies['source/root_fixture_originals.py']),
        'protocol collector must be the actual current RFO and prepare modules')
    return modules


def epoch_protocol_collector(common,binding,*,budget_check):
    import sys
    prepared=sys.modules.get('prepare_component')
    _epoch_protocol_context(prepared,common,budget_check)
    return _EpochProtocolOriginalCollector(common,binding,budget_check)


def _epoch_protocol_collect_initialization(prepared,common,collector):
    root=common.EPOCH_REGISTRY_ROOT
    original,raw=collector.file(root+'/INITIALIZATION.json')
    value=common._ep_strict(raw)
    common._ep_exact(value,common.EPOCH_INITIALIZATION_FIELDS,'complete actual initialization fields required')
    common._ep_need(value['schema']=='hepta.native-guard.epoch-registry-initialization.v2'
        and value['epoch_id']==common.EPOCH_ID and value['boot_id']==collector.binding['boot_id'],
        'collector cannot use an old or foreign initialization')
    stage=common._epoch_stage_api()
    installed=value['installed_artifacts']
    common._ep_need(type(installed) is list and len(installed)==2,'both actual installed originals required')
    for row in installed:
        common._ep_exact(row,{'role','path','presence','original'},'complete installed phase row required')
        pin=row['original'];common._ep_pin(pin,original=True)
        common._ep_need(row['presence']=='present' and row['path']==pin['path']
            and stage.epoch_installed_artifact_path(row['path']),
            'an initialization cannot authorize an arbitrary file leaf')
        _actual,body=collector.file(pin['path'],expected=pin)
        stage.epoch_installed_original_value(pin,body)
    # The reviewed source provides the historical seven originals; the new
    # initialization cannot enlarge this original read authority on its own.
    fixed=stage._est_binding(common)['retained_failed_native_branches']
    common._ep_need(type(fixed) is list and len(fixed)==1,
        'exact separately retained failed-native source branch required')
    for branch in fixed:
        originals=branch['originals']
        common._ep_exact(originals,{'lease','runtime','combination','boundary','inventory','closure','publish_intent'},
            'all seven actual retained failed-native originals required')
        for pin in originals.values():
            common._ep_pin(pin,original=True)
            existing=collector.fixed.get(pin['path'])
            common._ep_need(existing is None or common._ep_same(existing,pin),
                'retained branch conflicts with a fixed historical original')
            collector.fixed[pin['path']]=pin;collector.file(pin['path'],expected=pin)
    return value


def _epoch_protocol_collect_phase(prepared,common,collector,identity,ordinal):
    root=common.EPOCH_REGISTRY_ROOT;prefix=root+'/slots/%02d/'%ordinal
    home=str(common.BASE/'native-guard-r10-r1'/identity['label'])
    def pin_at(pin,path):
        common._ep_pin(pin,original=True)
        common._ep_need(pin['path']==path,'phase dependency escaped its actual fixed case path')
        collector.approved_saved.add(path)
        return collector.file(path,expected=pin)
    def known(path):
        collector.approved_saved.add(path);return collector.file(path)
    stage_raw=collector.raw.get(prefix+'STAGE.json')
    if stage_raw is not None:
        stage=common._ep_strict(stage_raw)
        common._ep_exact(stage,{'schema','epoch_id','ordinal','identity','lease','stage_original',
            'package_manifest','phase_source','inventory_roots'},'complete stage dependency binding required')
        common._ep_need(stage['schema']=='hepta.native-guard.epoch-stage-binding.v1'
            and stage['epoch_id']==common.EPOCH_ID and type(stage['ordinal']) is int and stage['ordinal']==ordinal,
            'phase dependencies require their actual stage identity')
        paths={'lease':home+'/LEASE.json','stage_original':home+'/STAGE-COMPLETE.json',
            'package_manifest':home+'/package/MANIFEST.json','phase_source':home+'/package/source/stage_component.py'}
        for key,path in paths.items():pin_at(stage[key],path)
        common._ep_need(collector.raw[paths['package_manifest']]==
                common.__dict__['__reviewed_package_manifest_raw__']
            and collector.raw[paths['phase_source']]==
                common.__dict__['__reviewed_package_sources__']['source/stage_component.py'],
            'actual case package and phase source differ from the complete current runtime')
    admission_raw=collector.raw.get(prefix+'ADMISSION.json')
    if admission_raw is not None:
        common._ep_need(stage_raw is not None,'lifecycle admission cannot precede actual stage')
        admission=common._ep_strict(admission_raw)
        common._ep_exact(admission,{'schema','epoch_id','ordinal','retired_original'},
            'complete actual lifecycle admission fields required')
        pin_at(admission['retired_original'],home+'/RETIRED-BASELINE-VERIFIED.json')
    scope_raw=collector.raw.get(prefix+'SCOPE-BINDING.json')
    if scope_raw is not None:
        common._ep_need(admission_raw is not None,'accepted scope cannot precede actual admission')
        scope=common._ep_strict(scope_raw)
        _pin,accepted_raw=pin_at(scope['accepted'],home+'/ACCEPTED.json')
        _pin,bound_raw=known(home+'/BOUND-CONTRACT.json');bound=common._ep_strict(bound_raw)
        common._ep_need(bound.get('schema')=='hepta.native-guard.bound-contract.v1'
            and type(bound.get('run_basename')) is str
            and common._ep_re.fullmatch(r'[0-9]{8}-[0-9]{6}-'+identity['nonce'],bound['run_basename']),
            'actual native run basename is not tied to this one-use nonce')
        run=str(common.COMPONENT_EVIDENCE)+'/'+bound['run_basename']
        common._ep_need(common._ep_strict(accepted_raw).get('run_dir')==run,
            'actual native accepted run directory differs')
        known(home+'/claims/'+identity['nonce']+'.json');known(run+'/accepted.json')
    launch_raw=collector.raw.get(prefix+'LAUNCH.json')
    if launch_raw is not None:
        common._ep_need(scope_raw is not None,'fixture permission cannot precede actual scope')
        launch=common._ep_strict(launch_raw)
        for key,path in (('root_fixture_plan',home+'/ROOT-SETUP-PLAN.json'),
                ('bound_contract',home+'/BOUND-CONTRACT.json'),('accepted',home+'/ACCEPTED.json'),
                ('root_source_authorization',root+'/ROOT-AUTHORIZATION.json')):
            pin_at(launch[key],path)


def epoch_protocol_collect(prepared,lease,*,mode,budget_check,inventory_validator):
    common,_lifecycle=prepared._epoch_inventory_module()
    _epoch_protocol_context(prepared,common,budget_check)
    common._ep_need(common.epoch_actual_context(common.__dict__)=='phone'
        and mode in ('preclose','prepublish','published') and callable(inventory_validator),
        'explicit phone collection mode and original inventory gate required')
    if mode in ('preclose','prepublish'):common.epoch_lease_protocol_value(lease)
    else:common._ep_need(lease is None,'published frontier collection must not fabricate a current lease')
    budget_check();binding=common.epoch_binding_value()
    collector=_EpochProtocolOriginalCollector(common,binding,budget_check)
    for root in binding['control_roots']:collector.tree(root)
    for row in binding['fixed_inputs']+binding['control_leaves']:collector.file(row['path'],expected=row)
    initialization=_epoch_protocol_collect_initialization(prepared,common,collector)
    slotroot=common.EPOCH_REGISTRY_ROOT+'/slots';directory=collector.directories[slotroot]
    names=directory['names'];claims=[n for n in names if common._ep_re.fullmatch(r'0[1-8]\.CLAIM\.json',n)]
    count=len(claims)
    common._ep_need(0<=count<=common.EPOCH_MAX_SLOTS
        and claims==['%02d.CLAIM.json'%i for i in range(1,count+1)]
        and set(names)==set(claims+['%02d'%i for i in range(1,count+1)]),
        'partial or unclaimed slot namespace cannot be collected as a complete frontier')
    if mode in ('preclose','prepublish'):common._ep_need(count>0,'preclose requires its actual allocated identity')
    labels=[];identities={};forbidden=set(common.epoch_forbidden_nonces());previous=None
    for ordinal in range(1,count+1):
        prefix=slotroot+'/%02d/'%ordinal;path=prefix+'IDENTITY.json'
        common._ep_need(path in collector.raw,'preidentity or unknown slot blocks complete frontier collection')
        claim_pin=collector.files[slotroot+'/%02d.CLAIM.json'%ordinal]
        claim=common._ep_strict(collector.raw[claim_pin['path']])
        common.epoch_reservation_value(claim,binding=binding,ordinal=ordinal,previous_terminal=previous)
        identity=common._ep_strict(collector.raw[path])
        common.epoch_identity_value(identity,claim,claim_pin,forbidden_nonces=forbidden)
        label=identity['label'];common._ep_need(label not in labels,'actual slot labels cannot repeat')
        labels.append(label);identities[ordinal]=identity;forbidden.add(identity['nonce'])
        collector.approved_saved.update(prepared._epoch_saved_input_paths(common,label).values())
        collector.approved_saved.update(prepared._epoch_saved_inventory_paths(common,label).values())
        _epoch_protocol_collect_phase(prepared,common,collector,identity,ordinal)
        if prefix+'COMMIT.json' in collector.files:previous=collector.files[prefix+'COMMIT.json']
    if mode in ('preclose','prepublish'):
        common._ep_need(lease['label']==labels[-1] and lease['nonce']==identities[count]['nonce']
            and lease['epoch']['ordinal']==count,'reader lease is not the actual highest consumed identity')
        leasepath=prepared._epoch_saved_input_paths(common,lease['label'])['lease']
        _pin,raw=collector.file(leasepath)
        common._ep_need(common._ep_same(common._ep_strict(raw),lease),
            'reader lease differs from its actual immutable phone original')
    for ordinal in range(1,count+1):
        prefix=slotroot+'/%02d/'%ordinal;terminal=prefix+'COMMIT.json'
        epoch=None
        if terminal not in collector.raw:
            common._ep_need(mode in ('preclose','prepublish') and ordinal==count,
                'published frontier cannot omit a consumed terminal')
            if mode=='preclose':continue
            common._ep_need(prefix+'BOUNDARY.json' not in collector.raw,
                'prepublication cannot adopt an already written boundary')
        else:
            boundary_path=prefix+'BOUNDARY.json'
            common._ep_need(boundary_path in collector.raw,'actual terminal lacks its native boundary original')
            boundary=common._ep_strict(collector.raw[boundary_path]);epoch=boundary.get('epoch')
            common._ep_need(type(epoch) is dict,'epoch native boundary lacks explicit domain binding')
        saved_paths=prepared._epoch_saved_input_paths(common,labels[ordinal-1])
        for key,path in saved_paths.items():
            if epoch is None:
                collector.file(path)
            else:
                pin=epoch.get(key);common._ep_pin(pin,original=True)
                common._ep_need(pin['path']==path,'saved preclose dependency escaped its actual case path')
                collector.file(path,expected=pin)
        prepared._epoch_collect_saved_inventory_inputs(common,collector,labels[ordinal-1],saved_paths)
        manifest_raw=collector.raw[saved_paths['capture_manifest']];saved=common._ep_strict(manifest_raw)
        common._ep_exact(saved,{'schema','files','directories'},'saved preclose manifest fields differ')
        common._ep_need(saved['schema']=='hepta.native-guard.epoch-capture-inputs.v1'
            and common._ep_encoded(saved)==manifest_raw and type(saved['files']) is list
            and 1<=len(saved['files'])<=common.EPOCH_MAX_INPUT_FILES,
            'saved preclose manifest must retain canonical bounded original data')
        subset={}
        for row in saved['files']:
            common._ep_pin(row,original=True)
            common._ep_need(collector.allowed_file(row['path']),
                'saved manifest cannot enlarge fixed historical/control/phase authority')
            _pin,body=collector.file(row['path'],expected=row);subset[row['path']]=body
        common.epoch_manifest_value(saved,subset,binding=binding)
    manifest=collector.manifest();originals=dict(collector.raw)
    common.epoch_manifest_value(manifest,originals,binding=binding)
    if mode in ('preclose','prepublish'):
        verified=prepared.epoch_registry_replay(lease,manifest,originals,mode=mode,
            inventory_validator=inventory_validator,
            observation_verifier=_lifecycle.verify_epoch_inventory_observation)
    else:
        verified=prepared.epoch_verify_publication_protocol(manifest,originals,inventory_validator=inventory_validator)
    prepared.epoch_recheck_input_originals(manifest,budget_check=budget_check);budget_check()
    return {'manifest':manifest,'originals_by_path':originals,'verified':verified}


def epoch_protocol_frontier_semantics(prepared,lease,manifest,originals_by_path,verified,*,late_module,budget_check):
    """Verify the real committed prefix without inventing a next lease/admission."""
    common,_life,context,runtime_raw,_sources=prepared._eps_modules(late_module)
    _epoch_protocol_context(prepared,common,budget_check)
    mode=verified.get('registry',{}).get('mode') if type(verified) is dict else None
    common._ep_need(mode in ('preclose','published'),'actual protocol frontier mode required')
    if mode=='published':
        common._ep_need(lease is None,'published predecessor verification cannot invent a lease')
        replayed=prepared.epoch_verify_publication_protocol(manifest,originals_by_path,
            inventory_validator=late_module.inventory_value)
    else:
        common.epoch_lease_protocol_value(lease)
        replayed=prepared.epoch_verify_capture_protocol(lease,manifest,originals_by_path,
            inventory_validator=late_module.inventory_value)
    common._ep_need(common._ep_same(replayed,verified),'complete predecessor protocol replay changed')
    budget_check()
    checked,index=prepared._eps_verify_prefix(replayed,manifest,originals_by_path,
        late_module=late_module,budget_check=budget_check)
    registry=replayed['registry'];slots=registry['slots'];records=replayed['active']['closed_native_records']
    expected=len(slots)-(1 if mode=='preclose' else 0)
    common._ep_need(expected>=0 and len(checked)==len(records)==expected
        and common._ep_same([item['record'] for item in checked],records),
        'every committed predecessor must be semantically verified exactly once')
    current=None
    if mode=='preclose':
        current=slots[-1]
        common._ep_need(current['identity'] is not None and current['terminal'] is None
            and common._ep_same(current['identity']['original'],lease['epoch']['identity'])
            and current['identity']['value']['nonce']==lease['nonce'],
            'pre-admission frontier must bind the actual current uncommitted identity')
    generations=registry['generations']
    common._ep_need(type(generations) is list and len(generations)==1,
        'a later source generation needs its own finite source verification increment')
    generation=generations[0];common.epoch_generation_value(generation['value'])
    common._ep_need(common._ep_bare(runtime_raw)==
        {k:generation['value']['runtime'][k] for k in ('bytes','sha256')},
        'the actual predecessor verifier is not the current catalogued full runtime')
    if current is not None:
        common._ep_need(common._ep_same(current['claim']['value']['generation'],generation['original']),
            'current claim selected a different source generation')
    if checked:
        final=checked[-1];preservation=final['inventory'];preservation_pin=final['record']['inventory']
        prior=final['record']['boundary'];terminal=final['record']['terminal']
    else:
        initialization=registry['initialization']
        preservation=initialization['preservation_inventory']
        preservation_pin=initialization['preservation_inventory_original']
        prior=replayed['legacy']['native_chain'][0]['boundary'];terminal=None
    raw=common._ep_manifest_raw(preservation_pin,index,originals_by_path)
    common._ep_need(common._ep_same(common._ep_strict(raw),preservation),
        'predecessor preservation view differs from its complete actual inventory original')
    late_module.inventory_value(preservation)
    if current is not None:
        identity=current['identity']['value']
        common._ep_need(common._ep_same(identity['prior_boundary'],prior)
            and common._ep_same(identity['predecessor_terminal'],terminal)
            and common._ep_same(lease['prior_boundary'],prior),
            'current identity skipped or substituted the actual verified predecessor')
    roles=[];nonces=[];scopes=[]
    for item in checked:
        roles.extend(prepared._eps_roles(item['boundary']['component_role_identities']))
        nonces.append(item['boundary']['nonce']);scopes.append(item['boundary']['scope'])
    common._ep_need(len(set(nonces))==len(nonces)
        and len({tuple(row) for row in roles})==len(roles),
        'committed predecessor nonces or original native role generations repeat')
    if mode=='published':
        legacy=late_module.epoch_verified_legacy_frontier_context(manifest,originals_by_path,
            replayed,budget_check=budget_check)
    else:
        legacy=late_module.epoch_verified_legacy_context(lease,manifest,originals_by_path,
            replayed,budget_check=budget_check)
    qualified=[item for item in checked if item['boundary']['component_qualified'] is True]
    active={'schema':'hepta.native-guard.epoch-committed-prefix-proof.v1',
        'state':'EVERY_ACTUAL_COMMITTED_NATIVE_RECORD_VERIFIED',
        'actual_context':context,'epoch_id':common.EPOCH_ID,'boot_id':registry['boot_id'],
        'source_generation':generation['original'],'source_manifest':common._ep_bare(runtime_raw),
        'closed_records':records,'closed_native_components':len(checked),
        'native_nonces':nonces,'native_scopes':scopes,'retired_active_role_identities':roles,
        'qualified_case_ids':[item['boundary']['case_id'] for item in qualified],
        'qualified_records':[item['record'] for item in qualified],
        'preservation_inventory_original':preservation_pin,'prior_boundary':prior,
        'predecessor_terminal':terminal,'legacy_domains_flattened':False,
        'current_lifecycle_admission_verified_here':False,'current_inventory_observed_here':False,
        'role_absence_observed_here':False,'endpoints_observed_here':False,
        'native_boundary_created':False,'component_qualified':False,'business_qualified':False}
    predecessor=None
    if current is not None:
        predecessor={'schema':'hepta.native-guard.epoch-predecessor-context.v1',
            'epoch_id':common.EPOCH_ID,'ordinal':current['ordinal'],
            'legacy_head':replayed['legacy']['native_chain'][0]['boundary'],
            'previous_active_boundary':None if not checked else prior,
            'previous_active_closed_components':len(records),
            'consumed_slots_before_current':current['ordinal']-1,
            'predecessor_terminal':terminal,'source_generation':identity['source_generation'],
            'preservation_inventory_original':preservation_pin}
    budget_check()
    return {'schema':'hepta.native-guard.epoch-predecessor-semantic-proof.v1',
        'state':'COMPLETE_ACTUAL_COMMITTED_PREFIX_VERIFIED_WITHOUT_NEW_ADMISSION',
        'actual_context':context,'mode':mode,'epoch_id':common.EPOCH_ID,'boot_id':registry['boot_id'],
        'source_generation':generation['original'],'source_manifest':common._ep_bare(runtime_raw),
        'closed_native_records':records,'current_identity':None if current is None else current['identity']['original'],
        'predecessor_terminal':terminal,'prior_boundary':prior,
        'preservation_inventory_original':preservation_pin,'preservation_inventory':preservation,
        'committed_nonces':nonces,'committed_scopes':scopes,'retired_active_role_identities':roles,
        'qualified_case_ids':active['qualified_case_ids'],'qualified_records':active['qualified_records'],
        'legacy_semantic':legacy,'active_semantic':active,'predecessor_context':predecessor,
        'current_inventory_observed_here':False,'role_absence_observed_here':False,
        'endpoints_observed_here':False,'native_boundary_created':False,
        'component_qualified':False,'business_qualified':False}


def epoch_protocol_retained_boundaries(prepared,verified,index,originals,*,budget_check):
    common,_life=prepared._epoch_inventory_module()
    _epoch_protocol_context(prepared,common,budget_check)
    fixed=common._epoch_stage_api()._est_binding(common)['retained_failed_native_branches']
    common._ep_need(type(fixed) is list and len(fixed)==1,
        'exact separately retained failed-native domain required')
    result=[]
    for row in fixed:
        pin=row['originals']['boundary']
        raw=prepared._eps_read(pin,index,originals,budget_check);value=common._ep_strict(raw)
        common._ep_need(value.get('component_qualified') is False
            and value.get('native_status')=='provider_failed'
            and type(value.get('actual_native_calls')) is int and value['actual_native_calls']==1
            and value['nonce'] in common.epoch_forbidden_nonces(),
            'retained native failure cannot become a new qualification or fresh identity')
        common.scope(value['scope']);prepared._eps_roles(value['component_role_identities'])
        result.append(value)
    return result


def epoch_protocol_prepublication(prepared,lease,boundary_candidate,inventory_raw,closure_raw,
        *,manifest,originals_by_path,budget_check):
    """Verify actual precommit originals without fabricating a boundary inode."""
    common,_life=prepared._epoch_inventory_module()
    modules=_epoch_protocol_context(prepared,common,budget_check)
    late=modules['late_boundary']
    common,lifecycle,context,runtime_raw,sources=prepared._eps_modules(late)
    common._ep_need(callable(budget_check),'same enclosing prepublication clock required')
    common.epoch_lease_protocol_value(lease);budget_check()
    verified=prepared.epoch_registry_replay(lease,manifest,originals_by_path,
        mode='prepublish',inventory_validator=late.inventory_value,
        observation_verifier=lifecycle.verify_epoch_inventory_observation)
    checked,index=prepared._eps_verify_prefix(verified,manifest,originals_by_path,
        late_module=late,budget_check=budget_check)
    registry=verified['registry'];slots=registry['slots'];slot=slots[-1]
    ordinal=slot['ordinal'];identity=slot['identity']['value']
    common._ep_need(ordinal==len(checked)+1==len(slots) and slot['terminal'] is None
        and slot['launch'] is not None and slot['scope_binding'] is not None,
        'prepublication requires the actual highest launched uncommitted identity')
    boundary=boundary_candidate
    common._ep_exact(boundary,prepared._EPS_BOUNDARY_FIELDS,'exact in-memory candidate boundary required')
    common._ep_exact(boundary['epoch'],prepared._EPS_BOUNDARY_EPOCH_FIELDS,
        'complete in-memory candidate epoch binding required')
    epoch=boundary['epoch'];prefix=common.EPOCH_REGISTRY_ROOT+'/slots/%02d/'%ordinal
    common._ep_need(prefix+'BOUNDARY.json' not in index['files']
        and prefix+'COMMIT.json' not in index['files'],
        'prepublication cannot consume or replace an already published native boundary')
    common._ep_need(boundary['schema']=='hepta.native-guard.epoch-boundary.v1'
        and boundary['state']=='CLOSED_COMPONENT_AND_CUMULATIVE_ORIGINALS_PRESERVED'
        and epoch['schema']=='hepta.native-guard.epoch-boundary-binding.v1'
        and epoch['epoch_id']==common.EPOCH_ID and type(epoch['ordinal']) is int
        and epoch['ordinal']==ordinal,'candidate changed the actual epoch identity')
    for key in ('nonce','case_id'):
        common._ep_need(boundary[key]==identity[key],'candidate changed actual identity: '+key)
    common._ep_need(boundary['boot_id']==registry['boot_id']==lease['boot_id']
        and boundary['owner_request_sha256']==identity['owner_request']['sha256']
        and common._ep_same(boundary['scope'],slot['scope_binding']['value']['scope']),
        'candidate changed actual boot, owner authorization or accepted scope')
    common.scope(boundary['scope'])
    generation_rows=[row for row in registry['generations']
        if common._ep_same(row['original'],slot['claim']['value']['generation'])]
    common._ep_need(len(generation_rows)==1 and generation_rows[0]['value']['ordinal']==1,
        'candidate source generation needs its actual finite catalog')
    generation_record=generation_rows[0];generation=generation_record['value']
    common._ep_need(boundary['package_sha256']==common._ep_sha(runtime_raw)==generation['runtime']['sha256']
        and boundary['combination_sha256']==generation['combination']['sha256']
        and boundary['publisher_source_sha256']==common._ep_sha(sources['source/stage_component.py']),
        'candidate publisher or complete runtime differs from the actual source catalog')
    for key,wanted in (('identity',slot['identity']['original']),
            ('scope_binding',slot['scope_binding']['original']),('generation',generation_record['original']),
            ('reservation',slot['claim']['original'])):
        common._ep_need(common._ep_same(epoch[key],wanted),'candidate actual link differs: '+key)
    actual_pins={}
    for key,filename,raw in (('inventory','AFTER-INVENTORY.json',inventory_raw),
            ('closure','CLOSURE.json',closure_raw)):
        actual=index['files'].get(prefix+filename)
        common._ep_need(actual is not None and type(raw) is bytes
            and raw==prepared._eps_read(actual,index,originals_by_path,budget_check)
            and common._ep_same(boundary[key],actual),
            'candidate must bind the complete actual create-only '+key+' original')
        actual_pins[key]=actual
    previous=None if not checked else checked[-1]['record']['boundary']
    terminal=None if not checked else checked[-1]['record']['terminal']
    common._ep_need(common._ep_same(boundary['prior_boundary'],identity['prior_boundary'])
        and common._ep_same(epoch['previous_active_boundary'],previous)
        and common._ep_same(epoch['predecessor_terminal'],terminal)
        and common._ep_same(identity['predecessor_terminal'],terminal),
        'candidate skipped the actual committed predecessor')
    common._ep_need(boundary['original_retirement_rewritten'] is False
        and boundary['business_qualified'] is False and boundary['automatic_replay'] is False
        and type(boundary['model_requests']) is int and boundary['model_requests']==0
        and type(boundary['component_qualified']) is bool,
        'candidate grants unsupported authority or qualification')
    inventory=common._ep_strict(inventory_raw);closed=common._ep_strict(closure_raw)
    late.inventory_value(inventory)
    common._ep_need(common._ep_same(boundary['roots'],inventory['roots']),
        'candidate omitted complete inventory roots')
    capture=prepared._eps_capture_view(boundary,inventory,index,originals_by_path,checked,
        late_module=late,budget_check=budget_check)
    common._ep_need(common._ep_same(capture['lease'],lease)
        and common._ep_same(epoch['lease'],slot['stage']['value']['lease'])
        and common._ep_same(capture['lease']['retirement'],boundary['retirement']),
        'candidate substituted the actual immutable stage lease or retirement')
    prepared._eps_closure_details(boundary,inventory_raw,closed,capture,
        sources=sources,budget_check=budget_check)
    legacy=late.epoch_verified_legacy_context(lease,capture['manifest'],capture['originals_by_path'],
        capture['verified'],budget_check=budget_check)
    common._ep_need(common._ep_same(legacy['semantic'],capture['saved']['legacy_semantic']['semantic']),
        'candidate saved legacy semantics differ from the actual unchanged original reader')
    roles=prepared._eps_roles(boundary['component_role_identities'])
    forbidden=set(common.epoch_forbidden_nonces());scopes=[]
    historical_roles=list(legacy['semantic']['all_retired_role_identities'])
    scopes.extend(legacy['semantic']['native_scopes'])
    for retained in epoch_protocol_retained_boundaries(prepared,verified,index,originals_by_path,
            budget_check=budget_check):
        scopes.append(retained['scope'])
        historical_roles.extend(prepared._eps_roles(retained['component_role_identities']))
    for item in checked:
        forbidden.add(item['boundary']['nonce']);scopes.append(item['boundary']['scope'])
        historical_roles.extend(item['roles'])
    head=common._ep_strict(prepared._eps_read(verified['legacy']['native_chain'][0]['boundary'],
        index,originals_by_path,budget_check))
    common._ep_need(boundary['nonce'] not in forbidden
        and not any(common._ep_same(boundary['scope'],row) for row in scopes)
        and not (set(map(tuple,roles)) & set(map(tuple,historical_roles)))
        and common._ep_same(boundary['non_native_sidebranch'],head['non_native_sidebranch']),
        'candidate nonce, accepted scope or native role generation reuses another domain')
    # This object names only existing identity/source originals, never a terminal.
    action={'ordinal':ordinal,'identity':slot['identity']['original'],
        'generation':generation_record['original']}
    candidate_raw=common._ep_encoded(boundary)
    authority=prepared.epoch_verify_closure_action_authority(action,slot,registry,index,originals_by_path,
        boundary_raw=candidate_raw,inventory_raw=inventory_raw,closure_raw=closure_raw,
        capture=capture,budget_check=budget_check)
    common._ep_need(type(authority) is dict
        and authority.get('schema')=='hepta.native-guard.epoch-closure-action-verification.v1'
        and authority.get('state')=='SOURCE_BOUND_ORIGINAL_HOST_CLOSURE_AND_OUTPUTS_VERIFIED'
        and common._ep_same(authority.get('closure'),common._ep_bare(closure_raw))
        and authority.get('host_deep_closure_execution_verified') is True
        and authority.get('host_archive_read_by_phone_or_consumer') is False,
        'actual host execution and complete closure originals were not independently verified')
    budget_check()
    return {'schema':'hepta.native-guard.epoch-prepublication-proof.v1',
        'state':'ACTUAL_CLOSURE_AND_HOST_AUTHORITY_VERIFIED_BEFORE_NATIVE_PUBLICATION',
        'boundary_candidate':common._ep_bare(candidate_raw),'inventory':actual_pins['inventory'],
        'closure':actual_pins['closure'],'identity':slot['identity']['original'],
        'source_generation':generation_record['original'],'predecessor_terminal':terminal,
        'authority':authority,'native_boundary_created':False,
        'component_qualified':boundary['component_qualified'],'business_qualified':False}
