# Plain host-only material construction from an already exclusive actual claim.
# This fragment is appended to the existing native_guard_session_r2 member.
# No import-time action, old prepare() call, phone operation or nonce generation.
EPOCH_HOST_MATERIAL_BINDING = None


class _EHMHostIO:
    def __init__(self, common, base, output, check):
        import os
        self.c=common;self.os=os;self.check=check
        self.base=common._ep_path(base);self.output=common._ep_path(output)
        self.uid=os.geteuid();self.gid=os.getegid()
        self.read_bytes=0;self.write_bytes=0;self.read_calls=0
        self.inputs={};self.outputs={};self.directories={};self.parents={}
        common._ep_need(self.base in self.output.parents and callable(check),
            'fixed new material namespace and enclosing clock required')

    def _chain(self,path):
        self.check();c=self.c;path=c._ep_path(str(path))
        c._ep_need(self.base in path.parents,'host material input escaped fixed Mac base')
        chain,name=c._ep_parent_chain(path)
        try:
            c._ep_need(len(chain)+1<=64,'host material open descriptor bound exceeded')
            parts=path.parent.parts
            for index,row in enumerate(chain):
                ancestor=str(type(path)(*parts[:index+1]))
                identity=row[3][:5]
                c._ep_need(ancestor not in self.parents or self.parents[ancestor]==identity,
                    'host material parent identity changed between operations')
                self.parents[ancestor]=identity
            return chain,name
        except BaseException:
            self._close(chain);raise

    def _close(self,chain):
        for row in reversed(chain):self.os.close(row[0])

    def read(self,row,maximum=16*1024*1024,*,remember=True):
        import stat
        c=self.c;o=self.os;full='metadata' in row
        c._ep_pin(row,original=full,maximum=maximum)
        c._ep_need(type(maximum) is int and 0<=maximum<=16*1024*1024,
            'host material leaf read bound differs')
        chain,name=self._chain(row['path']);fd=None
        try:
            fd=o.open(name,o.O_RDONLY|o.O_NONBLOCK|o.O_NOFOLLOW|o.O_CLOEXEC,dir_fd=chain[-1][0])
            before=c._ep_metadata(o.fstat(fd))
            c._ep_need(stat.S_ISREG(before[2]) and before[5]==1
                and before[6]==row['bytes'] and before[3:5]==[self.uid,self.gid],
                'actual Mac regular original ownership, link or size differs')
            if full:c._ep_need(before==row['metadata'],'actual Mac full9 original differs')
            if row['path'] in self.inputs:
                c._ep_need(before==self.inputs[row['path']]['metadata'],
                    'immutable Mac input was replaced between complete reads')
            chunks=[];remaining=row['bytes']+1
            while remaining:
                self.check();piece=o.read(fd,min(65536,remaining))
                self.read_bytes+=len(piece)
                c._ep_need(self.read_bytes<=64*1024*1024,'one materializer physical read pool exceeded')
                if not piece:break
                chunks.append(piece);remaining-=len(piece)
            raw=b''.join(chunks);self.read_calls+=1
            c._ep_need(self.read_calls<=2048 and c._ep_bare(raw)=={k:row[k] for k in ('bytes','sha256')}
                and before==c._ep_metadata(o.fstat(fd))
                ==c._ep_metadata(o.stat(name,dir_fd=chain[-1][0],follow_symlinks=False)),
                'complete Mac original body, EOF or full9 bookends differ')
            c._ep_chain_check(chain,metadata_unchanged=True);self.check()
            actual=dict(path=row['path'],**c._ep_bare(raw),metadata=before)
            if remember:
                c._ep_need(len(self.inputs)<1024 or row['path'] in self.inputs,
                    'host material immutable input count exceeded')
                self.inputs[row['path']]=actual
            return raw,actual
        finally:
            if fd is not None:o.close(fd)
            self._close(chain)

    def read_unpinned(self,path,maximum):
        # Only fixed five-role map and separately fixed prior-copy paths use this.
        # Their bodies must immediately bind to actual phone identities or result.
        import stat
        c=self.c;o=self.os;chain,name=self._chain(path);fd=None
        try:
            fd=o.open(name,o.O_RDONLY|o.O_NONBLOCK|o.O_NOFOLLOW|o.O_CLOEXEC,dir_fd=chain[-1][0])
            before=c._ep_metadata(o.fstat(fd))
            c._ep_need(stat.S_ISREG(before[2]) and before[5]==1
                and before[3:5]==[self.uid,self.gid] and 0<=before[6]<=maximum,
                'fixed carrier must be an actual bounded Mac regular original')
            chunks=[];remaining=before[6]+1
            while remaining:
                self.check();piece=o.read(fd,min(65536,remaining));self.read_bytes+=len(piece)
                c._ep_need(self.read_bytes<=64*1024*1024,'one materializer physical read pool exceeded')
                if not piece:break
                chunks.append(piece);remaining-=len(piece)
            raw=b''.join(chunks);self.read_calls+=1
            c._ep_need(len(raw)==before[6] and self.read_calls<=2048
                and before==c._ep_metadata(o.fstat(fd))
                ==c._ep_metadata(o.stat(name,dir_fd=chain[-1][0],follow_symlinks=False)),
                'fixed Mac carrier complete read or full9 bookends differ')
            c._ep_chain_check(chain,metadata_unchanged=True)
            actual=dict(path=str(path),**c._ep_bare(raw),metadata=before)
            c._ep_need(len(self.inputs)<1024 and str(path) not in self.inputs,
                'unexpected duplicate fixed carrier read')
            self.inputs[str(path)]=actual;self.check();return raw,actual
        finally:
            if fd is not None:o.close(fd)
            self._close(chain)

    def mkdir(self,path):
        import stat
        c=self.c;o=self.os;path=c._ep_path(str(path))
        c._ep_need(path==self.output or self.output in path.parents,
            'create-only material directory escaped fixed output')
        chain,name=self._chain(path);fd=None
        try:
            o.mkdir(name,0o700,dir_fd=chain[-1][0]);o.fsync(chain[-1][0])
            fd=o.open(name,o.O_RDONLY|o.O_DIRECTORY|o.O_NOFOLLOW|o.O_CLOEXEC,dir_fd=chain[-1][0])
            actual=c._ep_metadata(o.fstat(fd))
            c._ep_need(stat.S_ISDIR(actual[2]) and stat.S_IMODE(actual[2])==0o700
                and actual[3:5]==[self.uid,self.gid]
                and actual==c._ep_metadata(o.stat(name,dir_fd=chain[-1][0],follow_symlinks=False)),
                'new material directory ownership or held identity differs')
            c._ep_chain_check(chain);self.directories[str(path)]=actual[:5];self.check()
        finally:
            if fd is not None:o.close(fd)
            self._close(chain)

    def write(self,path,raw):
        import stat
        c=self.c;o=self.os;path=c._ep_path(str(path))
        c._ep_need(type(raw) is bytes and self.output in path.parents
            and str(path.parent) in self.directories and str(path) not in self.outputs
            and len(self.outputs)<256,'new bounded material file namespace differs')
        self.write_bytes+=len(raw)
        c._ep_need(self.write_bytes<=16*1024*1024,'one materializer physical write pool exceeded')
        chain,name=self._chain(path);fd=None
        try:
            fd=o.open(name,o.O_WRONLY|o.O_CREAT|o.O_EXCL|o.O_NOFOLLOW|o.O_CLOEXEC,
                0o600,dir_fd=chain[-1][0])
            start=c._ep_metadata(o.fstat(fd))
            c._ep_need(stat.S_ISREG(start[2]) and stat.S_IMODE(start[2])==0o600
                and start[3:7]==[self.uid,self.gid,1,0],'new exclusive material leaf identity differs')
            offset=0
            while offset<len(raw):
                self.check();count=o.write(fd,raw[offset:offset+65536])
                c._ep_need(count>0,'material write made no progress');offset+=count
            o.fsync(fd);after=c._ep_metadata(o.fstat(fd));o.fsync(chain[-1][0])
            c._ep_need(after[:6]==start[:6] and after[6]==len(raw)
                and after==c._ep_metadata(o.stat(name,dir_fd=chain[-1][0],follow_symlinks=False)),
                'exclusive material file was replaced or partially written')
            c._ep_chain_check(chain)
            original=dict(path=str(path),**c._ep_bare(raw),metadata=after)
            self.outputs[str(path)]=original
        finally:
            if fd is not None:o.close(fd)
            self._close(chain)
        actual,_=self.read(original,remember=False)
        c._ep_need(actual==raw,'new material complete readback differs');return original

    def parents_for(self,path):
        path=self.c._ep_path(str(path))
        missing=[];parent=path.parent
        while str(parent) not in self.directories:
            self.c._ep_need(self.output==parent or self.output in parent.parents,
                'new material parent escaped exact output')
            missing.append(parent);parent=parent.parent
        for directory in reversed(missing):self.mkdir(directory)

    def recheck(self,*,outputs=True):
        c=self.c;o=self.os
        rows=list(self.inputs.values())+(list(self.outputs.values()) if outputs else [])
        for row in rows:self.read(row,remember=False)
        for path,identity in self.directories.items():
            chain,name=self._chain(path)
            try:
                actual=c._ep_metadata(o.stat(name,dir_fd=chain[-1][0],follow_symlinks=False))
                c._ep_need(actual[:5]==identity,'owned material directory was renamed or substituted')
                c._ep_chain_check(chain,metadata_unchanged=True)
            finally:self._close(chain)
        self.check()


def _ehm_host3(common,value):
    common._ep_pin(value);return value


def _ehm_bare3(value):
    return {key:value[key] for key in ('path','bytes','sha256')}


def _ehm_binding(common,stage,plan):
    value=EPOCH_HOST_MATERIAL_BINDING
    common._ep_exact(value,{'schema','epoch_id','mac_base','shared_root',
        'retirement_descriptor','retirement_carriers','policy_adoption','live_policy','sender_sources'},
        'complete source-fixed host material binding required')
    operation=stage._est_binding(common)
    common._ep_need(value['schema']=='hepta.native-guard.epoch-host-material-source-binding.v1'
        and value['epoch_id']==common.EPOCH_ID,'fixed material epoch source identity differs')
    base=common._ep_path(value['mac_base']);shared=common._ep_path(value['shared_root'])
    common._ep_need(base in shared.parents and shared==common._ep_path(plan['shared_materials']['path']).parent
        and operation['case_out_root']==str(base/'native-guard-root-chains-r10-r1'),
        'actual fixed Mac material namespace differs')
    for key in ('retirement_descriptor','policy_adoption','live_policy'):_ehm_host3(common,value[key])
    common._ep_exact(value['retirement_carriers'],{'proof','preflight','probe','bound_inputs','disabled_flag'},
        'exact five actual retirement carrier roles required')
    for pair in value['retirement_carriers'].values():
        common._ep_exact(pair,{'phone_original','carrier'},'retirement semantic origin and actual carrier differ')
        common._ep_pin(pair['phone_original'],original=True);_ehm_host3(common,pair['carrier'])
    common._ep_exact(value['sender_sources'],{'sender','ready_helper'},'both original sender sources required')
    for row in value['sender_sources'].values():_ehm_host3(common,row)
    return value


def _ehm_allocation(common,stage,plan,allocation,io,case):
    request={'operation':'allocate','boot_id':plan['boot_id'],'payload':{'action':'claim'}}
    stage.epoch_operation_result_value('allocate',allocation,request)
    c=common;names={'claim':'CLAIM.original.json','directory_binding':'DIRECTORY-BINDING.original.json',
        'identity':'IDENTITY.original.json','owner_request':'OWNER-REQUEST.original.txt',
        'allocation_admission':'ALLOCATION-ADMISSION.original.json'}
    raw,map_pin=io.read_unpinned(case/'epoch/ALLOCATION-ORIGINALS.json',262144);mapping=c.strict(raw)
    c._ep_exact(mapping,{'schema','allocation','files'},'exact actual allocation carrier map required')
    c._ep_need(mapping['schema']=='hepta.native-guard.epoch-allocation-originals.v1'
        and c._ep_same(mapping['allocation'],c._ep_bare(c._ep_encoded(allocation))),
        'five-role map does not bind the complete actual allocation result')
    c._ep_exact(mapping['files'],names,'exact five original allocation roles required')
    originals={};carriers={}
    for role,filename in names.items():
        pair=mapping['files'][role]
        c._ep_exact(pair,{'phone_original','carrier'},'actual phone origin and Mac carrier pair required')
        c._ep_pin(pair['phone_original'],original=True);c._ep_pin(pair['carrier'],original=True)
        c._ep_need(c._ep_same(pair['phone_original'],allocation[role])
            and pair['carrier']['path']==str(case/'epoch'/filename),
            'actual allocation origin or fixed carrier path differs')
        body,actual=io.read(pair['carrier'],16000 if role=='owner_request' else 16*1024*1024)
        c._ep_need(c._ep_bare(body)=={k:pair['phone_original'][k] for k in ('bytes','sha256')},
            'Mac copy must match the complete actual phone body, not phone metadata')
        originals[role]=body;carriers[role]=actual
    claim=c.strict(originals['claim']);identity=c.strict(originals['identity'])
    directory=c.strict(originals['directory_binding']);admission=c.strict(originals['allocation_admission'])
    c.epoch_reservation_value(claim,binding=c.epoch_binding_value(),ordinal=allocation['ordinal'],
        previous_terminal=allocation['predecessor_terminal'])
    c._ep_need(c._ep_same(claim['generation'],plan['generation'])
        and c._ep_same(claim['authorization_request'],plan['authorization_request']),
        'exclusive claim changed source generation or preclaim authorization')
    c.epoch_identity_value(identity,claim,allocation['claim'],forbidden_nonces=c.epoch_forbidden_nonces())
    for key in ('epoch_id','boot_id','ordinal','nonce','label','case_id','selected_session_id',
            'selected_profile_id','owner_request','prior_boundary','predecessor_terminal'):
        c._ep_need(c._ep_same(identity[key],allocation[key]),'actual allocation/identity mismatch: '+key)
    for key in ('boot_id','case_id','selected_session_id','selected_profile_id','initialization','generation'):
        c._ep_need(c._ep_same(allocation[key],plan[key]),'actual allocation changed preclaim selection: '+key)
    slot=c.EPOCH_REGISTRY_ROOT+'/slots/%02d/'%allocation['ordinal']
    expected={'claim':c.EPOCH_REGISTRY_ROOT+'/slots/%02d.CLAIM.json'%allocation['ordinal'],
        'directory_binding':slot+'DIRECTORY-BINDING.json','identity':slot+'IDENTITY.json',
        'owner_request':slot+'owner-request.original.txt','allocation_admission':slot+'ALLOCATION-ADMISSION.json'}
    for key,path in expected.items():
        c._ep_need(allocation[key]['path']==path,'actual immutable allocation path differs: '+key)
    linked=directory.get('directory',{})
    c._ep_exact(linked,{'path','first_observed_metadata'},'actual claimed directory observation required')
    c.epoch_directory_claim_value(directory,ordinal=allocation['ordinal'],claim=allocation['claim'],
        directory={'path':slot[:-1],'metadata':linked['first_observed_metadata']})
    c._ep_exact(admission,stage.EPOCH_ALLOCATION_ADMISSION_FIELDS,'complete actual allocation admission required')
    c._ep_need(admission['schema']=='hepta.native-guard.epoch-allocation-admission.v1'
        and admission['state']=='PRECLAIM_OBSERVATION_AND_CAPACITY_BOUND_TO_EXCLUSIVE_IDENTITY'
        and admission['nonce_generated_after_exclusive_claim'] is True
        and all(admission[key] is False for key in ('native_scope_assigned','component_qualified',
            'business_qualified','automatic_retry')),'allocation admission cannot infer scope or qualification')
    for key in ('epoch_id','ordinal','boot_id','initialization','generation','claim','identity',
            'predecessor_terminal','prior_boundary'):
        c._ep_need(c._ep_same(admission[key],allocation[key]),'actual admission/claim linkage differs: '+key)
    c._ep_pin(admission['anchor'],original=True)
    c._ep_need(c._ep_same(_ehm_bare3(admission['anchor']),claim['anchor'])
        and c._ep_same(admission['resource_reservation'],claim['resource_reservation'])
        and c._ep_same(admission['authorization_original'],plan['authorization_request']['origin']),
        'actual allocation authority, anchor or capacity reservation differs')
    observation=admission['preclaim_observation']
    c._ep_need(type(observation) is dict
        and observation.get('schema')=='hepta.native-guard.epoch-preclaim-observation.v1'
        and c._ep_same(claim['resource_reservation']['observation'],c._ep_bare(c._ep_encoded(observation))),
        'complete actual preclaim observation differs from the reserved resource profile')
    owner=originals['owner_request'];authorized=plan['authorization_request']['utf8'].replace('{{EPOCH_NONCE}}',identity['nonce'])
    c._ep_need(owner==allocation['owner_request_utf8'].encode('utf-8')==authorized.encode('utf-8')
        and 20<=len(owner)<=16000 and b'\0' not in owner and owner.decode('utf-8').count(identity['nonce'])==1,
        'actual postclaim owner request differs from its exact authorized substitution')
    c._ep_need(stage._est_read_paths(c,'allocate',identity)['PRIOR-BOUNDARY.json']==identity['prior_boundary']['path'],
        'actual prior boundary must be the fixed historical head or immediate preceding slot')
    prior,prior_carrier=io.read_unpinned(case/'epoch/PRIOR-BOUNDARY.original.json',16*1024*1024)
    c._ep_need(c._ep_bare(prior)=={k:identity['prior_boundary'][k] for k in ('bytes','sha256')},
        'separate actual prior-boundary carrier body differs')
    epoch={'schema':'hepta.native-guard.epoch-lease-binding.v1','epoch_id':c.EPOCH_ID,
        'anchor':admission['anchor'],'initialization':plan['initialization'],'ordinal':identity['ordinal'],
        'reservation':allocation['claim'],'identity':allocation['identity'],'generation':plan['generation']}
    return identity,owner,prior,prior_carrier,carriers,epoch


def _ehm_production(common,plan,binding,io,manifest,manifest_raw,bodies):
    import re
    c=common;package=c._ep_path(plan['runtime']['path']).parent
    mf,_=io.read(plan['runtime'],262144)
    c._ep_need(mf==manifest_raw and manifest.get('state')=='HOST_REVIEWED_NOT_PHONE_QUALIFIED',
        'actual current runtime MF differs from the complete loaded source map')
    files={'package/MANIFEST.json':mf}
    for row in manifest['files']:
        raw,_=io.read(dict(row,path=str(package/c.relative(row['path']))),
            131072 if row['path'].endswith('.py') else 16*1024*1024)
        c._ep_need(raw==bodies[row['path']],'current original source changed after admission')
        files['package/'+row['path']]=raw
    reviewed=c.strict(bodies['reference/REVIEWED-PRODUCTION-PINS.json'])
    c._ep_need(type(reviewed) is dict and len(reviewed)==15
        and all(re.fullmatch('[a-z_]+[.]py',name) for name in reviewed),
        'exact reviewed production15 source names required')
    shared_raw,_=io.read(plan['shared_materials'],262144);shared=c.strict(shared_raw)
    c._ep_need(shared.get('schema')=='hepta.r10.shared-production-materials.v1'
        and shared.get('state')=='HOST_SHARED_PRODUCTION_BYTES_NOT_INSTALLABLE'
        and shared.get('production_source_count')==15 and shared.get('phone_calls')==0
        and shared.get('phone_qualification') is False and shared.get('policy_adoption_inferred') is False,
        'original shared production material state differs')
    rows=shared.get('files');c._ep_need(type(rows) is list and len(rows)==17,'complete shared17 originals required')
    names={'provider/source/'+name for name in reviewed}|{'local-config-r10-r1.json','PHONE-SERVICE-INPUTS-v150-r10-r1.json'}
    index={};raws={};root=c._ep_path(binding['shared_root'])
    for row in rows:
        c._ep_exact(row,{'path','bytes','sha256'},'exact shared original row required')
        c._ep_need(row['path'] in names and row['path'] not in index,'extra or duplicate shared original')
        index[row['path']]=row;raws[row['path']],_=io.read(dict(row,path=str(root/row['path'])))
    c._ep_need(set(index)==names,'missing actual shared production original')
    production=[]
    for name,h in sorted(reviewed.items()):
        raw=raws['provider/source/'+name];c._ep_need(c.sha(raw)==h,'actual production byte pin differs')
        files['inputs/production/'+name]=raw;production.append(dict(path='production/'+name,**c.descriptor(raw)))
    cfg_raw=raws['local-config-r10-r1.json'];svc_raw=raws['PHONE-SERVICE-INPUTS-v150-r10-r1.json']
    cfg=c.strict(cfg_raw);c.strict(svc_raw)
    c._ep_need(cfg.get('service_manifest_sha256')==c.sha(svc_raw)
        and cfg.get('schema')=='hepta.phone-local-provider.v150.1'
        and type(cfg.get('approved_apps')) is dict and cfg.get('inference_location')=='phone'
        and cfg.get('expected_parallel_slots')==1,'actual production configuration/service binding differs')
    source={'schema':'hepta.native-guard.component-source-seal.v150.r10.1',
        'state':'REVIEWED_COMPONENT_BYTES_NOT_FINAL_RELEASE','intended_module_release':'v150-r10-r1',
        'configuration':c.descriptor(cfg_raw),'phone_service_inputs_sha256':c.sha(svc_raw),
        'production_files':[dict(path='source/'+c._ep_path('/'+r['path']).name,
            bytes=r['bytes'],sha256=r['sha256']) for r in production]}
    source_raw=c.encoded(source);combo_raw,_=io.read(plan['combination']);combo=c.strict(combo_raw)
    artifacts=combo.get('artifacts')
    c._ep_exact(artifacts,{'client','sidecar','worker','screen_helper','focus_helper','unicode_helper','busybox','python'},
        'exact eight reviewed external artifact identities required')
    for row in artifacts.values():
        c._ep_exact(row,{'path','bytes','sha256','uid','gid','mode','selinux'},'complete artifact identity required')
        c._ep_path(row['path'])
        c._ep_need(row['uid']==row['gid']==0 and type(row['mode']) is int
            and type(row['bytes']) is int and row['bytes']>0
            and type(row['sha256']) is str and c.EPOCH_HASH.fullmatch(row['sha256']),
            'external original artifact bytes or metadata differs')
    expected={'schema':'hepta.native-guard.component-combination.v150.r10.1',
        'state':'REVIEWED_COMPONENT_BYTES_NOT_FOUR_ROLE_READY','source_seal':c.descriptor(source_raw),
        'configuration':c.descriptor(cfg_raw),'service_inputs':c.descriptor(svc_raw),
        'production_files':production,'artifacts':artifacts,'live_policy_sha256':binding['live_policy']['sha256']}
    c._ep_need(combo_raw==c.encoded(expected) and c._ep_same(combo,expected)
        and manifest.get('current_combination_sha256')==c.sha(combo_raw)
        and c._ep_same(manifest.get('epoch_shared_materials'),plan['shared_materials']),
        'actual final combination must equal its complete actual construction')
    files.update({'inputs/COMBINATION.json':combo_raw,'inputs/SOURCE-SEAL.original.json':source_raw,
        'inputs/configuration.original.json':cfg_raw,'inputs/service-inputs.original.json':svc_raw})
    return files,combo_raw,artifacts


def _ehm_retirement(common,binding,io,boot):
    import ast
    c=common;raw,_=io.read(binding['retirement_descriptor']);value=c.strict(raw)
    c._ep_exact(value,{'schema','boot_id','files'},'complete original retirement descriptor required')
    c._ep_need(value['schema']=='hepta.native-guard.retirement-original-input.v1' and value['boot_id']==boot,
        'retirement original boot or schema differs')
    rows=value['files'];c._ep_exact(rows,binding['retirement_carriers'],'exact actual retirement role set required')
    code=c.BASE/'module-r10-r1-retirement-code-r1';out=c.BASE/'module-retire-r9-r2-for-r10-r1-01'
    paths={'proof':out/'RETIREMENT.json','preflight':out/'PREFLIGHT.json','probe':code/'retirement_probe.py',
        'bound_inputs':code/'BOUND-INPUTS.json',
        'disabled_flag':c.ANDROID/'data/adb/modules/trillionnium_hepta_phone_local_v150_r9_r2/disable'}
    originals={}
    for key,path in paths.items():
        row=rows[key];pair=binding['retirement_carriers'][key];c._ep_pin(row,original=True)
        c._ep_need(row['path']==str(path) and c._ep_same(row,pair['phone_original']),
            'actual original retirement phone path/full9 differs')
        body,_=io.read(pair['carrier']);originals[key]=body
        c._ep_need(c._ep_bare(body)=={k:row[k] for k in ('bytes','sha256')},
            'actual Mac retirement carrier differs from complete phone original')
    proof,before,bound=(c.strict(originals[k]) for k in ('proof','preflight','bound_inputs'))
    c._ep_need(proof.get('schema')=='hepta.r9-r2-retirement-observation.v1'
        and proof.get('state')=='ORIGINAL_FOUR_GROUPS_ABSENT_STATE_PRESERVED' and proof.get('boot_id')==boot
        and proof.get('server_lock_now_unheld') is True and proof.get('global_pending_clear') is True
        and all(proof.get(k) is False for k in ('old_claims_deleted','old_task_terminal_rewritten',
            'automatic_restart','automatic_replay')),'actual complete retirement semantics differ')
    c._ep_need(before.get('state')=='READY_FOR_DISABLE_AND_ONE_SUPERVISOR_TERM'
        and before['groups']==proof['original_role_identities']
        and set(before['groups'])=={'supervisor','provider','model','sidecar'}
        and before['preserved_state']==proof['preserved_state']
        and bound.get('complete_current_accepted_case_union_verified') is True
        and originals['disabled_flag']==b'','retirement original preserved-state or group identity differs')
    tree=ast.parse(originals['probe']);constants={}
    for node in tree.body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            name=node.targets[0].id
            if name in ('BOUND','GROUPS'):
                c._ep_need(name not in constants,'duplicate original retirement constant')
                constants[name]=ast.literal_eval(node.value)
    c._ep_need(constants.get('BOUND')==bound
        and {k:list(v) for k,v in constants.get('GROUPS',{}).items()}==before['groups'],
        'actual retirement probe must bind its complete original inputs')
    return raw,rows,originals


def _ehm_archive(common,files,check):
    import gzip
    import io
    import tarfile
    common._ep_need(len(files)<=80 and sum(map(len,files.values()))<=8*1024*1024,
        'existing component archive count or uncompressed byte bound exceeded')
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for name,raw in sorted(files.items()):
            check();common.relative(name)
            entry=tarfile.TarInfo(name);entry.mode=0o600;entry.uid=entry.gid=0;entry.mtime=0;entry.size=len(raw)
            archive.addfile(entry,io.BytesIO(raw))
    check();raw=gzip.compress(stream.getvalue(),compresslevel=9,mtime=0);check();return raw


def epoch_host_prepare_material(plan_raw,allocation,*,common,stage,budget_check):
    # Validate through the current actual stage API before any material I/O.
    plan=stage.epoch_allocation_plan_value(plan_raw)
    c,modules,manifest,manifest_raw,bodies=stage._est_modules(budget_check=budget_check)
    import base64
    import os
    import sys
    import time
    current=sys.modules.get('native_guard_session_r2')
    c._ep_need(c is common and modules['stage_component'] is stage
        and current is not None and current.__dict__ is globals()
        and globals().get('__reviewed_package_sources__') is bodies
        and globals().get('__reviewed_package_manifest_raw__')==manifest_raw
        and globals().get('__reviewed_source_sha256__')==c.sha(bodies['source/native_guard_session_r2.py'])
        and c.epoch_actual_context(globals())=='mac' and sys.platform=='darwin'
        and os.geteuid()==501 and os.getegid()==20,
        'host materializer requires its actual verified Mac module and owner')
    binding=_ehm_binding(c,stage,plan);base=c._ep_path(binding['mac_base'])
    c._ep_need(type(allocation) is dict and type(allocation.get('label')) is str
        and c.EPOCH_LABEL.fullmatch(allocation['label']),'actual allocated label required')
    case=base/'native-guard-root-chains-r10-r1'/allocation['label'];out=case/'material'
    io=_EHMHostIO(c,str(base),str(out),budget_check)
    identity,owner,prior,prior_carrier,carriers,epoch=_ehm_allocation(c,stage,plan,allocation,io,case)
    files,combo_raw,artifacts=_ehm_production(c,plan,binding,io,manifest,manifest_raw,bodies)
    # Preserve actual phone original bytes in each physical material tree.
    # These are verified Mac carriers, never replacements for phone metadata.
    for role,name in (('claim','EPOCH-CLAIM.original.json'),
            ('allocation_admission','EPOCH-ALLOCATION-ADMISSION.original.json')):
        body,_actual=io.read(carriers[role])
        c._ep_need(c._ep_bare(body)=={k:allocation[role][k] for k in ('bytes','sha256')},
            'material allocation copy differs from its actual phone original')
        files['inputs/'+name]=body
    retirement_raw,retirement,retirement_bodies=_ehm_retirement(c,binding,io,plan['boot_id'])
    sender=plan['sender_inputs'];sender_bodies={}
    for key,row in sender.items():sender_bodies[key],_=io.read(row)
    previous=c.strict(sender_bodies['previous']);draft=c.strict(sender_bodies['preserved_draft'])
    c._ep_need(previous['identity']['session_id']==identity['selected_session_id']
        and previous['identity']['profile_id']==identity['selected_profile_id'],
        'original previous selected session/profile differs from actual allocation')
    d=base64.b64decode(draft['exact_utf8_b64'],validate=True)
    c._ep_need(base64.b64encode(d).decode()==draft['exact_utf8_b64'] and d
        and d.decode('utf-8').encode('utf-8')==d and c.sha(d)==draft['utf8_sha256'] and d!=owner,
        'exact preserved nonempty user draft must remain distinct from new owner request')
    source_names={'sender':'send_new_native_guard_task_r10_r4.py','ready_helper':'sender_native_guard_ready_r10_r4.py'}
    current_rows={row['path']:row for row in manifest['files']}
    for key,name in source_names.items():
        row=binding['sender_sources'][key]
        c._ep_need(row['path']==str(base/name)
            and {k:row[k] for k in ('bytes','sha256')}==
                {k:current_rows['source/'+name][k] for k in ('bytes','sha256')},
            'original Mac sender source differs from actual reviewed current package')
        body,_=io.read(row,131072)
        c._ep_need(body==bodies['source/'+name],'complete original sender source differs')
    policy_input=manifest.get('epoch_policy_history_input');_ehm_host3(c,policy_input)
    policy_raw,_=io.read(policy_input,65536)
    policy=modules['native_proc_profile'].verify_epoch_policy_history(policy_raw,
        read_pinned=lambda row:io.read(row)[0],budget_check=budget_check)
    c._ep_need(policy.get('schema')=='hepta.native-guard.epoch-policy-history-verification.v1'
        and policy.get('state')=='ORIGINAL_POLICY_ADOPTION_REVERIFIED_BY_OWNED_HOST_AUDIT'
        and c._ep_same(policy.get('original_adoption'),binding['policy_adoption'])
        and c._ep_same(c.strict(policy_raw)['actual_export'],binding['live_policy']),
        'actual material policy must retain the original source/action adoption authority')
    io.recheck(outputs=False)
    # Create a new immutable lease only after complete source and original gates.
    expires=time.time_ns()//1000000+510000
    lease={'schema':'hepta.native-guard.epoch-lease.v1','label':identity['label'],
        'boot_id':identity['boot_id'],'case_id':identity['case_id'],'nonce':identity['nonce'],
        'owner_request_sha256':c.sha(owner),'selected_session_id':identity['selected_session_id'],
        'selected_profile_id':identity['selected_profile_id'],'expires_unix_ms':expires,
        'combination':c.descriptor(combo_raw),'retirement':retirement,'prior_boundary':identity['prior_boundary'],
        'android_journal':str(c.ANDROID_BASE/'native-guard-r10-r1'/identity['label']/'executor'),
        'package_sha256':plan['runtime']['sha256'],'epoch':epoch}
    c.epoch_lease_protocol_value(lease);lease_raw=c.encoded(lease)
    contract={'schema':'hepta.native-guard.sender-contract.v1',**{k:lease[k] for k in
        ('label','nonce','case_id','boot_id','owner_request_sha256','selected_session_id',
         'selected_profile_id','expires_unix_ms','package_sha256')},
        'lease_sha256':c.sha(lease_raw),'combination_sha256':c.sha(combo_raw)}
    contract_raw=c.encoded(contract)
    files.update({'inputs/PRIOR-BOUNDARY.original.json':prior,'LEASE.json':lease_raw,
        'owner-request.txt':owner,'sender-contract.json':contract_raw})
    archive=_ehm_archive(c,files,budget_check)
    io.mkdir(out)
    for name,raw in sorted(files.items()):
        path=out/'tree'/c.relative(name);io.parents_for(path);io.write(path,raw)
    archive_pin=io.write(out/'component-inputs.tar.gz',archive)
    artifacts_pin=io.write(out/'ARTIFACTS.original.json',c.encoded(artifacts))
    prior_descriptor=io.write(out/'PRIOR-BOUNDARY-DESCRIPTOR.json',c.encoded(identity['prior_boundary']))
    io.mkdir(out/'retirement-originals')
    for key,raw in sorted(retirement_bodies.items()):io.write(out/'retirement-originals'/(key+'.original'),raw)
    policy_pin=io.write(out/'POLICY-HISTORY-VERIFICATION.json',c.encoded(policy))
    sender_result={'request':_ehm_bare3(carriers['owner_request']),**sender}
    root_plan={'schema':'hepta.native-guard.epoch-root-plan.v1','label':identity['label'],
        'case_id':identity['case_id'],'nonce':identity['nonce'],'boot_id':identity['boot_id'],
        'session_id':identity['selected_session_id'],'profile_id':identity['selected_profile_id'],
        'request':sender_result['request'],'previous':sender['previous'],'preserved_draft':sender['preserved_draft'],
        'sender_retirement_resolution':sender['retirement_resolution'],'package':plan['runtime'],
        'shared_materials':plan['shared_materials'],'shared_root':binding['shared_root'],
        'artifacts':_ehm_bare3(artifacts_pin),'policy_adoption':binding['policy_adoption'],
        'live_policy_sha256':binding['live_policy']['sha256'],'retirement_descriptor':binding['retirement_descriptor'],
        'retirement_originals':str(out/'retirement-originals'),
        'prior_boundary_descriptor':_ehm_bare3(prior_descriptor),'prior_boundary_original':prior_carrier['path'],
        'source_package':plan['root_source_manifest'],'out':str(case),'combination':plan['combination'],
        'epoch':epoch,'code_receipt':plan['code_receipt']}
    home=c.BASE/'native-guard-r10-r1'/identity['label']
    prepared={'schema':'hepta.native-guard.epoch-host-preparation.v1','state':'HOST_MATERIAL_ONLY_NOT_DEPLOYED',
        'label':identity['label'],'case_id':identity['case_id'],'nonce':identity['nonce'],
        'owner_request_sha256':c.sha(owner),'package_sha256':plan['runtime']['sha256'],
        'lease':c.descriptor(lease_raw),'combination':c.descriptor(combo_raw),'archive':c.descriptor(archive),
        'archive_members':len(files),'phone_home':str(home),'epoch':epoch,
        'root_detached_launcher_argv':None,'root_shell_launch_fragment':None,'finite_operation_required':'launch',
        'launcher_fork_is_not_readiness':True,'supervisor_native_init_parent_required':True,
        'sender_contract_path':str(out/'tree/sender-contract.json'),'sender_contract_sha256':c.sha(contract_raw),
        'retirement_descriptor_sha256':c.sha(retirement_raw),
        'original_sender_sha256':binding['sender_sources']['sender']['sha256'],
        'original_sender_sources':binding['sender_sources'],'policy_history_verification':_ehm_bare3(policy_pin),
        'immutable_host_originals':sorted(io.inputs.values(),key=lambda row:row['path']),
        'phone_calls':0,'model_requests':0,'native_submissions':0,'nonces_generated':0,
        'component_qualified':False,'business_qualified':False,'automatic_retry':False,
        'final_r10_builder_must_compare_all_component_bytes_and_consume_late_inventory':True}
    prepared_pin=io.write(out/'PREPARED.json',c.encoded(prepared));io.recheck()
    c._ep_need(0<expires-time.time_ns()//1000000<=510000,
        'new actual lease expired or host wall clock changed during material construction')
    return {'schema':'hepta.native-guard.epoch-material-result.v1',
        'state':'ACTUAL_CLAIM_BOUND_HOST_MATERIAL_PREPARED_NOT_DEPLOYED',
        'prepared':_ehm_bare3(prepared_pin),'lease':_ehm_bare3(io.outputs[str(out/'tree/LEASE.json')]),
        'archive':_ehm_bare3(archive_pin),'root_plan':root_plan,'sender_inputs':sender_result}
