"""Host-only source-chain constructor; no BUILD, installation or READY qualification.
The public API refuses before parsing or callbacks while FROZEN_INPUTS is None.
Actual runtime/consumer/material descriptors must be reviewed and source-bound.
All returned files are source candidates. Actual execution-input slots stay None.
"""
import ast,copy,hashlib,json,re,types
from pathlib import PurePosixPath

FROZEN_INPUTS = None
REFS = json.loads("{\"builder\":{\"path\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-release-owner-finalizer-a1055-r1/source/build_release_r10.py\",\"bytes\":61822,\"sha256\":\"991465020b2012372d677cc4c7cf9fc02c668a406a0af0fc6fc08514d3f0073e\"},\"release_reader\":{\"path\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-install-ready-source-a1055-20261106-01/references/release_reader.original.py\",\"bytes\":28483,\"sha256\":\"e947a3b2de75a0820fcc3cb5cfe758f874cd85625cb11bac793b38256a670c43\"},\"installer\":{\"path\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-install-ready-source-a1055-20261106-01/references/installer.original.py\",\"bytes\":34100,\"sha256\":\"714a2916680e2313bfcee5a4319d6484b3c6ea5539854818c1134ad84ea02446\"},\"readiness\":{\"path\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-install-ready-source-a1055-20261106-01/references/readiness.original.py\",\"bytes\":16407,\"sha256\":\"2b4ff90f7078af2481feb8a2d33c39d1a0e260102cd769a4ee3b46d9bec47e11\"},\"exact8\":{\"path\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-install-ready-source-a1055-20261106-01/references/exact8.original.py\",\"bytes\":29027,\"sha256\":\"24db28bee38671322b11ce4c2afd5dd47425381101dd85f887141f567811b490\"},\"formal\":{\"path\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-release-owner-finalizer-a1055-r1/contracts/FINAL-INTEGRATION-INPUTS.json\",\"bytes\":28873,\"sha256\":\"8443393552d1b322b0bf3f86d9e91474ece860e1efd708c80ad15ba8c539df9f\"},\"protocol\":{\"path\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-install-ready-source-fc33-env-v2-type-checks-candidate01/source/install_ready_execution_protocol.py\",\"bytes\":12782,\"sha256\":\"79f2a227e0d0c991bcc08c9edf6d5916faed798c358f27906d53a226beeda353\"},\"install_reader\":{\"path\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-install-ready-source-fc33-env-v2-type-checks-candidate01/source/verify_install_start_ready_UNBOUND.py\",\"bytes\":35031,\"sha256\":\"d1de5b63f24cee899c47f7c3019ac4d7939d6212c9c798f812dc0266a97b569f\"},\"retention\":{\"path\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-install-retention-source-fc33-candidate01/source/verify_install_retention_UNBOUND.py\",\"bytes\":22066,\"sha256\":\"a95977c049b1d1a079014480cd37b9a52414bc60c2f584c4a36e21f5f8791144\"},\"retention_protocol\":{\"path\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-install-retention-source-fc33-candidate01/source/install_retention_protocol_UNBOUND.py\",\"bytes\":20851,\"sha256\":\"280df226c4bde2294bfaefec93da40fcbc0c685e7c20a2359444e856fbd0bb7a\"},\"owner_service\":{\"path\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-release-owner-finalizer-a1055-r1/preview-module/service.sh\",\"bytes\":21310,\"sha256\":\"8efdb9929f31550f7f0f4dd8580230be4fdd0d1671a40e6dd14817bda7323315\"},\"owner_provenance\":{\"path\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-release-owner-finalizer-a1055-r1/preview-module/RESIDENT-OWNER-FINALIZER.json\",\"bytes\":3354,\"sha256\":\"4bbdea92b59606348dbb26f530b253a1a85cbeef7000284c2389e84ec97b6094\"},\"component_fragment\":{\"path\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-release-owner-finalizer-a1055-r1/source/component_activation_gate.fragment.py\",\"bytes\":4568,\"sha256\":\"6c0a0ffb21c7aa89adf18e8a6ee9f2c2920238fb156e10fe0ad9349383449b97\"}}")
R4 = json.loads("{\"combination\":{\"path\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-final-v3-getattr-a1055-r4/COMBINATION.json\",\"bytes\":4695,\"sha256\":\"02c2a26af79e367afe48cb1bc378808f3c5a32800548498a0262ea0265c9f708\"},\"source_seal\":{\"path\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-final-v3-getattr-a1055-r4/SOURCE-SEAL.json\",\"bytes\":2341,\"sha256\":\"78c39b4cc4afd438bb149013fff20bbecc0a78241c3ed979e101320736eadcc0\"},\"shared\":{\"path\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-final-v3-getattr-a1055-r4/shared/SHARED-MATERIALS.json\",\"bytes\":3519,\"sha256\":\"2ea9a478b366d6a69fdb8942699b6241d72330cfa789baa4b3132fdaca169e68\"},\"configuration\":{\"path\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-final-v3-getattr-a1055-r4/shared/local-config-r10-r1.json\",\"bytes\":1493,\"sha256\":\"22f57380a8bf92d88f0a0d7eda700adc7c711464975d7184b0dce48b3bdd5d3e\"},\"service\":{\"path\":\"/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-final-v3-getattr-a1055-r4/shared/PHONE-SERVICE-INPUTS-v150-r10-r1.json\",\"bytes\":10654,\"sha256\":\"e0522c5d743fd9bdc30343d93200a894d58016f935f564284bb6b0d924ba898a\"}}")
OLD_BLOCKS = json.loads("{\"daily\":\"    need(sha(source['daily_phone_local.py'])=='ca23c60bbb4114960c6a571492cacd9e0bdc3404191409ac78bcf0c34a06c1d0',\\n         'derived daily integration bytes differ from reviewed fifteen-source candidate')\",\"service_parent\":\"    service['parent_service_inputs_sha256']=sha(parent_service_raw)\",\"final_material\":\"    need(len(config_raw)==1493 and sha(config_raw)=='22f57380a8bf92d88f0a0d7eda700adc7c711464975d7184b0dce48b3bdd5d3e'\\n         and len(service_raw)==10654 and sha(service_raw)=='e0522c5d743fd9bdc30343d93200a894d58016f935f564284bb6b0d924ba898a',\\n         'final release must retain the actual v3 configuration and service bytes')\",\"shared_parents\":\"        source_input_sha256=sha(input_raw),parent_configuration_sha256=sha(parent_config_raw),\\n        parent_service_inputs_sha256=sha(parent_service_raw),files=shared_files,\"}")
FORMAL_VERIFIER = "def verify_current_formal_parent(raw, value, readiness_raw):\n    \"\"\"Exact five reviewed production rows and this derived readiness row only.\"\"\"\n    binding=REVIEWED_SOURCE_BINDING\n    need(type(binding)is dict,'UNBOUND_REVIEWED_SOURCE_BINDING_NO_IO')\n    previous_raw=read(binding['formal_parent']);previous=json.loads(previous_raw)\n    need(enc(previous)==previous_raw and enc(value)==raw,'exact canonical formal input bytes')\n    expected=copy.deepcopy(previous)\n    selected=binding['production_replacements']\n    need(set(selected)=={'daily_phone_local.py','phone_local_tools.py','phone_observation_tools.py',\n                         'provider_codex_host.py','provider_phone_local.py'},'exact reviewed five-source family')\n    for row in expected['production_sources']:\n        if row['name']in selected:\n            name=row['name'];row.clear();row.update(name=name,**selected[name])\n    rows=[row for row in expected['provider_helpers']if row['name']=='collect_r10_readiness.py']\n    need(len(rows)==1 and len(readiness_raw)==binding['readiness']['bytes']\n         and sha(readiness_raw)==binding['readiness']['sha256'],'exact derived readiness source')\n    rows[0].clear();rows[0].update(name='collect_r10_readiness.py',**binding['readiness'])\n    need(enc(expected)==raw and len(raw)==binding['formal']['bytes']\n         and sha(raw)==binding['formal']['sha256'],'formal input changed beyond five production rows and readiness')\n    material_input_raw=read(binding['material_source_input'])\n    need(json.loads(material_input_raw)['changed_sources']==sorted(selected),\n         'shared source derivation must select these same five reviewed sources')\n    return sha(material_input_raw)\n"
FIVE={'daily_phone_local.py','phone_local_tools.py','phone_observation_tools.py',
      'provider_codex_host.py','provider_phone_local.py'}
MATERIAL_NAMES={'combination':'COMBINATION.json','source_seal':'SOURCE-SEAL.json',
 'configuration':'shared/local-config-r10-r1.json','service':'shared/PHONE-SERVICE-INPUTS-v150-r10-r1.json',
 'shared':'shared/SHARED-MATERIALS.json','source_inputs':'SOURCE-INPUTS.json','derivation':'DERIVATION.json'}
INPUT_SCHEMA='hepta.reviewed-release-source-chain-inputs.v1'
MAX_ONE=4*1024*1024
MAX_TOTAL=32*1024*1024
HASH=re.compile('[0-9a-f]{64}')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):
 need(type(raw)is bytes,'complete original bytes')
 return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def strict(raw):
 need(type(raw)is bytes and 0<len(raw)<=MAX_ONE,'bounded complete JSON')
 def pairs(items):
  d={}
  for k,v in items:need(k not in d,'duplicate JSON key');d[k]=v
  return d
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def enc(value,pretty=True):
 k=dict(sort_keys=True,ensure_ascii=False,allow_nan=False)
 k.update(dict(indent=2)if pretty else dict(separators=(',',':')))
 return(json.dumps(value,**k)+'\n').encode()
def same(a,b):return enc(a,False)==enc(b,False)
def styled(raw):
 v=strict(raw);styles=[p for p in (True,False)if enc(v,p)==raw]
 need(len(styles)==1,'exact known complete JSON serializer')
 return v,styles[0]
def path(value):
 need(type(value)is str and value and not any(c in value for c in '\0\r\n\t'),'plain absolute path')
 p=PurePosixPath(value)
 need(p.is_absolute()and str(p)==value and '..'not in p.parts,'canonical absolute path')
 return p
def descriptor(row,maximum=MAX_ONE):
 need(type(row)is dict and set(row)=={'path','bytes','sha256'},'exact source descriptor')
 path(row['path'])
 need(type(row['bytes'])is int and 0<=row['bytes']<=maximum and type(row['sha256'])is str
      and HASH.fullmatch(row['sha256']),'typed bounded source pin')
 return row
def located(name,raw):return dict(path=str(path(name)),**pin(raw))
class Originals:
 def __init__(self,callback):
  need(callable(callback),'original byte reader');self.callback=callback;self.rows={};self.total=0
 def read(self,row):
  descriptor(row);raw=self.callback(dict(row))
  need(type(raw)is bytes and pin(raw)=={k:row[k]for k in ('bytes','sha256')},'complete exact original source bytes')
  if row['path']in self.rows:need(self.rows[row['path']]==(row,raw),'one original path changed')
  else:
   need(len(self.rows)<256 and self.total+len(raw)<=MAX_TOTAL,'bounded source-original pool')
   self.rows[row['path']]=(dict(row),raw);self.total+=len(raw)
  return raw
 def recheck(self):
  for row,raw in self.rows.values():need(self.callback(dict(row))==raw,'source originals changed before return')
def assignment(raw,name):
 tree=ast.parse(raw);rows=[n for n in tree.body if isinstance(n,ast.Assign)
  and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id==name]
 need(len(rows)==1,'one reviewed source assignment: '+name);return rows[0]
def literal(raw,name):return ast.literal_eval(assignment(raw,name).value)
class Changes:
 def __init__(self,raw):self.original=raw;self.text=raw.decode();self.changes=[]
 def once(self,before,after):
  need(type(before)is str and type(after)is str and before!=after and self.text.count(before)==1,'one full source transformation anchor')
  self.text=self.text.replace(before,after,1)
  self.changes.append(dict(before=before,after=after))
 def rhs(self,name,value):
  raw=self.text.encode();node=assignment(raw,name);lines=raw.splitlines(keepends=True)
  start=sum(map(len,lines[:node.lineno-1]))+node.col_offset
  stop=sum(map(len,lines[:node.end_lineno-1]))+node.end_col_offset
  value_start=sum(map(len,lines[:node.value.lineno-1]))+node.value.col_offset
  old=raw[start:stop].decode();new=(raw[start:value_start]+repr(value).encode()).decode()
  self.once(old,new)
 def function(self,name,replacement):
  raw=self.text.encode();nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name==name]
  need(len(nodes)==1 and not nodes[0].decorator_list,'one reviewed undecorated function')
  n=nodes[0];lines=raw.splitlines(keepends=True);old=b''.join(lines[n.lineno-1:n.end_lineno]).decode()
  self.once(old,replacement)
 def finish(self):
  raw=self.text.encode();compile(raw,'<reviewed-source-candidate>','exec')
  inverse=self.text
  for change in reversed(self.changes):
   need(inverse.count(change['after'])==1,'one complete inverse anchor')
   inverse=inverse.replace(change['after'],change['before'],1)
  need(inverse.encode()==self.original,'entire parent source byte inverse')
  return raw,dict(parent=pin(self.original),candidate=pin(raw),changes=self.changes,complete_inverse=True)
def _material(value,pool,*,require_five=True):
 need(type(value)is dict and set(value)==set(MATERIAL_NAMES)|{'producer'},'complete source material descriptors')
 base=path(value['combination']['path']).parent
 for k,n in MATERIAL_NAMES.items():need(value[k]['path']==str(base/n),'exact material member namespace')
 old_raw={k:pool.read(r)for k,r in R4.items()}
 old={};styles={}
 for k,r in old_raw.items():old[k],styles[k]=styled(r)
 raw={k:pool.read(value[k])for k in MATERIAL_NAMES}
 current={k:strict(r)for k,r in raw.items()}
 old_rows=old['combination']['production_files'];new_rows=current['combination']['production_files']
 need(len(old_rows)==len(new_rows)==15,'complete fifteen source rows')
 def source_rows(rows,root):
  found={};bodies={}
  for row in rows:
   need(type(row)is dict and set(row)=={'path','bytes','sha256'},'exact production pin')
   name=PurePosixPath(row['path']).name
   need(row['path']=='production/'+name and name not in found,'unique production filename')
   item=dict(path=str(root/'shared/provider/source'/name),bytes=row['bytes'],sha256=row['sha256'])
   bodies[name]=pool.read(item);found[name]=item
  return found,bodies
 old_desc,old_src=source_rows(old_rows,path(R4['combination']['path']).parent)
 new_desc,new_src=source_rows(new_rows,base)
 need(set(old_src)==set(new_src),'unchanged complete source member family')
 changed=sorted(n for n in old_src if old_src[n]!=new_src[n])
 need({'daily_phone_local.py','phone_observation_tools.py'}<=set(changed)<=FIVE,'closed reviewed production change family')
 if require_five:need(set(changed)==FIVE,'final native source binding requires all five reviewed replacements')
 expected=old_src['daily_phone_local.py']
 for name in sorted(FIVE-{'daily_phone_local.py'}):
  oldsha=pin(old_src[name])['sha256'].encode();newsha=pin(new_src[name])['sha256'].encode()
  need(expected.count(oldsha)==1,'one daily dependency pin for reviewed source')
  expected=expected.replace(oldsha,newsha,1)
 need(expected==new_src['daily_phone_local.py'],'daily differs beyond its actual four dependency hashes')
 parents=literal(new_src['daily_phone_local.py'],'PARENTS')
 need(same(parents,{n:pin(b)['sha256']for n,b in new_src.items()if n!='daily_phone_local.py'}),'all fourteen actual daily dependencies')
 for name,body in new_src.items():compile(body,name,'exec')
 sin=current['source_inputs'];producer=pool.read(value['producer'])
 need(type(sin)is dict and set(sin)=={'schema','state','original_component','builder','original_request_sha256',
  'reviewed_replacements','changed_sources','phone_calls','actual_cleanup_closure_bound'},'exact material source input')
 need(sin['schema']=='hepta.reviewed-source-material-derivation-input.v1'
  and sin['state']=='HOST_SOURCE_ONLY_NOT_RUNTIME_ADOPTION' and same(sin['original_component'],R4['combination'])
  and same(sin['builder'],value['producer'])and sin['changed_sources']==changed
  and type(sin['phone_calls'])is int and sin['phone_calls']==0 and sin['actual_cleanup_closure_bound']is False
  and type(sin['original_request_sha256'])is str and HASH.fullmatch(sin['original_request_sha256']),
  'material derivation source binding')
 need(type(sin['reviewed_replacements'])is dict and set(sin['reviewed_replacements'])==set(changed),'all reviewed replacement originals')
 for name,row in sin['reviewed_replacements'].items():need(pool.read(row)==new_src[name],'material copy differs from reviewed replacement original')
 def rows(rows,prefix):
  need(len(rows)==15 and {r['path']for r in rows}=={prefix+n for n in old_src},'exact source row membership')
  return[dict(path=r['path'],**pin(new_src[PurePosixPath(r['path']).name]))for r in rows]
 expected_service=copy.deepcopy(old['service'])
 expected_service['provider_sources']=rows(expected_service['provider_sources'],'provider-r10-r1/source/')
 expected_service['parent_service_inputs_sha256']=pin(old_raw['service'])['sha256']
 need(enc(expected_service,styles['service'])==raw['service'],'whole new service derives only five sources and immediate parent')
 expected_config=copy.deepcopy(old['configuration']);expected_config['service_manifest_sha256']=pin(raw['service'])['sha256']
 need(enc(expected_config,styles['configuration'])==raw['configuration'],'whole new configuration derives only actual service')
 expected_seal=copy.deepcopy(old['source_seal'])
 expected_seal.update(configuration=pin(raw['configuration']),phone_service_inputs_sha256=pin(raw['service'])['sha256'],
  production_files=rows(expected_seal['production_files'],'source/'))
 need(enc(expected_seal,styles['source_seal'])==raw['source_seal'],'whole component source seal inverse')
 expected_combo=copy.deepcopy(old['combination'])
 expected_combo.update(configuration=pin(raw['configuration']),service_inputs=pin(raw['service']),source_seal=pin(raw['source_seal']),
  production_files=rows(expected_combo['production_files'],'production/'))
 need(enc(expected_combo,styles['combination'])==raw['combination'],'whole component combination inverse')
 expected_shared=copy.deepcopy(old['shared'])
 material_files={'local-config-r10-r1.json':raw['configuration'],'PHONE-SERVICE-INPUTS-v150-r10-r1.json':raw['service']}
 material_files.update({'provider/source/'+n:b for n,b in new_src.items()})
 need(len(expected_shared['files'])==17 and {r['path']for r in expected_shared['files']}==set(material_files),'closed seventeen shared originals')
 expected_shared['files']=[dict(path=r['path'],**pin(material_files[r['path']]))for r in expected_shared['files']]
 expected_shared.update(parent_configuration_sha256=pin(old_raw['configuration'])['sha256'],
  parent_service_inputs_sha256=pin(old_raw['service'])['sha256'],source_input_sha256=pin(raw['source_inputs'])['sha256'])
 need(enc(expected_shared,styles['shared'])==raw['shared'],'whole shared manifest inverse')
 d=current['derivation']
 need(d.get('schema')=='hepta.reviewed-source-material-derivation.v1'and d.get('state')=='DERIVED_SHARED_SOURCE_MATERIAL_ONLY'
  and d.get('changed_sources')==changed and same(d.get('builder'),pin(producer)),'source derivation record matches selected material')
 for k in ('actual_BUILD','actual_READY','actual_install','actual_cleanup_closure_bound','runtime_freeze','root_plan_generated','native_history_rebased'):
  need(d.get(k)is False,'material source record cannot grant actual execution: '+k)
 for k,n in (('source_count',15),('daily_dependency_count',14),('shared_member_count',17),('phone_calls',0),('new_nonces',0),('fixed19_credit',0)):
  need(type(d.get(k))is int and d[k]==n,'typed source derivation count: '+k)
 for key,target in (('combination','combination'),('source_seal','source_seal'),('configuration','configuration'),('service_inputs','service'),('shared_manifest','shared')):
  need(same(d[key],pin(raw[target])),'actual material summary pin')
 expected_files={MATERIAL_NAMES[k]:b for k,b in raw.items()if k!='derivation'}
 expected_files.update({'shared/'+n:b for n,b in material_files.items()})
 expected_files.update({'reference/'+MATERIAL_NAMES[k].replace('/','__'):b for k,b in old_raw.items()})
 need(type(d.get('files'))is list and same(d['files'],[dict(path=n,**pin(b))for n,b in sorted(expected_files.items())]),'complete material output manifest')
 return dict(root=str(base),descriptors=value,raw=raw,values=current,sources=new_src,source_descriptors=new_desc,
  changed=changed,old_raw=old_raw,old_sources=old_src,old_source_descriptors=old_desc)
def _consumer(value,material,pool):
 need(type(value)is dict and set(value)=={'source','runtime_package'},'exact consumer and runtime descriptors')
 raw=pool.read(value['source']);manifest_raw=pool.read(value['runtime_package']);manifest=strict(manifest_raw)
 expected={'PACKAGE_SHA':pin(manifest_raw)['sha256'],'CURRENT_COMBINATION_SHA':pin(material['raw']['combination'])['sha256']}
 for name,v in expected.items():need(literal(raw,name)==v,'consumer exact runtime/material source pin: '+name)
 count=literal(raw,'PACKAGE_FILE_COUNT');chain=literal(raw,'CURRENT_COMPONENT_CHAIN_LENGTH')
 budget=literal(raw,'COMPONENT_ROLE_BUDGET')
 need(type(count)is int and 1<=count<=128 and type(manifest.get('files'))is list and count==len(manifest['files'])
  and len({r['path']for r in manifest['files']})==count,'actual complete runtime member count')
 need(type(chain)is int and 2<chain<=64,'actual reviewed component history chain length')
 need(type(budget)is int and 3<=budget<=60 and budget==3*(chain+2),
  'actual reviewed component role budget includes two fixed non-native sidebranches')
 need(manifest.get('schema')=='hepta.native-guard.adapter-package.v1'
  and manifest.get('state')=='HOST_REVIEWED_NOT_PHONE_QUALIFIED','runtime source package cannot grant phone qualification')
 retained=literal(raw,'R8_RETAINED_PREACCEPT_BINDING')
 need(retained==manifest.get('retained_preaccept_binding')
  and retained['native_case_credit']==0 and retained['component_qualified']is False
  and count==38 and chain==12 and budget==42
  and manifest.get('current_complete_inventory_root_count')==49
  and manifest.get('maximum_complete_inventory_roots_after_two_final_NEG_cases')==55,
  'R9 source consumer preserves native42 and the same separate R7 two generations')
 retained_staged=literal(raw,'R9_RETAINED_FAILED_STAGED_BINDING')
 need(retained_staged==manifest.get('retained_failed_staged_binding')
  and retained_staged['retained_preaccept_binding']==retained
  and retained_staged['component_role_identities']=={}
  and retained_staged['native_case_credit']==0 and retained_staged['component_qualified']is False
  and retained_staged['native_terminal']is None and retained_staged['global_unknown_effect_count']is None
  and retained_staged['standalone_execution_authorized']is False,
  'R9 source consumer preserves the exact zero-role failed R8 proof and historical unknowns')
 retained_transport=literal(raw,'R10_RETAINED_FAILED_TRANSPORT_BINDING')
 need(retained_transport==manifest.get('retained_failed_transport_binding')
  and retained_transport['retained_preaccept_binding']==retained
  and retained_transport['retained_failed_staged_binding']==retained_staged
  and retained_transport['private_roots']==[] and retained_transport['component_role_identities']=={}
  and retained_transport['first_launch_receipt_gap']is True and retained_transport['original_start_reused']is True
  and retained_transport['native_case_credit']==0 and retained_transport['native_terminal']is None
  and retained_transport['global_unknown_effect_count']is None and retained_transport['baseline_device_shell_wire_dispatched']is None
  and retained_transport['remote_cleanup_proven']is False and retained_transport['standalone_execution_authorized']is False,
  'complete zero-root R9 failure-only binding preserves all original unknowns')
 need(len(raw)<=262144,'unchanged installed consumer source byte ceiling')
 compile(raw,'<reviewed-release-boundaries>','exec')
 return dict(raw=raw,runtime_sha256=expected['PACKAGE_SHA'],chain_length=chain,package_file_count=count,role_budget=budget,retained_preaccept_binding=retained,retained_failed_staged_binding=retained_staged,retained_failed_transport_binding=retained_transport,
  retained_failed_transport_runtime_adapter=manifest['retained_failed_transport_runtime_adapter'])
def _formal(parent_raw,material,readiness):
 previous,pretty=styled(parent_raw);need(pretty,'pretty formal source serializer')
 current=copy.deepcopy(previous)
 need(len(current['production_sources'])==15 and {r['name']for r in current['production_sources']}==set(material['sources']),'formal complete fifteen sources')
 for row in current['production_sources']:
  name=row['name']
  need({k:row[k]for k in ('bytes','sha256')}==pin(material['old_sources'][name]),'formal original production byte pin')
  if name in FIVE:
   row.clear();row.update(name=name,**material['source_descriptors'][name])
 rows=[r for r in current['provider_helpers']if r['name']=='collect_r10_readiness.py'];need(len(rows)==1,'one formal readiness row')
 rows[0].clear();rows[0].update(name='collect_r10_readiness.py',**readiness)
 reverse=copy.deepcopy(current);reverse['production_sources']=previous['production_sources'];reverse['provider_helpers']=previous['provider_helpers']
 need(enc(reverse)==parent_raw,'entire formal source inverse')
 return enc(current)
def _activation_fragment(raw, consumer):
 c=Changes(raw)
 c.once("reviewed_component_package_sha256 = '72d6dcb4c20547549debad6ef55001aa5c8d115574ac222312b158f9722e2515'",
  'reviewed_component_package_sha256 = '+repr(consumer['runtime_sha256']))
 c.once('3 <= len(roles) <= (11 * 3 + 2 * 3)',
  '3 <= len(roles) <= '+repr(consumer['role_budget']))
 c.once("'component_package_sha256', 'role_generations'}",
  "'component_package_sha256', 'role_generations', 'retained_preaccept_binding', 'retained_preaccept_role_generations', 'retained_failed_staged_binding', 'retained_failed_staged_role_generations', 'retained_failed_transport_binding', 'retained_failed_transport_role_generations'}")
 c.once("value['schema'] == 'hepta.module-r10-r1.closed-component-activation.v1'",
  "value['schema'] == 'hepta.module-r10-r1.closed-component-activation.v4'")
 anchor="    same_boot = epoch['current_boot_id'] == epoch['original_boot_id']"
 new="""    native_role_generation_count = len(roles)
    retained_binding = %r
    retained = value['retained_preaccept_role_generations']
    require(value['retained_preaccept_binding'] == retained_binding
            and retained_binding['native_case_credit'] == 0
            and retained_binding['component_qualified'] is False
            and isinstance(retained, list) and len(retained) == 2
            and retained == [retained_binding['component_role_identities'][name]
                             for name in sorted(retained_binding['component_role_identities'])]
            and all(isinstance(row, list) and len(row) == 4
                    and all(type(n) is int and n > 1 for n in row)
                    and row[:3] == [row[0]] * 3 for row in retained),
            'exact_separately_retained_preaccept_generations')
    retained_staged_binding = %r
    require(value['retained_failed_staged_binding'] == retained_staged_binding
            and value['retained_failed_staged_role_generations'] == []
            and retained_staged_binding['retained_preaccept_binding'] == retained_binding
            and retained_staged_binding['component_role_identities'] == {}
            and retained_staged_binding['native_case_credit'] == 0
            and retained_staged_binding['native_terminal'] is None
            and retained_staged_binding['global_unknown_effect_count'] is None
            and retained_staged_binding['component_qualified'] is False
            and retained_staged_binding['standalone_execution_authorized'] is False,
            'exact_retained_staged_originals_have_zero_role_generations_and_no_native_credit')
    retained_transport_binding = %r
    require(value['retained_failed_transport_binding'] == retained_transport_binding
            and value['retained_failed_transport_role_generations'] == []
            and retained_transport_binding['retained_failed_staged_binding'] == retained_staged_binding
            and retained_transport_binding['private_roots'] == []
            and retained_transport_binding['component_role_identities'] == {}
            and retained_transport_binding['first_launch_receipt_gap'] is True
            and retained_transport_binding['original_start_reused'] is True
            and retained_transport_binding['native_case_credit'] == 0
            and retained_transport_binding['native_terminal'] is None
            and retained_transport_binding['global_unknown_effect_count'] is None
            and retained_transport_binding['baseline_device_shell_wire_dispatched'] is None
            and retained_transport_binding['remote_cleanup_proven'] is False
            and retained_transport_binding['standalone_execution_authorized'] is False,
            'exact_retained_transport_originals_preserve_unknowns_without_new_role_generations')
    roles = roles + retained
    require(len(roles) <= 44 and len({tuple(row) for row in roles}) == len(roles),
            'native_and_separately_retained_generations_must_be_distinct')
""" % (consumer['retained_preaccept_binding'], consumer['retained_failed_staged_binding'], consumer['retained_failed_transport_binding'])
 c.once(anchor,new+anchor)
 c.once("        'role_generation_count': len(roles), 'numeric_generation_filter_applied': same_boot,",
  "        'role_generation_count': len(roles), 'native_role_generation_count': native_role_generation_count,\n"
  "        'retained_preaccept_generation_count': len(retained), 'retained_preaccept_native_case_credit': 0,\n"
  "        'retained_failed_staged_generation_count': 0, 'retained_failed_staged_native_case_credit': 0,\n"
  "        'retained_failed_transport_generation_count': 0, 'retained_failed_transport_native_case_credit': 0,\n"
  "        'numeric_generation_filter_applied': same_boot,")
 return c.finish()

def _builder(raw,binding,consumer_sha,readiness_sha,fragment_sha):
 c=Changes(raw)
 c.rhs('BOUNDARY_CONSUMER_SHA256',consumer_sha);c.rhs('READINESS_SOURCE_SHA256',readiness_sha)
 c.rhs('COMPONENT_FRAGMENT_SHA256',fragment_sha)
 c.rhs('OWNER_WIRING_CONFIGURATION_SHA256',binding['configuration']['sha256'])
 c.function('verify_current_formal_parent',FORMAL_VERIFIER)
 c.once('def verify_current_formal_parent(', 'REVIEWED_SOURCE_BINDING = '+repr(binding)+'\n\ndef verify_current_formal_parent(')
 c.once(OLD_BLOCKS['daily'],"    need(sha(source['daily_phone_local.py'])==REVIEWED_SOURCE_BINDING['production_replacements']['daily_phone_local.py']['sha256'],\n         'derived daily integration bytes differ from reviewed fifteen-source candidate')")
 c.once(OLD_BLOCKS['service_parent'],"    service['parent_service_inputs_sha256']=REVIEWED_SOURCE_BINDING['material_parent_service_sha256']")
 c.once(OLD_BLOCKS['final_material'],"    need(dict(bytes=len(config_raw),sha256=sha(config_raw))==REVIEWED_SOURCE_BINDING['configuration']\n         and dict(bytes=len(service_raw),sha256=sha(service_raw))==REVIEWED_SOURCE_BINDING['service'],\n         'final release must retain the actual reviewed shared configuration and service bytes')")
 c.once(OLD_BLOCKS['shared_parents'],"        source_input_sha256=sha(input_raw),parent_configuration_sha256=REVIEWED_SOURCE_BINDING['material_parent_configuration_sha256'],\n        parent_service_inputs_sha256=REVIEWED_SOURCE_BINDING['material_parent_service_sha256'],files=shared_files,")
 c.once("schema='hepta.module-r10-r1.closed-component-activation.v1',retirement_boot_id=BOOT,",
  "schema='hepta.module-r10-r1.closed-component-activation.v4',retirement_boot_id=BOOT,")
 c.once("role_generations=state['component_roles']))",
  "role_generations=state['component_roles'],\n"
  "        retained_preaccept_binding=state['retained_preaccept_binding'],\n"
  "        retained_preaccept_role_generations=state['retained_preaccept_roles'],\n"
  "        retained_failed_staged_binding=state['retained_failed_staged_binding'],\n"
  "        retained_failed_staged_role_generations=state['retained_failed_staged_roles'],\n"
  "        retained_failed_transport_binding=state['retained_failed_transport_binding'],\n"
  "        retained_failed_transport_role_generations=state['retained_failed_transport_roles']))")
 return c.finish()
def _owner(parent_service,provenance_raw,configuration):
 provenance,pretty=styled(provenance_raw);need(pretty,'original owner provenance serializer')
 old=R4['configuration']['sha256'];new=configuration['sha256']
 need(parent_service.count(old.encode())==1 and old!=new,'one original wired configuration pin')
 service=parent_service.replace(old.encode(),new.encode(),1)
 need(service.replace(new.encode(),old.encode(),1)==parent_service,'owner service complete inverse')
 previous=copy.deepcopy(provenance);provenance['wired_service']=pin(service);provenance['wired_configuration_sha256']=new
 reverse=copy.deepcopy(provenance)
 for key in ('wired_service','wired_configuration_sha256'):reverse[key]=previous[key]
 need(enc(reverse)==provenance_raw,'owner provenance complete inverse')
 return service,enc(provenance)
def _release_reader(raw,fixed,runtime_sha,chain_length,owner_files,owner_provenance):
 c=Changes(raw);c.rhs('FIXED',fixed);c.rhs('RUNTIME',runtime_sha)
 c.rhs('OWNER_MODULE_FILES',owner_files);c.rhs('OWNER_MODULE_PROVENANCE',owner_provenance)
 c.once("SCHEMA='hepta.r10.actual-final-release-original-inputs.v1'","CURRENT_COMPONENT_CHAIN_LENGTH = "+repr(chain_length)+"\nSCHEMA='hepta.r10.actual-final-release-original-inputs.v1'")
 c.once("and len(boundary['chain'])==11","and len(boundary['chain'])==CURRENT_COMPONENT_CHAIN_LENGTH")
 # Keep original process/argv/terminal gates; reject Python numeric equality aliases.
 c.once("and status['log_truncated']=={'stderr':False,'stdout':False},",
  "and type(status['log_truncated'])is dict and set(status['log_truncated'])=={'stderr','stdout'}\n          and all(status['log_truncated'][n]is False for n in ('stderr','stdout')),")
 c.once("need(row['offset']==0 and row['eof'] is True and row['next_offset']==row['size']==len(b)\n             and row['text'].encode()==b and status['log_bytes'][name]=={'seen':len(b),'stored':len(b)}",
  "need(type(row['offset'])is int and row['offset']==0 and row['eof'] is True\n              and type(row['next_offset'])is int and type(row['size'])is int and row['next_offset']==row['size']==len(b)\n              and row['text'].encode()==b and type(status['log_bytes'][name])is dict\n              and set(status['log_bytes'][name])=={'seen','stored'}\n              and all(type(status['log_bytes'][name][k])is int and status['log_bytes'][name][k]==len(b)for k in ('seen','stored'))")
 c.once("strict(outputs['stdout'])==build","canonical(strict(outputs['stdout']))==canonical(build)")
 return c.finish()
def _derive(value,pool):
 need(type(value)is dict and set(value)=={'schema','material','consumer','output_root'}
  and value['schema']==INPUT_SCHEMA,'exact source-chain input')
 output=path(value['output_root']);material=_material(value['material'],pool);consumer=_consumer(value['consumer'],material,pool)
 originals={k:pool.read(row)for k,row in REFS.items()}
 files={};changes={}
 def output_desc(name,raw):return located(str(output/name),raw)
 def emit(name,pair):
  raw,change=pair;files[name]=raw;changes[name]=change;return output_desc(name,raw)
 c=Changes(originals['readiness']);c.rhs('BOUNDARY_CONSUMER_SHA256',pin(consumer['raw'])['sha256'])
 readiness=emit('source/collect_r10_readiness.py',c.finish())
 c=Changes(originals['installer']);c.rhs('BOUNDARY_CONSUMER_SHA256',pin(consumer['raw'])['sha256'])
 installer=emit('source/install_phone_release_r10.py',c.finish())
 formal_raw=_formal(originals['formal'],material,readiness);files['contracts/FINAL-INTEGRATION-INPUTS.json']=formal_raw
 formal=output_desc('contracts/FINAL-INTEGRATION-INPUTS.json',formal_raw)
 binding=dict(formal_parent=REFS['formal'],formal=formal,readiness=readiness,
  production_replacements={n:material['source_descriptors'][n]for n in sorted(FIVE)},
  configuration=pin(material['raw']['configuration']),service=pin(material['raw']['service']),
  material_parent_configuration_sha256=R4['configuration']['sha256'],material_parent_service_sha256=R4['service']['sha256'],
  material_source_input=material['descriptors']['source_inputs'])
 fragment=emit('source/component_activation_gate.fragment.py',_activation_fragment(originals['component_fragment'],consumer))
 builder=emit('source/build_release_r10.py',_builder(originals['builder'],binding,pin(consumer['raw'])['sha256'],readiness['sha256'],fragment['sha256']))
 files['source/release_boundaries.py']=consumer['raw']
 # These exact module bytes are only source previews; no archive or BUILD-RESULT exists.
 service,provenance_raw=_owner(originals['owner_service'],originals['owner_provenance'],binding['configuration'])
 files['preview-module/service.sh']=service;files['preview-module/RESIDENT-OWNER-FINALIZER.json']=provenance_raw
 old_reader=types.ModuleType('original_release_source');exec(compile(originals['release_reader'],'<pinned-original-release-reader>','exec'),old_reader.__dict__)
 fixed=copy.deepcopy(old_reader.FIXED)
 for k,row in (('BUILDER',builder),('INSTALLER',installer),('FORMAL',formal),('COMBINATION',material['descriptors']['combination']),
  ('SHARED',material['descriptors']['shared']),('READINESS',readiness),('CONSUMER',output_desc('source/release_boundaries.py',consumer['raw']))):fixed[k]=row
 owner_files=copy.deepcopy(old_reader.OWNER_MODULE_FILES)
 owner_files['service.sh']=pin(service);owner_files['RESIDENT-OWNER-FINALIZER.json']=pin(provenance_raw)
 reader=emit('source/verify_final_release_inputs.py',_release_reader(originals['release_reader'],fixed,consumer['runtime_sha256'],
  consumer['chain_length'],owner_files,strict(provenance_raw)))
 c=Changes(originals['exact8'])
 for k,v in (('RELEASE_READER',reader),('RUNTIME',consumer['runtime_sha256']),
  ('COMBINATION',pin(material['raw']['combination'])['sha256']),('READY_PIN',pin(files['source/collect_r10_readiness.py']))):c.rhs(k,v)
 exact8=emit('source/verify_resident_output_bindings.py',c.finish())
 c=Changes(originals['protocol'])
 c.once("ACTOR_PIN = {'bytes': 5652, 'sha256': '179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'}","ACTOR_PIN = {'bytes': 7578, 'sha256': 'c74aec49cd4fa84238194242653d5d3798b7f5cdc4659f90bcb50ec0c424902f'}")
 c.once("         and PurePosixPath(P4) in path(plan['actor']['path']).parents,\n         'exact retained original actor under the established P4 project')","         and path(plan['actor']['path']) == PurePosixPath('/home/alex/codex-razr60-listener-generation-20261107-01/phone_once.py'),\n         'exact retained current listener actor at its independently published path')")
 need(pin(c.text.encode())=={'bytes': 12854, 'sha256': '2ca90ff6e8d7f51ca10ac680822ae6b80c5a9a7e0569dd49a1884cf3a95e128b'},'complete exact current-listener install protocol before installer and READY binding')
 c.rhs('INSTALLER_PIN',pin(files['source/install_phone_release_r10.py']));c.rhs('READY_PIN',pin(files['source/collect_r10_readiness.py']))
 protocol=emit('source/install_ready_execution_protocol.py',c.finish())
 c=Changes(originals['install_reader']);c.rhs('SOURCES',dict(protocol=protocol,release=reader,exact8=exact8))
 c.once("             'stage observation must preserve the actual current component boundary')",
  "             'stage observation must preserve the actual current component boundary')\n"
  "        need(observed.get('retained_preaccept_binding') == boundary['retained_preaccept_binding']\n"
  "             and observed.get('retained_preaccept_phone_originals') == boundary['retained_preaccept_phone_originals']\n"
  "             and observed.get('retained_preaccept_role_generations') == boundary['retained_preaccept_roles']\n"
  "             and type(observed.get('retained_preaccept_native_case_credit')) is int\n"
  "             and observed['retained_preaccept_native_case_credit'] == 0,\n"
  "             'both actual preservation bookends retain the same separate failed R7 proof and roles')\n"
  "        need(observed.get('retained_failed_staged_binding') == boundary['retained_failed_staged_binding']\n"
  "             and observed.get('retained_failed_staged_phone_originals') == boundary['retained_failed_staged_phone_originals']\n"
  "             and observed.get('retained_failed_staged_role_generations') == boundary['retained_failed_staged_roles'] == []\n"
  "             and type(observed.get('retained_failed_staged_native_case_credit')) is int\n"
  "             and observed['retained_failed_staged_native_case_credit'] == 0,\n"
  "             'both actual preservation bookends retain the same complete zero-role failed R8 proof')\n"
  "        need(observed.get('retained_failed_transport_binding') == boundary['retained_failed_transport_binding']\n"
  "             and observed.get('retained_failed_transport_phone_originals') == boundary['retained_failed_transport_phone_originals']\n"
  "             and observed.get('retained_failed_transport_runtime_adapter') == boundary['retained_failed_transport_runtime_adapter']\n"
  "             and observed.get('retained_failed_transport_role_generations') == boundary['retained_failed_transport_roles'] == []\n"
  "             and type(observed.get('retained_failed_transport_native_case_credit')) is int\n"
  "             and observed['retained_failed_transport_native_case_credit'] == 0,\n"
  "             'both preservation bookends retain exact R9 proof and separate runtime adapter')")
 install=emit('source/verify_install_start_ready_UNBOUND.py',c.finish())
 c=Changes(originals['retention']);c.rhs('INSTALL_READER',install)
 files['source/install_retention_protocol_UNBOUND.py']=originals['retention_protocol']
 c.rhs('PRODUCER',output_desc('source/install_retention_protocol_UNBOUND.py',originals['retention_protocol']))
 emit('source/verify_install_retention_UNBOUND.py',c.finish())
 for raw,names in ((files['source/verify_install_start_ready_UNBOUND.py'],('FROZEN_INPUTS','FROZEN_EXECUTION_PLAN')),
  (files['source/verify_install_retention_UNBOUND.py'],('FROZEN_PHASE_AUTHORITY','FROZEN_RETENTION_INPUTS')),
  (originals['retention_protocol'],('FROZEN_SCOPE',))):
  need(all(literal(raw,n)is None for n in names),'all actual execution inputs stay unbound')
 need(all('BUILD-RESULT'not in n and not n.endswith('.tar.gz')for n in files),'source candidates cannot become BUILD artifacts')
 return dict(files=files,changes=changes,source_binding=binding,consumer_runtime=dict(runtime_sha256=consumer['runtime_sha256'],
  package_file_count=consumer['package_file_count'],chain_length=consumer['chain_length'],role_budget=consumer['role_budget'],
  retained_preaccept_binding=consumer['retained_preaccept_binding'],retained_preaccept_role_count=2,
  retained_failed_staged_binding=consumer['retained_failed_staged_binding'],retained_failed_staged_role_count=0,
  retained_failed_transport_binding=consumer['retained_failed_transport_binding'],retained_failed_transport_role_count=0,
  retained_failed_transport_runtime_adapter=consumer['retained_failed_transport_runtime_adapter']),
  report=dict(schema='hepta.reviewed-release-source-chain-construction.v1',state='SOURCE_CANDIDATES_ONLY_ACTUAL_EXECUTION_UNBOUND',
   changed_production_sources=material['changed'],source_count=15,shared_member_count=17,complete_source_inverses=True,
   actual_execution_slots_unbound=True,root_counts_inferred=False,BUILD=False,install=False,READY=False,phone_calls=0,
   generated_acceptance_nonces=0,fixed19_credit=0))
def derive_reviewed_source_chain(inputs_raw,*,read_pinned):
 need(FROZEN_INPUTS is not None,'UNBOUND_REVIEWED_SOURCE_CHAIN_INPUTS_NO_IO')
 descriptor(FROZEN_INPUTS)
 need(pin(inputs_raw)=={k:FROZEN_INPUTS[k]for k in ('bytes','sha256')},'exact reviewed source-chain input')
 pool=Originals(read_pinned)
 need(pool.read(FROZEN_INPUTS)==inputs_raw,'original reviewed source input')
 result=_derive(strict(inputs_raw),pool);pool.recheck()
 result['report'].update(original_source_count=len(pool.rows),original_source_bytes=pool.total,all_originals_bookended=True)
 return result
if __name__=='__main__':
 raise SystemExit('UNBOUND source-construction API only; no BUILD, dispatch, installation or READY')
