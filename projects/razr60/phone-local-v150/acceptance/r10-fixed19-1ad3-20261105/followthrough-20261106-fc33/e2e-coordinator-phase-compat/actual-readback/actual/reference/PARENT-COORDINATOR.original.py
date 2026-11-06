#!/usr/bin/env python3
"""One actual E2E run from a pinned, already-prepared context.

The unbound template has no execution path. After a reviewed operator manifest
is bound, this runs the existing six actual child phases once. The historical
capture phase already exports its archive; export is never invoked a second
time. Whole business credit requires the original collector and independent
closure. A failure preserves every original and never creates another nonce.
"""
import argparse,base64,hashlib,json,os,re,stat,sys,types
from pathlib import Path
sys.dont_write_bytecode=True
B=Path("/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1")
OPERATOR_MANIFEST_PIN = {'bytes': 5011, 'sha256': 'f078a6ccaac60874a37ef269aed4ca168c599eaf1e5b184067b6e47533fbab3f'}
CAPTURE_PIN = {'bytes':37720,'sha256':'9d273d66adc09c670ae09aa06fae699d2d1de9e1981afd3980bec7e4eda6cb29'}
SHARED_PIN = {'bytes':3519,'sha256':'cc7eb624333216e510b540c3af8277e948aa689a108950fa78e8d01c2177e5b1'}
CASES={'visual':'E2E-01','unicode':'E2E-02','calculator':'E2E-03','settings':'E2E-04'}
PHASES=(('register',240),('sender_preview',30),('sender_execute',650),
        ('capture_export',500),('collect',135),('close',135))
OPERATORS={'root_acceptance_r10.py','registration_phone_r10.py','capture_originals_r10.py',
           'read_archive_chunk_r10.py','export_originals_r10.py','close_original_r10.py'}
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
# This child program executes the exact raw source bytes. It never loads a local
# pyc or an ambient local root_acceptance module. Descendants inherit an unused
# bytecode prefix and no PYTHONPATH; all original business bodies stay unchanged.
PHASE_PROGRAM=r'''
import hashlib,json,os,stat,sys,types
from pathlib import Path
def need(v,m):
 if not v:raise ValueError(m)
def read(row):
 p=Path(row['path']);need(p.is_absolute() and p.resolve(strict=True)==p,'canonical phase input')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);ks=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns');m=[getattr(a,k)for k in ks]
  need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==row['bytes']<=1048576,'bounded original phase input')
  with os.fdopen(fd,'rb',closefd=False)as f:b=f.read(a.st_size+1)
  need(len(b)==a.st_size and hashlib.sha256(b).hexdigest()==row['sha256']
   and m==[getattr(os.fstat(fd),k)for k in ks]==[getattr(p.lstat(),k)for k in ks],'phase original full9/hash')
  return b
 finally:os.close(fd)
raw=sys.stdin.buffer.read(65537);need(0<len(raw)<=65536,'bounded original phase stdin')
p=json.loads(raw);need(set(p)=={'phase','operator_manifest','context','unused_pycache','report_sha256'},'phase payload')
m=json.loads(read(p['operator_manifest']));home=Path(p['operator_manifest']['path']).parent
need(m['schema']=='hepta.root-acceptance-sources.v150.r10.1','exact operator family')
names={'root_acceptance_r10.py','registration_phone_r10.py','capture_originals_r10.py',
 'read_archive_chunk_r10.py','export_originals_r10.py','close_original_r10.py'}
need(len(m['files'])==6 and {x['path']for x in m['files']}==names,'six exact operator sources')
need(sorted(x.name for x in home.iterdir())==sorted(names|{'SOURCE-MANIFEST.json'}),'closed operator directory')
sources={x['path']:read(dict(x,path=str(home/x['path'])))for x in m['files']}
read(p['context'])
prefix=Path(p['unused_pycache'])
need(prefix.is_absolute() and prefix.parent.resolve(strict=True)==prefix.parent and not prefix.exists() and not prefix.is_symlink(),'unused bytecode prefix')
os.environ.pop('PYTHONPATH',None);os.environ['PYTHONPYCACHEPREFIX']=str(prefix);os.environ['PYTHONDONTWRITEBYTECODE']='1'
sys.pycache_prefix=str(prefix);sys.dont_write_bytecode=True
core=types.ModuleType('root_acceptance_r10');core.__file__=str(home/'root_acceptance_r10.py')
sys.modules['root_acceptance_r10']=core;exec(compile(sources['root_acceptance_r10.py'],core.__file__,'exec'),core.__dict__)
phase=p['phase'];context=['--context',p['context']['path'],'--context-sha256',p['context']['sha256']]
if phase in ('register','sender_preview','sender_execute'):
 module=core;argv=[phase.replace('_','-')]+context
 if phase=='register':argv+=['--execute-register-once']
 if phase=='sender_execute':argv+=['--execute-send-once']
elif phase in ('capture_export','collect'):
 name='export_originals_r10.py';module=types.ModuleType('reviewed_e2e_export');module.__file__=str(home/name)
 exec(compile(sources[name],module.__file__,'exec'),module.__dict__)
 argv=['capture' if phase=='capture_export' else 'collect']+context
 if phase=='capture_export':argv+=['--execute-read-once']
elif phase=='close':
 need(type(p['report_sha256'])is str and len(p['report_sha256'])==64,'actual report digest for close')
 name='close_original_r10.py';module=types.ModuleType('reviewed_e2e_close');module.__file__=str(home/name)
 exec(compile(sources[name],module.__file__,'exec'),module.__dict__)
 argv=context+['--report-sha256',p['report_sha256'],'--execute-close-once']
else:raise ValueError('unknown fixed E2E phase')
sys.argv=[module.__file__]+argv
raise SystemExit(module.main())
'''
def need(v,m):
 if not v:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def descriptor(p,b):return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
def encoded(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode()
def strict(raw):
 def pairs(xs):
  v={}
  for k,x in xs:need(k not in v,'duplicate JSON field');v[k]=x
  return v
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def read(path,maximum=1048576):
 path=Path(path);need(path.is_absolute() and path.resolve(strict=True)==path,'canonical original')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);before=[getattr(a,k)for k in META]
  need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=maximum,'bounded one-link original')
  with os.fdopen(fd,'rb',closefd=False)as f:raw=f.read(maximum+1)
  need(len(raw)==a.st_size and before==[getattr(os.fstat(fd),k)for k in META]==[getattr(path.lstat(),k)for k in META],'original full9 changed')
  return raw
 finally:os.close(fd)
def pinned(row):
 need(type(row)is dict and set(row)=={'path','bytes','sha256'} and type(row['bytes'])is int
  and 0<row['bytes']<=1048576 and re.fullmatch('[0-9a-f]{64}',row['sha256']),'explicit original descriptor')
 raw=read(row['path']);need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'original pin differs');return raw
def module(raw,path,name):
 value=types.ModuleType(name);value.__file__=str(path)
 exec(compile(raw,str(path),'exec'),value.__dict__);return value
def put(path,value):
 raw=encoded(value);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 need(read(path,8*1024*1024)==raw,'new result readback')
 return descriptor(path,raw)
def validate_plan(raw,plan_path):
 need(OPERATOR_MANIFEST_PIN is not None,'UNBOUND_E2E_OPERATOR_MANIFEST_NO_EXECUTION')
 p=strict(raw)
 need(type(p)is dict and set(p)=={'schema','case_id','coordinator_sha256','operator_manifest',
  'capture_source','shared_materials','context','output'},'exact E2E coordinator plan')
 need(p['schema']=='hepta.fixed19.e2e.coordinator-plan.v1' and p['case_id']in CASES.values(),'fixed E2E case')
 own=read(Path(__file__))
 need(p['coordinator_sha256']==sha(own),'actual coordinator source')
 for key,expected in (('operator_manifest',OPERATOR_MANIFEST_PIN),('capture_source',CAPTURE_PIN),('shared_materials',SHARED_PIN)):
  need({k:p[key][k]for k in ('bytes','sha256')}==expected,'only exact reviewed '+key)
 op_raw=pinned(p['operator_manifest']);op=strict(op_raw);opdir=Path(p['operator_manifest']['path']).parent
 need(op['schema']=='hepta.root-acceptance-sources.v150.r10.1' and len(op['files'])==6
  and {x['path']for x in op['files']}==OPERATORS,'six exact operator sources')
 need(B in opdir.parents and sorted(x.name for x in opdir.iterdir())==sorted(OPERATORS|{'SOURCE-MANIFEST.json'}),'closed owned operator source directory')
 rows={r['path']:dict(r,path=str(opdir/r['path']))for r in op['files']}
 sources={n:pinned(row)for n,row in rows.items()}
 context_raw=pinned(p['context']);ctx=strict(context_raw)
 need(ctx['case']==p['case_id']==CASES.get(ctx['kind']) and ctx['operator_directory']==str(opdir)
  and ctx['inputs']['operator_manifest']==p['operator_manifest']
  and ctx['operator_files']=={n:r['sha256']for n,r in rows.items()},'actual selected context and exact operators')
 core=module(sources['root_acceptance_r10.py'],opdir/'root_acceptance_r10.py','reviewed_e2e_context_core')
 actual,release=core.load_context(Path(p['context']['path']),p['context']['sha256'])
 need(actual==ctx,'original context changed')
 shared_raw=pinned(p['shared_materials']);shared=strict(shared_raw)
 supplied={'provider/source/'+n:b for n,b in release['source'].items()}
 supplied.update({'local-config-r10-r1.json':release['config_raw'],'PHONE-SERVICE-INPUTS-v150-r10-r1.json':release['service_raw']})
 need(len(supplied)==len(shared['files'])==17 and {r['path']:{k:r[k]for k in ('bytes','sha256')}for r in shared['files']}
  =={n:{'bytes':len(b),'sha256':sha(b)}for n,b in supplied.items()},'same exact17 production materials')
 for row in shared['files']:pinned(dict(row,path=str(Path(p['shared_materials']['path']).parent/row['path'])))
 out=Path(p['output']);workflow=Path(ctx['workflow_dir'])
 need(B in workflow.parents and workflow.resolve(strict=True)==workflow and out==workflow/'owned-coordinator'
  and out.parent.resolve(strict=True)==out.parent and not out.exists() and not out.is_symlink(),'fresh exact owned output')
 for name in ('register','sender-preview','sender-execute','export','closure'):
  need(not (workflow/name).exists() and not (workflow/name).is_symlink(),'previous phase exists; inspect original, no replay')
 transport_raw=pinned(p['capture_source']);transport=module(transport_raw,p['capture_source']['path'],'reviewed_e2e_owned_capture')
 plan_desc=descriptor(Path(plan_path),raw)
 return p,ctx,core,transport,out,rows,plan_desc,descriptor(Path(__file__),own)
def verify_previous_and_digest_domains(ctx,report,closure,previous):
 """Bind raw-owner and native-envelope digests through the actual close outputs."""
 owner=ctx.get('request_sha256');native=report.get('native_turn_request_sha256')
 need(all(type(v)is str and re.fullmatch('[0-9a-f]{64}',v)for v in (owner,native)),
  'typed owner/native digest domains required')
 need(report.get('request_utf8_sha256')==owner and closure.get('native_request_sha256')==native,
  'owner bytes and independently audited native envelope are separate bindings')
 keys={'identity','request_sha256','terminal','known_no_phone_tool_execution',
  'known_all_dispatched_tools_confirmed_terminal','scope','complete_business_success',
  'health_qualification_pass','original_failed_status_unchanged','model_business_return_credit_from_draft_restore'}
 need(type(previous)is dict and set(previous)==keys,'exact actual previous-input producer fields')
 scope=closure.get('scope');scope_keys={'session_id','profile_id','task_id','turn_id','turn_stream_id'}
 need(type(scope)is dict and set(scope)==scope_keys
  and all(type(v)is str and 0<len(v.encode())<=256 and '\0'not in v for v in scope.values())
  and previous['identity']==scope==report.get('scope'),'same complete actual native scope')
 terminal=report.get('native_terminal')
 need(type(terminal)is dict and terminal.get('status')in ('completed','provider_failed','cancelled')
  and terminal.get('turn_request_sha256')==native
  and previous['terminal']==terminal and previous['request_sha256']==native
  and closure.get('native_status')==terminal['status'],'actual previous native envelope/terminal binding')
 count=closure.get('tool_dispatch_count')
 need(type(count)is int and 0<=count<=7 and ctx.get('max_tool_calls')==7
  and type(report.get('observed_tool_dispatch_count'))is int
  and report['observed_tool_dispatch_count']==count and type(report.get('tools'))is list
  and len(report['tools'])==count,'actual original tool cardinality')
 bool_keys={'known_no_phone_tool_execution','known_all_dispatched_tools_confirmed_terminal',
  'complete_business_success','health_qualification_pass','original_failed_status_unchanged',
  'model_business_return_credit_from_draft_restore'}
 need(all(type(previous[k])is bool for k in bool_keys)
  and type(closure.get('complete_business_success'))is bool
  and type(closure.get('health_qualification_pass'))is bool,'exact previous qualification boolean types')
 need(previous['known_no_phone_tool_execution']is(count==0)
  and previous['known_all_dispatched_tools_confirmed_terminal']is(count>0)
  and previous['complete_business_success']is closure['complete_business_success']
  and previous['health_qualification_pass']is closure['health_qualification_pass']is False
  and previous['original_failed_status_unchanged']is(terminal['status']!='completed')
  and previous['model_business_return_credit_from_draft_restore']is False,
  'actual previous cleanup/qualification facts differ')
 need(ctx.get('kind')in CASES and closure.get('kind')==ctx['kind']
  and previous['scope']=='Original task lifecycle only. Next sender independently rechecks current selection and global action gate.',
  'previous scope statement cannot grant a future dispatch')
 return {'owner_request_sha256':owner,'native_turn_request_sha256':native,
  'actual_previous_identity_and_terminal_verified':True}
def execute(p,ctx,core,T,out,operators,plan_desc,own_desc):
 capture=T.OwnedCapture(out);receipts=[];report_pin=None
 common=[p['context'],p['capture_source'],p['shared_materials'],*ctx['inputs'].values(),*operators.values()]
 need(len(common)<=32,'phase original bound')
 try:
  for index,(phase,budget)in enumerate(PHASES,1):
   core.load_context(Path(p['context']['path']),p['context']['sha256'])
   if phase=='close':
    report_path=Path(ctx['export_dir'])/'audit-01/REPORT.json'
    report_raw=read(report_path,8*1024*1024);report_pin=sha(report_raw)
   payload={'phase':phase,'operator_manifest':p['operator_manifest'],'context':p['context'],
    'unused_pycache':str(out/'unused-pycache'),'report_sha256':report_pin}
   binding={'schema':'hepta.fixed19.e2e.phase-command.v1','case_id':p['case_id'],'phase_kind':phase,
    'context_sha256':p['context']['sha256'],'owner_request_sha256':ctx['request_sha256'],
    'source':own_desc,'plan':plan_desc,'manifest':p['operator_manifest'],'input_originals':common,
    'expected_result_state':'ORIGINAL_HOST_CHILD_JOINED'}
   result=capture.run_phase_original('%02d-%s'%(index,phase.replace('_','-')),
    ['/usr/bin/python3','-I','-B','-c',PHASE_PROGRAM],budget,input_raw=encoded(payload),command_binding=binding)
   need(result['state']=='ORIGINAL_HOST_CHILD_JOINED','original phase not joined')
   receipts.append(dict(phase=phase,**result))
   need(type(result['returncode'])is int and result['returncode'] in ((0,2)if phase=='collect'else(0,)),
    'original E2E phase failed; inspect existing originals: '+phase)
  closure_path=Path(ctx['closure_dir'])/'CLOSURE-CHECK.private.json'
  closure_raw=read(closure_path,8*1024*1024);closure=strict(closure_raw)
  report_path=Path(ctx['export_dir'])/'audit-01/REPORT.json'
  report_raw=read(report_path,8*1024*1024);report=strict(report_raw)
  need(sha(report_raw)==report_pin and closure['schema']=='hepta.root-host-original-closure.v150.r10.1'
   and closure['state']=='ORIGINAL_TASK_LIFECYCLE_CLOSED' and closure['case']==p['case_id']
   and closure['context_sha256']==p['context']['sha256'] and closure['report_sha256']==report_pin
   and closure['release_pins']==ctx['release_pins']
   and closure['combination_manifest_sha256']==ctx['combination_manifest_sha256']
   and closure['native_request_sha256']==report['native_turn_request_sha256'],'exact actual closed business original')
  need(report['case_id']==p['case_id'] and report['request_utf8_sha256']==ctx['request_sha256']
   and report['scope']==closure['scope'] and report['candidate_source_seal_sha256']==ctx['release_pins']['source_seal_sha256']
   and closure['all_original_effect_terminals_verified'] is True
   and closure['model_workers_joined_and_original_server_releases_verified'] is True
   and closure['capture_actor_and_phone_actual_zero'] is True
   and closure['collector_actual_exit_zero'] is True,'actual original business scope and cleanup')
  passed=bool(report['proof_complete'] is True and report['complete_business_success'] is True
   and closure['report_proof_complete_preserved'] is True and closure['complete_business_success'] is True
   and closure['native_status']=='completed' and all(r['returncode']==0 for r in receipts))
  need(closure['previous']['path']==str(Path(ctx['closure_dir'])/'ACTUAL-PREVIOUS-INPUT.json'),
   'actual previous original must be the selected closure output')
  previous_raw=pinned(closure['previous'])
  digest_bindings=verify_previous_and_digest_domains(ctx,report,closure,strict(previous_raw))
  core.load_context(Path(p['context']['path']),p['context']['sha256'])
  pinned(plan_desc)  # Re-read and verify the exact original raw plan descriptor.
  result={'schema':'hepta.fixed19.e2e.original-execution.v1','state':'ACTUAL_E2E_CLOSED_PASS'if passed else'ACTUAL_E2E_CLOSED_NOT_PASS',
   'case_id':p['case_id'],'case_pass':passed,'context':p['context'],'plan':plan_desc,'coordinator':own_desc,
   'operator_manifest':p['operator_manifest'],'owned_capture_source':p['capture_source'],'shared_materials':p['shared_materials'],
   'formal_combination_manifest_sha256':ctx['combination_manifest_sha256'],
   'formal_combination_canonical_sha256':ctx['combination_sha256'],'release_pins':ctx['release_pins'],
   'original_closure':descriptor(closure_path,closure_raw),'original_report':descriptor(report_path,report_raw),
   'actual_previous':closure['previous'],'scope':closure['scope'],'request_hash_bindings':digest_bindings,
   'original_phase_executions':receipts,
   'actual_child_phase_count':6,'capture_phase_also_exported_once':True,'export_replayed':False,
   'maximum_new_native_sends':1,'new_nonce_generated':False,'automatic_retry':False,
   'historical_pass_inherited':False,'full19_qualified':False}
  row=put(out/'E2E-RESULT.json',result)
  print(json.dumps({'state':result['state'],'case_id':p['case_id'],'case_pass':passed,'result':row,
   'actual_previous':closure['previous'],'automatic_retry':False},sort_keys=True))
  return 0 if passed else 2
 except BaseException as error:
  try:cleanup=capture.close_owned_host_outputs()
  except BaseException as e:cleanup={'state':'OWNED_CLEANUP_UNKNOWN','error_type':type(e).__name__}
  failure={'schema':'hepta.fixed19.e2e.execution-failure.v1','state':'FAILED_OR_UNKNOWN_EXISTING_ORIGINALS_PRESERVED',
   'case_id':p['case_id'],'plan':plan_desc,'context':p['context'],'error_type':type(error).__name__,
   'detail':str(error)[:1024],'actual_joined_phase_receipts':receipts,'host_cleanup':cleanup,
   'case_pass':False,'automatic_retry':False,'new_identity_retry':False,'signals_sent_by_coordinator':0}
  try:put(out/'E2E-FAILURE.json',failure)
  except BaseException:pass
  raise
def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--plan',type=Path);ap.add_argument('--plan-sha256')
 ap.add_argument('--execute-e2e-once',action='store_true');a=ap.parse_args()
 if not a.execute_e2e_once:
  print(json.dumps({'state':'SOURCE_PREVIEW_UNBOUND'if OPERATOR_MANIFEST_PIN is None else'SOURCE_PREVIEW_NO_EXECUTION',
   'phone_calls':0,'new_nonce_generated':False,'case_pass':False,'phase_order':[x[0]for x in PHASES],
   'capture_includes_export':True,'requires':'reviewed final operator manifest, actual BUILD/READY/context and explicit execute'},sort_keys=True));return 0
 need(a.plan is not None and a.plan_sha256 is not None,'explicit actual plan required')
 os.umask(0o077)
 raw=read(a.plan);need(sha(raw)==a.plan_sha256,'original plan digest')
 return execute(*validate_plan(raw,a.plan))
if __name__=='__main__':raise SystemExit(main())
