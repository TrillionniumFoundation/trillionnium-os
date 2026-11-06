#!/usr/bin/env python3
"""Prepare exact production COMP-01 return mapping and audit typed originals.
This host-only entry never invokes a phone transport. Default is zero-I/O.
Actual dispatch uniqueness, current live admission and restoration are still
Root transport obligations. A typed receipt alone never grants case PASS.
"""
import argparse,base64,hashlib,json,os,re,shlex,stat,sys,time,types
from pathlib import Path
sys.dont_write_bytecode=True
def context(manifest_sha):
 def exact(raw):
  def pairs(rows):
   result={}
   for key,value in rows:
    if key in result:raise ValueError('duplicate JSON key')
    result[key]=value
   return result
  return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
 def md(st):return tuple(getattr(st,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
 def read(path,maximum):
  if path.resolve(strict=True)!=path:raise ValueError('canonical original required')
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   st=os.fstat(fd)
   if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or not 0<st.st_size<=maximum:raise ValueError('bounded single-link source required')
   with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(st.st_size+1)
   if len(raw)!=st.st_size or md(st)!=md(os.fstat(fd)) or md(st)!=md(path.lstat()):raise ValueError('source changed')
   return raw
  finally:os.close(fd)
 root=Path(__file__).absolute().parent.parent
 raw=read(root/'MANIFEST.json',262144)
 if not isinstance(manifest_sha,str) or hashlib.sha256(raw).hexdigest()!=manifest_sha:raise ValueError('explicit package manifest pin required')
 manifest=exact(raw)
 rows=[r for r in manifest['files'] if r['path']=='source/component_source_context.py']
 if len(rows)!=1:raise ValueError('single pinned source context required')
 row=rows[0];path=root/row['path'];source=read(path,262144)
 if len(source)!=row['bytes'] or hashlib.sha256(source).hexdigest()!=row['sha256']:raise ValueError('source context differs')
 module=types.ModuleType('fixed19_component_source_context');module.__file__=str(path)
 exec(compile(source,str(path),'exec',optimize=0),module.__dict__)
 originals=module.Originals()
 package=module.verify_source_package(originals,root,manifest_sha)
 return module,originals,package

def bounded_wire(command):
 wire=('shell,v2,raw:/debug_ramdisk/su -c '+shlex.quote(command)).encode()
 if len(wire)>=65536:raise ValueError('fixed original ADB transport bound exceeded')
 return {'bytes':len(wire),'sha256':hashlib.sha256(wire).hexdigest(),'limit_exclusive':65536}
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def baseline_request(obs,guards,nonce):
 t=obs.PhoneTools('/not-used-for-read-only-command',lambda *_:(_ for _ in ()).throw(ValueError('unexpected mapper write')))
 shell=t._serial_guard()+guards.page_capture('hepta_comp_page')
 shell+="hepta_comp_vp=$(dumpsys display | grep 'mViewports='); "
 shell+="hepta_comp_boot=$(cat /proc/sys/kernel/random/boot_id); "
 shell+="hepta_comp_stay=$(settings get global stay_on_while_plugged_in); "
 shell+="hepta_comp_fingerprint=$(getprop ro.build.fingerprint); "
 for source,target in [('hepta_comp_page','hepta_comp_page_b64'),('hepta_comp_vp','hepta_comp_vp_b64'),
                       ('hepta_comp_fingerprint','hepta_comp_fingerprint_b64')]:
  shell+=guards.b64_variable(source,target)
 fmt='{"schema":"hepta.fixed19.comp01.foreground-original.v1","nonce":"'+nonce+'","boot_id":"%s","stay_on":"%s","page_b64":"%s","viewport_b64":"%s","fingerprint_b64":"%s"}\n'
 shell+='printf '+shlex.quote(fmt)+' "$hepta_comp_boot" "$hepta_comp_stay" "$hepta_comp_page_b64" "$hepta_comp_vp_b64" "$hepta_comp_fingerprint_b64"'
 bounded_wire(shell)
 return {'kind':'shell','root':True,'timeout_seconds':15,'command':shell}
def actual_stdout(C,originals,rows,expected_request):
 C.need(isinstance(rows,dict) and set(rows)=={'request','wrapper','operation'},'three original transport descriptors required')
 request_raw=originals.descriptor(rows['request'],65536)
 wrapper_raw=originals.descriptor(rows['wrapper'],1048576)
 operation_raw=originals.descriptor(rows['operation'],2097152)
 C.need(C.strict(request_raw)==expected_request,'original request bytes do not name the prepared command')
 wrapper=C.strict(wrapper_raw);operation=C.strict(operation_raw)
 C.need(isinstance(operation,dict) and set(operation)=={'actor_rc','wrapper_sha256','wrapper'}
        and type(operation['actor_rc']) is int and operation['actor_rc']==0
        and operation['wrapper_sha256']==C.sha(wrapper_raw) and operation['wrapper']==wrapper,
        'actual Actor envelope or original wrapper differs')
 phone=wrapper.get('phone')
 C.need(isinstance(phone,dict) and type(phone.get('rc')) is int and phone['rc']==0
        and phone.get('stderr')=='' and isinstance(phone.get('stdout'),str),
        'actual phone command is not a complete zero/stderr-empty result')
 stdout=phone['stdout'].encode()
 C.need(0<len(stdout)<=65536,'bounded nonempty actual return original required')
 return stdout
def validate_baseline(C,obs,guards,raw,nonce,release_pins):
 value=C.strict(raw)
 C.need(isinstance(value,dict) and set(value)=={'schema','nonce','boot_id','stay_on','page_b64','viewport_b64','fingerprint_b64'}
        and value['schema']=='hepta.fixed19.comp01.foreground-original.v1'
        and value['nonce']==nonce and value['boot_id']==release_pins['boot_id']
        and isinstance(value['stay_on'],str) and re.fullmatch('[0-7]',value['stay_on']),
        'original baseline identity differs')
 page=C.decode64(value['page_b64'],16384).decode()
 viewport=C.decode64(value['viewport_b64'],16384).decode()
 fingerprint=C.decode64(value['fingerprint_b64'],1024).decode()
 C.need(fingerprint and '\0' not in fingerprint and '\n' not in fingerprint,'original device fingerprint is absent')
 observed=guards.page_state(page);obs.validate_viewport(viewport)
 C.need(observed['component'].split('/')[0]!='org.trillionnium.owneropen' and observed['keyguard_showing'] is False,
        'COMP-01 requires an actually observed non-HEPTA foreground on qualified inner display')
 return {'value':value,'page':page,'viewport':viewport,'fingerprint':fingerprint,'observed':observed}
def effect_request(guards,baseline,mapped_shell):
 value=baseline['value']
 prefix='[ "$(cat /proc/sys/kernel/random/boot_id)" = '+shlex.quote(value['boot_id'])+' ] || exit 64; '
 prefix+='[ "$(settings get global stay_on_while_plugged_in)" = '+shlex.quote(value['stay_on'])+' ] || exit 70; '
 prefix+='[ "$(getprop ro.build.fingerprint)" = '+shlex.quote(baseline['fingerprint'])+' ] || exit 64; '
 prefix+='[ "$(dumpsys display | grep \'mViewports=\')" = '+shlex.quote(baseline['viewport'])+' ] || exit 68; '
 prefix+=guards.page_equality_guard(baseline['page'])
 command=prefix+mapped_shell
 return {'kind':'shell','root':True,'timeout_seconds':20,'command':command},prefix
def validate_plan(C,originals,plan):
 C.need(isinstance(plan,dict) and set(plan)=={'schema','case_id','release','label','nonce','request','baseline','prepared','actual_return'}
        and plan['schema']=='hepta.fixed19.comp01.direct-return-plan.v1' and plan['case_id']=='COMP-01'
        and isinstance(plan['label'],str) and re.fullmatch('comp01-[a-z0-9-]{1,40}',plan['label'])
        and isinstance(plan['nonce'],str) and re.fullmatch('[0-9a-f]{32}',plan['nonce']),
        'explicit fresh operator component plan required')
 request=originals.descriptor(plan['request'],4096)
 text=request.decode('utf-8')
 C.need(text and '\0' not in text and text.count(plan['nonce'])==1,'exact private component request must contain its explicit nonce once')
 return request
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--mode',choices=('baseline-request','prepare-return','verify-return'))
 p.add_argument('--plan');p.add_argument('--plan-sha256');p.add_argument('--package-manifest-sha256')
 p.add_argument('--out');p.add_argument('--execute-host-once',action='store_true')
 a=p.parse_args()
 if not a.execute_host_once:
  print(json.dumps({'schema':'hepta.fixed19.comp01.source-preview.v1','state':'SOURCE_ONLY_NO_INPUTS_READ',
       'case_id':'COMP-01','modes':['baseline-request','prepare-return','verify-return'],
       'phone_calls':0,'new_nonce':False,'component_case_passed':False,
       'requires':'Actual sealed sources and explicit Root-supplied originals; Root alone performs one dispatch and full transport/restoration audit.'},sort_keys=True))
  return 0
 if not all((a.mode,a.plan,a.plan_sha256,a.package_manifest_sha256,a.out)):raise ValueError('all actual inputs and source pins required')
 C,originals,package=context(a.package_manifest_sha256)
 raw=C.read_plan(originals,Path(a.plan),a.plan_sha256);plan=C.strict(raw)
 request=validate_plan(C,originals,plan)
 output=Path(a.out).absolute();package_root=Path(__file__).absolute().parent.parent
 C.need(output!=package_root and package_root not in output.parents,'output may not modify source package')
 C.need(output!=Path(plan['release']['path']) and Path(plan['release']['path']) not in output.parents,'output may not modify release')
 out=C.fresh_directory(output);audit=C.audit_no_effects(out)
 C.put(out/'INTENT.json',C.encode({'schema':'hepta.fixed19.comp01.host-intent.v1','mode':a.mode,
   'plan':{'path':str(Path(a.plan)),**C.pin(raw)},'source_package':package['descriptor'],
   'maximum_host_starts':1,'phone_calls':0,'automatic_retry':False}))
 try:
  result,release_pins=C.sealed_sources(originals,plan['release'])
  protocol,case=C.protocol(originals,'COMP-01')
  C.put(out/'PLAN.original.json',raw);C.put(out/'PROTOCOL.original.json',protocol)
  identity={'schema':'hepta.operator-direct-component-identity.v1','case_id':'COMP-01',
            'label':plan['label'],'nonce':plan['nonce'],'request_sha256':C.sha(request)}
  C.need(not ({'session_id','profile_id','task_id','turn_id','stream_id'}&set(identity)),'native task scope must not be fabricated')
  with C.production_modules(result['source']) as modules:
   obs=modules['phone_observation_tools'];guards=modules['phone_task_guards']
   baseline_req=baseline_request(obs,guards,plan['nonce'])
   if a.mode=='baseline-request':
    C.need(plan['baseline'] is None and plan['prepared'] is None and plan['actual_return'] is None,'baseline planning must not inherit a prior result')
    descriptor=C.put(out/'BASELINE-REQUEST.json',C.encode(baseline_req))
    report={'state':'READ_ONLY_BASELINE_REQUEST_PREPARED_NOT_EXECUTED','request':descriptor,
            'wire_bound':bounded_wire(baseline_req['command']),'baseline_actual':False}
   else:
    baseline_raw=actual_stdout(C,originals,plan['baseline'],baseline_req)
    baseline=validate_baseline(C,obs,guards,baseline_raw,plan['nonce'],release_pins)
    C.put(out/'BASELINE-STDOUT.original.json',baseline_raw)
    call_id='comp01-return-'+plan['nonce']
    if a.mode=='prepare-return':
     C.need(plan['prepared'] is None and plan['actual_return'] is None,'one new mapping must not inherit a prior mapped return')
     mapped=[]
     def record(path,value):
      mapped.append(value);return C.put(path,C.encode(value))
     mapper=obs.PhoneTools(out,record);mapper.bind(identity)
     decision={'call_id':call_id,'tool':'phone.return_hepta','argv':[],'command':''}
     wire_args=mapper.map(decision)
     C.need(len(mapped)==1 and set(mapper.calls)=={call_id},'exactly one production return mapping required')
     call=mapper.calls[call_id];wire=call['wire_call']
     C.need(wire=={'call_id':call_id,'tool':'adb.exec','argv':wire_args}
            and wire_args[:3]==['-s',obs.SERIAL,'shell'] and len(wire_args)==4,
            'original inherited return mapping wire differs')
     mapped_shell=wire_args[-1]
     C.need(mapped_shell==guards.return_command(mapper._serial_guard(),call['capture_id'])
            and mapped_shell.count('am start -W -n ')==1 and 'input -d ' not in mapped_shell,
            'mapped command is not the one exact production public-return branch')
     actual_request,prefix=effect_request(guards,baseline,mapped_shell)
     effect=C.put(out/'RETURN-REQUEST.json',C.encode(actual_request))
     original=C.put(out/'MAPPED-WIRE.original.json',C.encode(wire))
     C.put(out/'MAPPED-SHELL.original.sh',mapped_shell.encode())
     C.put(out/'ACTUAL-OPERATOR-SHELL.original.sh',actual_request['command'].encode())
     semantic_path=out/('semantic-'+C.sha(call_id.encode())+'.json')
     semantic=C.encode(call)
     prepared={'schema':'hepta.fixed19.comp01.prepared-return.v1','state':'ONE_PRODUCTION_MAPPING_REQUIRES_ROOT_SINGLE_DISPATCH',
       'case_id':'COMP-01','identity':identity,'call_id':call_id,'capture_id':call['capture_id'],
       'source_package':package['descriptor'],'release_pins':release_pins,'baseline':plan['baseline'],
       'baseline_stdout':C.pin(baseline_raw),'baseline_observed':baseline['observed'],
       'baseline_stay_on':baseline['value']['stay_on'],
       'semantic_original':{'path':str(semantic_path),**C.pin(semantic)},
       'mapped_wire':original,'actual_request':effect,'actual_wire_bound':bounded_wire(actual_request['command']),
       'pre_effect_read_only_prefix':C.pin(prefix.encode()),'production_mapping_calls':1,'phone_dispatches':0,
       'mapping_entry':'phone_observation_tools.PhoneTools.map, unchanged inherited return branch of PhoneLocalTools',
       'phone_local_client_constructed':False,'native_or_model_task_started':False,
       'root_admission_and_once_transport_still_required':True,
       'current_live_admission_verified':False,'component_case_passed':False,'native_task_qualified':False,
       'model_qualified':False,'business_verified':False,'automatic_retry':False}
     prepared_row=C.put(out/'PREPARED.json',C.encode(prepared))
     report={'state':prepared['state'],'prepared':prepared_row,'request':effect,'phone_dispatches':0,
             'current_live_admission_verified':False}
    else:
     prepared_raw=originals.descriptor(plan['prepared'],65536);prepared=C.strict(prepared_raw)
     C.need(prepared['schema']=='hepta.fixed19.comp01.prepared-return.v1'
            and prepared['state']=='ONE_PRODUCTION_MAPPING_REQUIRES_ROOT_SINGLE_DISPATCH'
            and prepared['identity']==identity and prepared['call_id']==call_id
            and prepared['source_package']==package['descriptor'] and prepared['release_pins']==release_pins
            and prepared['baseline']==plan['baseline'] and prepared['baseline_stdout']==C.pin(baseline_raw)
            and prepared['production_mapping_calls']==1 and prepared['phone_dispatches']==0
            and prepared['component_case_passed'] is False,'original one-mapping preparation differs')
     semantic=C.strict(originals.descriptor(prepared['semantic_original'],65536))
     mapped=C.strict(originals.descriptor(prepared['mapped_wire'],65536))
     token=C.sha(json.dumps([identity,call_id],sort_keys=True,separators=(',',':')).encode())[:32]
     C.need(prepared['capture_id']==token and semantic['capture_id']==token and semantic['turn']==identity
            and semantic['semantic_tool']=='phone.return_hepta' and semantic['call_id']==call_id
            and semantic['wire_call']==mapped and semantic['wire_tool']=='adb.exec',
            'original semantic mapping identity differs')
     serial_guard='[ "$(getprop ro.serialno)" = '+shlex.quote(obs.SERIAL)+' ] || exit 64; '
     mapped_shell=guards.return_command(serial_guard,token)
     C.need(mapped=={'call_id':call_id,'tool':'adb.exec','argv':['-s',obs.SERIAL,'shell',mapped_shell]},
            'original production return shell differs')
     expected,prefix=effect_request(guards,baseline,mapped_shell)
     C.need(C.strict(originals.descriptor(prepared['actual_request'],65536))==expected
            and prepared['pre_effect_read_only_prefix']==C.pin(prefix.encode())
            and prepared['actual_wire_bound']==bounded_wire(expected['command']),'prepared actual operator request differs')
     stdout=actual_stdout(C,originals,plan['actual_return'],expected)
     value=C.strict(stdout);observed,viewport=guards.verify_return(value,token)
     viewport_sha=obs.validate_viewport(viewport)
     C.put(out/'RETURN-STDOUT.original.json',stdout)
     report={'state':'ORIGINAL_TYPED_RETURN_VERIFIED_PENDING_ROOT_TRANSPORT_AND_RESTORATION_AUDIT',
       'prepared':plan['prepared'],'actual_return':plan['actual_return'],'launch_exit_code':value['launch_exit_code'],
       'observed':observed,'viewport_sha256':viewport_sha,'operation_id':token,
       'original_return_and_viewport_parsers_passed':True,'production_mapping_calls_in_this_verification':0,
       'dispatch_uniqueness_independently_verified':False,'current_live_admission_verified':False,
       'root_transport_and_restore_audit_required':True,'component_case_passed':False}
  C.recheck_source_package(originals,package)
  C.need(audit['network_or_process_attempts']==0 and audit['writes_outside_output']==0,'host-only boundary violated')
  report.update(schema='hepta.fixed19.comp01.host-entry-result.v1',case_id='COMP-01',mode=a.mode,
     source_package=package['descriptor'],release_pins=release_pins,
     original_inputs=list(originals.seen.values()),phone_calls_by_this_entry=0,
     native_task_qualified=False,model_qualified=False,business_verified=False,
     component_case_passed=False,automatic_retry=False,isolation=audit)
  row=C.put(out/'RESULT.json',C.encode(report));print(json.dumps({'state':report['state'],'result':row,
      'component_case_passed':False,'phone_calls':0},sort_keys=True));return 0
 except BaseException as error:
  C.put(out/'FAILURE.json',C.encode({'schema':'hepta.fixed19.comp01.host-entry-failure.v1',
      'state':'FAILED_HOST_ENTRY_ORIGINALS_PRESERVED','error_type':type(error).__name__,
      'detail':str(error)[:1024],'phone_calls':0,'component_case_passed':False,'automatic_retry':False}))
  raise
if __name__=='__main__':raise SystemExit(main())
