#!/usr/bin/env python3
"""Root-only two-point resource observation. No task, nonce or model query."""
from pathlib import Path
import argparse,base64,hashlib,importlib.util,json,os,re,sys
B=Path('/operator-workspace/phone-local-v150')
D=B/'resource-sampler-r7-r2-r1'
SHELL_SHA='2546cefc88f447fcb62c6f7b31b5970cecd2aa20a62259669aaac1d248ded44d'
BOOT='<INSTANCE_UUID_REQUIRED>'
CONTEXT={'model':'u:r:magisk:s0','sidecar':'u:r:trillionnium_owner_open_phone_executor:s0','provider':'u:r:magisk:s0'}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def put(p,raw):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def writej(p,value):
 raw=(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
 put(p,raw);return raw
def decode(raw):
 lines=raw.decode().splitlines()
 if not lines or lines[0]!='HEPTA_RESOURCE_SAMPLE_V1' or lines[-1]!='END\t0':raise ValueError('incomplete capture')
 rows={}
 for line in lines[1:-1]:
  kind,name,rc,encoded=line.split('\t',3)
  if kind not in ('F','C') or name in rows:raise ValueError('invalid record')
  output=base64.b64decode(encoded,validate=True)
  row={'command_exit_code':int(rc),'errno':None,'value':None,'error':None}
  if int(rc)!=0:row['error']=output.decode(errors='replace')
  else:
   value=base64.b64decode(b''.join(output.split()),validate=True) if kind=='F' else output
   row.update(value=value.decode(),raw_bytes=len(value),raw_sha256=sha(value))
  rows[name]=row
 return rows
def value(rows,name):
 row=rows.get(name)
 if row is None:return None,{'error':'record_missing','errno':None}
 if row['error'] is not None:return None,{'error':row['error'],'errno':None,'command_exit_code':row['command_exit_code']}
 return row['value'],None
def integer(rows,name):
 text,error=value(rows,name)
 if error:return {'value':None,**error}
 if not re.fullmatch(r'-?[0-9]+',text.strip()):return {'value':None,'errno':None,'error':'not_integer'}
 return {'value':int(text.strip()),'error':None,'errno':None}
def proc(raw):
 first,tail=raw.rsplit(') ',1);pid=int(first.split(' (',1)[0]);v=tail.split()
 if len(v)<20:raise ValueError('proc field count')
 return {'pid':pid,'pgid':int(v[2]),'sid':int(v[3]),'start_ticks':int(v[19]),
         'utime_ticks':int(v[11]),'stime_ticks':int(v[12]),'state':v[0]}
def mem(text,name):
 if text is None:return {'value':None,'unit':None,'error':'source_unavailable'}
 fields=[x.split(':',1)[1].strip().split() for x in text.splitlines() if x.startswith(name+':')]
 if len(fields)!=1 or len(fields[0])!=2 or not fields[0][0].isdigit():return {'value':None,'unit':None,'error':'field_missing_or_invalid'}
 return {'value':int(fields[0][0]),'unit':fields[0][1],'error':None}
def summarize(rows,phase,expected):
 report={'schema':'hepta.readonly-resource-sample.v150.r7.r2.1','phase':phase,'identity_verified':False,
 'roles':{},'system':{},'battery':{},'model_requests':0,'task_submissions':0,'service_changes':0,
 'key_files_read':0,'model_usage_source':'original HTTP receipts; not sampled here',
 'hardware_energy_joules':None,'monetary_cost':None,
 'limits':'Non-atomic file observations. CPU ticks are cumulative counters. Battery attributes remain raw vendor values, without inferred units/sign/scaling or power/cost estimates.'}
 boot,error=value(rows,'boot_id');report['boot_id_matches']=boot is not None and boot.strip()==BOOT;report['boot_error']=error
 marker,error=value(rows,'services_started');report['services_started_marker_observed']=bool(marker and not error)
 report['clock_ticks_per_second']=integer(rows,'clk_tck')
 for role in ('model','sidecar','provider'):
  row={'identity_verified':False,'errors':[],'cpu_begin':None,'cpu_end':None}
  try:
   ids=[]
   for suffix in ('begin','end'):
    text,error=value(rows,role+'.identity.'+suffix)
    if error:raise ValueError('claim identity unavailable: '+str(error))
    parts=text.strip().split(':')
    if len(parts)!=4 or not all(p.isdigit() for p in parts):raise ValueError('claim shape')
    numbers=list(map(int,parts))
    if min(numbers)<=1:raise ValueError('claim numeric identity')
    ids.append(dict(zip(('pid','pgid','sid','start_ticks'),numbers)))
   if ids[0]!=ids[1]:raise ValueError('claim identity changed')
   start,e1=value(rows,role+'.identity_stat.begin');end,e2=value(rows,role+'.identity_stat.end')
   if e1 or e2 or start!=end:raise ValueError('claim metadata unavailable or changed')
   fields=start.strip().split(':')
   if len(fields)!=9 or fields[2:6]!=['0','0','600','1']:raise ValueError('claim ownership/mode/link differs')
   if list(ids[0].values())!=expected['role_identities'][role]:raise ValueError('actual role differs from frozen expected startup identity')
   row['claim_identity']=ids[0]
   for suffix in ('begin','end'):
    text,error=value(rows,role+'.proc_stat.'+suffix)
    if error:raise ValueError('process stat unavailable: '+str(error))
    observed=proc(text)
    if {k:observed[k] for k in ids[0]}!=ids[0]:raise ValueError('actual process identity differs')
    row['cpu_'+suffix]=observed
   context,error=value(rows,role+'.context')
   if error or context.rstrip('\0\n')!=CONTEXT[role]:raise ValueError('role context differs or unavailable')
   row['context']=context.rstrip('\0\n');row['identity_verified']=True
  except (ValueError,TypeError,IndexError,AttributeError) as error:row['errors'].append(str(error))
  status,error=value(rows,role+'.status')
  row['status_read_error']=error;row['rss']=mem(status,'VmRSS');row['hwm']=mem(status,'VmHWM')
  row['executable'],row['executable_read_error']=value(rows,role+'.executable')
  report['roles'][role]=row
 memory,error=value(rows,'meminfo');report['system']={'mem_available':mem(memory,'MemAvailable'),'read_error':error}
 for attr in ('temp','capacity','current_now','voltage_now'):report['battery'][attr]=integer(rows,'battery.'+attr)
 for name in ('utc.begin','utc.end','uptime.begin','uptime.end'):
  observed,error=value(rows,name);report[name]={'value':observed,'error':error}
 report['input_bindings']={};binding_ok=True
 for field,pin in [('source_seal',expected['provider_source_seal_sha256']),('config',expected['configuration_sha256']),('daily',expected['daily_source_sha256']),('module',expected['module_manifest_sha256'])]:
  text,error=value(rows,'binding.'+field+'.sha256');observed=text.split()[0] if text else None
  good=error is None and observed==pin
  report['input_bindings'][field]={'matches':good,'observed_sha256':observed,'error':error};binding_ok=binding_ok and good
 text,error=value(rows,'binding.ready')
 try:
  ready=json.loads(text)
  good=error is None and ready['pid']==expected['role_identities']['provider'][0] and ready['accepting'] is True and ready['port']==18080 and ready['source_sha256']==expected['daily_source_sha256'] and ready['config_sha256']==expected['configuration_sha256'] and ready['service_manifest_sha256']==expected['service_inputs_sha256'] and ready['backend']=='phone_local_http' and ready['readiness_scope']=='transport_only'
 except (ValueError,TypeError,KeyError):good=False
 report['input_bindings']['ready']={'matches':good,'error':error};binding_ok=binding_ok and good
 report['frozen_combination_sha256']=expected['combination_sha256']
 report['expected_role_origin_sha256']=expected['origin_readiness_capture_sha256']
 report['input_bindings_verified']=binding_ok
 report['identity_verified']=binding_ok and report['boot_id_matches'] and report['services_started_marker_observed'] and all(x['identity_verified'] for x in report['roles'].values())
 return report
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=('before-health','after-health','before-visual','after-visual','before-unicode','after-unicode'))
 p.add_argument('--expected-roles',type=Path,required=True);p.add_argument('--expected-roles-sha256',required=True)
 p.add_argument('--execute-read-once',action='store_true');a=p.parse_args()
 if not a.execute_read_once:raise SystemExit('Root --execute-read-once required; no operation issued')
 expected_raw=a.expected_roles.read_bytes()
 if sha(expected_raw)!=a.expected_roles_sha256:raise ValueError('expected role source pin differs')
 expected=json.loads(expected_raw)
 if expected['schema']!='hepta.resource-expected-roles.v150.r7.r2' or expected['boot_id']!=BOOT or expected['combination_sha256']!='1f4763e8bf56cf25392a944298d08e4284495b0b7f44b3edb77060a250b598c5' or expected['provider_source_seal_sha256']!='7c20af425fa88cf6fd90aa7b902bd7c5c0cb0f1d4e808ac26ddbd4445f61c4ab':raise ValueError('expected role input combination differs')
 if set(expected['role_identities'])!={'model','sidecar','provider','supervisor'} or any(type(v) is not list or len(v)!=4 or any(type(n) is not int or n<=1 for n in v) for v in expected['role_identities'].values()):raise ValueError('expected identities shape')
 os.umask(0o077);source=(D/'sample_resources.sh').read_bytes()
 if sha(source)!=SHELL_SHA:raise ValueError('fixed read-only source pin differs')
 out=D/a.phase;out.mkdir(mode=0o700)
 put(out/'EXPECTED-ROLES.original.json',expected_raw)
 harness=B/'root-operators-r6-cycle03/run_cycle03.py'
 if sha(harness.read_bytes())!='630c4cb2b9ec5363c7dc464af59455ea252abb1f4f56b3920002f73de177efb6':raise ValueError('original phone wrapper pin differs')
 spec=importlib.util.spec_from_file_location('root_resources_read_once',harness)
 m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);m.D=out
 req={'kind':'shell','root':True,'timeout_seconds':20,'command':source.decode()}
 label='sample-r7-r2-resources-'+a.phase+'-01';writej(out/'REQUEST.json',req)
 ph=m.call_phone(label,req)
 raw=ph['stdout'].encode();put(out/'ORIGINAL-RESOURCE-CAPTURE.tsv',raw)
 rows=decode(raw);report=summarize(rows,a.phase,expected);report['capture_sha256']=sha(raw);report['captured_records']=len(rows)
 result=writej(out/'REPORT.json',report)
 print(json.dumps({'state':'RESOURCE_SAMPLE_OBSERVED','phase':a.phase,'identity_verified':report['identity_verified'],
 'report':str(out/'REPORT.json'),'report_sha256':sha(result),
 'roles':{r:{k:x[k] for k in ('rss','hwm','cpu_begin','cpu_end')} for r,x in report['roles'].items()},
 'clock_ticks_per_second':report['clock_ticks_per_second'],'mem_available':report['system']['mem_available'],
 'battery':report['battery'],'hardware_energy_joules':None,'monetary_cost':None,
 'phone_read_operations':1,'model_requests':0,'task_submissions':0},sort_keys=True))
 return 0 if report['identity_verified'] else 2
if __name__=='__main__':sys.exit(main())
