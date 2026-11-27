#!/usr/bin/env python3
"""Narrow ce5 final-replacement incomplete-D gate over actual producer methods.
No Android, model process, Phone transport, or installed-source mutation."""
import argparse, difflib, hashlib, importlib.util, json, os, stat, subprocess, sys, time
from pathlib import Path
sys.dont_write_bytecode = True
PKG = Path('src/org/trillionnium/hepta/local')
SERVICE = PKG/'HeptaAccessibilityService.java'
JSON_SHA = '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
ORIGINALS = [(358195,'16754f841eea1b35166eee4e22a6c26dda5f104ca74c9a6f1029c4569c17ec2b')]
ACTION_START = '    private volatile SearchActionWork activeSearchAction;'
ACTION_END = '    private final class ActionWork {'
MAIN = '    public static void main(String[] args)throws Exception {'
NEW_MAIN = MAIN+'\n        ce5ReplacementCases(args);\n    }'
def sha(raw): return hashlib.sha256(raw).hexdigest()
def meta(path):
 p=Path(path).absolute();st=p.lstat()
 if not stat.S_ISREG(st.st_mode):raise RuntimeError('regular input required: '+str(p))
 b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':sha(b),'mode':stat.S_IMODE(st.st_mode)}
def put(path,raw):
 p=Path(path);p.parent.mkdir(parents=True,exist_ok=True)
 if isinstance(raw,str):raw=raw.encode()
 with p.open('xb') as f:f.write(raw)
 os.chmod(p,0o600)
def save(path,value):put(path,json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
def unique(rows):
 result={}
 for r in rows:
  if r['path'] in result and result[r['path']]!=r:raise RuntimeError('conflicting input metadata')
  result[r['path']]=r
 return [result[k] for k in sorted(result)]
def recheck(rows):
 after=[meta(r['path']) for r in rows]
 if rows!=after:raise RuntimeError('frozen source/tool/original changed')
 return after
def module(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def environment():
 env=dict(os.environ);env['PYTHONDONTWRITEBYTECODE']='1'
 for k in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'):env.pop(k,None)
 return env
def run(out,name,argv,timeout=180):
 start=time.monotonic()
 with (out/(name+'.stdout')).open('xb') as stdout,(out/(name+'.stderr')).open('xb') as stderr:
  completed=subprocess.run(list(map(str,argv)),cwd=out,env=environment(),stdout=stdout,stderr=stderr,timeout=timeout)
 return {'name':name,'argv':list(map(str,argv)),'exit_code':completed.returncode,'elapsed_seconds':time.monotonic()-start,
  'stdout':meta(out/(name+'.stdout')),'stderr':meta(out/(name+'.stderr'))}
def prepare(args):
 source=args.source.absolute();out=args.output.absolute();jdk=args.java_home.absolute();jar=args.json_jar.absolute()
 if out.exists() or source in out.parents:raise RuntimeError('fresh output outside source required')
 actual=meta(source/SERVICE)
 if actual['sha256']!=args.expected_service_sha256:raise RuntimeError('actual whole Service SHA differs')
 originals=[meta(args.original)]
 if [(r['bytes'],r['sha256']) for r in originals]!=ORIGINALS:raise RuntimeError('exact complete ce5 action original required')
 if meta(jar)['sha256']!=JSON_SHA:raise RuntimeError('actual JSON jar differs')
 out.mkdir(mode=0o700,parents=True)
 legacy=source/'tests/native-search-producer/run_producer.py'
 stage=run(out,'legacy-prepare',[sys.executable,'-B',legacy,'--source',source,'--output',out/'legacy',
  '--java-home',jdk,'--json-jar',jar,'--prepare-only'])
 if stage['exit_code']!=0:raise RuntimeError('unchanged producer pure generation failed')
 prepared=json.loads((out/'legacy/PREPARED.json').read_text())
 extractor=module(source/'tests/observation-diagnostics/run_host.py','ce5_incomplete_extractor')
 body,section=extractor.body,extractor.section
 generated=out/'legacy/generated/ports/org/trillionnium/hepta/local/HeptaAccessibilityService.java'
 original_generated=generated.read_text();old_main=body(original_generated,MAIN)
 fragment=Path(__file__).with_name('FinalReplacementIncompleteCases.fragment').read_text()
 if original_generated.count(old_main)!=1 or not original_generated.endswith('}\n'):raise RuntimeError('exact generated main boundary')
 replaced=original_generated.replace(old_main,NEW_MAIN,1)
 current=replaced[:-2]+fragment+'}\n'
 reverse=current[:-len(fragment+'}\n')]+'}\n'
 if reverse.replace(NEW_MAIN,old_main,1)!=original_generated:raise RuntimeError('full generated fixture inverse differs')
 raw=(source/SERVICE).read_text();action=section(raw,ACTION_START,ACTION_END)
 if current.count(action)!=1:raise RuntimeError('actual complete search action block not preserved verbatim')
 if 'ce5ReplacementCases(args);' not in current:raise RuntimeError('new focused main missing')
 put(out/'GENERATED-MAIN-DELTA.patch',''.join(difflib.unified_diff(original_generated.splitlines(True),current.splitlines(True),
  fromfile='legacy-generated-Service.java',tofile='focused-generated-Service.java')))
 put(out/'ORIGINAL-MAIN.java',old_main+'\n')
 generated.write_text(current)
 paths=[r['path'] for r in prepared['compile_inputs_before']]
 compile_inputs=[meta(p) for p in paths]
 sources=unique([meta(r['path']) for r in prepared['source_inputs']]+[
  actual,meta(legacy),meta(source/'tests/observation-diagnostics/run_host.py'),meta(Path(__file__)),
  meta(Path(__file__).with_name('FinalReplacementIncompleteCases.fragment')),meta(Path(__file__).with_name('EXPECTED-CASES.json'))])
 tools=[meta(r['path']) for r in prepared['tools_before']]
 proof={'schema':'hepta.ce5-incomplete-replacement-focused-prepare.v1','preparation_only':True,'jvm_started':False,
  'source':str(source),'output':str(out),'java_home':str(jdk),'json_jar':str(jar),'counterfactual':args.counterfactual,
  'actual_service':actual,'originals':originals,'source_inputs':sources,'compile_inputs':compile_inputs,'tools':tools,
  'legacy_preparation':meta(out/'legacy/PREPARED.json'),'legacy_extraction':meta(out/'legacy/EXTRACTION.json'),
  'generator_main_delta':meta(out/'GENERATED-MAIN-DELTA.patch'),'complete_action_bytes':len(action.encode()),
  'complete_action_sha256':sha(action.encode()),'complete_action_occurrences':1,'generated_whole_inverse':True,
  'original_test_case_bodies_preserved':True,'original_full_suite_executed':False,
  'boundary':'Only generated test main is replaced and new fragment appended. Real whole Session/Attempt/Role/Gate and complete current Service action/callback/drain section stay compiled. SDK, events, clock and fixed proposal are explicit host IO.',
  'stages':[stage],'phone_operations':0,'actual_model_calls':0,'new_device_success_claimed':False}
 recheck(sources);recheck(tools);recheck(originals)
 save(out/'PREPARED.json',proof)
 print(json.dumps({'prepared':meta(out/'PREPARED.json'),'java_execution':False,'compile_inputs':len(compile_inputs)}))
 return 0
def execute(args):
 out=args.output.absolute();pp=out/'PREPARED.json';p=json.loads(pp.read_text())
 if (out/'RESULT.json').exists():raise RuntimeError('single execution output already exists')
 source_rows=p['source_inputs'];compile_rows=p['compile_inputs'];tools=p['tools'];originals=p['originals']
 jdk=Path(p['java_home']);jar=Path(p['json_jar'])
 report={'schema':'hepta.ce5-incomplete-replacement-focused-execution.v1','all_pass':False,'prepared':meta(pp),
  'actual_service':p['actual_service'],'counterfactual':p['counterfactual'],'stages':[],
  'phone_operations':0,'actual_model_calls':0,'new_device_success_claimed':False}
 try:
  recheck(source_rows);recheck(compile_rows);recheck(tools);recheck(originals)
  available=None
  for line in Path('/proc/meminfo').read_text().splitlines():
   if line.startswith('MemAvailable:'):available=int(line.split()[1])*1024
  if available is None or available<1024**3:raise RuntimeError('at least 1 GiB host memory required')
  report['host_memavailable_bytes_before_jvm']=available
  classes=out/'classes';classes.mkdir()
  argsfile=out/'javac.args';put(argsfile,'\n'.join('"'+r['path']+'"' for r in compile_rows)+'\n')
  stage=run(out,'strict',[jdk/'bin/javac','-J-Xmx768m','--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-cp',jar,'-d',classes,'@'+str(argsfile)])
  report['stages'].append(stage)
  if stage['exit_code']!=0:raise RuntimeError('strict compilation failed')
  argv=[jdk/'bin/java','-Xmx512m','-ea',
   '-Dhepta.test.ce5Original='+originals[0]['path'],
   '-Dhepta.test.ce5Counterfactual='+str(p['counterfactual']).lower(),
   '-cp',str(classes)+':'+str(jar),'org.trillionnium.hepta.local.HeptaAccessibilityService',out/'CASES.json',out/'private-fixture']
  stage=run(out,'focused-cases',argv);report['stages'].append(stage)
  if (out/'CASES.json').is_file():
   report['cases']=meta(out/'CASES.json');c=json.loads((out/'CASES.json').read_text())
   report['case_count']=c['case_count'];report['assertions']=c['assertions'];report['case_all_pass']=c['all_pass']
   report['case_names']=[r['name'] for r in c['results']]
   expected=json.loads(Path(__file__).with_name('EXPECTED-CASES.json').read_text())
   if p['counterfactual']:expected=expected[:1]
   report['case_names_exact']=report['case_names']==expected
   report['all_pass']=stage['exit_code']==0 and c['all_pass'] and report['case_names_exact']
  if not report['all_pass']:raise RuntimeError('focused behavior cases failed')
 except Exception as e:
  report['error']=type(e).__name__+': '+str(e)
 finally:
  try:
   for key,rows in [('source_inputs',source_rows),('compile_inputs',compile_rows),('tools',tools),('originals',originals)]:
    report[key+'_after']=recheck(rows)
   report['all_inputs_unchanged']=True
  except Exception as e:
   report['all_inputs_unchanged']=False;report['all_pass']=False;report['input_error']=str(e)
  save(out/'RESULT.json',report)
 print(json.dumps({'all_pass':report['all_pass'],'stages':[(r['name'],r['exit_code']) for r in report['stages']],
  'result':meta(out/'RESULT.json')}))
 return 0 if report['all_pass'] else 1
def main():
 ap=argparse.ArgumentParser();ap.add_argument('mode',choices=('prepare','execute'));ap.add_argument('--output',type=Path,required=True)
 for name in ('source','java-home','json-jar','original'):ap.add_argument('--'+name,type=Path)
 ap.add_argument('--expected-service-sha256');ap.add_argument('--counterfactual',action='store_true');args=ap.parse_args()
 if args.mode=='prepare' and any(getattr(args,n) is None for n in ('source','java_home','json_jar','original','expected_service_sha256')):
  ap.error('prepare requires all exact source/tool/original arguments')
 return prepare(args) if args.mode=='prepare' else execute(args)
if __name__=='__main__':raise SystemExit(main())
