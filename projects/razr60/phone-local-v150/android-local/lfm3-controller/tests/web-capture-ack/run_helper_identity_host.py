#!/usr/bin/env python3
"""Execute the exact production helper artifact predicate; package hashing itself remains an Android build/device gate."""
import argparse,hashlib,importlib.util,json,os,pathlib,re,subprocess,time
p=argparse.ArgumentParser()
for k in ('source','output','java-home','json-jar'):p.add_argument('--'+k,type=pathlib.Path,required=True)
a=p.parse_args();out=a.output;out.mkdir(parents=True,exist_ok=False);(out/'classes').mkdir()
tracked={};sha=lambda b:hashlib.sha256(b).hexdigest()
def read(p):b=p.read_bytes();tracked[str(p)]=b;return b
def need(x,s):
 if not x:raise RuntimeError(s)
q=a.source/'tests/web-flight/run_query_host_tests.py';spec=importlib.util.spec_from_file_location('query',q);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);read(q)
src=read(a.source/'src/org/trillionnium/hepta/local/WebHelperIdentity.java')
block=mod.java_block(src,'private static void requireApprovedHelperArtifact(String name,JSONObject hashes)')
fullread=mod.java_block(src,'static WebHelperIdentity read(Context context,String name)')
need(fullread.count('requireApprovedHelperArtifact(name,hashes);')==1 and fullread.index('hashes.put(')<fullread.index('requireApprovedHelperArtifact(name,hashes);')<fullread.index('JSONObject evidence='),'actual installed-file hash result precedes artifact pin and evidence')
const=re.search(rb'    private static final String HELPER_APK_SHA256="[0-9a-f]{64}";',src)
need(const is not None,'one production artifact constant');constant=const.group().decode()
need('edd439f2432f84ba97ed641eaba5d4f3e2b852f652f90e0ef311ca04ee150313' in constant,'actual signed helper pin')
gen=out/'ProjectedHelperIdentity.java'
gen.write_text('package org.trillionnium.hepta.local;\nimport org.json.JSONObject;\nimport org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;\nfinal class ProjectedHelperIdentity {\n'+constant+'\n'+block+'\nstatic void check(String n,JSONObject h)throws Exception{requireApprovedHelperArtifact(n,h);}\n}\n')
sources=[gen,a.source/'src/org/trillionnium/hepta/local/WebEvidenceJson.java',a.source/'src/org/trillionnium/hepta/webprotocol/WebEvidenceProtocol.java',a.source/'tests/web-capture-ack/PairedHelperIdentityHostTest.java']
for s in sources:read(s)
need(sha(read(a.json_jar))=='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed','JSON dependency')
result={'schema':'hepta.paired-helper-artifact-host.v1','all_pass':False,'actual_android_package_manager_executed':False,'production_method_sha256':sha(block.encode()),'production_read_method_sha256':sha(fullread.encode()),'production_call_after_real_hash':True,'steps':[]}
try:
 for name,argv in [('javac',[str(a.java_home/'bin/javac'),'--release','8','-encoding','UTF-8','-proc:none','-cp',str(a.json_jar),'-d',str(out/'classes'),*map(str,sources)]),('cases',[str(a.java_home/'bin/java'),'-cp',str(out/'classes')+os.pathsep+str(a.json_jar),'org.trillionnium.hepta.local.PairedHelperIdentityHostTest',str(out/'CASES.json')])]:
  t=time.monotonic();r=subprocess.run(argv,capture_output=True,timeout=120);(out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr);result['steps'].append({'name':name,'argv':argv,'exit_code':r.returncode,'elapsed_seconds':time.monotonic()-t,'stdout_sha256':sha(r.stdout),'stderr_sha256':sha(r.stderr)});need(r.returncode==0,name+' failed')
 result['cases']=json.loads((out/'CASES.json').read_bytes());need(result['cases']['all_pass'] and result['cases']['cases']==8,'8 artifact cases');result['all_pass']=True
except Exception as e:result['error']=str(e)
finally:
 result['source_unchanged']=all(pathlib.Path(p).read_bytes()==b for p,b in tracked.items());result['all_pass']&=result['source_unchanged'];result['inputs']=[{'path':p,'bytes':len(b),'sha256':sha(b)} for p,b in sorted(tracked.items())];raw=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode();(out/'RESULT.json').write_bytes(raw);print(json.dumps({'all_pass':result['all_pass'],'error':result.get('error'),'result':str(out/'RESULT.json'),'bytes':len(raw),'sha256':sha(raw)}))
raise SystemExit(0 if result['all_pass'] else 1)
