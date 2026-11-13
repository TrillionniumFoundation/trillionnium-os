#!/usr/bin/env python3
"""Replay unchanged helper6 capture bytes through current helper7 and exact original parsers."""
import argparse,gzip,hashlib,io,json,os,pathlib,subprocess,tarfile,time
p=argparse.ArgumentParser()
for n in ('source','helper-source','output','java-home','json-jar'):p.add_argument('--'+n,type=pathlib.Path,required=True)
a=p.parse_args();closure=a.source/'helper-build/code7';out=a.output;out.mkdir(parents=True,exist_ok=False);(out/'classes').mkdir();(out/'history').mkdir()
sha=lambda b:hashlib.sha256(b).hexdigest();tracked={}
def read(p):b=p.read_bytes();tracked[str(p)]=b;return b
def need(v,s):
 if not v:raise RuntimeError(s)
result={'schema':'hepta.capture-parser-original-replay.v1','all_pass':False,'phone_actions':0,'historical_helper_version':6,'helper7_authority_granted_from_history':False,'steps':[]}
try:
 receipt=json.loads(read(closure/'tests/ACTUAL-HELPER6-CAPTURES.json'));arc=read(closure/receipt['archive']['path']);need(len(arc)==receipt['archive']['bytes'] and sha(arc)==receipt['archive']['sha256'],'original fixture archive')
 members={r['name']:r for r in receipt['members']};need(len(members)==67,'full original request/raw/reply22 and binding')
 with tarfile.open(fileobj=io.BytesIO(arc),mode='r:gz') as tar:
  seen=set()
  for entry in tar.getmembers():
   need(entry.isfile() and entry.name in members and entry.name not in seen and pathlib.PurePosixPath(entry.name).name==entry.name,'regular unique original fixture member')
   raw=tar.extractfile(entry).read();row=members[entry.name];need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'original fixture '+entry.name);(out/'history'/entry.name).write_bytes(raw);seen.add(entry.name)
  need(seen==set(members),'complete original67')
 legacy=read(closure/'reference-helper6/src/org/trillionnium/hepta/webhelper/Jsons.java')
 need(sha(legacy)=='484c6daa3a95a9e1849a70e4ceffb3666e23dd148851d2ae356361c2a6693ee5','actual unchanged helper6 parser')
 text=legacy.decode();need(text.count('final class Jsons {')==1 and text.count('private Jsons() { }')==1,'only original class and constructor names')
 renamed=text.replace('final class Jsons {','final class OriginalJsons {').replace('private Jsons() { }','private OriginalJsons() { }')
 oldpath=out/'OriginalJsons.java';oldpath.write_text(renamed)
 files=[oldpath,a.helper_source/'src/org/trillionnium/hepta/webhelper/Jsons.java',a.helper_source/'src/org/trillionnium/hepta/webprotocol/WebEvidenceProtocol.java',a.source/'tests/web-capture-ack/CaptureParserHostTest.java']
 for f in files:read(f)
 need(sha(read(a.json_jar))=='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed','JSON dependency')
 for name,argv in [('javac',[str(a.java_home/'bin/javac'),'--release','8','-encoding','UTF-8','-proc:none','-cp',str(a.json_jar),'-d',str(out/'classes'),*map(str,files)]),('parser',[str(a.java_home/'bin/java'),'-cp',str(out/'classes')+os.pathsep+str(a.json_jar),'org.trillionnium.hepta.webhelper.CaptureParserHostTest',str(out/'CASES.json'),str(out/'history')])]:
  start=time.monotonic();r=subprocess.run(argv,capture_output=True,timeout=120);(out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr);result['steps'].append({'name':name,'argv':argv,'exit_code':r.returncode,'elapsed_seconds':time.monotonic()-start,'stdout_sha256':sha(r.stdout),'stderr_sha256':sha(r.stderr)});need(r.returncode==0,name+' failed')
 result['cases']=json.loads((out/'CASES.json').read_bytes());need(result['cases']['all_pass'] is True and result['cases']['cases']==27 and result['cases']['assertions']==113,'all original27/113 parser cases')
 result['historical_originals_unchanged']=all(sha((out/'history'/r['name']).read_bytes())==r['sha256'] for r in members.values());need(result['historical_originals_unchanged'],'history unchanged')
 result['all_pass']=True
except Exception as e:
 import traceback
 result['error']=str(e);(out/'ERROR.txt').write_text(traceback.format_exc())
finally:
 result['inputs_unchanged']=all(pathlib.Path(p).read_bytes()==b for p,b in tracked.items());result['all_pass']&=result['inputs_unchanged'];result['inputs']=[{'path':p,'bytes':len(b),'sha256':sha(b)} for p,b in sorted(tracked.items())]
 raw=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode();(out/'RESULT.json').write_bytes(raw);print(json.dumps({'all_pass':result['all_pass'],'error':result.get('error'),'result':str(out/'RESULT.json'),'bytes':len(raw),'sha256':sha(raw)}))
raise SystemExit(0 if result['all_pass'] else 1)
