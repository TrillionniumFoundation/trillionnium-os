#!/usr/bin/env python3
import argparse,hashlib,json,pathlib,subprocess,time
def sha(p):
 b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def main():
 p=argparse.ArgumentParser();p.add_argument('--source',required=True);p.add_argument('--output',required=True);p.add_argument('--java-home',required=True);a=p.parse_args()
 s=pathlib.Path(a.source).resolve();out=pathlib.Path(a.output).resolve();out.mkdir(exist_ok=False,parents=True)
 tests=s/'tests/observation-png';pkg=pathlib.Path('src/org/trillionnium/hepta/local')
 original=s/pkg/'HeptaAccessibilityService.java';text=original.read_text()
 signature='    private void writeObservationPng('
 assert text.count(signature)==1
 begin=text.index(signature);brace=text.index('{',begin);depth=1;at=brace+1
 while depth:
  if text[at]=='{':depth+=1
  if text[at]=='}':depth-=1
  at+=1
 helper=text[begin:at]
 template=(tests/'HeptaAccessibilityService.template').read_text();assert template.count('{{actual_helper}}')==1
 generated=out/'generated/org/trillionnium/hepta/local/HeptaAccessibilityService.java';generated.parent.mkdir(parents=True)
 generated.write_text(template.replace('{{actual_helper}}',helper))
 files=[s/pkg/'ObservationPngEncoder.java',tests/'ObservationPngEncoderHostTest.java',generated]
 files+=sorted((tests/'stubs').rglob('*.java'))
 inputs=[sha(x) for x in [original,*files,tests/'HeptaAccessibilityService.template',pathlib.Path(__file__).resolve()]]
 jdk=pathlib.Path(a.java_home).resolve();classes=out/'classes';classes.mkdir()
 report={'schema':'hepta.observation-png-host.v1','passed':False,'phone_operations':0,'android_execution':False,'business_verified':False,'inputs':inputs,'actual_helper_sha256':hashlib.sha256(helper.encode()).hexdigest(),'stages':[]}
 try:
  commands=[('javac',[str(jdk/'bin/javac'),'--release','8','-Xlint:all','-Werror','-encoding','UTF-8','-d',str(classes),*[str(f) for f in files]]),
            ('pixel-and-boundary',[str(jdk/'bin/java'),'-Xmx512m','-Djava.awt.headless=true','-ea','-cp',str(classes),'org.trillionnium.hepta.local.ObservationPngEncoderHostTest',str(out/'private-fixture')])]
  for name,argv in commands:
   start=time.monotonic();r=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
   stdout=out/(name+'.stdout');stderr=out/(name+'.stderr');stdout.write_bytes(r.stdout);stderr.write_bytes(r.stderr)
   report['stages'].append({'name':name,'argv':argv,'exit_code':r.returncode,'seconds':time.monotonic()-start,'stdout':sha(stdout),'stderr':sha(stderr)})
   if r.returncode:raise RuntimeError(name+' failed')
  report['result']=json.loads((out/'pixel-and-boundary.stdout').read_text().splitlines()[0])
  report['inputs_unchanged']=all(sha(pathlib.Path(x['path']))==x for x in inputs)
  assert report['inputs_unchanged'] and report['result']['all_pass'] is True
  report['passed']=True
 except Exception as e:report['error']=str(e)
 (out/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'result':sha(out/'RESULT.json'),'passed':report['passed'],'error':report.get('error'),'summary':report.get('result')}))
 return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
