import argparse,hashlib,json,os,shlex,subprocess,time
from pathlib import Path
D=Path('/operator-workspace/phone-local-v150/acceptance-r7-r3-host-cancel-faults-r1')
P='/operator-home/razr60-local-model-v150/acceptance-r7-r3-host-cancel-faults-r1/namespace-harness-r1/execute_namespace_once.py'
WRAPPER='15aba67496d46bcfe87a3a2235439512b1f4f8b77325c274e9ba3267e9e3cb3f'
RUNNER='6163449a9c92fd370fb5e27b190461ae46f2bfe11c180ea7ca1987bdb190b178'
SERVER='4848e66e94115f64baddc47b575aab53f34d947e7cebc89173f604870504a049'
COUNTER='53aa97adbba5ad9df7fe9e21a00bd5fadcf41aa3d2211521826e6dd00b80f59b'
def write(name,v):
 raw=(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
 fd=os.open(D/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 return {'path':str(D/name),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def main():
 p=argparse.ArgumentParser();p.add_argument('--execute-once',action='store_true');a=p.parse_args()
 if not a.execute_once:print('review-only; no host fixture launched');return 0
 os.umask(0o077)
 assert hashlib.sha256((D/'execute_namespace_once.py').read_bytes()).hexdigest()==WRAPPER
 args=['--execute-once','--attempt','fault-attempt-01','--expected-runner-sha256',RUNNER,'--expected-server-sha256',SERVER,'--expected-counter-sha256',COUNTER]
 code='import hashlib,runpy,sys;from pathlib import Path;p='+repr(P)+';assert hashlib.sha256(Path(p).read_bytes()).hexdigest()=='+repr(WRAPPER)+';sys.argv=[p]+'+repr(args)+';runpy.run_path(p,run_name="__main__")'
 argv=['ssh','-J','operator-jump-host','-o','HostName=192.0.2.4','-p','22','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','operator-secondary-host','/usr/bin/python3 -B -c '+shlex.quote(code)]
 write('MAIN-EXECUTION-01.intent.json',{'scope':'host isolated only','attempt':'fault-attempt-01','wrapper_sha256':WRAPPER,'runner_sha256':RUNNER,'server_sha256':SERVER,'counter_sha256':COUNTER,'phone_calls':0,'real_model_requests':0})
 begin=time.monotonic()
 try:
  r=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
  report={'state':'process_terminal','returncode':r.returncode,'stdout':r.stdout.decode(),'stderr':r.stderr.decode(),'elapsed_seconds':time.monotonic()-begin,'phone_calls':0,'real_model_requests':0}
 except subprocess.TimeoutExpired as ex:
  report={'state':'ssh_deadline_original_remote_outcome_unknown','returncode':None,'stdout':(ex.stdout or b'').decode(),'stderr':(ex.stderr or b'').decode(),'elapsed_seconds':time.monotonic()-begin,'automatic_retry':False,'phone_calls':0,'real_model_requests':0}
 rec=write('MAIN-EXECUTION-01.json',report)
 print(json.dumps({'result':rec,'state':report['state'],'returncode':report['returncode'],'elapsed_seconds':report['elapsed_seconds'],'phone_calls':0,'real_model_requests':0}))
 return 0 if report['returncode']==0 else 1
if __name__=='__main__':raise SystemExit(main())
