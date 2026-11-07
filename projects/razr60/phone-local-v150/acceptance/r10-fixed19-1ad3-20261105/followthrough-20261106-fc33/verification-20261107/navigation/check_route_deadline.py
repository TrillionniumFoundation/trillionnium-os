#!/usr/bin/env python3
"""Exercise the exact candidate route/host/request/read path with local fixtures."""
import argparse,hashlib,json,socket,struct,subprocess,threading,time,types
from pathlib import Path

CANDIDATE_SHA='06cab5903387dd10c29ea6fbddb6e4f4e6ceb6e2e3e835de1148619d89e139e0'


def read(peer,n):
 data=b''
 while len(data)<n:
  piece=peer.recv(n-len(data))
  if not piece:raise EOFError()
  data+=piece
 return data


def fixture(path,slow):
 raw=path.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=CANDIDATE_SHA:raise RuntimeError('candidate pin mismatch before import')
 m=types.ModuleType('actual_helper_route_fixture');m.__file__=str(path)
 exec(compile(raw,str(path),'exec'),m.__dict__)
 services=[];connections=[];subprocesses=[];threads=[];errors=[];sockets=[]
 def serve(peer,port):
  try:
   service=read(peer,int(read(peer,4),16)).decode();services.append((port,service));peer.sendall(b'OKAY')
   if service in ('host:version','host:devices-l'):
    payload=(b'0029' if service=='host:version' else b'ZY22LS7WZT device transport_id:23\n' if port==5037 else b'')
    peer.sendall(('%04x'%len(payload)).encode())
    if slow and service=='host:version':
     for part in payload:
      time.sleep(0.09);peer.sendall(bytes([part]))
    else:peer.sendall(payload)
   elif service=='host:transport-id:23':
    service=read(peer,int(read(peer,4),16)).decode();services.append((port,service));peer.sendall(b'OKAY')
    if service!='shell,v2,raw:fixture-one-observation':raise AssertionError(service)
    peer.sendall(struct.pack('<BI',3,1)+b'\0')
   else:raise AssertionError(service)
  except (BrokenPipeError,ConnectionResetError,EOFError):pass
  except Exception as e:errors.append(str(e))
  finally:peer.close()
 def connect(address,timeout):
  if address not in (('127.0.0.1',5037),('127.0.0.1',5061)):raise AssertionError(address)
  connections.append({'port':address[1],'timeout':timeout})
  a,b=socket.socketpair();a.settimeout(timeout);b.settimeout(2);sockets.append(a)
  t=threading.Thread(target=serve,args=(b,address[1]),daemon=True);threads.append(t);t.start();return a
 def run(argv,**kwargs):
  port=int(argv[-1].split(':')[-1]);subprocesses.append({'argv':argv,'timeout':kwargs.get('timeout')})
  if argv!=['ss','-ltnp','sport = :'+str(port)] or port not in (5037,5061):raise AssertionError(argv)
  return types.SimpleNamespace(returncode=0,stdout=('pid='+str(111 if port==5037 else 222)).encode())
 m.os=types.SimpleNamespace(uname=lambda:types.SimpleNamespace(nodename='fixture-pocket4'),getuid=lambda:1000)
 m.subprocess=types.SimpleNamespace(run=run)
 m.socket=types.SimpleNamespace(create_connection=connect)
 config={'execution_host':'fixture-pocket4','server_pids':{'5037':111,'5061':222}}
 start=time.monotonic();result=None;error=None
 try:result=m.shell('fixture-one-observation',config,(5037,'23'),timeout=0.2)
 except Exception as e:error={'type':type(e).__name__,'message':str(e)}
 elapsed=time.monotonic()-start
 for t in threads:t.join(2)
 if errors or any(t.is_alive() for t in threads):raise AssertionError(errors)
 if not all(s.fileno()==-1 for s in sockets):raise AssertionError('socket remained open')
 if not all(0<r['timeout']<=0.2 for r in subprocesses+connections):raise AssertionError('budget not propagated')
 effects=sum('shell,v2,raw:' in service for _,service in services)
 if slow:
  if error is None or error['type']!='TimeoutError' or result is not None or effects!=0 or elapsed>0.35:
   raise AssertionError({'slow_route_accepted':result,'error':error,'effects':effects,'elapsed':elapsed})
 else:
  expected=[(5037,'host:version'),(5037,'host:devices-l'),(5061,'host:version'),(5061,'host:devices-l'),(5037,'host:transport-id:23'),(5037,'shell,v2,raw:fixture-one-observation')]
  if services!=expected or error or result['rc']!=0 or effects!=1:raise AssertionError('route or wire command changed')
 return {'slow_route':slow,'elapsed_seconds':elapsed,'budget_seconds':0.2,'error':error,
         'result':result,'services':services,'subprocess_calls':subprocesses,'connections':connections,
         'effect_service_requests':effects,'sockets_closed':True,'fixture_threads_joined':True}


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--candidate',required=True,type=Path);p.add_argument('--out',required=True,type=Path);a=p.parse_args()
 if a.out.exists():raise RuntimeError('output exists')
 report={'schema':'hepta.sender-route-deadline-source-review.v1','candidate_sha256':CANDIDATE_SHA,
         'controls':[fixture(a.candidate,False),fixture(a.candidate,True)],'passed':2,'total':2,
         'phone_calls':0,'adb_daemon_connections':0,'native_dispatches':0,
         'remote_process_cleanup_verified':False,'frozen_R6_adopted':False,'fixed19_credit':0}
 a.out.parent.mkdir(parents=True,exist_ok=True)
 with a.out.open('x')as f:json.dump(report,f,sort_keys=True,indent=2);f.write('\n')
 print(json.dumps({'passed':2,'total':2,'slow_route_zero_effect_services':True,'phone_calls':0}))


if __name__=='__main__':main()
