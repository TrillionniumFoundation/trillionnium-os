#!/usr/bin/env python3
"""Isolated reproduction of the retained sender helper's per-recv timeout.

The only connection is socket.socketpair inside this process. The source's route
and socket.create_connection are replaced by bounded test fixtures; no ADB daemon,
SSH target, phone, actor or model is contacted. No source entry point is run.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import struct
import threading
import time
import types

ORIGINAL_SHA = '6d7597e55af1ba8330029352076b2c6715172056e6ea28dea97b57c7775fd35b'


def load_source(path, expected):
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=expected:
        raise RuntimeError('helper_source_pin_mismatch_before_import')
    module=types.ModuleType('isolated_sender_helper')
    module.__file__=str(path)
    exec(compile(raw,str(path),'exec'),module.__dict__)
    return module


def receive(peer,count):
    data=b''
    while len(data)<count:
        part=peer.recv(count-len(data))
        if not part:raise EOFError('test peer client closed')
        data+=part
    return data


def exercise(module,mode,budget=0.2):
    client,peer=socket.socketpair()
    peer.settimeout(2)
    services=[];peer_errors=[];connections=[]
    def connection(address,timeout):
        if address!=('127.0.0.1',5037):raise AssertionError('unexpected test address')
        connections.append({'address':list(address),'timeout':timeout})
        if len(connections)!=1:raise AssertionError('unexpected retry')
        client.settimeout(timeout)
        return client
    module.socket=types.SimpleNamespace(create_connection=connection)
    module.route=lambda _config, *_args, **_kwargs:(5037,'23')
    def server():
        try:
            for _ in range(2):
                size=int(receive(peer,4),16)
                services.append(receive(peer,size).decode())
                peer.sendall(b'OKAY')
            if mode=='drip':
                for _ in range(4):
                    time.sleep(0.1)
                    peer.sendall(struct.pack('<BI',1,1)+b'x')
                peer.sendall(struct.pack('<BI',3,1)+b'\0')
            elif mode=='killed':
                peer.sendall(struct.pack('<BI',2,7)+b'Killed\n'+struct.pack('<BI',3,1)+b'\x89')
            elif mode=='success':
                peer.sendall(struct.pack('<BI',1,2)+b'ok'+struct.pack('<BI',3,1)+b'\0')
            elif mode=='silence':
                # No sleep: the peer observes the client close at its deadline.
                while peer.recv(1):pass
            else:raise AssertionError('unknown fixture')
        except (BrokenPipeError,ConnectionResetError,EOFError):
            pass
        except Exception as error:
            peer_errors.append(type(error).__name__+': '+str(error))
        finally:peer.close()
    worker=threading.Thread(target=server,name='local-socketpair-peer',daemon=True)
    worker.start();start=time.monotonic();result=None;error=None
    try:
        result=module.shell('fixture-one-observation',{},(5037,'23'),timeout=budget)
    except Exception as caught:
        error={'type':type(caught).__name__,'message':str(caught)}
    elapsed=time.monotonic()-start
    closed=client.fileno()==-1
    client.close();worker.join(2)
    if worker.is_alive() or peer_errors:raise AssertionError({'peer_errors':peer_errors,'thread_alive':worker.is_alive()})
    if services!=['host:transport-id:23','shell,v2,raw:fixture-one-observation']:
        raise AssertionError({'unexpected_services':services})
    return {'mode':mode,'budget_seconds':budget,'elapsed_seconds':elapsed,
            'result':result,'error':error,'socket_closed':closed,
            'connection_count':len(connections),'shell_service_requests':1,
            'service_requests':services,'fixture_thread_joined':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original',type=Path,required=True)
    parser.add_argument('--candidate',type=Path)
    parser.add_argument('--candidate-sha256')
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    if args.out.exists():raise RuntimeError('output_exists')
    baseline=exercise(load_source(args.original,ORIGINAL_SHA),'drip')
    reproduced=(baseline['error'] is None and baseline['result']['rc']==0
                and baseline['elapsed_seconds']>1.5*baseline['budget_seconds']
                and baseline['socket_closed'] and baseline['connection_count']==1)
    if not reproduced:raise AssertionError({'reproduction_failed':baseline})
    report={'schema':'hepta.sender-socket-deadline-source-review.v1',
            'original_sha256':ORIGINAL_SHA,'baseline_exceeds_requested_total_timeout':True,
            'baseline':baseline,'phone_calls':0,'adb_daemon_connections':0,
            'native_dispatches':0,'remote_process_cleanup_verified':False,
            'bound01_exit137_root_cause':None,'frozen_R6_adopted':False,'fixed19_credit':0}
    if args.candidate is not None:
        if not args.candidate_sha256:raise RuntimeError('candidate_pin_required')
        results={mode:exercise(load_source(args.candidate,args.candidate_sha256),mode)
                 for mode in ('drip','killed','success','silence')}
        for mode in ('drip','silence'):
            r=results[mode]
            if (not r['error'] or r['error']['type']!='TimeoutError'
                    or r['result'] is not None or r['elapsed_seconds']>r['budget_seconds']+0.15):
                raise AssertionError({'candidate_deadline_failed':r})
        for mode in ('killed','success'):
            r=results[mode]
            if r['error'] is not None or r['result']['rc']!=(137 if mode=='killed' else 0):
                raise AssertionError({'candidate_result_changed':r})
        if not all(r['socket_closed'] and r['connection_count']==1 and r['shell_service_requests']==1
                   and r['fixture_thread_joined'] for r in results.values()):
            raise AssertionError('candidate cleanup or no-retry fixture failed')
        # Budget consumed by the route precheck must not admit a shell connection.
        module=load_source(args.candidate,args.candidate_sha256)
        attempted=[]
        def late_route(_config,*_args,**_kwargs):
            time.sleep(0.04);return (5037,'23')
        def forbidden_connection(*_args,**_kwargs):
            attempted.append(True);raise AssertionError('connection after expired route')
        module.route=late_route
        module.socket=types.SimpleNamespace(create_connection=forbidden_connection)
        try:module.shell('fixture-one-observation',{},(5037,'23'),timeout=0.02)
        except TimeoutError:pass
        else:raise AssertionError('expired route did not raise timeout')
        if attempted:raise AssertionError('expired route reached connection')
        report.update(candidate_sha256=args.candidate_sha256,candidate_results=results,
                      candidate_route_expiry_zero_connections=True,candidate_controls_passed=5)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    with args.out.open('x') as stream:json.dump(report,stream,sort_keys=True,indent=2);stream.write('\n')
    print(json.dumps({'baseline_reproduced':reproduced,'baseline_seconds':baseline['elapsed_seconds'],
                      'budget_seconds':baseline['budget_seconds'],
                      'candidate_controls_passed':report.get('candidate_controls_passed',0),
                      'phone_calls':0,'fixed19_credit':0}))


if __name__=='__main__':main()
