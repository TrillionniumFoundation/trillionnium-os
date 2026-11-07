#!/usr/bin/env python3
"""Verify the exact retained UI helper failure path without running an actor."""
import argparse,ast,hashlib,json,re,tempfile,types
from pathlib import Path
import xml.etree.ElementTree as ET

CONTROL_SHA='ca200ab35d39ec42232e853c785ab298958858cb4f03e2092231d1ccc638fc70'
SENDER_SHA='f90c6ffbf3278b22bf3a48bf055c5ca1cf43c3073c5cc7a852dd09a4cf2eab73'


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--ui-helper',required=True,type=Path);p.add_argument('--sender',required=True,type=Path);p.add_argument('--out',required=True,type=Path);a=p.parse_args()
 raw=a.ui_helper.read_bytes();sender=a.sender.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=CONTROL_SHA or hashlib.sha256(sender).hexdigest()!=SENDER_SHA:raise RuntimeError('source pin mismatch before compile')
 old=raw.decode();label='isolated-source-control'
 helpers=old[old.index('def save('):old.index("sh('svc power stayon")]
 # These two literal transformations are the exact statements of the pinned sender.
 transforms=["helpers = helpers.replace('hepta-control-v146-', 'hepta-natural-' + label + '-v150-')", "helpers = helpers.replace(\"'uiautomator dump '+path+'; cat '+path\", \"'test ! -e '+path+' && uiautomator dump '+path+' && cat '+path\")"]
 if not all(x in sender.decode() for x in transforms):raise RuntimeError('sender helper derivation changed')
 for transform in transforms:
  namespace={'helpers':helpers,'label':label};exec(compile(transform,'exact-pinned-sender-transform','exec'),namespace);helpers=namespace['helpers']
 tree=ast.parse(helpers)
 # Retain original sh/dump bodies only; neither sender main nor its prelude runs.
 definitions=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in ('sh','dump')]
 if len(definitions)!=2:raise RuntimeError('helper definitions differ')
 calls=[];saved=[]
 def shell(command,c,t,timeout):
  calls.append({'command':command,'timeout':timeout})
  return {'command':command,'rc':137,'route':[5037,'23'],'stdout':'','stderr':'Killed\n'}
 ns={'f':types.SimpleNamespace(shell=shell),'c':{},'t':(5037,'23'),'counter':0,'ET':ET,'save':lambda *x:saved.append(x)}
 exec(compile(ast.Module(body=definitions,type_ignores=[]),'verified-ui-helper-sh-and-dump','exec'),ns)
 try:ns['dump']('INITIAL')
 except AssertionError as e:failure=e.args[0]
 else:raise AssertionError('dump137 accepted')
 path='/data/local/tmp/hepta-natural-'+label+'-v150-1.xml'
 expected='test ! -e '+path+' && uiautomator dump '+path+' && cat '+path
 if calls!=[{'command':expected,'timeout':25}] or saved or ns['counter']!=1 or failure['rc']!=137:raise AssertionError('failure path changed')
 report={'schema':'hepta.sender-ui-dump-failure-source-control.v1','passed':1,'total':1,
         'ui_helper_sha256':CONTROL_SHA,'sender_sha256':SENDER_SHA,'wire_calls':calls,
         'original_failure_preserved':failure,'dump_attempts':1,'successful_dump_receipts':0,
         'ui_helper_fragment_evaluated':True,'sender_actor_constructions':0,
         'phone_calls':0,'native_dispatches':0,'bound01_exit137_root_cause':None,
         'remote_process_cleanup_verified':False,'frozen_R6_changed':False,'fixed19_credit':0}
 a.out.parent.mkdir(parents=True,exist_ok=True)
 with a.out.open('x') as f:json.dump(report,f,sort_keys=True,indent=2);f.write('\n')
 print(json.dumps({'passed':1,'dump_attempts':1,'sender_timeout_argument':25,'phone_calls':0,'bound01_exit137_root_cause':None}))


if __name__=='__main__':main()
