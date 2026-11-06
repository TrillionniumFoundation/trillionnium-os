#!/usr/bin/env python3
"""Repeat the four recorded refusal controls without writing or dispatching."""
import hashlib
import json
from pathlib import Path
import types

ROOT=Path(__file__).resolve().parent

def main():
    p=ROOT/'bind_actual_controller_input.py';raw=p.read_bytes()
    m=types.ModuleType('binding_refusal_controls');m.__file__=str(p)
    exec(compile(raw,str(p),'exec'),m.__dict__)
    checks=[];calls=[]
    def callback(row):calls.append(row);raise AssertionError('unexpected original IO')
    def rejected(name,action,needle):
        try:action()
        except ValueError as error:assert needle in str(error)
        else:raise AssertionError(name)
        checks.append(dict(name=name,passed=True))
    value=dict(schema=m.SCHEMA,constructor='component_build',actual_inputs=None,output_root=None,
               execution_idempotency_key=None,execution_timeout_seconds=180)
    body=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    row=dict(path=m.B+'/CONTROL-NOT-ACTUAL.json',**m.pin(body))
    rejected('unknown actual binding slots refuse before original callback',lambda:m.prepare_controller_binding(
        body,input_descriptor=row,read_pinned=callback),'UNBOUND_ACTUAL_CONSTRUCTOR_BINDING_NO_IO')
    rejected('binding input byte drift rejected before original callback',lambda:m.prepare_controller_binding(
        body+b' ',input_descriptor=row,read_pinned=callback),'complete explicitly selected binding input bytes')
    for n in (False,float(len(body))):
        changed=dict(row,bytes=n)
        rejected('typed input descriptor rejects '+repr(n),lambda changed=changed:m.prepare_controller_binding(
            body,input_descriptor=changed,read_pinned=callback),'exact typed actual host descriptor')
    assert not calls
    result=dict(schema='hepta.fc33.actual-constructor-binding-source-controls.v1',state='UNBOUND_REFUSAL_SOURCE_CONTROLS_PASSED',
        source=m.pin(raw),checks=checks,passed=len(checks),phone_calls=0,actual_positive_binding=False,actual_BUILD=None,actual_READY=None)
    expected=json.loads((ROOT/'BINDER-CONTROL-RESULT.json').read_bytes())
    assert result==expected
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
