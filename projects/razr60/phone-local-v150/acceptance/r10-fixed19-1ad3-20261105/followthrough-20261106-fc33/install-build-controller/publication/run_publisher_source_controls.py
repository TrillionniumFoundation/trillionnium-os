#!/usr/bin/env python3
"""Repeat the four recorded publisher preparation controls; never publish to Mac."""
import json
from pathlib import Path
import tempfile
import types

ROOT=Path(__file__).resolve().parent

def main():
    p=ROOT/'publish_controller_source_package_once.py';raw=p.read_bytes()
    m=types.ModuleType('publisher_preparation_controls');m.__file__=str(p)
    exec(compile(raw,str(p),'exec'),m.__dict__)
    files,terminal,H=m.decode_payload();checks=[]
    assert len(files)==27 and terminal['source_file_count']==5
    checks.append(dict(name='complete actual prepared payload27 and five source pins validate without publication',passed=True))
    assert m.pin((ROOT/'PAYLOAD.original.json').read_bytes())==m.PAYLOAD_PIN
    checks.append(dict(name='original payload bytes match exact embedded payload pin',passed=True))
    request=json.loads((ROOT/'REQUEST.json').read_bytes())
    assert request['stdin'].encode()==raw and request['host']=='mac'and request['args']==['-I','-B','-']
    checks.append(dict(name='actual prepared controller stdin equals the complete publisher source bytes',passed=True))
    with tempfile.TemporaryDirectory(prefix='fc33-publisher-exists-control-')as directory:
        output=Path(directory);before=list(output.iterdir())
        try:H.publish_material(output,files)
        except FileExistsError:pass
        else:raise AssertionError('existing output accepted')
        assert list(output.iterdir())==before
    checks.append(dict(name='existing isolated host output rejected before any child or file mutation',passed=True))
    result=dict(schema='hepta.fc33.host-controller-source-publisher-controls.v1',
        state='FOUR_PREPARATION_AND_CREATE_ONLY_CONTROLS_PASSED_NO_ACTUAL_PUBLICATION',
        publisher=m.pin(raw),payload=m.PAYLOAD_PIN,checks=checks,passed=len(checks),actual_publication=None,
        actual_BUILD=None,actual_READY=None,phone_calls=0,actor_dispatches=0)
    assert result==json.loads((ROOT/'CONTROL-RESULT.json').read_bytes())
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
