#!/usr/bin/env python3
"""Finite source/isolated-host controls. No actual BUILD or phone fixture."""
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import tempfile
import types

ROOT = Path(__file__).resolve().parent

def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def load(path, name):
    raw = path.read_bytes(); module = types.ModuleType(name); module.__file__ = str(path)
    exec(compile(raw,str(path),'exec'),module.__dict__)
    return module, raw

def main():
    S, source = load(ROOT/'derive_release_install_stages_UNBOUND.py','stage_source_controls')
    H, helper = load(ROOT/'derive_component_build_inputs_UNBOUND.py','component_source_helper')
    O, observer = load(ROOT/'observe_p4_install_phase_UNBOUND.py','p4_source_controls')
    R, unused = load(ROOT.parent/'R5-actual-release-source-chain/derived/source/verify_install_start_ready_UNBOUND.py','published_unbound_install_helper')
    checks=[]; io=[]
    def forbidden(row):
        io.append(row); raise AssertionError('unexpected actual original callback')
    def rejects(action, text):
        try: action()
        except ValueError as e:
            assert text in str(e), (text,str(e))
        else: raise AssertionError('accepted: '+text)
    def check(name, action):
        action(); checks.append(dict(name=name,passed=True))
    def must(value):
        assert value
    check('stage UNBOUND rejects before parsing or both original callbacks', lambda: rejects(
        lambda:S.derive_release_install_stage(b'invalid',read_pinned=forbidden,host_metadata=forbidden),
        'UNBOUND_ACTUAL_RELEASE_INSTALL_STAGE_NO_IO'))
    check('stage CLI UNBOUND refuses before argument parser or source reads', lambda: rejects(S.main,
        'UNBOUND_ACTUAL_RELEASE_INSTALL_STAGE_NO_IO'))
    for stage in S.STAGES:
        value=dict(schema=S.SCHEMA,stage=stage,output_root=None,actual=None)
        raw=H.encoded(value); row=dict(path=S.B+'/CONTROL-NOT-ACTUAL.json',**pin(raw))
        candidate, proof=S.bind_none(source,{'FROZEN_INPUTS':row})
        bound=types.ModuleType('bound_source_control');bound.__file__='<source-only-control>'
        exec(compile(candidate,bound.__file__,'exec'),bound.__dict__)
        check(stage+' actual slots None refuse before source/callback IO',lambda bound=bound,raw=raw:rejects(
            lambda:bound.derive_release_install_stage(raw,read_pinned=forbidden,host_metadata=forbidden),
            'UNBOUND_ACTUAL_STAGE_INPUT_NO_IO'))
    assert io==[]
    check('complete input byte drift refuses before all callback IO',lambda:rejects(
        lambda:bound.derive_release_install_stage(raw+b' ',read_pinned=forbidden,host_metadata=forbidden),
        'exact whole separately bound'))
    for n in (False,0.0):
        check('typed original descriptor rejects '+repr(n)+' as byte count',lambda n=n:rejects(
            lambda:S.exact_descriptor(dict(path=S.B+'/CONTROL',bytes=n,sha256='0'*64)),
            'typed complete actual host descriptor'))
    check('duplicate stage JSON key refuses',lambda:rejects(
        lambda:S.input_value(b'{"stage":"a","stage":"b"}'),'duplicate construction input'))
    scrambled=json.loads(json.dumps(row,sort_keys=True))
    check('descriptor JSON key reordering preserves the exact bound source bytes',lambda:must(
        S.bind_none(source,{'FROZEN_INPUTS':row})[0]==S.bind_none(source,{'FROZEN_INPUTS':scrambled})[0]))
    reversed_lines=candidate.splitlines(keepends=True)
    for change in proof['changes']:reversed_lines[change['line']-1]=change['before'].encode()
    check('whole-source literal inverse returns every original byte',lambda:must(b''.join(reversed_lines)==source))
    check('P4 observer UNBOUND refuses before any filesystem callback',lambda:rejects(
        lambda:O.run_bound(b'invalid'),'UNBOUND_P4_PHASE_FILE_OBSERVATION_NO_IO'))
    request=H.encoded(dict(kind='shell',root=True,timeout_seconds=1,command='CONTROL_SOURCE_ONLY_NEVER_EXECUTED'))
    spec=dict(schema='hepta.fc33.p4-install-phase-file-observation.v1',phase='stage',mode='prepare',
        actor=dict(path=O.P4+'/actor.py',**O.ACTOR_PIN),request_path=O.P4+'/control.request.json',
        request_base64=base64.b64encode(request).decode(),request_pin=pin(request),actor_operation_dir=O.P4+'/operations/control')
    for n in (False,float(len(request))):
        changed=dict(spec,request_pin=dict(spec['request_pin'],bytes=n))
        check('P4 observation request pin rejects '+repr(n),lambda changed=changed:rejects(
            lambda:O.validate_spec(changed),'complete exact original request bytes'))
    check('P4 specification accepts exact request bytes without executing them',lambda:must(O.validate_spec(spec)==request))
    class PureContext:
        def __init__(self):
            self.H=H;self.root=PurePosixPath(S.B+'/CONTROL-SOURCE-OUTPUT-NOT-PUBLISHED');self.files={};self.pool=self
        def read(self,row,maximum=None):
            if H.same(row,S.P4_OBSERVER):return observer
            raw=self.files[row['path']];assert pin(raw)=={k:row[k]for k in ('bytes','sha256')};return raw
        def add(self,name,body):
            path=str(self.root/name);assert path not in self.files;self.files[path]=body;return dict(path=path,**pin(body))
    pure=PureContext();identity=dict(label='control-source-only',request_path=spec['request_path'],idempotency_key='control-source-only')
    plan=dict(actor=spec['actor'],phases={'stage':identity});expected=dict(request_raw=request,actor_operation_dir=spec['actor_operation_dir'])
    request_row=S.observer_spec(pure,plan,'stage','prepare',expected)
    actual=S.expected_observer(pure,request_row,plan,'stage','prepare',expected,identity)
    check('observer request and complete bound source rederive after JSON transport',lambda:must(
        H.same(actual,json.loads(pure.read(request_row)))))
    original=pure.files[request_row['path']]
    changed=json.loads(original);changed['stdin']+='\n# changed complete source\n'
    pure.files[request_row['path']]=H.encoded(changed)
    changed_row=dict(path=request_row['path'],**pin(pure.files[request_row['path']]))
    check('changed observer source rejected by byte rederivation',lambda:rejects(
        lambda:S.expected_observer(pure,changed_row,plan,'stage','prepare',expected,identity),
        'observer source, exact binding/specification and request fully rederived'))
    with tempfile.TemporaryDirectory(prefix='fc33-install-source-control-')as directory:
        O.P4=directory;S.B=directory
        p=Path(directory)/'once.request';body=b'host-only-source-control\n'
        created=O.create_request(str(p),body)
        check('host request written exclusively and full bytes/full9 read back',lambda:must(
            p.read_bytes()==body and O.read_file(str(p),len(body))[1]==created))
        try:O.create_request(str(p),body)
        except FileExistsError:checks.append(dict(name='existing host request refuses overwrite/replay',passed=True))
        else:raise AssertionError('request overwritten')
        sub=Path(directory)/'real';sub.mkdir(mode=0o700)
        link=Path(directory)/'alias';link.symlink_to(sub,target_is_directory=True)
        check('host request symlink parent refused',lambda:rejects(
            lambda:O.create_request(str(link/'new'),body),'canonical original request parent'))
        reader=S.HostOriginals();first=dict(path=str(p),**pin(body));full=dict(first,metadata=reader.metadata(first))
        check('retained host reader independently checks supplied full9',lambda:must(reader(full)==body))
        alternate=Path(directory)/'alternate';alternate.write_bytes(body);alternate.chmod(0o600)
        other=dict(path=str(alternate),**pin(body));other['metadata']=reader.metadata(other)
        origin=dict(full,path='/home/alex/razr60-local-model-v150/CONTROL.original')
        ctx=types.SimpleNamespace(H=H,install=R,callback=reader,host_metadata=reader.metadata,pool=types.SimpleNamespace(rows={}))
        maps=[dict(namespace='pocket4',original=origin,retained=x)for x in (full,other)]
        selected=S.Context.original_catalog(ctx,maps)
        check('same original may select one of two separately verified retained full copies',lambda:must(len(selected)==1))
        check('retained alias cannot change original namespace',lambda:rejects(
            lambda:S.Context.original_catalog(ctx,[maps[0],dict(maps[1],namespace='host')]),
            'conflicting original namespace'))
        p.write_bytes(body)
        check('host reader rejects original metadata change even with same bytes',lambda:rejects(
            lambda:reader(full),'actual retained original full9'))
    check('published installation helper actual slots remain None',lambda:must(
        R.FROZEN_INPUTS is None and R.FROZEN_EXECUTION_PLAN is None))
    assert io==[]
    report=dict(schema='hepta.fc33.release-install-stage-source-controls.v1',
        state='SOURCE_AND_ISOLATED_HOST_CONTROLS_PASSED_ACTUAL_STAGES_UNBOUND',
        source=pin(source),observer=pin(observer),component_helper=pin(helper),checks=checks,passed=len(checks),
        actual_BUILD_positive=False,actual_current_component_positive=False,actual_install_positive=False,
        actual_READY_positive=False,actual_retention_positive=False,phone_calls=0,actor_dispatches=0,
        model_requests=0,fixed19_credit=0,
        limitation='Only complete future actual originals can qualify each production reader. No synthetic BUILD/READY or phone effect was used.')
    output=ROOT/'STAGE-CONTROL-RESULT.json'
    with output.open('xb')as stream:stream.write(H.encoded(report))
    print(json.dumps(report,sort_keys=True))

if __name__=='__main__':main()
