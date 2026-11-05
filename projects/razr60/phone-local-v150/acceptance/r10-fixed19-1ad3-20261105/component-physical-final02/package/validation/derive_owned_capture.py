#!/usr/bin/env python3
"""Extract the already reviewed host capture methods without changing their bodies."""
import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DONOR = ROOT/'transport_fix/root-runtime-properties-transport-r6-20261105-1ad3/source/run_component_root_once.py'
EXPECTED = '0374a8858a26114a6184e2e40949e33dbb9b0014117ce4637b55b72e7629a5bd'
raw = DONOR.read_bytes()
assert len(raw)==68481 and hashlib.sha256(raw).hexdigest()==EXPECTED
source = raw.decode()
tree = ast.parse(raw)
functions = ['need','sha','enc','strict','desc','read','pin','put','syncdir','newdir','original_stream',
    'close_streams_owned','finish_stream','filedesc','capture_stat','close_unclaimed_capture_readers',
    'capture_output_worker','write_captured_output','capture_observation']
constants = ['HOST_OUTPUT_LIMIT','HOST_CAPTURE_POLL','HOST_CAPTURE_STOP_WAIT']
methods = ['stop_host_capture','persist_host_capture','verify_host_capture_outputs',
    'join_host_capture','execute_process','close_owned_host_outputs']
selected = []
for node in tree.body:
    if isinstance(node,(ast.Import,ast.ImportFrom)):
        selected.append(node)
    elif isinstance(node,ast.FunctionDef) and node.name in functions:
        selected.append(node)
    elif isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) \
            and node.targets[0].id in constants:
        selected.append(node)
chain = next(node for node in tree.body if isinstance(node,ast.ClassDef) and node.name=='Chain')
picked = [node for node in chain.body if isinstance(node,ast.FunctionDef) and node.name in methods]
assert len(picked)==len(methods)
body = '#!/usr/bin/env python3\n"""Owned host child capture; exact 0374 function/method bodies, independent constructor."""\n'
body += '\n\n'.join(ast.get_source_segment(source,node) for node in selected)+'\n\n'
body += '''class OwnedCapture:
    def __init__(self,out):
        out=Path(out)
        need(out.is_absolute() and out.parent.resolve(strict=True)==out.parent,
             'canonical owned host capture parent required')
        need(not out.exists() and not out.is_symlink(),'owned capture directory already exists')
        newdir(out)
        self.out=out
        self.steps=[]
'''
for node in picked:
    lines = source.splitlines(keepends=True)[node.lineno-1:node.end_lineno]
    body += '\n'+''.join(lines)
new = body.encode()
compile(new,'owned_capture.py','exec')
parsed = ast.parse(new)
original_nodes = {node.name:node for node in selected if isinstance(node,ast.FunctionDef)}
new_nodes = {node.name:node for node in parsed.body if isinstance(node,ast.FunctionDef)}
assert set(original_nodes)==set(new_nodes)==set(functions)
for name,node in original_nodes.items():
    assert ast.dump(node,include_attributes=False)==ast.dump(new_nodes[name],include_attributes=False)
new_class = next(node for node in parsed.body if isinstance(node,ast.ClassDef))
new_methods = {node.name:node for node in new_class.body if isinstance(node,ast.FunctionDef)}
for node in picked:
    assert ast.dump(node,include_attributes=False)==ast.dump(new_methods[node.name],include_attributes=False)
for name in constants:
    old = next(n for n in selected if isinstance(n,ast.Assign) and n.targets[0].id==name)
    newnode = next(n for n in parsed.body if isinstance(n,ast.Assign) and n.targets[0].id==name)
    assert ast.dump(old,include_attributes=False)==ast.dump(newnode,include_attributes=False)
out = Path(__file__).resolve().parents[1]/'source'
out.mkdir(mode=0o700,exist_ok=True)
target=out/'owned_capture.py'
assert not target.exists()
target.write_bytes(new)
report={'schema':'hepta.physical-component.owned-capture-derivation.v1','donor_sha256':EXPECTED,
    'output':{'path':str(target),'bytes':len(new),'sha256':hashlib.sha256(new).hexdigest()},
    'unchanged_function_bodies':functions,'unchanged_method_bodies':methods,
    'unchanged_limits':constants,'new_logic':'private create-only standalone constructor only',
    'phone_calls':0,'process_starts':0,'signals_sent':0,'qualification_claimed':False}
(Path(__file__).parent/'CAPTURE-DERIVATION.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps(report,sort_keys=True))
