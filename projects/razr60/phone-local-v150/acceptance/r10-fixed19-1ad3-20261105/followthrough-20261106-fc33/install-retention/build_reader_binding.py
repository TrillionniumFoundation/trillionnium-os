#!/usr/bin/env python3
"""Pure exact-RHS host-reader construction. This does not verify actual inputs or dispatch."""
import argparse,ast,hashlib,json,os,re
from pathlib import Path,PurePosixPath
PARENT_PIN = {"bytes":22066,"sha256":"a95977c049b1d1a079014480cd37b9a52414bc60c2f584c4a36e21f5f8791144"}
def need(v,m):
    if not v:raise ValueError(m)
def pin(raw):return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
def descriptor(row):
    need(type(row)is dict and set(row)=={"path","bytes","sha256"},"exact3 actual input descriptor")
    need(type(row["path"])is str and row["path"]and not any(c in row["path"]for c in "\0\r\n\t"),"plain original path")
    p=PurePosixPath(row["path"])
    need(p.is_absolute()and str(p)==row["path"]and ".."not in p.parts,"canonical absolute original path")
    need(type(row["bytes"])is int and 0<row["bytes"]<=4*1024*1024
         and type(row["sha256"])is str and re.fullmatch("[0-9a-f]{64}",row["sha256"]),"typed bounded actual input descriptor")
    return {k:row[k]for k in("path","bytes","sha256")}
def derive(template,phase_authority=None,retention_inputs=None):
    need(type(template)is bytes and pin(template)==PARENT_PIN,"exact selected unbound reader source")
    need(retention_inputs is None or phase_authority is not None,"retention needs explicit phase authority descriptor")
    output=template;edits=[]
    for field,row in (("FROZEN_PHASE_AUTHORITY",phase_authority),("FROZEN_RETENTION_INPUTS",retention_inputs)):
        original=(field+" = None\n").encode()
        need(output.count(original)==1,"one exact unbound source slot")
        if row is not None:
            replacement=(field+" = "+repr(descriptor(row))+"\n").encode()
            output=output.replace(original,replacement,1);edits.append((original,replacement))
    inverse=output
    for original,replacement in reversed(edits):
        need(inverse.count(replacement)==1,"one exact bound slot")
        inverse=inverse.replace(replacement,original,1)
    need(inverse==template,"complete source inverse")
    ast.parse(output)
    return output,dict(schema="hepta.install-retention.reader-source-construction.v1",
        state="SOURCE_ONLY_ACTUAL_DESCRIPTOR_CONTENTS_NOT_VERIFIED",
        parent=pin(template),selected=pin(output),phase_authority=phase_authority,retention_inputs=retention_inputs,
        exact_forward_inverse=True,actual_inputs_verifier_executed=False,phone_calls=0,actual_install=0,actual_READY=0,
        new_nonces=0,qualification_granted=False)
def strict(raw):
    need(0<len(raw)<=4096,"bounded descriptor JSON")
    def pairs(items):
        result={}
        for k,v in items:
            need(k not in result,"duplicate descriptor key");result[k]=v
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in()).throw(ValueError("nonfinite descriptor")))
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--phase-authority-descriptor",type=Path)
    p.add_argument("--retention-inputs-descriptor",type=Path)
    p.add_argument("--out",type=Path)
    a=p.parse_args();root=Path(__file__).resolve().parent
    phase=None if a.phase_authority_descriptor is None else descriptor(strict(a.phase_authority_descriptor.read_bytes()))
    original=None if a.retention_inputs_descriptor is None else descriptor(strict(a.retention_inputs_descriptor.read_bytes()))
    selected,facts=derive((root/"source/verify_install_retention_UNBOUND.py").read_bytes(),phase,original)
    if a.out is not None:
        a.out.mkdir(mode=0o700)
        for name,raw in (("verify_install_retention.py",selected),("SOURCE-DERIVATION.json",(json.dumps(facts,sort_keys=True,indent=2)+"\n").encode())):
            with(a.out/name).open("xb")as f:f.write(raw);f.flush();os.fsync(f.fileno())
    print(json.dumps(facts,sort_keys=True))
if __name__=="__main__":main()
