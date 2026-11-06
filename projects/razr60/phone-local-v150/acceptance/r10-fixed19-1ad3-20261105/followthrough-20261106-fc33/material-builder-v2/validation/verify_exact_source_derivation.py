"""Read-only complete source inverse; no material graph or phone operations."""
import hashlib,json
from pathlib import Path
root=Path(__file__).resolve().parent.parent
def need(value,why):
 if not value:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
a=(root/"references/derive_reviewed_source_material.original.py").read_bytes()
b=(root/"source/derive_reviewed_source_material_v2.py").read_bytes()
need(len(a)==13037 and sha(a)=="324e2a0cde4a3436284c56e7ddb3d7ab0ec51a9fab02a2af460175527030907b","complete original source pin")
need(len(b)==16348 and sha(b)=="2102adcc334c3c0a2c284a7bdd4cbfabb280ef08e3f22d4effbb923fdb8a03d8","complete candidate source pin")
t=json.loads((root/"validation/source-transforms.json").read_bytes())
s=a.decode()
need(s.count("def main():\n")==1 and s.count(t["oldSetup"])==1 and s.count(t["oldWrite"])==1,"exact transform locations")
s=s.replace("def main():\n",t["publisher"]+"def main():\n",1).replace(t["oldSetup"],"",1).replace(t["oldWrite"]," publish_material(out,files)\n",1)
need(s.encode()==b,"full forward reconstruction")
s=s.replace(t["publisher"],"",1).replace(" files.update({'reference/'",""+t["oldSetup"]+" files.update({'reference/'",1).replace(" publish_material(out,files)\n",t["oldWrite"],1)
need(s.encode()==a,"full inverse reconstruction")
compile(b,"reviewed_material_v2","exec")
print(json.dumps({"state":"PASS_SOURCE_ONLY","complete_forward":True,"complete_inverse":True,"phone_calls":0,"actual_BUILD":False,"actual_READY":False},sort_keys=True))
