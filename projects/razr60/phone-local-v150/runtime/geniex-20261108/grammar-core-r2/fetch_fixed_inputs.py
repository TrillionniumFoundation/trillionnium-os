import json,hashlib,subprocess,os,tarfile,urllib.request,re,time
from pathlib import Path
os.umask(0o077)
request=json.load(__import__("sys").stdin)
base=Path("/home/alex/razr60-local-model-v150/offline-gpu-integration-20261108")
out=base/"grammar-core-r2-build-inputs"
out.mkdir(mode=0o700,exist_ok=False)
(out/"logs").mkdir()
(out/"SOURCE-SELECTION.json").write_text(json.dumps(request,indent=2)+"\n")
ab=base/"grammar-core-r2-abi-baseline"
old=json.loads((ab/"ABI-BASELINE.json").read_text())
corrected={"schema":"hepta.qairt-core-abi-baseline-dynamic-correction.v1","original_file_sha256":hashlib.sha256((ab/"ABI-BASELINE.json").read_bytes()).hexdigest(),"reason":"Correct overescaped parser; original raw readelf outputs and baseline preserved","libraries":[]}
for row in old["libraries"]:
 name=Path(row["file"]).name
 raw=(ab/(name+".dynamic.stdout")).read_bytes()
 s=raw.decode()
 corrected["libraries"].append({"file":row["file"],"sha256":row["sha256"],"raw_dynamic_sha256":hashlib.sha256(raw).hexdigest(),"soname":re.findall(r"\(SONAME\).*?\[(.*?)\]",s),"needed":re.findall(r"\(NEEDED\).*?\[(.*?)\]",s)})
(ab/"ABI-DYNAMIC-CORRECTION.json").write_text(json.dumps(corrected,indent=2)+"\n")
print(json.dumps({"stage":"original_dynamic","data":corrected}),flush=True)
env=dict(os.environ,GIT_TERMINAL_PROMPT="0")
allfiles=[]
def run(label,argv,timeout=180):
 start=time.monotonic()
 with (out/"logs"/(label+".stdout")).open("wb") as so,(out/"logs"/(label+".stderr")).open("wb") as se:
  r=subprocess.run(argv,stdout=so,stderr=se,env=env,timeout=timeout)
 print(json.dumps({"stage":label,"returncode":r.returncode,"seconds":round(time.monotonic()-start,3)}),flush=True)
 if r.returncode: raise RuntimeError(label+" failed")
for key in ("qairt","proc"):
 cfg=request[key];root=out/key;root.mkdir()
 run(key+"-init",["/usr/bin/git","-C",str(root),"init"])
 run(key+"-remote",["/usr/bin/git","-C",str(root),"remote","add","origin","https://github.com/"+cfg["repository"]+".git"])
 run(key+"-sparse-config",["/usr/bin/git","-C",str(root),"config","core.sparseCheckout","true"])
 # Exact fixed-tree regular file patterns prevent materializing bundled DSP or model weights.
 (root/".git/info/sparse-checkout").write_text("".join("/"+e["path"]+"\n" for e in cfg["entries"]))
 run(key+"-fetch",["/usr/bin/git","-C",str(root),"-c","protocol.version=2","fetch","--filter=blob:none","--depth=1","--no-tags","origin",cfg["commit"]],240)
 run(key+"-checkout",["/usr/bin/git","-C",str(root),"checkout","--detach",cfg["commit"]],300)
 head=subprocess.check_output(["/usr/bin/git","-C",str(root),"rev-parse","HEAD"],text=True).strip()
 assert head==cfg["commit"]
 expected={e["path"]:e for e in cfg["entries"]}
 for rel,e in sorted(expected.items()):
  p=root/rel
  assert p.is_file() and not p.is_symlink(),(key,rel,"missing/nonregular")
  raw=p.read_bytes()
  blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
  assert blob==e["sha"],(key,rel,blob,e["sha"])
  assert len(raw)==e["size"],(key,rel,"size")
  allfiles.append({"input":key,"path":rel,"git_blob":blob,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()})
 print(json.dumps({"stage":key+"-verified","files":len(expected),"bytes":sum(e["size"] for e in expected.values())}),flush=True)
tc=request["toolchain"]
url="https://raw.githubusercontent.com/"+tc["repository"]+"/"+tc["commit"]+"/"+tc["path"]
with urllib.request.urlopen(urllib.request.Request(url,headers={"User-Agent":"Hepta-fixed-source-build"}),timeout=60) as r:
 raw=r.read(100000)
blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
assert blob==tc["blob_sha"]
(out/"arm64-android-llvm.cmake").write_bytes(raw)
allfiles.append({"input":"sdk","path":tc["path"],"git_blob":blob,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"url":url})
proc=base/"geniex-npu-v0.10.0/package/geniex-bench-android-arm64-v0.10.0/lib/qairt/libgeniex-proc.so"
raw=proc.read_bytes();sha=hashlib.sha256(raw).hexdigest()
assert sha=="7a1a80346ddd7d1e775a00435b87303d7794c08d3c75251bcfc5d911fa82227d"
(out/"prebuilt").mkdir()
(out/"prebuilt/libgeniex-proc.so").write_bytes(raw)
allfiles.append({"input":"official-prebuilt","path":"prebuilt/libgeniex-proc.so","bytes":len(raw),"sha256":sha})
result={"schema":"hepta.qairt-core-build-inputs.v1","phone_accessed":False,"compiler_invoked":False,"qairt_commit":request["qairt"]["commit"],"processor_commit":request["proc"]["commit"],"sdk_commit":tc["commit"],"files":allfiles}
(out/"INPUTS-MANIFEST.json").write_text(json.dumps(result,indent=2)+"\n")
archive=out/"core-r2-fixed-inputs.tar.gz"
with tarfile.open(archive,"w:gz") as t:
 for row in allfiles:
  path=(out/row["input"]/row["path"]) if row["input"] in ("qairt","proc") else (out/"arm64-android-llvm.cmake" if row["input"]=="sdk" else out/row["path"])
  arc=str(path.relative_to(out))
  t.add(path,arcname=arc,recursive=False)
 t.add(out/"SOURCE-SELECTION.json",arcname="SOURCE-SELECTION.json",recursive=False)
 t.add(out/"INPUTS-MANIFEST.json",arcname="INPUTS-MANIFEST.json",recursive=False)
raw=archive.read_bytes()
final={"stage":"ready","root":str(out),"archive":str(archive),"archive_bytes":len(raw),"archive_sha256":hashlib.sha256(raw).hexdigest(),"manifest_sha256":hashlib.sha256((out/"INPUTS-MANIFEST.json").read_bytes()).hexdigest(),"file_count":len(allfiles)}
(out/"RESULT.json").write_text(json.dumps(final,indent=2)+"\n")
print(json.dumps(final),flush=True)

