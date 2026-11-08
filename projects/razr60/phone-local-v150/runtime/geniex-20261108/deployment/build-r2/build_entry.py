import base64,hashlib,io,json,pathlib,shlex,subprocess,sys,tarfile,time
req=json.load(sys.stdin);root=pathlib.Path(req["workdir"]);root.mkdir(mode=0o700,parents=True,exist_ok=False);(root/"logs").mkdir();(root/"src").mkdir()
raw=base64.b64decode(req["archive"]["base64"],validate=True);assert len(raw)==156018 and hashlib.sha256(raw).hexdigest()=="7cd5ae788c47a266b90791ce3df7f5746779c865d35860e78f898bd2ac9fd015"
(root/"source.tar.gz").write_bytes(raw)
files=[]
with tarfile.open(fileobj=io.BytesIO(raw),mode="r:gz") as tf:
 for m in tf.getmembers():
  rel=pathlib.PurePosixPath(m.name);assert not rel.is_absolute() and ".." not in rel.parts
  if m.isdir():continue
  assert m.isfile() and m.size<2000000
  b=tf.extractfile(m).read();p=root/"src"/str(rel);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
  files.append({"path":str(rel),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()})
entry=root/"src/provider_entry.cpp"
assert hashlib.sha256(entry.read_bytes()).hexdigest()=="c1c9698c1fbc4976fdbb9ac778e932990168fc6d7d005c9a1090cbaa42784fa4"
tool=pathlib.Path(req["ndk"])/"toolchains/llvm/prebuilt/darwin-x86_64/bin";vendor=root/"src/vendor";steps=[]
def run(label,argv):
 t=time.monotonic();p=subprocess.run([str(x) for x in argv],capture_output=True,timeout=60)
 (root/"logs"/(label+".stdout")).write_bytes(p.stdout);(root/"logs"/(label+".stderr")).write_bytes(p.stderr)
 steps.append({"label":label,"argv":[str(x) for x in argv],"rc":p.returncode,"seconds":time.monotonic()-t});(root/"STEPS.json").write_text(json.dumps(steps,indent=2)+"\n")
 print(json.dumps({"label":label,"rc":p.returncode}),flush=True)
 if p.returncode:raise RuntimeError(label+": "+p.stderr.decode(errors="replace")[-6000:])
 return p.stdout
version=run("compiler-version",[tool/"aarch64-linux-android28-clang++","--version"]).decode()
run("sha256",[tool/"aarch64-linux-android28-clang","-std=c11","-O2","-Wall","-Wextra","-Werror","-Wpedantic","-I",vendor/"hash","-c",vendor/"hash/sha256/sha256.c","-o",root/"sha256.o"])
binary=root/"hepta-provider-entry"
run("entry",[tool/"aarch64-linux-android28-clang++","-std=c++17","-O2","-Wall","-Wextra","-Werror","-Wpedantic","-isystem",vendor,entry,vendor/"hash/hash.cpp",root/"sha256.o","-static-libstdc++","-o",binary])
run("strip",[tool/"llvm-strip","--strip-unneeded",binary]);elf=run("elf",[tool/"llvm-readelf","-h","-d",binary]).decode()
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
manifest={"schema":"hepta.init-provider-entry-build.v1","candidate_only":True,"deployed_to_phone":False,"source_archive_sha256":sha(root/"source.tar.gz"),"source_files":files,"compiler":version,"ndk_properties":(pathlib.Path(req["ndk"])/"source.properties").read_text(),"api":28,"host_fixture_defined":False,"steps":steps,"binary":{"bytes":binary.stat().st_size,"sha256":sha(binary)},"elf":elf}
(root/"BUILD-MANIFEST.json").write_text(json.dumps(manifest,indent=2)+"\n")
remote=req["p4dir"];ssh=["/usr/bin/ssh","-o","BatchMode=yes","-o","ConnectTimeout=10","-o","StrictHostKeyChecking=yes","hepta-pocket4"]
run("mkdir-remote",ssh+[shlex.join(["/usr/bin/python3","-c","import pathlib;pathlib.Path("+repr(remote)+").mkdir(mode=0o700,parents=True,exist_ok=False)"])])
scp=["/usr/bin/scp","-p","-o","BatchMode=yes","-o","ConnectTimeout=10","-o","StrictHostKeyChecking=yes"]
run("transfer",scp+[binary,root/"BUILD-MANIFEST.json","hepta-pocket4:"+remote+"/"])
print(json.dumps({"p4dir":remote,"manifest_sha256":sha(root/"BUILD-MANIFEST.json"),"binary":manifest["binary"]}),flush=True)
