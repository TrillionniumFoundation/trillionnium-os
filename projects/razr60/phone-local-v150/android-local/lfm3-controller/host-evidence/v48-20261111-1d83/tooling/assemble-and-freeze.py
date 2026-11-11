from pathlib import Path,PurePosixPath
import hashlib,json,subprocess,sys,tarfile
build_root=Path("/home/alex/hepta-local-1d83-20261111/v48-build-r1")
pins={"mac-artifacts.tar.gz":"de50a0a036745e7ba4f4d803d05bcc1db4dac807070135ab32fef362de7291ba","v48_assembly_filled.py":"d2339f831158c95636440aef77b268ddc801dbee2b84c05ab28f2b2672288bac","PACKAGE.json":"ec4d454d4ca04da712a5af5c48c168704f09feb61ceb9df0177587f7eecd1c69","portable-freeze-v48.tar.gz":"f07c0c32a0ba93708083b6bcf167ad4487982469e38a1065eaa5a4bf0fc10a0c","own-cooperative-owner.py":"8925718527df04479374df4f37cda628cf54c298e5ea55c8b252e284ad6c87d1"}
for name,pin in pins.items():
 p=build_root/name
 assert p.is_file() and not p.is_symlink() and hashlib.sha256(p.read_bytes()).hexdigest()==pin, name
subprocess.run([sys.executable,'-B',str(build_root/'v48_assembly_filled.py')],check=True,timeout=900)
receipt=json.loads((build_root/'assembly-r1/RESULT.json').read_bytes())
assert receipt['all_pass'] is True and receipt['source_commit']=="588e79570b87417dbbc754ecec1ca4fc5a0012ba" and receipt['version_code']==48
dest=build_root/'phone-freeze-inputs'
assert not dest.exists()
with tarfile.open(build_root/'portable-freeze-v48.tar.gz','r:gz') as tar:
 members=tar.getmembers()
 assert len(members)==14 and len({m.name for m in members})==14
 contents={}
 for member in members:
  rel=PurePosixPath(member.name)
  assert member.isfile() and not rel.is_absolute() and '..' not in rel.parts and member.size<=262144
  raw=tar.extractfile(member).read()
  assert len(raw)==member.size
  contents[member.name]=raw
 manifest=json.loads(contents['PORTABLE-MANIFEST.json'])
 assert manifest['schema']=='hepta.v48-portable-freezer.v1' and len(manifest['files'])==13
 assert {r['path'] for r in manifest['files']}==set(contents)-{'PORTABLE-MANIFEST.json'}
 for row in manifest['files']:
  raw=contents[row['path']]
  assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']
 dest.mkdir(mode=0o700)
 for name,raw in contents.items():
  p=dest/name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
  with p.open('xb') as f:f.write(raw)
args=[sys.executable,'-B',str(dest/'derive_v48.py'),'--base',str(dest/'base'),'--source',str(build_root/'source'),'--out',str(build_root/'phone-adapters-v48'),'--build-receipt',str(build_root/'assembly-r1/RESULT.json'),'--source-inventory',str(build_root/'SOURCE-INVENTORY.json'),'--package-receipt',str(build_root/'PACKAGE.json'),'--source-package',str(build_root/'candidate-source.tar.gz'),'--assembly-script',str(build_root/'v48_assembly_filled.py'),'--apk',str(build_root/'out/hepta-local-0.48.0.apk')]
subprocess.run(args,check=True,timeout=120)
print(json.dumps({'stage':'assembly_and_phone_adapter_freeze','passed':True,'phone_contacted':False,'apk_sha256':receipt['apk_sha256']}))
