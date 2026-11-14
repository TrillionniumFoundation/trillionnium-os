#!/usr/bin/env python3
"""Reproduce helper7 from this complete source/resource closure and exact dependency pins.
Outputs are new and unsigned. No phone access, key access, downloaded inputs, or reused classes/DEX.
The original helper6 resource table is retained; seven fresh R sources must match its source contract.
"""
import argparse,hashlib,io,json,os,pathlib,stat,struct,subprocess,time,zipfile
ROOT=pathlib.Path(__file__).resolve().parent
p=argparse.ArgumentParser()
p.add_argument('--output',type=pathlib.Path,required=True)
p.add_argument('--java-home',type=pathlib.Path)
p.add_argument('--android-jar',type=pathlib.Path)
p.add_argument('--aapt2',type=pathlib.Path)
p.add_argument('--r8',type=pathlib.Path)
p.add_argument('--runtime-jars-root',type=pathlib.Path)
args=p.parse_args();SOURCE=ROOT/'source';OUT=args.output.resolve()
track={}
def need(ok,msg):
 if not ok:raise RuntimeError(msg)
def sha(data):return hashlib.sha256(data).hexdigest()
def enc(v):return (json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
def read(p,expected=None,size=None):
 p=pathlib.Path(p);a=p.lstat();need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=64<<20,'bounded ordinary file '+str(p));data=p.read_bytes();b=p.lstat()
 key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 need(key(a)==key(b) and len(data)==a.st_size,'stable bytes '+str(p))
 if expected:need(sha(data)==expected,'SHA '+str(p))
 if size is not None:need(len(data)==size,'size '+str(p))
 track[str(p)]=(sha(data),key(a));return data
def ref(p,data=None):
 if data is None:data=read(p)
 return {'path':str(p),'bytes':len(data),'sha256':sha(data)}
def put(p,data):
 p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 need(p.read_bytes()==data,'output readback');return ref(p,data)
def zipdata(data):
 with zipfile.ZipFile(io.BytesIO(data)) as z:
  need(z.testzip() is None,'ZIP CRC');out={}
  for i in z.infolist():
   if i.is_dir():continue
   n=i.filename;need(n not in out and not n.startswith('/') and '..' not in pathlib.PurePosixPath(n).parts and not i.flag_bits&1,'safe unique ZIP');out[n]=z.read(i)
  return out
def layout(data):
 with zipfile.ZipFile(io.BytesIO(data)) as z:
  i=z.getinfo('resources.arsc');off=i.header_offset;name,extra=struct.unpack_from('<HH',data,off+26);at=off+30+name+extra
  need(i.compress_type==0 and struct.unpack_from('<H',data,off+8)[0]==0 and at%4==0,'stored aligned resources')
  return {'method':0,'data_offset':at,'data_offset_mod4':at%4}
def run(name,argv,timeout=180):
 begin=time.monotonic();env={k:v for k,v in os.environ.items() if k not in ('CLASSPATH','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS')};p=subprocess.run(list(map(str,argv)),capture_output=True,timeout=timeout,env=env);so=put(OUT/(name+'.stdout'),p.stdout);se=put(OUT/(name+'.stderr'),p.stderr)
 result['steps'].append({'name':name,'argv':list(map(str,argv)),'exit_code':p.returncode,'elapsed_seconds':time.monotonic()-begin,'stdout':so,'stderr':se})
 need(p.returncode==0,name+' failed: '+p.stderr.decode(errors='replace')[-5000:])

pinraw=read(ROOT/'BUILD-PINS.json','77261c3741563b1db2a624bf014727588b839465d84e119e5e43f45b42d22104')
pins=json.loads(pinraw)
inventory_raw=read(ROOT/'SOURCE-INVENTORY.json',pins['source_inventory_sha256'])
inventory=json.loads(inventory_raw)['files']
base_raw=read(ROOT/'provenance/BASE-SOURCE-INVENTORY.json',pins['base_source_inventory_sha256'])
base=json.loads(base_raw)['files']
need(len(inventory)==44 and len(base)==43,'complete helper7/helper6 source inventory')
sources={str(p.relative_to(SOURCE)):read(p) for p in sorted(SOURCE.rglob('*')) if p.is_file()}
need(len(sources)==44 and len([p for p in sources if p.endswith('.java')])==42,'complete runtime44/Java42')
need(set(sources)=={v['path'] for v in inventory},'exact source membership')
for row in inventory:need(len(sources[row['path']])==row['bytes'] and sha(sources[row['path']])==row['sha256'],'source pin '+row['path'])
preimages={v['path'].removeprefix('reference-helper6/'):v for v in pins['helper6_source_preimages']}
changed=[]
for row in base:
 name=row['path'];need(name in sources,'original runtime member retained')
 if name in preimages:
  entry=preimages[name];original=read(ROOT/entry['path'],entry['sha256'],entry['bytes'])
 else:original=sources[name]
 need(len(original)==row['bytes'] and sha(original)==row['sha256'],'exact helper6 source preimage '+name)
 if original!=sources[name]:changed.append(name)
added=set(sources)-{x['path'] for x in base}
expected={'AndroidManifest.xml','src/org/trillionnium/hepta/webhelper/EvidenceFiles.java','src/org/trillionnium/hepta/webhelper/EvidenceService.java','src/org/trillionnium/hepta/webhelper/EvidenceSession.java','src/org/trillionnium/hepta/webhelper/TaskBinding.java','src/org/trillionnium/hepta/webhelper/Jsons.java','src/org/trillionnium/hepta/webprotocol/WebEvidenceProtocol.java'}
need(set(changed)==expected and added=={'src/org/trillionnium/hepta/webprotocol/WebCaptureAcknowledgement.java'},'exact helper production8 delta')
need(sha(sources['assets/readonly_dom.js'])=='05bb7c1e4e1929b961c42af1e5c0e01918bf6ff64f153132ca11c7d85873e705','original observer')
tool_paths={}
for row in pins['tool_inputs']:
 name=pathlib.Path(row['path']).name;actual=pathlib.Path(row['path'])
 if name in ('java','javac') and args.java_home:actual=args.java_home/'bin'/name
 if name=='android.jar' and args.android_jar:actual=args.android_jar
 if name=='aapt2' and args.aapt2:actual=args.aapt2
 if name=='r8-8.13.17.jar' and args.r8:actual=args.r8
 read(actual,row['sha256'],row['bytes']);tool_paths[name]=actual
tools=tool_paths;jars=[]
for row in pins['runtime_library_jars']:
 original=pathlib.Path(row['path']);actual=(args.runtime_jars_root/original.parent.name/original.name) if args.runtime_jars_root else original
 read(actual,row['sha256'],row['bytes']);jars.append(actual)
need(len(jars)==14,'14 pinned runtime JARs')
resources=[]
for row in pins['compiled_resource_archives']:
 path=ROOT/row['path'];read(path,row['sha256'],row['bytes']);resources.append(path)
seedrow=pins['resource_seed'];seed=zipdata(read(ROOT/seedrow['path'],seedrow['sha256'],seedrow['bytes']))
seedproof=json.loads(read(ROOT/'provenance/RESOURCE-SEED.json'))
need(len(seed)==370 and set(seed)=={r['name'] for r in seedproof['members']},'complete 370 original resource payloads')
for row in seedproof['members']:need(len(seed[row['name']])==row['bytes'] and sha(seed[row['name']])==row['sha256'],'seed member '+row['name'])
need('classes.dex' not in seed and 'AndroidManifest.xml' not in seed and not any(n.startswith('lib/') for n in seed),'no precompiled app DEX/native payload')
need(not OUT.exists(),'new output stage');OUT.mkdir(parents=True)
for name in ['generated','classes','dex']:(OUT/name).mkdir()
result={'schema':'hepta.helper7-source-closure-build.v1','all_pass':False,'started_epoch':time.time(),'phone_operations':0,'installed':False,'signed':False,'helper_version_code':7,'helper_version_name':'0.7.0-web-evidence-v4','build_pins':ref(ROOT/'BUILD-PINS.json',pinraw),'base_source_inventory_sha256':sha(base_raw),'source_inventory_sha256':sha(inventory_raw),'source_inputs':inventory,'source_file_count':44,'runtime_java_input_count':42,'production_delta':sorted(changed+list(added)),'steps':[]}
try:
 result['source_inventory']=put(OUT/'SOURCE-INVENTORY.json',inventory_raw)
 result['tool_inputs']=pins['tool_inputs'];result['runtime_library_jars']=pins['runtime_library_jars']
 run('aapt2-link',[tools['aapt2'],'link','-I',tools['android.jar'],'--manifest',SOURCE/'AndroidManifest.xml','--java',OUT/'generated','--output-text-symbols',OUT/'R.txt','-o',OUT/'base.apk','--extra-packages','androidx.annotation.experimental:androidx.core:androidx.lifecycle:androidx.versionedparcelable:androidx.webkit',*resources])
 generated=sorted((OUT/'generated').rglob('*.java'));need(len(generated)==7,'generated7')
 generated_rows={str(p.relative_to(OUT/'generated')):read(p) for p in generated}
 expected_generated={x['path']:x for x in pins['generated_java_sources']}
 need(set(generated_rows)==set(expected_generated),'same seven generated R paths')
 for name,raw in generated_rows.items():
  row=expected_generated[name];need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'fresh R equals original resource contract '+name)
 java_inputs=[SOURCE/name for name in sorted(sources) if name.endswith('.java')]
 run('javac',[tools['javac'],'--release','8','-encoding','UTF-8','-proc:none','-classpath',os.pathsep.join(map(str,[tools['android.jar'],*jars])),'-d',OUT/'classes',*java_inputs,*generated])
 class_files=sorted((OUT/'classes').rglob('*.class'));need(len(class_files)>166,'actual fresh classes include ACK')
 run('d8',[tools['java'],'-cp',tools['r8-8.13.17.jar'],'com.android.tools.r8.D8','--lib',tools['android.jar'],'--min-api','30','--output',OUT/'dex',*class_files,*jars],240)
 dex_files=sorted((OUT/'dex').glob('*'));need([p.name for p in dex_files]==['classes.dex'],'one fresh DEX');dex=read(dex_files[0]);need(dex.startswith(b'dex\n'),'actual DEX format')
 fresh=zipdata(read(OUT/'base.apk'));need(set(fresh)=={'AndroidManifest.xml','resources.arsc'}|{n for n in seed if n.startswith('res/')},'same resource membership')
 need(all(fresh[n]==seed[n] for n in fresh if n not in ('AndroidManifest.xml','resources.arsc')),'all ordinary resource file bytes unchanged')
 payload=dict(seed);payload['AndroidManifest.xml']=fresh['AndroidManifest.xml'];payload['classes.dex']=dex
 need(payload['assets/readonly_dom.js']==sources['assets/readonly_dom.js'],'observer APK asset exact source')
 expected_payload={v['name']:v for v in pins['expected_payloads']}
 need(set(payload)==set(expected_payload) and len(payload)==372,'expected complete APK membership')
 for name,data in payload.items():
  row=expected_payload[name];need(len(data)==row['bytes'] and sha(data)==row['sha256'],'fresh compiled APK payload pin '+name)
 target=io.BytesIO()
 with zipfile.ZipFile(target,'w') as z:
  for name,data in sorted(payload.items()):
   info=zipfile.ZipInfo(name,(1980,1,1,0,0,0));info.external_attr=0o100644<<16;info.compress_type=zipfile.ZIP_STORED if name=='resources.arsc' else zipfile.ZIP_DEFLATED
   if info.compress_type==zipfile.ZIP_STORED:
    pad=(-(target.tell()+30+len(name.encode())))%4
    if pad:info.extra=struct.pack('<HH',0xffff,pad)+bytes(pad)
   z.writestr(info,data)
 final=target.getvalue();need(zipdata(final)==payload,'whole APK payload roundtrip')
 need(sha(final)==pins['expected_unsigned_apk_sha256'] and len(final)==pins['expected_unsigned_apk_bytes'],'byte-exact original fresh helper7 unsigned build reproduction')
 result['resource_layout']=layout(final);result['unsigned_apk']=put(OUT/'helper7-unsigned.apk',final)
 result['compiled_members']=[ref(p) for p in class_files];result['dex']=ref(dex_files[0],dex)
 result['generated_sources']=[{'path':p,'bytes':len(d),'sha256':sha(d)} for p,d in sorted(generated_rows.items())]
 result['original_resource_payloads_preserved']=True;result['resource_table_source']='original helper6 payload, all7 fresh generated R classes equal original';result['fresh_resource_table_sha256']=sha(fresh['resources.arsc']);result['packaged_resource_table_sha256']=sha(payload['resources.arsc'])
 result['compiled_payloads']=[{'name':p,'bytes':len(d),'sha256':sha(d)} for p,d in sorted(payload.items())]
 result['java_compiled_here']=True;result['dex_compiled_here']=True;result['manifest_linked_here']=True;result['byte_exact_unsigned_reproduced']=True
 run('badging',[tools['aapt2'],'dump','badging',OUT/'helper7-unsigned.apk'])
 bad=(OUT/'badging.stdout').read_text();need("name='org.trillionnium.hepta.webhelper' versionCode='7' versionName='0.7.0-web-evidence-v4'" in bad and "sdkVersion:'30'" in bad and "targetSdkVersion:'35'" in bad and 'native-code:' not in bad,'actual package7/SDK/no native')
 result['all_pass']=True
except Exception as e:
 import traceback
 result['error']=str(e);put(OUT/'ERROR.txt',traceback.format_exc().encode())
finally:
 result['source_inputs_unchanged']=all(read(SOURCE/name)==raw for name,raw in sources.items());result['all_pass']=result['all_pass'] and result['source_inputs_unchanged'];result['finished_epoch']=time.time()
 result['input_reads']=[{'path':p,'sha256':v[0],'identity':v[1]} for p,v in sorted(track.items())]
 receipt=put(OUT/'RESULT.json',enc(result));print(json.dumps({'all_pass':result['all_pass'],'error':result.get('error'),'source_inventory':result.get('source_inventory'),'unsigned_apk':result.get('unsigned_apk'),'result':receipt},ensure_ascii=False))
raise SystemExit(0 if result['all_pass'] else 1)
