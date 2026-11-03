"""Root-only existing-transport phone actor with durable single-dispatch UI intent."""
from pathlib import Path
import argparse,datetime,json,os,subprocess,sys
base=Path(__file__).resolve().parent
ap=argparse.ArgumentParser();ap.add_argument('label');ap.add_argument('command');ap.add_argument('--root',action='store_true');ap.add_argument('--effect',action='store_true');ap.add_argument('--timeout',type=int,default=30);args=ap.parse_args()
assert all(x in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for x in args.label)
state=json.loads((base.parent/'STOCK16-HEPTA-LIVE-STATE-Root-v143.json').read_text());boot=state['phone']['boot']
record={'label':args.label,'command':args.command,'root':args.root,'effect':args.effect,'boot':boot,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
with (base/(args.label+'.intent.json')).open('x') as s:
 json.dump(record,s,ensure_ascii=False,indent=2);s.write('\n');s.flush();os.fsync(s.fileno())
fd=os.open(base,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
source='''from pathlib import Path
import hashlib,json,shlex,types
m=Path('/home/alex/codex-preserved-ui-root12-materials-20261101-01');p=m/'preserved_ui_package_phase_r7.py';b=p.read_bytes()
assert __debug__ and hashlib.sha256(b).hexdigest()=='6d7597e55af1ba8330029352076b2c6715172056e6ea28dea97b57c7775fd35b'
f=types.ModuleType('stock16_v144_actor');f.__file__=str(p);exec(compile(b,str(p),'exec'),f.__dict__)
c=json.loads((m/'preserved-ui-package-config.json').read_text());t=f.route(c)
'''
source+='expected_boot='+repr(boot)+'\ncommand='+repr(args.command)+'\n'
source+='''assert f.read('cat /proc/sys/kernel/random/boot_id',c,t)==expected_boot
assert f.read('getprop ro.build.fingerprint',c,t)=='motorola/leap_cn/leap:16/W1VL36H.59-53-11/643c83-3ed541:user/release-keys'
assert f.read('getprop sys.usb.config',c,t)=='adb'
assert f.read('getenforce',c,t)=='Enforcing'
'''
if args.root:source+="command='/debug_ramdisk/su -c '+shlex.quote(command)\n"
source+='r=f.shell(command,c,t,timeout='+str(args.timeout)+')\nprint(json.dumps(r,ensure_ascii=False))\n'
ssh=['ssh','-J','ai395-usb4','-o','HostName=10.77.0.4','-p','22','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','pocket4-usb4-fast','python3','-I','-']
try:
 p=subprocess.run(ssh,input=source.encode(),capture_output=True,timeout=args.timeout+20)
 result={'ssh_rc':p.returncode,'stdout':p.stdout.decode(errors='replace'),'stderr':p.stderr.decode(errors='replace')}
except Exception as e:result={'UNKNOWN':str(e),'automatic_replay':False}
with (base/(args.label+'.result.json')).open('x') as s:json.dump(result,s,ensure_ascii=False,indent=2);s.write('\n')
if result.get('stdout'):
 try:
  visible=json.loads(result['stdout'])
  if len(visible.get('command',''))>1200:visible['command']='Saved exact command in '+args.label+'.intent.json'
  if '<?xml' in visible.get('stdout',''):
   import xml.etree.ElementTree as ET
   tree=ET.fromstring(visible['stdout'][visible['stdout'].index('<?xml'):])
   visible['stdout']=[{k:n.attrib.get(k,'') for k in ['text','content-desc','class','resource-id','clickable','enabled','bounds']} for n in tree.iter('node') if n.attrib.get('text') or n.attrib.get('content-desc') or n.attrib.get('clickable')=='true']
  print(json.dumps(visible,ensure_ascii=False,indent=2))
 except Exception:print(result['stdout'])
else:print(json.dumps(result,ensure_ascii=False,indent=2))
sys.exit(0 if result.get('ssh_rc')==0 else 1)

