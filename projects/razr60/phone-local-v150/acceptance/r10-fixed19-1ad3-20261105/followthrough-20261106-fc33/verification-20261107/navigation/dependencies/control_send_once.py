from pathlib import Path
import hashlib,json,os,re,shlex,time,types,xml.etree.ElementTree as ET
m=Path('/home/alex/codex-preserved-ui-root12-materials-20261101-01');p=m/'preserved_ui_package_phase_r7.py';b=p.read_bytes();assert hashlib.sha256(b).hexdigest()=='6d7597e55af1ba8330029352076b2c6715172056e6ea28dea97b57c7775fd35b'
f=types.ModuleType('actual_app_fixed_turn');f.__file__=str(p);exec(compile(b,str(p),'exec'),f.__dict__);c=json.loads((m/'preserved-ui-package-config.json').read_text());t=f.route(c)
assert f.read('cat /proc/sys/kernel/random/boot_id',c,t)=='f8019f83-20a7-4f18-bea1-51c980621e4d'
assert f.read('getprop sys.usb.config',c,t)=='adb'
assert f.read('getenforce',c,t)=='Enforcing'
root=lambda q:f.shell('/debug_ramdisk/su -c '+shlex.quote(q),c,t)
assert root('getprop trillionnium.owner_open.ready')['stdout'].strip()=='1'
expected='Verify control of Moto ZY22LS7WZT. Use only adb.exec to request these exact argv arrays, one call at a time, each once, in this order: [["-s","ZY22LS7WZT","shell","getprop ro.serialno; dumpsys activity activities | grep topResumedActivity"],["-s","ZY22LS7WZT","shell","am start -W -a android.settings.SETTINGS; dumpsys activity activities | grep topResumedActivity"],["-s","ZY22LS7WZT","shell","input keyevent 4; sleep 1; dumpsys activity activities | grep topResumedActivity"]]. Wait for each real tool.result before the next call. If any tool fails or its result is unknown, stop and report it; do not retry or use alternative commands. Do not access files or private app content, change settings, manage ADB or USB, reboot, send messages, or use shell.exec. After all three results, report the observed device serial and foreground activity for each step. Say HEPTA_MOTO_CONTROL_OK only if the serial is ZY22LS7WZT, step 2 opened com.android.settings, and step 3 returned to org.trillionnium.owneropen.'
assert expected.isascii()
out=Path('/home/alex/codex-stock16-hepta-control-once-root-v146-r1');os.umask(0o077);out.mkdir(mode=0o700,exist_ok=False)
def save(n,v):
 with (out/n).open('x') as s:json.dump(v,s,ensure_ascii=False,indent=2);s.write('\n');s.flush();os.fsync(s.fileno())
 fd=os.open(out,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def sh(q):
 r=f.shell(q,c,t,timeout=25);assert r['rc']==0,r;return r
counter=0
def dump(tag):
 global counter
 counter+=1;path='/data/local/tmp/hepta-control-v146-'+str(counter)+'.xml';r=sh('uiautomator dump '+path+'; cat '+path);save(tag+'.json',r);tree=ET.fromstring(r['stdout'][r['stdout'].index('<?xml'):]);assert any(n.attrib.get('package')=='org.trillionnium.owneropen' for n in tree.iter('node'));return list(tree.iter('node'))
def node(nodes,rid):
 hits=[n for n in nodes if n.attrib.get('resource-id')==rid];assert len(hits)==1,(rid,len(hits));return hits[0]
def tap(n):
 assert n.attrib.get('enabled')=='true';a=list(map(int,re.findall(r'\d+',n.attrib['bounds'])));return sh('input tap '+str((a[0]+a[2])//2)+' '+str((a[1]+a[3])//2))
sh('svc power stayon usb; input keyevent 224; wm dismiss-keyguard; am start -W -n org.trillionnium.owneropen/.OwnerOpenShellActivity')
nodes=dump('INITIAL')
for index in range(2):
 if any(n.attrib.get('resource-id')=='org.trillionnium.owneropen:id/ui_prompt' for n in nodes):break
 dismiss=[n for n in nodes if n.attrib.get('package')=='org.trillionnium.owneropen' and n.attrib.get('resource-id')=='android:id/button2' and n.attrib.get('text') in ('关闭','返回','完成') and n.attrib.get('clickable')=='true']
 assert len(dismiss)==1,'Unknown modal retained, no Send'
 tap(dismiss[0]);nodes=dump('DISMISSED-INFO-'+str(index))
status=[n.attrib.get('text','') for n in nodes if n.attrib.get('resource-id')=='org.trillionnium.owneropen:id/ui_control_status']
if any('暂停' in value for value in status):
 tap(node(nodes,'org.trillionnium.owneropen:id/ui_tools'));nodes=dump('INITIALIZE-MENU')
 initialize=[n for n in nodes if n.attrib.get('clickable')=='true' and n.attrib.get('content-desc','').startswith('启用新任务')];assert len(initialize)==1
 tap(initialize[0]);nodes=dump('INITIALIZE-CONFIRM');positive=node(nodes,'android:id/button1');assert positive.attrib.get('text')=='启用新任务';tap(positive);time.sleep(0.5);nodes=dump('INITIALIZED')
 assert not any('暂停' in n.attrib.get('text','') for n in nodes if n.attrib.get('resource-id')=='org.trillionnium.owneropen:id/ui_control_status'),'Initialization held; no Send'
editor=node(nodes,'org.trillionnium.owneropen:id/ui_prompt');existing=editor.attrib.get('text','');assert existing in ('','发消息或交代任务…','发消息或交代任务...',expected),('Unknown draft retained, not changed',existing)
if existing!=expected:
 tap(editor);sh('input text '+shlex.quote(expected.replace(' ','%s')))
nodes=dump('VERIFIED-DRAFT');assert node(nodes,'org.trillionnium.owneropen:id/ui_prompt').attrib['text']==expected
tap(node(nodes,'org.trillionnium.owneropen:id/ui_tools'));nodes=dump('CONNECT-MENU');tap(node(nodes,'org.trillionnium.owneropen:id/ui_reconnect'));time.sleep(0.5)
nodes=dump('HELLO-AND-DRAFT');assert any(n.attrib.get('text')=='已连接' for n in nodes),'No actual hello UI; Send held';assert node(nodes,'org.trillionnium.owneropen:id/ui_prompt').attrib['text']==expected
summary=[n for n in nodes if n.attrib.get('resource-id')=='org.trillionnium.owneropen:id/ui_task_summary']
if summary:tap(summary[0])
else:
 tap(node(nodes,'org.trillionnium.owneropen:id/ui_tools'));nodes=dump('OLD-TASK-MENU');tap(node(nodes,'org.trillionnium.owneropen:id/ui_inspect'))
nodes=dump('OLD-TASK-CONTROLS');tap(node(nodes,'org.trillionnium.owneropen:id/ui_inspect'));time.sleep(0.5);nodes=dump('ORIGINAL-TASK-RECONCILED')
assert node(nodes,'org.trillionnium.owneropen:id/ui_prompt').attrib['text']==expected
send=node(nodes,'org.trillionnium.owneropen:id/ui_send');save('SEND.once.json',{'prompt':expected,'prompt_sha256':hashlib.sha256(expected.encode()).hexdigest(),'bounds':send.attrib['bounds'],'automatic_replay':False})
try:r=tap(send);save('SEND.result.json',r)
except Exception as e:save('SEND.unknown.json',{'error':str(e),'next':'Inspect original identity only; never resubmit'});raise
print(json.dumps({'state':'MOTO_CONTROL_TURN_SEND_DISPATCHED_ONCE','out':str(out),'route':t,'prompt':expected,'prompt_sha256':hashlib.sha256(expected.encode()).hexdigest()}))
