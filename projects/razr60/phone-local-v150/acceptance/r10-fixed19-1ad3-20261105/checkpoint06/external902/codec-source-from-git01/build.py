"""Host-only reproducible DEX-jar build. Does not run or contact Android."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess,zipfile

BASE=Path(__file__).resolve().parent
SDK=Path('/Users/qianqi/Library/Android/sdk')
JDK=Path('/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home')
ANDROID=SDK/'platforms/android-34/android.jar'
TOOLS=SDK/'build-tools/34.0.0'
ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,default=BASE/'build-01');args=ap.parse_args()
OUT=args.out.resolve()
OUT.mkdir(mode=0o700,exist_ok=False)
for n in ['classes','dex']:(OUT/n).mkdir()
env=dict(os.environ)
for n in ['JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS']:env.pop(n,None)
receipt={'scope':'Host-only build; not installed or device-qualified','compile_sdk':34,'runtime_minimum_api':36,'steps':[],'inputs':{}}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
for p in sorted((BASE/'source').rglob('*.java')):receipt['inputs'][str(p.relative_to(BASE))]={'sha256':sha(p),'bytes':p.stat().st_size}
for p in [ANDROID,JDK/'bin/javac',TOOLS/'lib/d8.jar']:receipt['inputs'][str(p)]={'sha256':sha(p),'bytes':p.stat().st_size}
def run(name,args):
 p=subprocess.run([str(a) for a in args],capture_output=True,env=env,timeout=120)
 (OUT/(name+'.stdout.txt')).write_bytes(p.stdout);(OUT/(name+'.stderr.txt')).write_bytes(p.stderr)
 receipt['steps'].append({'name':name,'argv':[str(a) for a in args],'rc':p.returncode})
 (OUT/'BUILD-RECEIPT.json').write_text(json.dumps(receipt,indent=2)+'\n')
 assert p.returncode==0,name
sources=sorted((BASE/'source').rglob('*.java'))
run('javac',[JDK/'bin/javac','-J-XX:ActiveProcessorCount=2','-encoding','UTF-8','-source','8','-target','8','-bootclasspath',ANDROID,'-classpath',ANDROID,'-d',OUT/'classes',*sources])
with zipfile.ZipFile(OUT/'classes.jar','x') as z:
 for p in sorted((OUT/'classes').rglob('*.class')):
  i=zipfile.ZipInfo(str(p.relative_to(OUT/'classes')),(1980,1,1,0,0,0));i.compress_type=zipfile.ZIP_STORED;z.writestr(i,p.read_bytes())
run('d8',[JDK/'bin/java','-XX:ActiveProcessorCount=2','-cp',TOOLS/'lib/d8.jar','com.android.tools.r8.D8','--release','--min-api','36','--lib',ANDROID,'--output',OUT/'dex',OUT/'classes.jar'])
jar=OUT/'hepta-screen-codec-v148.jar'
with zipfile.ZipFile(jar,'x') as z:
 for p in sorted((OUT/'dex').glob('classes*.dex')):
  i=zipfile.ZipInfo(p.name,(1980,1,1,0,0,0));i.compress_type=zipfile.ZIP_STORED;z.writestr(i,p.read_bytes())
receipt['jar']={'path':str(jar),'bytes':jar.stat().st_size,'sha256':sha(jar)}
receipt['phone_operations']=receipt['SSH_operations']=receipt['services_changed']=0
receipt['status']='HOST_BUILD_COMPLETE_NOT_DEVICE_QUALIFIED'
(OUT/'BUILD-RECEIPT.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({'status':receipt['status'],'jar':receipt['jar']}))
