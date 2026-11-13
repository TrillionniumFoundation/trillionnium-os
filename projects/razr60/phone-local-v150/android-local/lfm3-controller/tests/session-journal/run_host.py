from pathlib import Path
import argparse
import hashlib
import json
import subprocess

parser=argparse.ArgumentParser()
parser.add_argument('--output',required=True)
args=parser.parse_args()
root=Path(__file__).resolve().parents[2]
out=Path(args.output).resolve()
out.mkdir(mode=0o700)
classes=out/'classes';classes.mkdir()
session=root/'src/org/trillionnium/hepta/local/LocalTaskSession.java'
queue=root/'src/org/trillionnium/hepta/local/SessionJournalQueue.java'
template=Path(__file__).resolve().with_name('SessionJournalHost.template')

def body(source,signature):
    assert source.count(signature)==1,signature
    start=source.index(signature);opening=source.index('{',start)
    depth=0;state='code';i=opening
    while i<len(source):
        c=source[i];n=source[i:i+2]
        if state=='line':
            if c=='\n':state='code'
        elif state=='block':
            if n=='*/':state='code';i+=1
        elif state in ('string','char'):
            if c=='\\':i+=1
            elif (state=='string' and c=='"') or (state=='char' and c=="'"):state='code'
        elif n=='//':state='line';i+=1
        elif n=='/*':state='block';i+=1
        elif c=='"':state='string'
        elif c=="'":state='char'
        elif c=='{':depth+=1
        elif c=='}':
            depth-=1
            if depth==0:return source[start:i+1]
        i+=1
    raise ValueError('unterminated method')

signatures=[
    'public boolean schedule(final String owner,String source,String testNonceSha,final String expectedScopeSha256,final TaskAuthorization authorization,\n                            final BackgroundSession.Selection selection,long delayMillis){',
    'public void stop() {',
    'private void receiveState(String value) {',
    'private void receiveFinished(LocalTaskController.TaskResult result) {',
    'private void setState(String value) {',
    'private void persist(String status,boolean cleanupKnown) {',
    'private void failSessionWrite(long expectedEpoch,Exception error){',
    'private SessionJournalQueue.Failure journalFailureHook(){',
]
source=session.read_text();methods=[body(source,s) for s in signatures]
text=template.read_text();assert text.count('{{SESSION_METHODS}}')==1
harness=out/'SessionJournalHost.java';harness.write_text(text.replace('{{SESSION_METHODS}}','\n'.join(methods)))
def identity(path):
    b=path.read_bytes();return {'path':str(path.relative_to(root)),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob_sha1':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
record={'schema':'hepta.session-journal-host-run.v1','all_pass':False,
        'source_inputs':[identity(p) for p in [session,queue,template,Path(__file__).resolve()]],
        'extracted_methods':[{'signature':s,'body_sha256':hashlib.sha256(b.encode()).hexdigest()} for s,b in zip(signatures,methods)],
        'android_compilation':False,'android_and_json_boundaries_stubbed':True,'physical_fsync_stall_test':False,
        'java8_bytecode_target':True,'java8_api_cross_compile':False,'phone_operations':0}
command=['/usr/bin/java','-m','jdk.compiler/com.sun.tools.javac.Main','-source','8','-target','8','-Xlint:all,-options','-Werror','-d',str(classes),str(queue),str(harness)]
record['compile_command']=command
p=subprocess.run(command,capture_output=True,timeout=60)
(out/'compiler.stdout').write_bytes(p.stdout);(out/'compiler.stderr').write_bytes(p.stderr)
record['compiler_returncode']=p.returncode
if p.returncode==0:
    command=['/usr/bin/java','-cp',str(classes),'org.trillionnium.hepta.local.SessionJournalHost'];record['run_command']=command
    p=subprocess.run(command,capture_output=True,timeout=40)
    (out/'runtime.stdout').write_bytes(p.stdout);(out/'runtime.stderr').write_bytes(p.stderr)
    record['runtime_returncode']=p.returncode
    if p.returncode==0:
        record['runtime']=json.loads(p.stdout)
        record['all_pass']=record['runtime']['all_pass'] is True
record['source_inputs_unchanged']=record['source_inputs']==[identity(p) for p in [session,queue,template,Path(__file__).resolve()]]
record['all_pass']=record['all_pass'] and record['source_inputs_unchanged']
(out/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps({'all_pass':record['all_pass'],'compiler_returncode':record['compiler_returncode'],'runtime_returncode':record.get('runtime_returncode'),'cases':record.get('runtime',{}).get('cases'),'result':str(out/'RESULT.json')}))
raise SystemExit(0 if record['all_pass'] else 1)
