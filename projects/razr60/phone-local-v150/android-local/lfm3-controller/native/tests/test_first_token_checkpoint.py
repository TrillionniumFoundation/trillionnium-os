#!/usr/bin/env python3
"""Actual generated callback, fake SDK: live metadata visibility, not phone/NPU qualification."""
import argparse,hashlib,importlib.util,json,os,re,select,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True

def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def main():
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(mode=0o700)
 native=a.source/'native';sys.path.insert(0,str(native));generator=module('checkpoint_generator',native/'generate_adapter.py');fixture=module('warm_fixture',native/'tests/test_warm_runtime.py');generator.generate(a.source,a.out)
 code=fixture.HARNESS
 first=code.index('int32_t geniex_llm_generate(');last=code.index('int32_t geniex_vlm_create(',first)
 code=code[:first]+r'''
static int host_first_token_return_contract(void) {
#ifdef HEPTA_FIRST_TOKEN_CHECKPOINT_H
    int saved=dup(STDERR_FILENO);int full=open("/dev/full",O_WRONLY);assert(saved>=0&&full>=0);
    assert(dup2(full,STDERR_FILENO)==STDERR_FILENO);close(full);clearerr(stderr);
#define HOST_RESET_CALLBACK() do { \
    cancel_signal=cancel_phase=0;current_phase=PH_GENERATE;deadline_hit=false;callback_limit=false; \
    callback_count=callback_bytes=callback_retained=0;deadline_ns=monotonic_ns()+UINT64_C(5000000000); \
    hepta_first_token_begin(&hepta_first_token_state,true,"11111111111111111111111111111111","22222222222222222222222222222222","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); \
} while(0)
    HOST_RESET_CALLBACK();errno=EAGAIN;
    assert(on_token("private",NULL)&&hepta_first_token_state.emitted&&callback_count==1&&callback_bytes==7);
    assert(errno==EAGAIN&&ferror(stderr)); /* ENOSPC logging does not become inference failure. */
    assert(on_token("next",NULL)&&callback_count==2&&callback_bytes==11);
    HOST_RESET_CALLBACK();assert(on_token("",NULL)&&!hepta_first_token_state.emitted&&callback_bytes==0);
    HOST_RESET_CALLBACK();assert(!on_token(NULL,NULL)&&callback_limit&&!hepta_first_token_state.emitted);
    HOST_RESET_CALLBACK();cancel_signal=SIGTERM;assert(!on_token("private",NULL)&&cancel_signal==SIGTERM);
    HOST_RESET_CALLBACK();deadline_ns=0;assert(!on_token("private",NULL)&&deadline_hit);
    HOST_RESET_CALLBACK();callback_retained=OUTPUT_LIMIT;assert(!on_token("x",NULL)&&callback_limit&&!hepta_first_token_state.emitted);
    assert(dup2(saved,STDERR_FILENO)==STDERR_FILENO);close(saved);clearerr(stderr);
#undef HOST_RESET_CALLBACK
    puts("HOST_CALLBACK_RETURN_CONTRACT_PASS");return 0;
#else
    return 2;
#endif
}
static void host_gate(const char *phase,int sequence) {
    fprintf(stderr,"HOST_FAKE_GATE phase=%s sequence=%d\n",phase,sequence);fflush(stderr);
    const char *value=getenv("HEPTA_HOST_TEST_GATE_FD");assert(value);
    char gate=0;assert(read(atoi(value),&gate,1)==1&&gate=='g');
}
int32_t geniex_llm_generate(geniex_LLM *handle,const geniex_LlmGenerateInput *in,geniex_LlmGenerateOutput *out){
    assert(handle==(geniex_LLM *)&fake_handle&&!dirty&&in->input_ids&&in->input_ids_count>0&&!in->prompt_utf8);
    int sequence=calls_generate+1;
    host_gate("before_callback",sequence);
    assert(in->on_token("",in->user_data));host_gate("empty_callback",sequence);
    assert(in->on_token("HOST_PRIVATE_TOKEN_MUST_NOT_APPEAR_IN_LOG",in->user_data));host_gate("first_nonempty_callback",sequence);
    assert(in->on_token("HOST_SECOND_PRIVATE_TOKEN",in->user_data));
    dirty=1;calls_generate++;out->full_text=strdup("x");out->profile_data.prompt_tokens=in->input_ids_count;
    out->profile_data.generated_tokens=2;out->profile_data.stop_reason="eos";return 0;
}
''' +code[last:]
 code=code.replace('int main(int argc,char **argv){','int main(int argc,char **argv){\n    if(argc==2&&!strcmp(argv[1],"--host-callback-return-contract"))return host_first_token_return_contract();')
 code=code.replace('TEST_MODEL_SHA',hashlib.sha256(fixture.WEIGHT).hexdigest()).replace('TEST_MODEL_BYTES',str(len(fixture.WEIGHT)))
 (a.out/'test.c').write_text(code);binary=a.out/'contract'
 cmd=['cc','-std=c11','-Wall','-Wextra','-Werror','-O1','-I'+str(a.out),'-I'+str(native),'-I'+str(native/'vendor'),'-I'+str(native/'vendor/llama'),str(a.out/'test.c'),'-o',str(binary)]
 subprocess.run(cmd,check=True,capture_output=True);cases=[]
 pattern=re.compile(rb'HEPTA_FIRST_NONEMPTY_TOKEN schema=hepta.first-token-checkpoint.v1 task_id=([0-9a-f]{32}) worker_generation=([0-9a-f]{32}) request_id=([0-9a-f]{32}) pid=([1-9][0-9]*) clock=CLOCK_MONOTONIC monotonic_ns=([1-9][0-9]*) callback_count=([1-9][0-9]*) diagnostics_only=true')
 for mode in ['normal','once']:
  root=a.out/mode;root.mkdir(mode=0o700);(root/'runs').mkdir(mode=0o700);(root/'runs'/fixture.G).mkdir(mode=0o700)
  model=root/'fixture.gguf';model.write_bytes(fixture.WEIGHT);model.chmod(0o600)
  for rid in [fixture.A,fixture.B]:fixture.request_files(root,rid,'host-only complete prompt')
  first=root/'runs'/fixture.A
  argv=[str(binary),'--request-id',fixture.A,'--mode','llm','--runtime','llama_cpp','--compute','npu','--model',str(model),'--prompt-file',str(first/'prompt.txt'),'--system-file',str(first/'system.txt'),'--grammar-file',str(first/'grammar.gbnf'),'--result-file',str(first/'native-result.json'),'--text-file',str(first/'raw-text.txt'),'--ctx-size','4096','--max-tokens','32','--threads','2','--timeout-ms','30000','--log-level','debug']
  if mode=='normal':argv+=['--warm-generation',fixture.G,'--warm-task-id',fixture.T,'--warm-session-dir',str(root/'runs'/fixture.G)]
  reader,writer=os.pipe();env=dict(os.environ);env['HEPTA_HOST_TEST_GATE_FD']=str(reader);logpath=root/'stderr.log'
  with logpath.open('wb') as logfile:
   process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=logfile,env=env,pass_fds=(reader,))
  os.close(reader)
  def send(line):process.stdin.write((line+'\n').encode());process.stdin.flush()
  def wait_gate(phase,seq):
   token=('HOST_FAKE_GATE phase='+phase+' sequence='+str(seq)+'\n').encode();end=time.monotonic()+5
   while time.monotonic()<end:
    raw=logpath.read_bytes()
    if token in raw:return raw
    assert process.poll() is None,'fake worker ended before callback gate';time.sleep(.01)
   raise AssertionError('host callback gate deadline')
  def checkpoints(raw):
   lines=[x for x in raw.splitlines() if x.startswith(b'HEPTA_FIRST_NONEMPTY_TOKEN ')]
   result=[pattern.fullmatch(x) for x in lines];assert all(result),'malformed checkpoint metadata';return result
  try:
   if mode=='normal':assert fixture.line(process)==f'HEPTA_WARM_READY {fixture.G} {fixture.T} {process.pid}'
   requests=[fixture.A,fixture.B] if mode=='normal' else [fixture.A]
   for seq,rid in enumerate(requests,1):
    if mode=='normal':send(f'RUN {fixture.G} {fixture.T} {rid} {seq} 32 30000')
    expected_prior=seq-1 if mode=='normal' else 0
    raw=wait_gate('before_callback',seq);assert len(checkpoints(raw))==expected_prior,'checkpoint before token callback';os.write(writer,b'g')
    raw=wait_gate('empty_callback',seq);assert len(checkpoints(raw))==expected_prior,'empty token must not emit checkpoint';os.write(writer,b'g')
    raw=wait_gate('first_nonempty_callback',seq);events=checkpoints(raw)
    assert process.poll() is None and not (root/'runs'/rid/'native-result.json').exists(),'checkpoint must be readable before native result publication'
    if mode=='normal':
     assert len(events)==seq,'missing first-token checkpoint while generate is still in flight'
     event=events[-1];assert event[1].decode()==fixture.T and event[2].decode()==fixture.G and event[3].decode()==rid and int(event[4])==process.pid and int(event[6])==2,'wrong actual request or callback identity'
    else:assert events==[],'one-shot has no task generation checkpoint'
    assert b'HOST_PRIVATE_TOKEN_MUST_NOT_APPEAR_IN_LOG' not in raw and b'HOST_SECOND_PRIVATE_TOKEN' not in raw,'generated token content leaked to log'
    os.write(writer,b'g')
    if mode=='normal':assert fixture.line(process)==f'HEPTA_WARM_DONE {fixture.G} {fixture.T} {rid} {seq} 0'
    else:process.wait(timeout=5)
    receipt=json.loads((root/'runs'/rid/'native-result.json').read_text());assert receipt['generation_complete'] is True and receipt['callback_count']==3
   if mode=='normal':send(f'CLOSE {fixture.G} {fixture.T}')
   process.wait(timeout=5);assert process.returncode==0,logpath.read_text(errors='replace')
   count=len(checkpoints(logpath.read_bytes()));assert count==(2 if mode=='normal' else 0),'duplicate checkpoint in same request'
   cases.append({'mode':mode,'requests':len(requests),'checkpoint_count':count,'live_before_result':True,'token_text_in_log':False})
  finally:
   os.close(writer)
   if process.poll() is None:process.kill();process.wait(timeout=5)
   process.stdin.close();process.stdout.close()
 fault=subprocess.run([str(binary),'--host-callback-return-contract'],capture_output=True,text=True,timeout=5);assert fault.returncode==0 and fault.stdout.strip()=='HOST_CALLBACK_RETURN_CONTRACT_PASS','callback return/failure contract changed: '+repr((fault.returncode,fault.stdout,fault.stderr))
 result={'passed':True,'actual_generated_callback_compiled':True,'callback_errno_cancel_deadline_null_limit_contract_passed':True,'sdk':'explicit host fake','phone_operations':0,'model_or_accelerator_execution':False,'cases':cases,'generated_source_sha256':hashlib.sha256((a.out/'worker-appuid.c').read_bytes()).hexdigest()}
 (a.out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
