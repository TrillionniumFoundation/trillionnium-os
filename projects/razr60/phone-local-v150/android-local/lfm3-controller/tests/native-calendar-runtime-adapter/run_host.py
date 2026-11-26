#!/usr/bin/env python3
"""Real ordinary runtime router, LTC calendar waiter, private VLM receipt and fresh publication.

No model, Android system, input dispatch, phone or settings transaction is run.
The existing reviewed fresh producer preparation is reused verbatim; only this
new gate adds the real runtime router and complete controller model waiter.
"""
import argparse, hashlib, importlib.util, json, os, re, stat, subprocess, sys, textwrap, time
from pathlib import Path
sys.dont_write_bytecode = True
PKG = Path('src/org/trillionnium/hepta/local')

def sha(data): return hashlib.sha256(data).hexdigest()
def ref(path):
    p = Path(path).resolve(); data = p.read_bytes()
    return dict(path=str(p), bytes=len(data), sha256=sha(data), mode=stat.S_IMODE(p.stat().st_mode))
def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
def replace_one(text, old, new):
    if text.count(old) != 1: raise RuntimeError('nonunique exact fixture replacement: ' + old[:120])
    return text.replace(old, new, 1)

def prepare(S, O, report):
    fresh_path = S/'tests/native-calendar-date-fresh/run_host.py'
    fresh = module(fresh_path, 'runtime_calendar_fresh_preparation')
    text = fresh_path.read_text()
    begin = "  helper=S/'tests/native-calendar-date-model/run_host.py';base=load(helper,'calendar_fresh_base')"
    end = "  report['source_inputs_before']=[ref(p) for p in originals];report['compile_inputs']=[ref(p) for p in paths];report['tools_before']=[ref(p) for p in tools]"
    if text.count(begin) != 1 or text.count(end) != 1: raise RuntimeError('reviewed fresh preparation boundaries changed')
    prefix = text[text.index(begin):text.index(end)]
    # Execute only the original fixture preparation, never its javac/java stages.
    ns = dict(fresh.__dict__, S=S, O=O, report=report, originals=[], __file__=str(fresh_path))
    exec(compile('if True:\n'+prefix, str(fresh_path)+'#prepare-only', 'exec'), ns)
    selected, originals = ns['selected'], ns['originals']
    originals += [fresh_path, Path(__file__).resolve()]
    extraction = list(ns['extracted'])
    bridge = O/'runtime-bridge'; bridge.mkdir()
    def generated(relative, contents):
        p = bridge/relative; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(contents)
        selected[ns['base'].classname(p)] = p; return p
    def member(name, anchor):
        p = S/PKG/name; b = fresh.body(p.read_text(), anchor); originals.append(p)
        extraction.append(dict(source=str(p), anchor=anchor, bytes=len(b.encode()), sha256=sha(b.encode()), verbatim=True))
        return b
    runtime = S/PKG/'RuntimeInferenceAdapter.java'
    selected['org.trillionnium.hepta.local.RuntimeInferenceAdapter'] = runtime; originals.append(runtime)
    engine = selected['org.trillionnium.hepta.local.LocalModelEngine'].read_text()
    engine = replace_one(engine, ' public LocalRuntimeConfig configuration(){return config;}',
        member('LocalModelEngine.java', '    public LocalRuntimeConfig configuration()')+'\n'+
        member('LocalModelEngine.java', '    RuntimeGeneration runtimeGeneration()'))
    # Explicit negative settings-publication port. RuntimeGeneration itself and
    # the router's object-identity checks remain actual production members.
    engine = engine[:engine.rfind('}')] + '''
 RuntimeGeneration fixtureReplaceRuntime(LocalRuntimeConfig next){
  RuntimeGeneration prior=runtime;runtime=new RuntimeGeneration(next,null,new ModelFileVerifier(),null);return prior;}
 void fixtureRestoreRuntime(RuntimeGeneration prior){runtime=prior;}
}
'''
    generated('org/trillionnium/hepta/local/LocalModelEngine.java', engine)
    generated('org/trillionnium/hepta/local/EngineInferenceAdapter.java', '''package org.trillionnium.hepta.local;
final class EngineInferenceAdapter implements LocalInference {
 EngineInferenceAdapter(LocalModelEngine unused){throw new UnsupportedOperationException("nonvisual model launch is outside this gate");}
 public LocalRuntimeConfig configuration(){throw new UnsupportedOperationException("no nonvisual model configuration");}
 public Handle generate(String p,String s,java.io.File i,DecisionGrammar g,int m,long t,Callback c){
  throw new UnsupportedOperationException("no nonvisual model execution");}
}
''')
    controller = selected['org.trillionnium.hepta.local.LocalTaskController'].read_text()
    controller = replace_one(controller, 'final class LocalTaskController {',
        'final class LocalTaskController {\n    LocalInference inference;\n'+
        '    NativeAppSession.CalendarModelRequest hostModel(NativeAppSession.CalendarOffer o,String p,long d)throws Exception{return awaitNativeCalendarModel(o,p,d);}')
    ltc = (S/PKG/'LocalTaskController.java').read_text()
    const = fresh.section(ltc, '    private static final String NATIVE_CALENDAR_SYSTEM=', '    private boolean nativeCalendarRoundRequested(')
    extraction.append(dict(source=str(S/PKG/'LocalTaskController.java'), start='NATIVE_CALENDAR_SYSTEM', bytes=len(const.encode()), sha256=sha(const.encode()), verbatim=True))
    run_task=fresh.body(ltc,'    private void runTask(')
    early_guard='requireLfm3VlToolsSelection(config,instruction,authorization.authorization,backgroundSelection,completion.nativeGoal());'
    if run_task.count(early_guard)!=1: raise RuntimeError('one actual early LFM3-VL tools guard required')
    guard_at=run_task.index(early_guard)
    effects=['BackgroundSession.experimentalPublicOwnGroup(', 'background.startWithPermissionInitialization(',
             'else background.start(', 'inference.beginTask(']
    if any(run_task.index(effect)<=guard_at for effect in effects): raise RuntimeError('LFM3-VL guard must precede every original bootstrap/model boundary')
    report['lfm3vl_early_guard_before_bootstrap_and_model']={'run_task_sha256':sha(run_task.encode()),
        'guard_offset':guard_at,'effect_offsets':{effect:run_task.index(effect) for effect in effects},'phone_operations':0}
    additions = [const,
        member('LocalTaskController.java', '    static void requireLfm3VlToolsSelection('),
        member('LocalTaskController.java', '    void requireNativeCalendarModelSource('),
        member('LocalTaskController.java', '    private NativeAppSession.CalendarModelRequest awaitNativeCalendarModel(')]
    if 'class CleanupUnknown' not in controller: additions.append(member('LocalTaskController.java', '    private static final class CleanupUnknown'))
    controller = controller[:controller.rfind('}')] + '\n'.join(additions)+'\n}\n'
    generated('org/trillionnium/hepta/local/LocalTaskController.java', controller)
    ha = selected['org.trillionnium.hepta.local.HeptaAccessibilityService'].read_text()
    if 'void requireExperimentalModelScope(' in ha: raise RuntimeError('unexpected pre-existing model-scope member')
    ha = ha[:ha.rfind('}')] + member('HeptaAccessibilityService.java', '    void requireExperimentalModelScope(')+'\n}\n'
    generated('org/trillionnium/hepta/local/HeptaAccessibilityService.java', ha)
    budget = S/PKG/'ConservativeTokenBudget.java'
    selected['org.trillionnium.hepta.local.ConservativeTokenBudget'] = budget; originals.append(budget)
    fixture_source = S/'tests/native-calendar-date-fresh/NativeCalendarDateFreshHostTest.java'
    source = fixture_source.read_text(); originals.append(fixture_source)
    old_env = fresh.body(source, '    static final class Env implements AutoCloseable {')
    env = old_env
    env = replace_one(env,'        Env()throws Exception{',
        '        final String owner;\n'+
        '        Env()throws Exception{this(NativeCalendarDateSessionHostTest.gui());}\n'+
        '        Env(LocalRuntimeConfig selectedRuntime)throws Exception{\n'+
        '            owner=selectedRuntime.profile==ModelProfile.LFM3_VL_2B?"在携程查询2026年11月27日北京到上海的单程机票，1名成人，读取真实航班和票价。只查询，不预订、不提交订单、不支付。":NativeCalendarDateSessionHostTest.OWNER;')
    env = re.sub(r'\bOWNER\b',lambda m:'owner',env)
    env = env.replace('NativeCalendarDateSessionHostTest.owner','NativeCalendarDateSessionHostTest.OWNER')
    env = replace_one(env, 'final LocalModelEngine engine;final VlmInferenceAdapter adapter;',
        'final LocalModelEngine engine;final VlmInferenceAdapter adapter;final RuntimeInferenceAdapter router;')
    env = replace_one(env,
        'engine=new LocalModelEngine(context,NativeCalendarDateSessionHostTest.gui(),executor);adapter=new VlmInferenceAdapter(context,engine);',
        'engine=new LocalModelEngine(context,selectedRuntime,executor);router=new RuntimeInferenceAdapter(context,engine);\n'+
        '            router.beginTask(TASK);adapter=(VlmInferenceAdapter)field(field(router,"binding"),"delegate");controller.inference=router;')
    env = replace_one(env, 'offer=session.offerCalendarDate(envelope,adapter,clock,START+30000);',
        'offer=session.offerCalendarDate(envelope,router,clock,START+30000);')
    env = replace_one(env, '            adapter.beginTask(TASK);\n', '')
    old_register = fresh.body(env, '        NativeAppSession.CalendarModelRequest register()throws Exception{')
    new_register = '''        final AtomicReference<NativeAppSession.CalendarModelRequest> modelValue=new AtomicReference<NativeAppSession.CalendarModelRequest>();
        final AtomicReference<Throwable> modelError=new AtomicReference<Throwable>();Thread modelThread;
        void startControllerModel()throws Exception{
            modelThread=new Thread(()->{try{modelValue.set(controller.hostModel(offer,"固定目标日期，只返回原图目标月份内一个日期格",START+30000));}
                catch(Throwable failure){modelError.set(failure);}},"actual-LTC-runtime-calendar-model");
            modelThread.start();takeNativeRequest();
        }
        void takeNativeRequest()throws Exception{
            executor.take();round=field(field(adapter,"task"),"current");
            check(round!=null,"actual router must forward to its original VLM task");
        }
        void prepareNativeReturn()throws Exception{
            call(adapter,"prepareInputs",round);
            Object parent=call(Class.forName("org.trillionnium.hepta.local.VlmInferenceAdapter$Parent"),"read");port(round,"parent",parent);
            String generation=(String)field(round,"generation"),token=(String)field(round,"token");
            OwnedGenerationScope scope=new OwnedGenerationScope(files.toFile(),files.resolve("host-no-native-worker").toFile(),generation,TASK,token);port(round,"scope",scope);
            NativeCalendarDateModelHostTest.FakeProcess process=new NativeCalendarDateModelHostTest.FakeProcess(false,0);port(round,"process",process);
            OwnedWorkerCancellation cancel=(OwnedWorkerCancellation)field(round,"cancellation");cancel.attach(process,generation,TASK);
            Object owner=field(round,"owner");LocalModelEngine.TaskExternalLease lease=(LocalModelEngine.TaskExternalLease)field(owner,"lease");lease.attach(process,cancel);
            port(round,"exitObserved",true);port(round,"exitCode",0);
            NativeCalendarDateModelHostTest.environmentRaw.put(round,raw);NativeCalendarDateModelHostTest.nativeOutputs(round,scope);
        }
        void finishNativeReturn()throws Exception{SystemClock.now=START+5000;call(adapter,"finishRequest",round,null);}
        NativeAppSession.CalendarModelRequest finishController(boolean accepted)throws Exception{
            modelThread.join(5000);check(!modelThread.isAlive(),"actual controller model waiter did not finish");
            if(accepted){if(modelError.get()!=null)throw new AssertionError("ordinary router/LTC chain rejected",modelError.get());
                model=modelValue.get();check(model!=null,"actual Session model registry missing");}
            else check(modelValue.get()==null&&modelError.get()!=null,"invalid original binding must not register a request");
            return model;
        }
        NativeAppSession.CalendarModelRequest register()throws Exception{
            startControllerModel();prepareNativeReturn();finishNativeReturn();return finishController(true);
        }
        Delivery deliverOnly()throws Exception{
            delivery=new Delivery(offer);issue(delivery);finishNativeReturn();
            check(delivery.proof!=null&&delivery.signal.ready==1&&delivery.signal.failed==0,"actual delegate private receipt missing");return delivery;
        }
        void issue(VlmInferenceAdapter.AcceptedRequestCallback callback)throws Exception{
            router.generateObserved("固定日期协议","host native-return boundary; no model",source,grammar,256,120000,callback);
            takeNativeRequest();prepareNativeReturn();
        }
        VlmInferenceAdapter.AcceptedRequest proof()throws Exception{
            return (VlmInferenceAdapter.AcceptedRequest)field(field(offer,"modelArrival"),"accepted");
        }'''
    env = replace_one(env, old_register, new_register)
    old_close = fresh.body(env, '        void closeTask()throws Exception{')
    new_close = '''        LocalInference.TaskCleanup closeTaskResult()throws Exception{
            if(field(router,"binding")==null)return LocalInference.TaskCleanup.noWorker(TASK);
            AtomicReference<Throwable> error=new AtomicReference<Throwable>();AtomicReference<LocalInference.TaskCleanup> cleanup=new AtomicReference<LocalInference.TaskCleanup>();
            Thread t=new Thread(()->{try{cleanup.set(router.endTask(TASK));}catch(Throwable failure){error.set(failure);}},"actual-router-task-finisher");
            t.start();executor.take().run();t.join(5000);
            check(!t.isAlive()&&error.get()==null&&cleanup.get()!=null,"actual router/aggregate finisher failed: "+error.get());
            LocalInference.TaskCleanup c=cleanup.get();
            Map<String,Object> terminal=new LinkedHashMap<String,Object>();terminal.put("cleanup_known",c.cleanupKnown);
            terminal.put("process_started",c.processStarted);terminal.put("process_exit_observed",c.processExitObserved);
            terminal.put("receipt_valid",c.receiptValid);terminal.put("exit_code",c.exitCode);
            Files.write(directory.resolve("host-runtime-terminal-"+id()+".json"),bytes(new JSONObject(terminal).toString(2)));
            return c;
        }
        void closeTask()throws Exception{closeTaskResult();}'''
    env = replace_one(env, old_close, new_close)
    # The whole original fresh fixture remains a compile input. Its 16 cases
    # are not invoked. This derived Env differs only in the actual router and
    # model waiter plumbing; all Android/graph/kernel ports stay explicit.
    imports = source[:source.index('/** Complete actual Session/Adapter')]
    helper_text = imports+'import static org.trillionnium.hepta.local.NativeCalendarDateFreshHostTest.*;\nfinal class RuntimeCalendarFixture {\n'+env+'\n}\n'
    generated('org/trillionnium/hepta/local/RuntimeCalendarFixture.java', helper_text)
    derivation = dict(original_env=ref(fixture_source), original_env_bytes=len(old_env.encode()), original_env_sha256=sha(old_env.encode()),
        derived_env_bytes=len(env.encode()), derived_env_sha256=sha(env.encode()),
        preparation_prefix_bytes=len(prefix.encode()), preparation_prefix_sha256=sha(prefix.encode()),
        ordinary_public_runtime_constructor=True, actual_runtime_default_factory=True,
        reflection_constructs_accepted_request=False, reflection_constructs_calendar_permit=False,
        worker_return_and_Android_graphs_are_explicit_ports=True, settings_publication_is_negative_fixture_only=True)
    test = S/'tests/native-calendar-runtime-adapter/NativeCalendarRuntimeAdapterHostTest.java'
    selected['org.trillionnium.hepta.local.NativeCalendarRuntimeAdapterHostTest'] = test; originals.append(test)
    (O/'RUNTIME-EXTRACTION.json').write_text(json.dumps(dict(actual_members=extraction, derivation=derivation),ensure_ascii=False,indent=2)+'\n')
    report['runtime_extraction'] = ref(O/'RUNTIME-EXTRACTION.json')
    report['boundary'] = 'Actual whole router/NAS/VLM/receipt contract; verbatim engine generation/reservation, LTC model/fresh waiters and HA fresh pixel producer. Android/services, native worker return, kernel cleanup and negative settings publication are explicit host ports. No model, settings transaction, Android input, ROM or business qualification.'
    return list(selected.values()), list(dict.fromkeys(originals))

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for key in ('source','output','java-home','json-jar'): ap.add_argument('--'+key,type=Path,required=True)
    a=ap.parse_args(); S=a.source.resolve(); O=a.output.resolve(); J=a.java_home.resolve(); jar=a.json_jar.resolve()
    if O.exists() or S in O.parents: raise RuntimeError('new independent output required')
    O.mkdir(parents=True,mode=0o700)
    if sha(jar.read_bytes())!='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed': raise RuntimeError('original JSON jar required')
    tools=[J/'bin/java',J/'bin/javac',J/'lib/modules',J/'lib/ct.sym',jar,Path(sys.executable).resolve()]
    def whole(): return [ref(p) for p in sorted(S.rglob('*')) if p.is_file()]
    report=dict(schema='hepta.calendar-runtime-adapter-host.v1',all_pass=False,source=str(S),phone_actions=0,model_executions=0,android_inputs=0,stages=[])
    report['whole_source_before']=whole(); originals=[]
    try:
        paths,originals=prepare(S,O,report)
        report['source_inputs_before']=[ref(p) for p in originals];report['compile_inputs']=[ref(p) for p in paths]
        report['tools_before']=[ref(p) for p in tools]
        classes=O/'classes';classes.mkdir()
        env={**os.environ,'JAVA_HOME':str(J),'PATH':str(J/'bin')+':/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1','PYTHONNOUSERSITE':'1'}
        for k in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH','PYTHONPATH','SOURCE_HEAD_SHA','HEPTA_ADMISSION_SOURCE','HEPTA_TEST_JAVA','HEPTA_TEST_JAVAC'):env.pop(k,None)
        stages=[('compile',[J/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror','-cp',jar,'-d',classes,*paths]),
                ('runtime',[J/'bin/java','-Djava.awt.headless=true','-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.NativeCalendarRuntimeAdapterHostTest',O,O/'work',S/'tests/vlm-contract/fixtures/gui-owl-chat-template.jinja',S/'tests/vlm-contract/fixtures/lfm3-vl-chat-template.jinja'])]
        for name,argv in stages:
            start=time.monotonic(); result=subprocess.run(list(map(str,argv)),cwd=O,env=env,capture_output=True,timeout=180)
            for k,b in [('stdout',result.stdout),('stderr',result.stderr)]: (O/(name+'.'+k)).write_bytes(b)
            report['stages'].append(dict(name=name,argv=list(map(str,argv)),cwd=str(O),exit_code=result.returncode,elapsed_seconds=time.monotonic()-start,stdout=ref(O/(name+'.stdout')),stderr=ref(O/(name+'.stderr'))))
            if result.returncode: raise RuntimeError('actual stage failed: '+name)
        report['cases']=json.loads((O/'CASES.json').read_text())
        if not report['cases']['all_pass']: raise RuntimeError('necessary runtime cases failed')
        report['all_pass']=True
    except Exception as error: report['error']=type(error).__name__+': '+str(error)
    finally:
        if originals and 'source_inputs_before' in report:
            report['source_inputs_after']=[ref(p) for p in originals]; report['tools_after']=[ref(p) for p in tools]
            report['source_inputs_unchanged']=report['source_inputs_before']==report['source_inputs_after']; report['tools_unchanged']=report['tools_before']==report['tools_after']
            report['all_pass'] &= report['source_inputs_unchanged'] and report['tools_unchanged']
        report['whole_source_after']=whole();report['whole_source_unchanged']=report['whole_source_before']==report['whole_source_after'];report['all_pass'] &= report['whole_source_unchanged']
        if (O/'CASES.json').exists(): report['cases']=json.loads((O/'CASES.json').read_text())
        report['artifacts']=[ref(p) for p in sorted(O.rglob('*')) if p.is_file() and p.name!='RESULT.json']
        (O/'RESULT.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(all_pass=report['all_pass'],error=report.get('error'),cases=report.get('cases',{}).get('cases'),assertions=report.get('cases',{}).get('assertions'),result=ref(O/'RESULT.json'))))
    return 0 if report['all_pass'] else 1
if __name__=='__main__': raise SystemExit(main())
