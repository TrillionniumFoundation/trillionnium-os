"""Deterministic host contracts around exact production await/caller source.

The existing run_host_checks.py python-tools gate discovers this module. It
compiles the actual awaitAction, checkActive and post-receipt caller prefix
against a host clock, scheduler and service boundary. No Android API is run.
The pinned Code22 method snapshots below are negative controls, not replacement
implementations of the candidate. Reconstructing the complete Code22-plus-click controller
must recover its original SHA256, proving that other controller logic is intact.
"""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
CONTROLLER=ROOT/'src/org/trillionnium/hepta/local/LocalTaskController.java'
TEMPLATE=ROOT/'tests/action-deadline/ActionDeadlineHarness.java'
BASE_SOURCE_MANIFEST_SHA256='3aa67e3a9e332fb0a8e0937d1ea652288d20e52fc909e9f951927bb8ff9190e1'
BASE_CONTROLLER_SHA256='31c4512045730f35ff81ae43712053d8e440f9cf9e73a72a7585e365594721ee'
BASE_CONTROLLER_SCOPE='Code22 plus exact PR121 click projection, before deadline transplant'
BASE_FRAGMENTS={'await': '    private HeptaAccessibilityService.ActionOutcome awaitAction(String id,PhoneObservation observed,ActionDecision action,ObservedTargetLabels targets,long deadline)throws Exception{\n        checkActive(deadline);final CountDownLatch ready=new CountDownLatch(1);final AtomicReference<HeptaAccessibilityService.ActionOutcome> value=new AtomicReference<HeptaAccessibilityService.ActionOutcome>();\n        service.perform(id,observed,action,targets,new HeptaAccessibilityService.Cancellation(){public boolean isCancelled(){return cancelled.get();}},\n                new HeptaAccessibilityService.ActionCallback(){public void onResult(HeptaAccessibilityService.ActionOutcome result){value.set(result);ready.countDown();}});\n        if(!ready.await(8000,TimeUnit.MILLISECONDS)){cancelled.set(true);throw new CleanupUnknown("动作回执超时，可能已有操作发生；已停止后续任务");}\n        HeptaAccessibilityService.ActionOutcome result=value.get();if(result==null)throw new IllegalStateException("动作未返回结果");return result;\n    }', 'check': '    private void checkActive(long deadline)throws Stopped{if(cancelled.get())throw new Stopped();if(SystemClock.elapsedRealtime()>deadline)throw new IllegalStateException("本次任务已超时，已停止继续操作");}', 'caller': '                HeptaAccessibilityService.ActionOutcome outcome=awaitAction(taskId,before,action,frame.targets,deadline);\n                JSONObject actionReceipt=new JSONObject().put("action",new JSONObject(answerJson(action))).put("accepted",outcome.accepted)\n                        .put("dispatched",outcome.dispatched).put("stale",outcome.stale).put("detail",outcome.detail)\n                        .put("model_run_id",decisionRunId).put("model_issued",true);\n                if(ActionPolicy.isReadOnlyDiscovery(action))actionReceipt.put("read_only",true).put("effect","launcher_catalogue_read");\n                record(evidence,String.format(java.util.Locale.ROOT,"step-%02d-action.json",steps),actionReceipt);\n'}

SCENARIOS=(
    'normal','entry-deadline','queued-deadline','queued-after-deadline',
    'callback-deadline','callback-after-deadline','waiter-after-deadline',
    'record-deadline','stop-queued','stop-callback','stop-record',
    'duplicate-first-wins','retire-success','timeout-unknown','perform-failure-retired',
)
REGRESSIONS={
    'entry-deadline':'entry at deadline rejects',
    'queued-deadline':'queued expired action must not dispatch',
    'queued-after-deadline':'queued expired action must not dispatch',
    'callback-deadline':'late callback is evidence only',
    'record-deadline':'receipt persistence cannot extend task authority',
    'stop-callback':'stop at receipt boundary remains stopped',
    'duplicate-first-wins':'first real callback wins',
    'retire-success':'completed attempt cannot regain authority',
    'timeout-unknown':'timeout retirement survives shared flag reset',
}


def method(source,signature):
    """Select the complete actual Java method while respecting strings/comments."""
    if source.count(signature)!=1:raise AssertionError('method identity differs: '+signature)
    start=source.index(signature);opening=source.index('{',start)
    level=0;i=opening;state=None
    while i<len(source):
        ch=source[i];nxt=source[i:i+2]
        if state in ('"',"'"):
            if ch=='\\':i+=2;continue
            if ch==state:state=None
        elif state=='line':
            if ch=='\n':state=None
        elif state=='block':
            if nxt=='*/':state=None;i+=2;continue
        elif nxt=='//':state='line';i+=2;continue
        elif nxt=='/*':state='block';i+=2;continue
        elif ch in ('"',"'"):state=ch
        elif ch=='{':level+=1
        elif ch=='}':
            level-=1
            if level==0:return source[start:i+1]
        i+=1
    raise AssertionError('unterminated actual method')


def caller_prefix(source):
    first='                HeptaAccessibilityService.ActionOutcome outcome=awaitAction('
    last='                if(outcome.stale&&!outcome.dispatched){'
    if source.count(first)!=1 or source.count(last)!=1:raise AssertionError('unique production callsite required')
    a=source.index(first);b=source.index(last,a)
    return source[a:b]


class ActionDeadlineDispatchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.java=shutil.which('java')
        if cls.java is None:raise AssertionError('host JDK required; do not skip contracts')
        cls.compiler=[shutil.which('javac')] if shutil.which('javac') else [cls.java,'-m','jdk.compiler/com.sun.tools.javac.Main']
        cls.temp=tempfile.TemporaryDirectory(prefix='hepta-action-deadline-')
        cls.root=Path(cls.temp.name);cls.source=CONTROLLER.read_text()
        cls.fragments={
            'await':method(cls.source,'    private HeptaAccessibilityService.ActionOutcome awaitAction('),
            'check':method(cls.source,'    private void checkActive('),
            'caller':caller_prefix(cls.source),
        }
        cls.outputs={}
        for name,fragments in [('candidate',cls.fragments),('code22',BASE_FRAGMENTS)]:
            directory=cls.root/name;directory.mkdir()
            text=TEMPLATE.read_text()
            for marker,key in [('/*__AWAIT_ACTION__*/','await'),('/*__CHECK_ACTIVE__*/','check'),('/*__CALLER_RECEIPT_BOUNDARY__*/','caller')]:
                if text.count(marker)!=1:raise AssertionError('host template marker differs')
                text=text.replace(marker,fragments[key])
            target=directory/'ActionDeadlineHarness.java';target.write_text(text)
            result=subprocess.run(cls.compiler+['--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-d',str(directory),str(target)],capture_output=True,text=True,timeout=60)
            if result.returncode:raise AssertionError(name+' compile failed:\n'+result.stderr)
            cls.outputs[name]=directory

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_contract(self,variant,scenario):
        return subprocess.run([self.java,'-cp',str(self.outputs[variant]),'ActionDeadlineHarness',scenario],capture_output=True,text=True,timeout=10)

    def test_only_await_and_immediate_receipt_boundary_changed(self):
        reconstructed=self.source
        for key in ('await','caller'):
            self.assertEqual(reconstructed.count(self.fragments[key]),1)
            reconstructed=reconstructed.replace(self.fragments[key],BASE_FRAGMENTS[key],1)
        self.assertEqual(self.fragments['check'],BASE_FRAGMENTS['check'])
        self.assertEqual(hashlib.sha256(reconstructed.encode()).hexdigest(),BASE_CONTROLLER_SHA256)
        # In particular runTask's CleanupUnknown/blocked and cleanup=false path is unchanged.


def candidate_case(scenario):
    def test(self):
        result=self.run_contract('candidate',scenario)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('PASS '+scenario+' ',result.stdout)
        print(result.stdout.strip())
    return test


def baseline_negative(scenario,message):
    def test(self):
        result=self.run_contract('code22',scenario)
        self.assertNotEqual(result.returncode,0,'old Code22 must expose this regression: '+scenario)
        self.assertIn('java.lang.AssertionError: '+message,result.stderr)
        print('EXPECTED_OLD_FAILURE '+scenario+': '+message)
    return test


for scenario in SCENARIOS:
    setattr(ActionDeadlineDispatchTest,'test_candidate_'+scenario.replace('-','_'),candidate_case(scenario))
for scenario,message in REGRESSIONS.items():
    setattr(ActionDeadlineDispatchTest,'test_negative_code22_'+scenario.replace('-','_'),baseline_negative(scenario,message))


if __name__=='__main__':unittest.main(verbosity=2)
