"""Run exact controller prompt code with frozen observations, not a copied budget.

The host supplies only the observation/JSON boundary. Both old and new production
prompt methods execute with the real ranker, budget, grammar and projections.
The old variant must reproduce the missing-query-completion failure. These are
host contracts; no Android build, model output or phone result is inferred.
"""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from discovery_scope import restore_discovery_base
from run_host_checks import PURE_CLASSES
from test_action_deadline_dispatch import method

ROOT=Path(__file__).resolve().parents[1]
FIXTURES=ROOT/'tests/app-discovery'
CONTROLLER=ROOT/'src/org/trillionnium/hepta/local/LocalTaskController.java'
BASE_SHA='f81e5daafb18b99f7f83840ad9b4ab892beed651c32c481273c6c07b6036cf58'
PINNED_INPUTS={
    'frozen-step02-prompt.txt':'eb63124abdce8944923bef6cc7158f384a42b935f54e939c66e8eea80c43a886',
    'frozen-system.txt':'a8e76236210702f1a091bb188dce489d7ce513e0de4723c5a42e47c313e6c98d',
    'frozen-step01-find-app.json':'e77be7402395bc9fffeb61315524f43014ed26e218852d2089f83a38ecb15389',
    'frozen-step02-before.json':'15d91704d85f27708a3f333cddc7f4175481da03a8995268c8e6e5b4376482e9',
    'frozen-step01-action.json':'32e1ad0999927dce3f3595dfb0bb0a4ea2bdc87dd2d627a686792e003c7a4373',
    'frozen-step01-before.json':'bf8cf006b99d7401984e122b7ad3e1e310dcc80d9a538665fa9c5a99f90e2a08',
    'frozen-step01-after.json':'15d91704d85f27708a3f333cddc7f4175481da03a8995268c8e6e5b4376482e9',
    'frozen-step02-grammar.gbnf':'29ab9f9227e87103924ba6bd0aa66b538a6d8f14a1feb557193095ddf17fa8d3',
}


def literal(value):
    return json.dumps(value,ensure_ascii=False)


def json_object(value):
    if value is None:return 'JSONObject.NULL'
    if isinstance(value,bool):return str(value).lower()
    if isinstance(value,(int,str)):return literal(value)
    if isinstance(value,list):return 'new JSONArray()'+''.join('.put('+json_object(v)+')' for v in value)
    if isinstance(value,dict):return 'new JSONObject()'+''.join('.put('+literal(k)+','+json_object(v)+')' for k,v in value.items())
    raise AssertionError('unsupported fixture type')


def frozen_input(prompt):
    data,owner=prompt.removeprefix('UNTRUSTED_DATA\n').split('\nOWNER\n')
    value=json.loads(data);screen=value['screen'];meta={v['node_id']:v for v in screen['editable_fields']+screen['visible_text']}
    observed=json.loads((FIXTURES/'frozen-step02-before.json').read_text())
    before=json.loads((FIXTURES/'frozen-step01-before.json').read_text())
    after=json.loads((FIXTURES/'frozen-step01-after.json').read_text())
    receipt=json.loads((FIXTURES/'frozen-step01-action.json').read_text());action=receipt['action']
    assert observed==after and receipt['accepted'] and not receipt['dispatched'] and not receipt['stale']
    assert observed['observation_id']==screen['observation_id']
    # Observation JSON does not expose per-child packageName. Derive only the
    # scope boundary actually evidenced by the bound grammar and complete text
    # projection; do not promote every visible c marker into an action grant.
    assert screen['visible_text_omitted']==screen['editable_fields_omitted']==0
    grammar=(FIXTURES/'frozen-step02-grammar.gbnf').read_text()
    capabilities=set()
    for line in grammar.splitlines():
        if line.startswith(('click-target ::=','type-target ::=','scroll-target ::=')):
            capabilities.update(re.findall(r'"(n\d+)"',line.replace('\\"','"')))
    lines=['    static PhoneObservation frozenObservation(){',
           '        List<PhoneObservation.Node> nodes=new ArrayList<PhoneObservation.Node>();']
    for row in observed['nodes']:
        node_id=row['id'];bounds=row['bounds'];text=row.get('text','');description=row.get('description','')
        label=text if text.strip() else description if description.strip() else row.get('child_text','')
        directions=row['scroll_directions'];interactive=row.get('clickable',False) or row.get('editable',False) or bool(directions)
        actions=('c' if row.get('clickable') else '')+('t' if row.get('editable') else '')+('s' if row.get('scrollable') else '')+('f' if row.get('focused') else '')
        in_scope=node_id in capabilities if interactive else node_id in meta or not (text or description)
        pkg=screen['package'] if in_scope else 'host.fixture.excluded_child'
        scroll='ObservedScrollActions.UNKNOWN' if directions is None else 'ObservedScrollActions.observed(Arrays.<String>asList('+','.join(literal(x) for x in directions)+'))'
        fields=[literal(node_id),literal(pkg),literal(label),literal(text),literal(description),literal(row.get('view_id','')),
                'new int[]{'+','.join(str(x) for x in bounds)+'}',literal(actions),scroll]
        lines.append('        nodes.add(new PhoneObservation.Node('+','.join(fields)+'));')
    ime='ImeVisibility.UNKNOWN' if screen['ime_visible'] is None else 'ImeVisibility.VISIBLE' if screen['ime_visible'] else 'ImeVisibility.HIDDEN'
    lines.append('        return new PhoneObservation('+','.join([literal(screen['observation_id']),literal(screen['package']),*[str(x) for x in screen['size']],ime,json_object(screen['window']),'nodes'])+');')
    changed=True if before['app_tree_sha256']!=after['app_tree_sha256'] else None if None in (before['ime_visible'],after['ime_visible']) else before['ime_visible']!=after['ime_visible']
    history={'step':1,'action':action['action'],'detail':receipt['detail'],'before_package':before['package'],
             'target_package':action['package'],'dispatched':False,'package_after':after['package'],
             'observation_after':after['observation_id'],'window_changed':changed,'ime_visible_before':before['ime_visible'],
             'ime_visible_after':after['ime_visible'],'query':action['query'],'offset':action['offset'],'read_only':True}
    lines.extend(['    }','    static JSONObject frozenHistory(){return '+json_object(history)+';}',
                  '    static String frozenOwner(){return '+literal(owner)+';}',
                  '    static String frozenTargetPackage(){return '+literal(value['apps'][0][0])+';}',
                  '    static String frozenTargetLabel(){return '+literal(value['apps'][0][1])+';}'])
    return '\n'.join(lines)


class AppSearchPromptTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.java=shutil.which('java')
        if cls.java is None:raise AssertionError('host JDK required; no skip')
        cls.compiler=[shutil.which('javac')] if shutil.which('javac') else [cls.java,'-m','jdk.compiler/com.sun.tools.javac.Main']
        for name,sha in PINNED_INPUTS.items():
            if hashlib.sha256((FIXTURES/name).read_bytes()).hexdigest()!=sha:raise AssertionError('frozen input changed: '+name)
        cls.base=(FIXTURES/'fdab-controller.java.txt').read_text()
        if hashlib.sha256(cls.base.encode()).hexdigest()!=BASE_SHA:raise AssertionError('pinned controller changed')
        cls.candidate=CONTROLLER.read_text();cls.frozen_prompt=(FIXTURES/'frozen-step02-prompt.txt').read_text()
        cls.temp=tempfile.TemporaryDirectory(prefix='hepta-app-search-');cls.out=Path(cls.temp.name);cls.outputs={}
        for variant,source in [('candidate',cls.candidate),('baseline',cls.base)]:
            text=(FIXTURES/'PromptProjectionHarness.java').read_text()
            start=source.index('    private static final String SYSTEM=');end=source.index('\n\n\n    public LocalTaskController',start)
            fragments={'SYSTEM':source[start:end],
                'HISTORY_LIMIT':re.search(r'    private static final int HISTORY_PROJECTION_UTF8_LIMIT=\d+;',source).group(),
                'PROMPT_FRAME':method(source,'    private static final class PromptFrame {'),
                'PROMPT':method(source,'    private static PromptFrame prompt('),
                'HISTORY_FIELDS':method(source,'    private static java.util.Map<String,Object> historyFields('),
                'NODE_SCORE':method(source,'    private static int nodeScore('),
                'SEARCH_METADATA':method(source,'    private static JSONObject searchMetadata('),
                'LIMITED':method((ROOT/'src/org/trillionnium/hepta/local/HeptaAccessibilityService.java').read_text(),'    static String limited('),
                'FROZEN_INPUT':frozen_input(cls.frozen_prompt),
                'CALL_PROMPT':'PromptFrame frame=prompt(owner,page,'+('provenance,' if variant=='candidate' else '')+'observation,history,null,config,guard);'}
            for name,body in fragments.items():
                marker='/*__'+name+'__*/'
                if text.count(marker)!=1:raise AssertionError('unique harness marker required: '+name)
                text=text.replace(marker,body)
            directory=cls.out/variant;directory.mkdir();java_file=directory/'PromptProjectionHarness.java';java_file.write_text(text)
            sources=[ROOT/'src/org/trillionnium/hepta/local'/(name+'.java') for name in PURE_CLASSES]
            result=subprocess.run(cls.compiler+['--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-d',str(directory),*[str(p) for p in sources],str(java_file)],capture_output=True,text=True,timeout=60)
            if result.returncode:raise AssertionError(variant+' actual prompt compile failed:\n'+result.stderr)
            cls.outputs[variant]=directory
        cls.cache={}

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def result(self,variant,scenario):
        key=(variant,scenario)
        if key not in self.cache:
            self.cache[key]=subprocess.run([self.java,'-cp',str(self.outputs[variant]),'PromptProjectionHarness',scenario],capture_output=True,text=True,timeout=15)
        return self.cache[key]

    def report(self,variant,scenario):
        result=self.result(variant,scenario)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        report=json.loads(result.stdout);data,owner=report['prompt'].removeprefix('UNTRUSTED_DATA\n').split('\nOWNER\n')
        report['data']=json.loads(data);report['owner']=owner
        return report

    def assert_completed(self,report,step=1):
        source=report['data']['app_search']
        self.assertIs(source.get('tool_completed'),True,'completed model query must survive optional history trimming')
        self.assertIs(source['model_issued'],True);self.assertEqual(source['source'],'model_find_app');self.assertEqual(source['source_step'],step)
        self.assertEqual(len(source['catalogue_sha256']),64)
        self.assertEqual(source,report['budget']['app_search'],'budget receipt and actual model prompt bind same query facts')

    def test_exact_predecessor_and_deadline_delta_remain_recoverable(self):
        self.assertEqual(restore_discovery_base(self.candidate),self.base)

    def test_baseline_reproduces_real_frozen_prompt_and_loses_completion(self):
        report=self.report('baseline','frozen')
        raw,owner=self.frozen_prompt.removeprefix('UNTRUSTED_DATA\n').split('\nOWNER\n')
        self.assertEqual(report['data'],json.loads(raw),'host observation boundary must reproduce actual frozen projected input')
        self.assertEqual(report['owner'],owner)
        self.assertEqual(report['prompt'],self.frozen_prompt,'frozen baseline prompt must match exact bytes, not only parsed fields')
        self.assertEqual(report['budget']['projection_context_score'],3930)
        self.assertEqual(hashlib.sha256(report['grammar'].encode()).hexdigest(),PINNED_INPUTS['frozen-step02-grammar.gbnf'])
        self.assertEqual(report['data']['recent'],[]);self.assertEqual(report['data']['history_omitted'],1)
        with self.assertRaisesRegex(AssertionError,'completed model query must survive'):
            self.assert_completed(report)
        print('EXPECTED_OLD_FAILURE: real prompt loses completed find_app after recent trimming')

    def test_completed_query_survives_actual_budget_with_owner_targets_grammar_intact(self):
        report=self.report('candidate','frozen');old=self.report('baseline','frozen')
        self.assert_completed(report)
        self.assertEqual(report['data']['recent'],[]);self.assertEqual(report['data']['history_omitted'],1)
        self.assertEqual(report['data']['screen'],old['data']['screen'])
        self.assertEqual(report['data']['apps'],old['data']['apps']);self.assertEqual(report['data']['open_allowed_packages'],old['data']['open_allowed_packages'])
        self.assertEqual(report['grammar'],old['grammar']);self.assertEqual(report['owner'],old['owner'])
        self.assertLessEqual(report['budget']['projection_context_score'],4096)
        print('PASS actual 4096 projection: old='+str(old['budget']['projection_context_score'])+' new='+str(report['budget']['projection_context_score'])+'; original screen/OWNER/grammar unchanged')

    def test_initial_ranking_is_distinct_from_model_tool_completion(self):
        report=self.report('candidate','initial');source=report['data']['app_search']
        self.assertEqual(source['source'],'initial_ranking');self.assertEqual(source['query'],'')
        self.assertIs(source['model_issued'],False);self.assertIs(source['tool_completed'],False);self.assertIsNone(source['source_step'])
        self.assertGreater(source['matches'],0)

    def test_many_queries_keep_one_latest_bound_completion(self):
        report=self.report('candidate','many-queries');self.assert_completed(report,19)
        source=report['data']['app_search'];self.assertEqual(source['query'],'synthetic');self.assertEqual(source['offset'],6)
        self.assertEqual(source['next_offset'],6+report['budget']['apps_shown'])
        self.assertEqual(len(source),10);self.assertEqual(report['data']['dispatched_sequence'],[])
        self.assertLessEqual(report['budget']['history_projection_utf8_bytes'],1024)

    def test_actual_budget_truncated_page_does_not_skip_unshown_results(self):
        report=self.report('candidate','truncated-page');self.assert_completed(report)
        shown=report['budget']['apps_shown'];self.assertGreater(shown,0);self.assertLess(shown,6)
        self.assertEqual(report['data']['app_search']['next_offset'],shown)
        self.assertEqual(report['data']['app_search']['offset'],0)

    def test_maximum_owner_stays_complete_and_source_is_mandatory(self):
        report=self.report('candidate','owner-bound');self.assert_completed(report)
        self.assertEqual(len(report['owner'].encode()),1600);self.assertTrue(report['owner'].startswith(self.report('baseline','frozen')['owner']))

    def test_page_binding_mismatch_rejects_before_a_model_prompt_is_returned(self):
        result=self.result('candidate','binding-mismatch');self.assertNotEqual(result.returncode,0)
        self.assertIn('app search provenance belongs to another page',result.stderr);self.assertEqual(result.stdout,'')

    def test_insufficient_context_rejects_without_omitting_mandatory_source(self):
        result=self.result('candidate','over-budget');self.assertNotEqual(result.returncode,0)
        self.assertIn('完整指令与必要画面信息超过本地上下文上限',result.stderr);self.assertEqual(result.stdout,'')


if __name__=='__main__':unittest.main(verbosity=2)
