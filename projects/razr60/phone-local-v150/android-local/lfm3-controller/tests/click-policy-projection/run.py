#!/usr/bin/env python3
"""Synthetic click-policy regressions: production Java fragments + independent GBNF.

Only the requested fresh output directory is written. No Android/device/model is invoked.
The full Android classes are not host-executed: four small source fragments
are compiled verbatim, changing only Android/JSON scaffold type names.
The actual pure PersistentActionPolicy, DecisionGrammar, label, scroll,
retention and bounded descendant classes are compiled without modification.
"""
import argparse
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
PURE = ['ActionDecision', 'ActionPolicy', 'PersistentActionPolicy', 'DecisionGrammar', 'ObservedTargetLabels',
        'ObservedScrollActions', 'ObservedChildText', 'PromptActionDomain',
        'RepeatActionGuard', 'SameStateNoEffectGuard', 'ObservationState', 'ImeVisibility']
CHANGED = ['PhoneObservation', 'HeptaAccessibilityService', 'DecisionGrammar', 'LocalTaskController']
PKG = 'org.example.controls'
OBS = '0' * 32


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def match_one(pattern, text):
    found = list(re.finditer(pattern, text, re.S))
    if len(found) != 1:
        raise AssertionError(f'Expected one production fragment, found {len(found)}: {pattern}')
    return found[0]


def fragment(text, pattern, label, records, filename):
    m = match_one(pattern, text)
    records.append(dict(name=label, source=filename.name,
                        first_line=text.count('\n', 0, m.start()) + 1,
                        last_line=text.count('\n', 0, m.end()) + 1,
                        sha256=hashlib.sha256(m.group().encode()).hexdigest()))
    return m.group()


def generate_bridge(source, out):
    service_path = source / 'HeptaAccessibilityService.java'
    controller_path = source / 'LocalTaskController.java'
    service = service_path.read_text()
    controller = controller_path.read_text()
    records = []
    raw = fragment(service,
        r'boolean password=node\.isPassword\(\);\s*String rawText=.*?String description=limited\(rawDescription,96\);',
        'raw_observation_capture', records, service_path)
    policy = fragment(service,
        r'PersistentActionPolicy\.Decision clickPolicy=PersistentActionPolicy\.evaluate\(.*?;',
        'observation_click_classification', records, service_path)
    projection = fragment(controller,
        r'JSONArray projectedNodes=new JSONArray\(\);.*?screen\.put\("nodes",projectedNodes\).*?;',
        'prompt_node_projection', records, controller_path)
    domain = fragment(controller,
        r'for\(int i=0;i<nodeCount;i\+\+\)\{\s*PhoneObservation\.Node node=nodes\.get\(i\);\s*if\(!node\.enabled.*?\n\s*\}',
        'grammar_node_domain', records, controller_path)
    no_effect_filter = fragment(controller,
        r'clicks=noEffects\.allowedClicks\(repeatGuard\.allowedClicks\(clicks,observation\.state\)\);',
        'existing_repeat_and_no_effect_domain_subtraction', records, controller_path)
    parse_gate = fragment(controller,
        r'action=ActionDecision\.parse\(answer\.text,DecisionGrammar\.SCHEMA\);.*?throw new ActionDecision\.InvalidActionException\("scroll node/direction was not supplied by this observation"\);',
        'post_parse_domain_validation', records, controller_path)
    limited = fragment(service, r'static String limited\(String text,int max\)\{[^\n]+\}',
                       'display_truncation', records, service_path)
    adapters = {'JSONArray': 'JArray', 'JSONObject': 'JObject', 'PhoneObservation.Node': 'Node'}
    for original, replacement in adapters.items():
        projection = projection.replace(original, replacement)
        domain = domain.replace(original, replacement)
    bridge = '''package org.trillionnium.hepta.local;
import java.util.*;
import static org.trillionnium.hepta.local.ClickProjectionProbe.*;
/** Generated source fragments; see fragment-manifest.json for source ranges. */
final class ProductionFragments {
  private ProductionFragments() {}
  private static String string(CharSequence value){return value==null?"":value.toString();}
  %s
  static void capture(Node node) {
    Child childText=node.childText;
    %s
    %s
    node.text=text;node.description=description;node.clickPolicy=clickPolicy;
  }
  static Snapshot project(Observation observation, Set<String> packages) {
    List<Node> nodes=observation.nodes;int nodeCount=nodes.size();String blockedClick=null;
    RepeatActionGuard repeatGuard=new RepeatActionGuard();
    SameStateNoEffectGuard.Snapshot noEffects=noEffectSnapshot(observation);
    JObject screen=new JObject();
    %s
    Set<String> clicks=new HashSet<String>(),edits=new HashSet<String>();
    Map<String,ObservedScrollActions> scrolls=new HashMap<String,ObservedScrollActions>();
    %s
    ObservedTargetLabels targets=ObservedTargetLabels.create(ObservedTargetLabels.SCHEMA,
        observation.id,observation.packageName,projectedLabels);
    %s
    DecisionGrammar grammar=DecisionGrammar.create(observation.id,observation.packageName,
        packages,clicks,edits,scrolls,targets);
    return new Snapshot(screen,grammar);
  }
  static void validate(String raw,Snapshot snapshot,Set<String> packages)
      throws ActionDecision.InvalidActionException {
    ActionDecision action;
    Answer answer=new Answer(raw);Frame frame=new Frame(snapshot,packages);
    Observation before=new Observation(snapshot.grammar.observationId,
        snapshot.grammar.currentPackage,Collections.<Node>emptyList());
    %s
  }
}
''' % (limited, raw, policy, projection, domain, no_effect_filter, parse_gate)
    path = out / 'ProductionFragments.java'
    path.write_text(bridge)
    (out / 'fragment-manifest.json').write_text(json.dumps(dict(
        fragments=records, scaffold_type_adaptations=adapters,
        full_android_controller_executed=False, repeat_guard_fixture_state='no blocked repeat',
        no_effect_fixture_state='empty plus a real pure-guard observed unchanged click on n15',
        production_sort_and_budget_loop_executed=False), indent=2) + '\n')
    return path


def node(node_id, text='', description='', child_text='', **kw):
    return dict(id=node_id, text=text, description=description, child_text=child_text,
                clickable=kw.get('clickable', True), editable=kw.get('editable', False),
                enabled=kw.get('enabled', True), password=kw.get('password', False),
                package=kw.get('package', PKG), scroll_directions=kw.get('scroll_directions', []),
                scroll_actions_observed=kw.get('scroll_actions_observed', True),
                focused=kw.get('focused', False))


def write_fixture(directory, name, observation, apps):
    encode = lambda value: base64.b64encode(value.encode()).decode()
    b = lambda value: str(value).lower()
    lines = ['\t'.join([observation['observation_id'], observation['package'], ','.join(apps),
                       ','.join(observation.get('no_effect_click_ids', []))])]
    for n in observation['nodes']:
        lines.append('\t'.join([n['id'], encode(n.get('text', '')), encode(n.get('description', '')),
            encode(n.get('child_text', '')), b(n.get('clickable', False)), b(n.get('editable', False)),
            b(n.get('enabled', True)), b(n.get('password', False)), encode(n.get('package', observation['package'])),
            ','.join(n.get('scroll_directions', [])) if n.get('scroll_actions_observed', True) else '?',
            b(n.get('focused', False))]))
    (directory / (name + '.tsv')).write_text('\n'.join(lines) + '\n')


def prepare_fixtures(directory):
    mixed = [
        node('n0', child_text='清除历史记录'),
        node('n1', '清除历史记录', editable=True, focused=True),
        node('n2', description='清除'),
        node('n3', 'x' * 120 + ' Clear history'),
        node('n4', '继续', description='y' * 120 + ' Delete files'),
        node('n5', child_text='z' * 45 + ' 清除历史记录'),
        node('n6', '取消删除'),
        node('n7', '卸载'),
        node('n8', '清除历史记录', clickable=False),
        node('n9', '查看记录', enabled=False),
        node('n10', 'SECRET Clear data', description='SECRET Description', editable=True, password=True),
        node('n11', 'Other window', package='org.example.other'),
        node('n12', 'Clear cache', scroll_directions=['down']),
        node('n13', 'ＣＬＥＡＲ　ＤＡＴＡ'),
        node('n14', ''),
        node('n15', '应用管理'),
        node('n16', 'Delete files'),
        node('n17', description='删除'),
        node('n18', '取消', child_text='清除历史记录'),
        node('n19', '历史记录'),
    ]
    write_fixture(directory, 'mixed', dict(observation_id=OBS, package=PKG, nodes=mixed), ['org.example.notes'])
    write_fixture(directory, 'mixed-no-effect', dict(observation_id=OBS, package=PKG, nodes=mixed,
                  no_effect_click_ids=['n15']), ['org.example.notes'])
    write_fixture(directory, 'all-blocked', dict(observation_id=OBS, package=PKG,
        nodes=[node('n0', child_text='Clear history'), node('n1', description='Uninstall')]), [])


def raw(action, observation=OBS, package=PKG, **fields):
    return json.dumps(dict(reason='依据当前观察推进任务', action=action,
                          observation_id=observation, package=package, **fields),
                      ensure_ascii=False, separators=(',', ':'))


class ProjectionRegressionTests(unittest.TestCase):
    def projection(self, name='mixed'):
        return json.loads((self.output / (name + '.json')).read_text())

    def grammar(self, name='mixed'):
        return self.Recognizer((self.output / (name + '.gbnf')).read_text())

    def test_unavailable_nodes_remain_observation_data_not_click_capability(self):
        p = self.projection()
        rows = {r[0]: r for r in p['screen']['nodes']}
        denied = {x['node_id'] for x in p['screen']['unavailable_clicks']}
        expected = {'n0', 'n3', 'n4', 'n5', 'n7', 'n12', 'n13', 'n16', 'n18'}
        self.assertEqual(denied, expected)
        self.assertEqual(len(rows), 20)
        for ident in expected:
            self.assertIn(ident, p['targets'])
            self.assertNotIn('c', rows[ident][3])
            self.assertNotIn(ident, p['click_nodes'])
        self.assertEqual(rows['n0'][1], '清除历史记录')
        self.assertEqual(rows['n8'][1], '清除历史记录')

    def test_prompt_click_flags_equal_the_final_grammar_click_domain(self):
        for name in ['mixed', 'all-blocked', 'mixed-no-effect']:
            with self.subTest(fixture=name):
                p = self.projection(name)
                prompt_clicks = {r[0] for r in p['screen']['nodes'] if 'c' in r[3]}
                self.assertEqual(prompt_clicks, set(p['click_nodes']))

    def test_valid_observed_pairs_still_require_the_postparse_click_gate(self):
        for name in ['mixed', 'all-blocked']:
            p = self.projection(name)
            for check in p['parser_checks']:
                with self.subTest(fixture=name, node=check['id']):
                    self.assertTrue(check['syntax_parsed'])
                    self.assertTrue(check['pair_validated'])
                    self.assertEqual(check['controller_accepted'], check['grammar_allows_click'])
            blocked = {x['id']: x for x in p['parser_checks']}['n0']
            self.assertFalse(blocked['controller_accepted'])

    def test_full_direct_text_is_classified_before_96_and_36_unit_projection(self):
        p = self.projection(); policy = {x['id']: x for x in p['policies']}['n3']
        self.assertNotIn('history', policy['display_text'])
        self.assertLessEqual(len(policy['display_text']), 97)
        self.assertFalse(policy['allowed'])
        self.assertNotIn('history', p['targets']['n3'])
        self.assertFalse(self.grammar().accepts(raw('click', node_label=p['targets']['n3'], node_id='n3')))

    def test_full_description_is_checked_even_when_short_direct_label_wins(self):
        p = self.projection(); policy = {x['id']: x for x in p['policies']}['n4']
        self.assertEqual(p['targets']['n4'], '继续')
        self.assertNotIn('files', policy['display_description'])
        self.assertFalse(policy['allowed'])
        self.assertFalse(self.grammar().accepts(raw('click', node_label='继续', node_id='n4')))

    def test_child_text_is_classified_before_36_unit_model_label_truncation(self):
        p = self.projection()
        self.assertNotIn('历史', p['targets']['n5'])
        self.assertNotIn('n5', p['click_nodes'])

    def test_editable_field_focus_and_type_keep_the_existing_exception(self):
        g = self.grammar()
        self.assertTrue(g.accepts(raw('click', node_label='清除历史记录', node_id='n1')))
        self.assertTrue(g.accepts(raw('type', node_label='清除历史记录', node_id='n1', text='新查询')))
        policies = {x['id']: x for x in self.projection()['policies']}
        self.assertEqual(policies['n1']['reason'], 'input_focus_not_persistent_command')
        self.assertFalse(policies['n16']['allowed'])  # Noneditable fake exposes inputType=1.

    def test_editable_same_label_cannot_transfer_permission_to_destructive_parent(self):
        g = self.grammar()
        self.assertFalse(g.accepts(raw('click', node_label='清除历史记录', node_id='n0')))
        self.assertFalse(g.accepts(raw('type', node_label='清除历史记录', node_id='n0', text='x')))
        self.assertFalse(g.accepts(raw('click', node_label='取消删除', node_id='n0')))

    def test_bare_calculator_labels_cancel_and_unclassified_controls_are_preserved(self):
        g = self.grammar(); p = self.projection()
        for ident in ['n2', 'n6', 'n14', 'n15', 'n17', 'n19']:
            with self.subTest(node=ident):
                self.assertTrue(g.accepts(raw('click', node_label=p['targets'][ident], node_id=ident)))

    def test_disabled_password_foreign_and_nonclickable_nodes_remain_excluded(self):
        g = self.grammar(); p = self.projection()
        for ident in ['n8', 'n9', 'n10', 'n11']:
            with self.subTest(node=ident):
                self.assertNotIn(ident, p['click_nodes'])
                self.assertFalse(g.accepts(raw('click', node_label=p['targets'][ident], node_id=ident)))
        self.assertEqual(p['targets']['n10'], '')
        self.assertNotIn('SECRET', json.dumps(p))
        self.assertFalse(g.accepts(raw('type', node_label='', node_id='n10', text='anything')))

    def test_scroll_capability_is_not_removed_with_click_capability(self):
        g = self.grammar()
        self.assertFalse(g.accepts(raw('click', node_label='Clear cache', node_id='n12')))
        self.assertTrue(g.accepts(raw('scroll', node_label='Clear cache', node_id='n12', direction='down')))
        self.assertFalse(g.accepts(raw('scroll', node_label='Clear cache', node_id='n12', direction='up')))

    def test_all_clicks_blocked_still_has_valid_nonclick_grammar(self):
        p = self.projection('all-blocked');g = self.grammar('all-blocked')
        self.assertEqual(p['click_nodes'], [])
        self.assertEqual(set(p['actions']), {'back', 'home', 'find_app', 'wait', 'done'})
        for action in ['back', 'home']:
            self.assertTrue(g.accepts(raw(action)))

    def test_nonclick_alternatives_remain_recognized(self):
        for name in ['mixed', 'all-blocked']:
            g = self.grammar(name)
            for action, fields in [('back', {}), ('home', {}),
                                   ('find_app', dict(query='notes', offset=0)),
                                   ('wait', dict(duration_ms=100)),
                                   ('done', dict(status='partial', summary='More navigation is needed'))]:
                with self.subTest(fixture=name, action=action):
                    self.assertTrue(g.accepts(raw(action, **fields)))
        self.assertTrue(self.grammar().accepts(raw('open', package='org.example.notes')))

    def test_blocked_clickable_labels_still_participate_in_retention_domain(self):
        policies = {x['id']: x for x in self.projection()['policies']}
        self.assertTrue(policies['n0']['retained_for_action_domain'])
        self.assertFalse(policies['n0']['allowed'])

    def test_executor_keeps_fresh_policy_before_actual_click(self):
        text = (self.source / 'HeptaAccessibilityService.java').read_text()
        start = text.index('    private void performOnMain(')
        executor = text[start:text.index('    private void coordinateClick(', start)]
        self.assertIn('freshChildText.text,node.isEditable()', executor)
        self.assertLess(executor.index('if(!policy.allowed)'), executor.index('node.performAction(AccessibilityNodeInfo.ACTION_CLICK)'))

    def test_controller_keeps_postparse_domain_gate_and_repeat_filter(self):
        text = (self.source / 'LocalTaskController.java').read_text()
        self.assertRegex(text, r'"click"\.equals\(action\.action\)&&!frame\.grammar\.allowsClick\(action\.nodeId\)')
        self.assertIn('click target is outside this observation\'s allowed click domain', text)
        self.assertIn('clicks=noEffects.allowedClicks(repeatGuard.allowedClicks(clicks,observation.state));', text)
        self.assertIn('screen.unavailable_clicks', text)
        self.assertIn('文字仍是观察数据，不授予点击', text)

    def test_existing_no_effect_evidence_still_blocks_prompt_grammar_and_postparse(self):
        p = self.projection('mixed-no-effect')
        rows = {r[0]: r for r in p['screen']['nodes']}
        self.assertNotIn('c', rows['n15'][3])
        self.assertNotIn('n15', p['click_nodes'])
        self.assertTrue({x['id']: x for x in p['policies']}['n15']['allowed'])
        self.assertFalse(self.grammar('mixed-no-effect').accepts(
            raw('click', node_label=p['targets']['n15'], node_id='n15')))
        check = {x['id']: x for x in p['parser_checks']}['n15']
        self.assertTrue(check['syntax_parsed'] and check['pair_validated'])
        self.assertFalse(check['controller_accepted'])
        self.assertIn('n15', self.projection('mixed')['click_nodes'])
        self.assertIn('n2', p['click_nodes'])

    def test_observation_classification_is_required_and_serialized(self):
        text = (self.source / 'PhoneObservation.java').read_text()
        self.assertIn('if(clickPolicy==null)throw new IllegalArgumentException', text)
        self.assertIn('value.put("click_policy_allowed",clickPolicy.allowed)', text)
        self.assertIn('.put("click_policy_reason",clickPolicy.reasonCode)', text)

    def test_bounded_descendant_limitation_is_explicit_not_claimed_fixed(self):
        limitation = json.loads((self.output / 'descendant-boundary.json').read_text())
        self.assertTrue(limitation['child_truncated'])
        self.assertLessEqual(limitation['child_units'], 96)
        self.assertFalse(limitation['full_raw_policy_allowed'])
        self.assertTrue(limitation['bounded_child_policy_allowed'])
        self.assertTrue(limitation['source_hash_retained'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True,
                        help='Application source root containing src/ and tests/action-grammar/')
    parser.add_argument('--out', type=Path, required=True, help='New directory for generated test results')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    generated = out / 'generated'; generated.mkdir()
    fixtures = out / 'fixtures'; fixtures.mkdir()
    classes = out / 'classes'; classes.mkdir()
    output = out / 'projection'; output.mkdir()
    source_root = args.source.resolve()
    source = source_root / 'src/org/trillionnium/hepta/local'
    input_paths = [source / (n + '.java') for n in set(PURE + CHANGED)]
    input_paths.append(source_root / 'tests/action-grammar/gbnf_recognizer.py')
    inputs = {str(path.relative_to(source_root)): sha(path) for path in input_paths}
    report = dict(schema='hepta.synthetic-click-policy-regression.v1', all_pass=False,
                  scope='synthetic_host_source_fragments_and_independent_gbnf', phone_tested=False,
                  native_grammar_model_tested=False, full_android_classes_executed=False,
                  started_wall_ms=int(time.time()*1000), source_inputs=inputs, checks=[])
    try:
        bridge = generate_bridge(source, generated)
        prepare_fixtures(fixtures)
        java = shutil.which('java')
        if not java:
            raise RuntimeError('Existing Java runtime required; no installation attempted')
        compiler = [shutil.which('javac')] if shutil.which('javac') else [java, '-m', 'jdk.compiler/com.sun.tools.javac.Main']
        def run(name, command):
            result = subprocess.run([str(x) for x in command], cwd=HERE, capture_output=True, timeout=60)
            (out / (name + '.stdout')).write_bytes(result.stdout)
            (out / (name + '.stderr')).write_bytes(result.stderr)
            report['checks'].append(dict(name=name, exit_code=result.returncode))
            if result.returncode:
                raise RuntimeError(name + ': ' + result.stderr.decode(errors='replace')[-3000:])
        run('compile', compiler + ['--release', '8', '-encoding', 'UTF-8', '-Xlint:all', '-Werror', '-d', classes,
            *[source / (n + '.java') for n in PURE], HERE / 'ClickProjectionProbe.java', bridge])
        run('java-projection', [java, '-cp', classes, 'org.trillionnium.hepta.local.ClickProjectionProbe', fixtures, output])
        recognizer_path = source_root / 'tests/action-grammar/gbnf_recognizer.py'
        spec = importlib.util.spec_from_file_location('synthetic_gbnf_recognizer', recognizer_path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        ProjectionRegressionTests.Recognizer = staticmethod(module.Recognizer)
        ProjectionRegressionTests.source = source
        ProjectionRegressionTests.output = output
        stream = io.StringIO()
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(ProjectionRegressionTests))
        (out / 'regressions.log').write_text(stream.getvalue())
        report['tests_run'] = result.testsRun
        report['failures'] = [str(t) for t, _ in result.failures]
        report['errors'] = [str(t) for t, _ in result.errors]
        if any(sha(source_root / path) != digest for path, digest in inputs.items()):
            raise RuntimeError('A production source input changed during testing')
        report['all_pass'] = result.wasSuccessful()
    except Exception as error:
        report['error'] = str(error)
    finally:
        report['finished_wall_ms'] = int(time.time()*1000)
        (out / 'result.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({key: report.get(key) for key in ['all_pass', 'tests_run', 'failures', 'errors', 'error']}, ensure_ascii=False))
    return 0 if report['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
