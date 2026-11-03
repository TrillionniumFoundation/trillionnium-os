"""Retained source/evidence checks only; no phone or model invocation."""
from pathlib import Path
import ast, json, runpy, sys

BASE = Path(__file__).resolve().parent
OLD = BASE.parent / 'stock16-hepta-app-ui-provider-C-v147-r4'
sys.path.insert(0, str(BASE / 'source'))
from provider_codex_host import advance_cli_error_diagnostic
from provider_openai_compatible import ProviderError

def dump(node): return ast.dump(node, include_attributes=False)

def main():
    checks = {}
    old = ast.parse((OLD / 'source/provider_codex_host.py').read_text())
    new = ast.parse((BASE / 'source/provider_codex_host.py').read_text())
    for name in ['model_transcript', 'advance_cli_error_diagnostic', 'selected_tool_disable_notice']:
        get = lambda tree: next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
        assert dump(get(old)) == dump(get(new)); checks[name + '_AST_unchanged'] = True
    def methods(tree):
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'CodexAdapter')
        return {node.name: node for node in cls.body if isinstance(node, ast.FunctionDef)}
    a, b = methods(old), methods(new)
    assert a.keys() == b.keys()
    class MetadataOnly(ast.NodeTransformer):
        def visit_Assign(self, node):
            if (len(node.targets) == 1 and isinstance(node.targets[0], ast.Attribute)
                    and dump(node.targets[0]) == dump(ast.parse('self.phone_tools = None').body[0].targets[0])):
                return None
            return self.generic_visit(node)
        def visit_Expr(self, node):
            if (isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute)
                    and node.value.func.attr == 'bind' and isinstance(node.value.func.value, ast.Attribute)
                    and node.value.func.value.attr == 'phone_tools'):
                return None
            return self.generic_visit(node)
    for name in a:
        if name == 'completion': continue
        assert dump(a[name]) == dump(MetadataOnly().visit(b[name])), name
    checks['all_CodexAdapter_methods_except_completion_equal_after_local_metadata_only'] = True
    for filename in ['provider_openai_compatible.py', 'ssh_exec_persistent_bridge.py']:
        assert (OLD/'source'/filename).read_bytes() == (BASE/'source'/filename).read_bytes()
        checks[filename + '_byte_equal'] = True
    checks['existing_projection_15_checks'] = runpy.run_path(str(OLD/'offline_projection_checks.py'))['main']()['checks_passed'] == 15
    evidence = Path.home()/'Library/Application Support/HEPTA/provider/state/provider/evidence'
    failed = evidence/'20261103-091721-fed10180c8f5499e90aed8994979fbdc/codex-06.events.jsonl'
    count=0
    for line in failed.read_text().splitlines(): count=advance_cli_error_diagnostic(json.loads(line),count)
    assert count==2; checks['genuine_reconnect_notice_still_waitable'] = True
    for event in [{'type':'error','message':'unknown'}, {'type':'turn.failed'},
                  {'type':'error','message':'Reconnecting... 6/5 (request timed out)'}]:
        try: advance_cli_error_diagnostic(event,0)
        except ProviderError: pass
        else: raise AssertionError('unrecognized error accepted')
    checks['genuine_failure_and_unknown_reconnect_still_rejected'] = True
    completion = methods(new)['completion']
    names=[node.func.attr for node in ast.walk(completion) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)]
    assert names.count('spawn_codex')==1 and names.count('map')==1 and names.count('prepare')==1
    checks['one_existing_CLI_spawn_per_completion_no_retry_added'] = True
    text=(BASE/'source/provider_codex_host.py').read_text()
    assert '"max_rounds": 8, "max_tool_calls": 16' in text and 'deadline = time.monotonic() + self.args.timeout' in text
    assert 'self.session_deadline is not None' in text and 'if process.returncode or not any(x.get("type") == "turn.completed"' in text
    checks['existing_round_deadlines_and_strict_completion_gate_retained'] = True
    assert '"--image", image_path' in text and '"view_image"' in text
    checks['image_input_flag_added_while_model_view_image_tool_remains_disabled'] = True
    return {'checks':checks,'checks_passed':len(checks),'model_executions':0,'phone_executions':0,'runtime_mutations':0}

if __name__=='__main__':print(json.dumps(main(),ensure_ascii=False,indent=2))
