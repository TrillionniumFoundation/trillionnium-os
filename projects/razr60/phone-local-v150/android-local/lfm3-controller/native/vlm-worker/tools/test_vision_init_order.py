#!/usr/bin/env python3
"""Execute the actual worker's vision initialization/metric statements using a host lifecycle double."""
from pathlib import Path
import argparse, hashlib, json, re, shutil, subprocess, sys
ROOT = Path(__file__).resolve().parents[1]

def pin(path):
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--cxx', default=shutil.which('c++'))
    args = parser.parse_args(); out = args.out.resolve()
    if not args.cxx or out.exists() or out == ROOT or ROOT in out.parents:
        raise ValueError('host compiler and new output outside source required')
    if sys.platform not in ('linux', 'darwin'):
        raise ValueError('Linux/macOS host required')
    out.mkdir(parents=True, mode=0o700)
    paths = [ROOT/'native/vlm-worker.cpp', ROOT/'tests/vision-init-order-fixture.cpp',
             Path(__file__).resolve()] + sorted((ROOT/'vendor/llama').glob('*.h'))
    before = {str(path.relative_to(ROOT)): pin(path) for path in paths}
    receipt = {'schema': 'hepta.vlm.vision-init-order-host-run.v1', 'sources': before,
               'commands': [], 'passed': False, 'phone_contacted': False,
               'model_inference_performed': False, 'opencl_backend_executed': False}
    def run(argv, name):
        result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=60)
        (out/(name+'.stdout')).write_bytes(result.stdout)
        (out/(name+'.stderr')).write_bytes(result.stderr)
        receipt['commands'].append({'argv': list(map(str, argv)), 'exit_code': result.returncode,
                                   'stdout': pin(out/(name+'.stdout')), 'stderr': pin(out/(name+'.stderr'))})
        if result.returncode:
            raise RuntimeError(name+' failed')
        return result.stdout
    try:
        source = (ROOT/'native/vlm-worker.cpp').read_text()
        selectors = {
            'parameters': r'^[ \t]*auto vp=mtmd_context_params_default\(\);vp.use_gpu=true;vp.device=gpu;vp.n_threads=4;[ \t]*$',
            'init': r'^[ \t]*res.vision=mtmd_init_from_file\(projector_fd.c_str\(\),res.model,vp\);[ \t]*$',
            'guard': r'^[ \t]*need\(res.vision && mtmd_support_vision\(res.vision\),"GPUOpenCL vision load failed; fallback forbidden"\);r.check\(\);[ \t]*$',
            'metric': r'^[ \t]*receipt\["vision_max_allocation_bytes"\]=uint64_t\(ggml_backend_buft_get_max_size\(ggml_backend_dev_buffer_type\(gpu\)\)\);[ \t]*$',
        }
        matches = {}
        for name, expression in selectors.items():
            found = list(re.finditer(expression, source, re.M))
            if len(found) != 1:
                raise ValueError('unique exact production statement missing: '+name)
            matches[name] = found[0]
        actual_order = sorted(('init', 'guard', 'metric'), key=lambda name: matches[name].start())
        statements = '\n'.join(matches[name].group() for name in actual_order)
        early_control = '\n'.join(matches[name].group() for name in ('metric', 'init', 'guard'))
        template = (ROOT/'tests/vision-init-order-fixture.cpp').read_text()
        replacements = {'@PARAMETERS@': matches['parameters'].group(),
                        '@PRODUCTION_STATEMENTS@': statements,
                        '@EARLY_METRIC_CONTROL@': early_control}
        for marker, replacement in replacements.items():
            if template.count(marker) != 1:
                raise ValueError('fixture placeholder differs')
            template = template.replace(marker, replacement)
        generated = out/'vision-init-order.cpp'; generated.write_text(template)
        (out/'production-statements.cpp.txt').write_text(statements+'\n')
        receipt['extraction'] = {'actual_source_order': actual_order,
            'statements': {name: {'line': source.count('\n', 0, match.start())+1,
                                 'utf8': match.group()} for name, match in matches.items()},
            'early_metric_control': 'same extracted statements reordered metric/init/guard, matching R5 failure order',
            'generated_fixture': pin(generated)}
        executable = out/'vision-init-order-test'
        run([args.cxx, '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', '-pedantic',
             '-I'+str(ROOT/'vendor/llama'), generated, '-o', executable], 'compile-test')
        result = json.loads(run([executable], 'execute-test'))
        if result.get('passed') is not True or type(result.get('cases')) is not int or result['cases'] != 5 \
                or type(result.get('checks')) is not int or result['checks'] != 23 \
                or result.get('production_statements_executed') is not True \
                or result.get('early_metric_control_rejected') is not True:
            raise ValueError('vision initialization lifecycle result differs')
        receipt['result'] = result
        receipt['sources_unchanged'] = all(pin(ROOT/name) == value for name, value in before.items())
        if not receipt['sources_unchanged']:
            raise ValueError('source changed during test')
        receipt['passed'] = True
    except Exception as error:
        receipt['error'] = str(error)
    finally:
        (out/'RESULT.json').write_text(json.dumps(receipt, indent=2)+'\n')
        print(json.dumps({'passed': receipt['passed'], 'result': receipt.get('result'), 'error': receipt.get('error')}))
    return 0 if receipt['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
