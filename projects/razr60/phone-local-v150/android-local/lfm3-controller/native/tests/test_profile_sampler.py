#!/usr/bin/env python3
"""Exercise the generated C worker with captured SDK arguments and fake tokens.

The model bytes, tokenizer and SDK are explicit test doubles. No model quality,
NPU/GPU execution, Android behavior or phone qualification is asserted.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import time

ORVENA = 'orvena-4b-q4_k_m'
G, T, A, B = '1' * 32, '2' * 32, 'a' * 32, 'b' * 32
WEIGHT = b'host-only fake model bytes\n'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def float32(value):
    return struct.unpack('<f', struct.pack('<f', value))[0]


def expected_sampler(profile):
    old = dict(temperature=0, top_p=1, top_k=1, repetition_penalty=1, seed=42)
    if profile != ORVENA:
        return old
    return dict(temperature=float32(.7), top_p=float32(.8), top_k=40,
                repetition_penalty=1, seed=42, min_p=float32(.05),
                presence_penalty=0, frequency_penalty=0)


def change_once(text, old, new):
    if text.count(old) != 1:
        raise AssertionError('frozen test harness anchor differs: ' + old)
    return text.replace(old, new)


def harness(existing):
    code = existing.HARNESS
    code = change_once(code, 'static const HeptaModelProfile test_profile=', 'static HeptaModelProfile test_profile=')
    code = change_once(code, '(void)hepta_take_model_profile;hepta_model_profile=&test_profile;', '''(void)hepta_take_model_profile;
    const HeptaModelProfile *selected=hepta_find_profile(getenv("HEPTA_TEST_PROFILE"));assert(selected);
    test_profile.id=selected->id;test_profile.exact_tokens=selected->exact_tokens;
    hepta_model_profile=&test_profile;''')
    code = change_once(code, '.exact=true,.model_sha256=test_profile.sha256', '.exact=test_profile.exact_tokens,.model_sha256=test_profile.sha256')
    code = change_once(code, 'assert(!strcmp(in->plugin_id,"llama_cpp")&&!strcmp(in->mode,"npu"));out->device_id=strdup("HTP0");out->ngl=-1;return 0;',
                        'assert(!strcmp(in->plugin_id,"llama_cpp")&&(!strcmp(in->mode,"npu")||!strcmp(in->mode,"gpu")));out->device_id=strdup(!strcmp(in->mode,"npu")?"HTP0":"GPUOpenCL");out->ngl=-1;return 0;')
    code = change_once(code, 'int n=asprintf(&out->formatted_text,"%s\\n%s",in->messages[0].content,in->messages[1].content);assert(n>0);return 0;',
                        '''int n=asprintf(&out->formatted_text,"%s\\n%s",in->messages[0].content,in->messages[1].content);assert(n>0);
    out->chat_template_grammar.grammar_type=GENIEX_GRAMMAR_TYPE_USER;
    out->chat_template_grammar.grammar=strdup("root ::= \\\"x\\\"\\n");return 0;''')
    code = change_once(code, '''    assert(handle==(geniex_LLM *)&fake_handle&&!dirty&&in->input_ids&&in->input_ids_count>0&&!in->prompt_utf8);
    assert(in->config&&in->config->sampler_config&&in->config->sampler_config->grammar_string&&in->on_token("x",in->user_data));''', r'''    assert(handle==(geniex_LLM *)&fake_handle&&!dirty);
    if(test_profile.exact_tokens)assert(in->input_ids&&in->input_ids_count>0&&!in->prompt_utf8);
    else assert(in->prompt_utf8&&!in->input_ids&&in->input_ids_count==0);
    assert(in->config&&in->config->sampler_config);
    const geniex_SamplerConfig *s=in->config->sampler_config;
    bool orvena=!strcmp(test_profile.id,"orvena-4b-q4_k_m");
    assert(s->temperature==(orvena?0.7f:0.0f));assert(s->top_p==(orvena?0.8f:1.0f));
    assert(s->top_k==(orvena?40:1));assert(s->min_p==(orvena?0.05f:0.0f));
    assert(s->repetition_penalty==1.0f&&s->presence_penalty==0.0f&&s->frequency_penalty==0.0f&&s->seed==42);
    assert(!s->grammar_path&&!s->ignore_eos&&!in->config->sliding_window);
    if(getenv("HEPTA_TEST_NO_EXPLICIT_GRAMMAR")){
        assert(!s->grammar_string&&s->chat_template_grammar.grammar_type==GENIEX_GRAMMAR_TYPE_USER);
        assert(s->chat_template_grammar.grammar&&!strcmp(s->chat_template_grammar.grammar,"root ::= \\\"x\\\"\\n"));
    }else{
        assert(s->grammar_string&&!strcmp(s->grammar_string,"root ::= \\\"x\\\"\\n"));
        assert(s->chat_template_grammar.grammar_type==GENIEX_GRAMMAR_TYPE_NONE&&!s->chat_template_grammar.grammar);
    }
    fprintf(stderr,"HOST_SAMPLER_CONFIG {\"temperature\":%.17g,\"top_p\":%.17g,\"top_k\":%d,\"min_p\":%.17g,\"repetition_penalty\":%.17g,\"presence_penalty\":%.17g,\"frequency_penalty\":%.17g,\"seed\":%d}\n",
        (double)s->temperature,(double)s->top_p,s->top_k,(double)s->min_p,(double)s->repetition_penalty,(double)s->presence_penalty,(double)s->frequency_penalty,s->seed);
    fputs("HOST_INPUT_IDS [",stderr);
    for(int32_t i=0;i<in->input_ids_count;i++){if(i)fputc(',',stderr);fprintf(stderr,"%" PRId32,in->input_ids[i]);}
    fputs("]\n",stderr);
    assert(in->on_token("x",in->user_data));''')
    code = change_once(code, 'out->profile_data.prompt_tokens=in->input_ids_count;',
                        'out->profile_data.prompt_tokens=test_profile.exact_tokens?in->input_ids_count:(int32_t)strlen(in->prompt_utf8)+1;')
    code = change_once(code, '(void)model;assert(!strcmp(key,"general.architecture"));return snprintf(buf,size,"host-test");',
                        '(void)model;if(!strcmp(key,"tokenizer.ggml.pre"))return snprintf(buf,size,"minicpm5");assert(!strcmp(key,"general.architecture"));return snprintf(buf,size,"host-test");')
    # JSON and C share these ASCII string escapes; keep one literal for both grammar checks.
    grammar_literal = json.dumps('root ::= "x"\n')
    lines = code.splitlines()
    for index, line in enumerate(lines):
        if 'assert(s->grammar_string&&!strcmp(s->grammar_string,' in line:
            lines[index] = '        assert(s->grammar_string&&!strcmp(s->grammar_string,' + grammar_literal + '));'
        if 'assert(s->chat_template_grammar.grammar&&!strcmp(s->chat_template_grammar.grammar,' in line:
            lines[index] = '        assert(s->chat_template_grammar.grammar&&!strcmp(s->chat_template_grammar.grammar,' + grammar_literal + '));'
    code = '\n'.join(lines) + '\n'
    return code.replace('TEST_MODEL_SHA', hashlib.sha256(WEIGHT).hexdigest()).replace('TEST_MODEL_BYTES', str(len(WEIGHT)))


def exercise(binary, root, profile, mode, existing, axis='npu', explicit_grammar=True):
    root.mkdir(mode=0o700)
    (root / 'runs').mkdir(mode=0o700)
    (root / 'runs' / G).mkdir(mode=0o700)
    model = root / 'fixture.gguf'
    model.write_bytes(WEIGHT + (b'changed' if mode == 'bad_model' else b''))
    model.chmod(0o600)
    prompts = {A: 'first complete synthetic prompt', B: 'second complete independent synthetic prompt'}
    if mode == 'overflow':
        prompts[A] = 'x' * 4096
    if mode == 'warm_overflow':
        prompts[B] = 'x' * 4096
    for request, prompt in prompts.items():
        existing.request_files(root, request, prompt)
    first = root / 'runs' / A
    argv = [str(binary), '--request-id', A, '--mode', 'llm', '--runtime', 'llama_cpp', '--compute', axis,
            '--model', str(model), '--prompt-file', str(first / 'prompt.txt'), '--system-file', str(first / 'system.txt'),
            '--result-file', str(first / 'native-result.json'), '--text-file', str(first / 'raw-text.txt'),
            '--ctx-size', '4096', '--max-tokens', '32', '--threads', '2', '--timeout-ms', '5000', '--log-level', 'debug']
    if explicit_grammar:
        argv += ['--grammar-file', str(first / 'grammar.gbnf')]
    warm = mode in ('warm', 'warm_overflow')
    if warm:
        argv += ['--warm-generation', G, '--warm-task-id', T, '--warm-session-dir', str(root / 'runs' / G)]
    environment = dict(os.environ, HEPTA_TEST_PROFILE=profile)
    if not explicit_grammar:
        environment['HEPTA_TEST_NO_EXPLICIT_GRAMMAR'] = '1'
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    control = []
    try:
        if warm:
            control.append(existing.line(process))
            assert control[-1] == f'HEPTA_WARM_READY {G} {T} {process.pid}'
            for sequence, request in enumerate((A, B), 1):
                process.stdin.write(f'RUN {G} {T} {request} {sequence} 32 5000\n'.encode())
                process.stdin.flush()
                control.append(existing.line(process))
                expected_status = 70 if mode == 'warm_overflow' and sequence == 2 else 0
                assert control[-1] == f'HEPTA_WARM_DONE {G} {T} {request} {sequence} {expected_status}'
                if sequence == 1:
                    assert process.poll() is None
            if mode == 'warm':
                process.stdin.write(f'CLOSE {G} {T}\n'.encode())
                process.stdin.flush()
            process.stdin.close()
            code = process.wait(timeout=10)
            stdout, stderr = process.stdout.read(), process.stderr.read()
        else:
            stdout, stderr = process.communicate(timeout=10)
            code = process.returncode
        (root / 'worker.stdout').write_bytes(stdout)
        (root / 'worker.stderr').write_bytes(stderr)
        (root / 'control.json').write_text(json.dumps(control) + '\n')
        expected_code = 70 if mode in ('overflow', 'warm_overflow', 'bad_model') else 0
        assert code == expected_code, f'exit {code}, expected {expected_code}: {stderr.decode(errors="replace")}'
        captures = [json.loads(line.removeprefix('HOST_SAMPLER_CONFIG ')) for line in stderr.decode().splitlines() if line.startswith('HOST_SAMPLER_CONFIG ')]
        input_captures = [json.loads(line.removeprefix('HOST_INPUT_IDS ')) for line in stderr.decode().splitlines() if line.startswith('HOST_INPUT_IDS ')]
        expected_count = 0 if mode in ('overflow', 'bad_model') else 1 if mode in ('once', 'warm_overflow') else 2
        assert len(captures) == expected_count, 'actual SDK generate call count differs'
        assert len(input_captures) == expected_count, 'actual SDK input IDs capture count differs'
        wanted = expected_sampler(profile)
        for capture in captures:
            assert capture == dict(wanted, min_p=wanted.get('min_p', 0), presence_penalty=0, frequency_penalty=0)
        for index, request in enumerate((A, B) if warm else (A,)):
            raw = (root / 'runs' / request / 'native-result.json').read_bytes()
            receipt = json.loads(raw)
            assert receipt['sampler_requested'] == wanted, 'receipt differs from actual submitted numeric policy'
            if profile != ORVENA:
                assert b'"sampler_requested":{"temperature":0,"top_p":1,"top_k":1,"repetition_penalty":1,"seed":42},"image_token_bounds_exposed_by_abi":false,' in raw
            if mode in ('overflow', 'warm_overflow') and request == (B if warm else A):
                assert receipt['generation_complete'] is False and receipt['generate_attempt_count'] == 0
                assert receipt['prompt_budget']['admitted'] is False
            if mode == 'bad_model':
                assert receipt['error'] == 'pinned_model_identity_failed' and receipt['generate_attempt_count'] == 0
            if receipt['generation_complete']:
                # Independent Python encoding/hash checks the actual fake SDK
                # argument capture against both published IDs and the receipt.
                # The token values still come from the declared fake tokenizer.
                submitted=input_captures[index]
                encoded=b''.join(struct.pack('<I',token) for token in submitted)
                directory=root/'runs'/request
                formatted=(directory/'formatted-prompt.txt').read_bytes()
                assert submitted==[1]+[byte+2 for byte in formatted]
                assert (directory/'formatted-input-ids.le32').read_bytes()==encoded
                evidence=json.loads((directory/'prompt-evidence.json').read_bytes())
                budget=receipt['prompt_budget']
                assert budget['method']=='llama_tokenize_exact_same_input_ids' and budget['is_exact_token_count'] is True
                assert budget['input_ids_passed_directly'] is True and evidence['input_ids_will_be_passed_directly'] is True
                assert len(submitted)==budget['prompt_tokens_exact']==budget['input_ids_count']==receipt['profile']['prompt_tokens']==evidence['input_ids_count']
                assert hashlib.sha256(encoded).hexdigest()==budget['input_ids_sha256']==evidence['input_ids_sha256']
        if warm:
            terminal = json.loads((root / 'runs' / G / 'native-session-result.json').read_bytes())
            assert terminal['requests_received'] == 2 and terminal['requests_completed'] == (1 if mode == 'warm_overflow' else 2)
            assert terminal['sdk_destroy_rc'] == terminal['sdk_deinit_rc'] == 0
        return dict(profile=profile, mode=mode, compute=axis, explicit_grammar=explicit_grammar,
                    exit_code=code, actual_generate_calls=len(captures), passed=True)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    output.mkdir(mode=0o700, exist_ok=False)
    existing = module('sampler_existing_native_harness', source / 'native/tests/test_warm_runtime.py')
    profiles = module('sampler_existing_profiles', source / 'tools/model_profiles.py').PROFILES
    sys.path.insert(0, str(source / 'native'))
    generator = module('sampler_actual_generator', source / 'native/generate_adapter.py')
    generated = output / 'generated'
    generated.mkdir()
    generation = generator.generate(source, generated)
    code = harness(existing)
    (generated / 'sampler-test.c').write_text(code)
    binary = generated / 'sampler-contract'
    compile_args = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1',
                    '-I' + str(generated), '-I' + str(source / 'native'), '-I' + str(source / 'native/vendor'),
                    '-I' + str(source / 'native/vendor/llama'), str(generated / 'sampler-test.c'), '-o', str(binary)]
    compiled = subprocess.run(compile_args, capture_output=True, timeout=60)
    (output / 'compile.stdout').write_bytes(compiled.stdout)
    (output / 'compile.stderr').write_bytes(compiled.stderr)
    input_pins={str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (source/'native').rglob('*') if p.is_file() and p.suffix in ('.c','.h','.inc','.py')}
    report = dict(scope='host_generated_worker_with_fake_sdk', all_pass=False, phone_contacted=False,
                  source_inputs=input_pins,test_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  model_or_tokenizer_executed=False, accelerator_executed=False, sdk_sampling_algorithm_executed=False,
                  compile_exit=compiled.returncode, generated_worker=generation, cases=[])
    if compiled.returncode == 0:
        for profile in profiles:
            for mode in ('once', 'warm'):
                label = profile + '-' + mode
                try:
                    report['cases'].append(exercise(binary, output / label, profile, mode, existing))
                except Exception as error:
                    report['cases'].append(dict(profile=profile, mode=mode, passed=False, error=type(error).__name__ + ': ' + str(error)))
        for label, mode, axis, explicit in [('orvena-gpu-once', 'once', 'gpu', True),
                ('orvena-gpu-warm', 'warm', 'gpu', True), ('orvena-template', 'once', 'npu', False),
                ('orvena-overflow', 'overflow', 'npu', True), ('orvena-warm-overflow', 'warm_overflow', 'npu', True),
                ('orvena-invalid-model', 'bad_model', 'npu', True)]:
            try:
                report['cases'].append(exercise(binary, output / label, ORVENA, mode, existing, axis, explicit))
            except Exception as error:
                report['cases'].append(dict(profile=ORVENA, mode=mode, compute=axis, explicit_grammar=explicit, passed=False,
                                           error=type(error).__name__ + ': ' + str(error)))
        lfm3='lfm3-1.7b-qad-q4_0'
        for label,mode in [('lfm3-overflow','overflow'),('lfm3-warm-overflow','warm_overflow')]:
            try:
                report['cases'].append(exercise(binary,output/label,lfm3,mode,existing))
            except Exception as error:
                report['cases'].append(dict(profile=lfm3,mode=mode,passed=False,error=type(error).__name__+': '+str(error)))
        report['all_pass'] = bool(report['cases']) and all(case['passed'] for case in report['cases'])
    report['finished_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    (output / 'RESULT.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(dict(all_pass=report['all_pass'], compile_exit=compiled.returncode, cases=len(report['cases']),
                         passed=sum(case['passed'] for case in report['cases']), output=str(output))))
    return 0 if report['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
