#!/usr/bin/env python3
"""Compile and execute the actual pure-Java protocol guard; never contacts Android."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java', required=True, type=Path)
    parser.add_argument('--javac', type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--development-platform-only', action='store_true',
                        help='Use current JDK platform, explicitly NOT the Java 8 release gate')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    classes = args.out / 'classes'
    classes.mkdir()
    root = Path(__file__).resolve().parents[2]
    files = [root/'src/org/trillionnium/hepta/background/BrokerProtocol.java',
             root/'tests/background-broker/BrokerProtocolHostTest.java']
    compiler = [str(args.javac)] if args.javac else [str(args.java), '-m', 'jdk.compiler/com.sun.tools.javac.Main']
    flags = [] if args.development_platform_only else ['--release', '8']
    compile_argv = compiler + flags + ['-Xlint:all', '-Werror', '-encoding', 'UTF-8', '-d', str(classes)] + list(map(str, files))
    compile_result = subprocess.run(compile_argv, text=True, capture_output=True, timeout=60)
    (args.out/'compile.stdout').write_text(compile_result.stdout)
    (args.out/'compile.stderr').write_text(compile_result.stderr)
    evidence = {'schema': 'hepta.background-broker-host-run.v1', 'android_runtime': False,
                'phone_operations': False, 'source_files': {str(f.relative_to(root)): hashlib.sha256(f.read_bytes()).hexdigest() for f in files},
                'java8_release_gate': not args.development_platform_only,
                'development_platform_only': args.development_platform_only,
                'compile_argv': compile_argv, 'compile_exit_code': compile_result.returncode}
    if compile_result.returncode == 0:
        run_argv = [str(args.java), '-cp', str(classes), 'org.trillionnium.hepta.background.BrokerProtocolHostTest']
        run_result = subprocess.run(run_argv, text=True, capture_output=True, timeout=30)
        (args.out/'run.stdout').write_text(run_result.stdout)
        (args.out/'run.stderr').write_text(run_result.stderr)
        evidence['run_exit_code'] = run_result.returncode
        if run_result.returncode == 0:
            evidence['tests'] = json.loads(run_result.stdout)
        else:
            evidence['run_error'] = run_result.stderr
    evidence['passed'] = evidence.get('compile_exit_code') == 0 and evidence.get('run_exit_code') == 0
    (args.out/'RESULT.json').write_text(json.dumps(evidence, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps(evidence, ensure_ascii=False))
    raise SystemExit(0 if evidence['passed'] else 1)


if __name__ == '__main__':
    main()
