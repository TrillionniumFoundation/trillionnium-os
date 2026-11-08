#!/usr/bin/env python3
"""Bounded, model-only Android CPU/OpenCL smoke test.

This does not start Hepta, its broker, an executor, or any UI operation. It never
clears a stop marker. Successful results qualify only this inference smoke test,
not app automation, production cancellation, NPU, or standalone operation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import struct
import subprocess
import time
import zlib

MODEL_NAME = 'GUI-Owl-1.5-2B-Instruct.Q4_K_M.gguf'
MMPROJ_NAME = 'GUI-Owl-1.5-2B-Instruct.mmproj-Q8_0.gguf'
EXPECTED = {
    MODEL_NAME: '5fd2c77781a14a91128928b5bd313252aab076b44682396af4bb2c99667f5ef5',
    MMPROJ_NAME: '16748786911f630d0c14869ac28999f77715053a62b2a00d2327021bd6d2afb7',
}


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def write_fixture(path, boxes, blue_index):
    """Write an exact synthetic PNG using only the Python standard library."""
    raw = bytearray()
    for y in range(768):
        raw.append(0)
        for x in range(384):
            color = (255, 255, 255)
            for index, (x1, y1, x2, y2) in enumerate(boxes):
                if x1 <= x <= x2 and y1 <= y <= y2:
                    color = (24, 93, 231) if index == blue_index else (228, 68, 68)
                    break
            raw.extend(color)
    def chunk(kind, data):
        return struct.pack('!I', len(data)) + kind + data + struct.pack('!I', zlib.crc32(kind + data) & 0xffffffff)
    path.write_bytes(b'\x89PNG\r\n\x1a\n'
                     + chunk(b'IHDR', struct.pack('!2I5B', 384, 768, 8, 2, 0, 0, 0))
                     + chunk(b'IDAT', zlib.compress(raw, 6)) + chunk(b'IEND', b''))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--adb', required=True)
    ap.add_argument('--adb-port', type=int, default=5061)
    ap.add_argument('--serial', required=True)
    ap.add_argument('--bin-dir', type=Path, required=True,
                    help='Directory with candidate llama-bench, llama-cli and optional .so files')
    ap.add_argument('--output', type=Path, required=True, help='New host output directory')
    ap.add_argument('--remote-dir', required=True, help='New /data/local/tmp/hepta-offline-* directory')
    ap.add_argument('--model-dir', default='/data/local/tmp/hepta-phone-local-v150-r1/models')
    ap.add_argument('--model-name', default=MODEL_NAME)
    ap.add_argument('--mmproj-name', default=MMPROJ_NAME)
    ap.add_argument('--model-sha256', default=EXPECTED[MODEL_NAME])
    ap.add_argument('--mmproj-sha256', default=EXPECTED[MMPROJ_NAME])
    ap.add_argument('--image-tokens', type=int, default=1024)
    ap.add_argument('--flash-attention', choices=('on', 'off'), default='on')
    ap.add_argument('--case-timeout', type=int, default=180)
    args = ap.parse_args()
    if not re.fullmatch(r'/data/local/tmp/hepta-offline-[a-zA-Z0-9_-]+', args.remote_dir):
        ap.error('remote directory must be an independently named hepta-offline directory')
    if not 30 <= args.case_timeout <= 300:
        ap.error('case timeout must be between 30 and 300 seconds')
    for name in (args.model_name, args.mmproj_name):
        if not re.fullmatch(r'[A-Za-z0-9_.-]+\.gguf', name):
            ap.error('model names must be plain GGUF basenames')
    if not 128 <= args.image_tokens <= 1024:
        ap.error('image token budget must be between 128 and 1024')
    expected = {args.model_name: args.model_sha256, args.mmproj_name: args.mmproj_sha256}
    if len(expected) != 2 or not all(re.fullmatch(r'[a-f0-9]{64}', h) for h in expected.values()):
        ap.error('two different model names and their complete SHA256 values are required')
    args.output.mkdir(parents=True, exist_ok=False)
    adb = [args.adb, '-P', str(args.adb_port), '-s', args.serial]
    results = []

    def call(name, argv, timeout=40):
        started = time.monotonic()
        row = {'name': name, 'argv': argv, 'started_unix': time.time()}
        try:
            p = subprocess.run(argv, capture_output=True, timeout=timeout)
            row.update(returncode=p.returncode, timed_out=False)
            stdout, stderr = p.stdout, p.stderr
        except subprocess.TimeoutExpired as e:
            row.update(returncode=None, timed_out=True)
            stdout, stderr = e.stdout or b'', e.stderr or b''
        row['elapsed_seconds'] = round(time.monotonic() - started, 3)
        for kind, raw in [('stdout', stdout), ('stderr', stderr)]:
            path = args.output / (name + '.' + kind + '.txt')
            path.write_bytes(raw)
            row[kind] = {'path': path.name, 'sha256': digest(path), 'bytes': len(raw)}
        results.append(row)
        print(json.dumps({k: v for k, v in row.items() if k not in ('argv',)}, ensure_ascii=False), flush=True)
        return row, stdout.decode('utf-8', 'replace'), stderr.decode('utf-8', 'replace')

    def shell(name, cmd, timeout=40):
        return call(name, adb + ['shell', cmd], timeout)

    def required(row):
        if row['returncode'] != 0 or row['timed_out']:
            raise RuntimeError('required preflight failed: ' + row['name'])

    report = {
        'schema': 'hepta.phone-local-independent-inference-smoke.v1',
        'kind': 'MODEL_ONLY_NO_PHONE_ACTIONS', 'results': results,
        'app_e2e_pass': False, 'production_runtime_compatible': False,
        'npu_tested': False, 'external_model_used': False,
        'external_network_isolation_tested': False,
        'source_note': 'Local weights and executable CLI only; no model API or Hepta executor is used.',
        'remote_directory': args.remote_dir,
    }
    try:
        for name in ('llama-bench', 'llama-cli'):
            if not (args.bin_dir / name).is_file():
                raise RuntimeError('missing candidate binary: ' + name)
        row, out, _ = shell('model_hashes', 'sha256sum ' + ' '.join(
            shlex.quote(args.model_dir + '/' + n) for n in expected), 90)
        required(row)
        actual = {line.split()[-1].rsplit('/', 1)[-1]: line.split()[0]
                  for line in out.splitlines() if len(line.split()) == 2}
        if actual != expected:
            raise RuntimeError('phone model hashes do not match the selected inputs')
        report['model_sha256'] = actual
        row, _, _ = shell('create_owned_directory', 'mkdir ' + shlex.quote(args.remote_dir))
        required(row)
        files = [p for p in args.bin_dir.iterdir()
                 if p.is_file() and (p.name in ('llama-bench', 'llama-cli') or '.so' in p.name)]
        report['candidate_files'] = {p.name: {'sha256': digest(p), 'bytes': p.stat().st_size} for p in files}
        for p in files:
            row, _, _ = call('push_' + p.name.replace('.', '_'), adb + ['push', str(p), args.remote_dir + '/' + p.name], 90)
            required(row)
        row, _, _ = shell('make_owned_binaries_executable', 'chmod 700 ' + ' '.join(
            shlex.quote(args.remote_dir + '/' + n) for n in ('llama-bench', 'llama-cli')))
        required(row)
        env = ['env', 'LD_LIBRARY_PATH=' + args.remote_dir + ':/vendor/lib64',
               'GGML_OPENCL_KERNEL_CACHE_DIR=' + args.remote_dir + '/kernel-cache']
        shell('before_thermal_gpu', 'cat /sys/class/kgsl/kgsl-3d0/gpubusy; '
              'cat /proc/meminfo | head -n 5; dumpsys battery | grep -E "level:|temperature:"')
        row, devices_out, devices_err = shell('list_devices', shlex.join(
            env + [args.remote_dir + '/llama-cli', '--list-devices']), 60)
        required(row)
        report['adreno_device_reported'] = 'Adreno' in devices_out + devices_err
        for backend, layers, device in [('cpu', '0', 'none'), ('opencl', '99', 'GPUOpenCL')]:
            # Android timeout bounds the actual phone process even if ADB disconnects.
            command = ['timeout', '-k', '5', '-s', 'TERM', str(args.case_timeout)] + env + [
                args.remote_dir + '/llama-bench', '-m', args.model_dir + '/' + args.model_name,
                '--device', device, '-ngl', layers, '-p', '128', '-n', '64', '-r', '1', '-t', '4', '-o', 'json']
            row, stdout, stderr = shell('bench_' + backend, shlex.join(command), args.case_timeout + 15)
            row['inference_exit_success'] = row['returncode'] == 0 and not row['timed_out']
            try:
                row['benchmark'] = json.loads(stdout)
            except json.JSONDecodeError:
                row['benchmark'] = None
            row['backend_log_excerpt'] = '\n'.join(line for line in stderr.splitlines()
                if re.search(r'OpenCL|Adreno|offload|buffer size|model size', line, re.I))[-6000:]
            command = ['timeout', '-k', '5', '-s', 'TERM', str(args.case_timeout)] + env + [
                args.remote_dir + '/llama-cli', '-m', args.model_dir + '/' + args.model_name,
                '--no-mmproj', '--device', device, '-ngl', layers, '-c', '4096', '-t', '4',
                '-n', '64', '--temp', '0', '-fa', 'off', '--no-warmup', '--single-turn',
                '--simple-io', '--log-verbosity', '4', '-p', '只输出数字42，不要输出其他内容。']
            row, stdout, stderr = shell('text_correctness_' + backend, shlex.join(command), args.case_timeout + 15)
            row['literal_42_response_pass'] = bool(re.search(r'^42\s*$', stdout, re.M)) and row['returncode'] == 0
            row['backend_log_excerpt'] = '\n'.join(line for line in stderr.splitlines()
                if re.search(r'OpenCL|Adreno|offload|buffer size', line, re.I))[-6000:]
        # Two different layouts prevent a fixed guessed coordinate from passing both.
        fixture_rows = []
        for i, blue_index in enumerate((0, 2), 1):
            boxes = [(42, 130 + n * 180, 342, 245 + n * 180) for n in range(3)]
            image_path = args.output / ('fixture_%d.png' % i)
            write_fixture(image_path, boxes, blue_index)
            row, _, _ = call('push_fixture_%d' % i, adb + ['push', str(image_path), args.remote_dir + '/' + image_path.name])
            required(row)
            prompt = '找到图片中蓝色按钮的中心。只输出 JSON {"x":整数,"y":整数}，坐标使用0到1000归一化范围。不要解释。'
            command = ['timeout', '-k', '5', '-s', 'TERM', str(args.case_timeout)] + env + [
                args.remote_dir + '/llama-cli', '-m', args.model_dir + '/' + args.model_name,
                '--mmproj', args.model_dir + '/' + args.mmproj_name,
                '--image', args.remote_dir + '/' + image_path.name,
                '--device', 'GPUOpenCL', '--mmproj-device', 'GPUOpenCL',
                '-ngl', '99', '-c', '4096', '-t', '4', '-n', '96', '--temp', '0',
                '-fa', args.flash_attention, '--no-warmup', '--single-turn', '--simple-io',
                '--log-verbosity', '4', '--image-min-tokens', str(args.image_tokens),
                '--image-max-tokens', str(args.image_tokens), '-p', prompt]
            row, stdout, stderr = shell('vision_opencl_%d' % i, shlex.join(command), args.case_timeout + 15)
            candidates = []
            for chunk in re.findall(r'\{[^{}]{1,160}\}', stdout):
                try:
                    obj = json.loads(chunk)
                    if set(obj) == {'x', 'y'} and all(type(obj[k]) is int for k in ('x', 'y')):
                        candidates.append(obj)
                except (ValueError, TypeError):
                    pass
            answer = candidates[-1] if candidates else None
            box = boxes[blue_index]
            correct = bool(answer and 0 <= answer['x'] <= 1000 and 0 <= answer['y'] <= 1000
                           and box[0] <= answer['x'] * 384 / 1000 <= box[2]
                           and box[1] <= answer['y'] * 768 / 1000 <= box[3])
            row['vision_answer'] = answer
            row['fixture_coordinate_pass'] = correct and row['returncode'] == 0 and not row['timed_out']
            row['backend_log_excerpt'] = '\n'.join(line for line in stderr.splitlines()
                if re.search(r'OpenCL|Adreno|offload|vision|projector|encode|eval time', line, re.I))[-8000:]
            fixture_rows.append({'case': row['name'], 'expected_pixel_box': box,
                                 'image_sha256': digest(image_path), 'pass': row['fixture_coordinate_pass']})
        report['synthetic_vision_results'] = fixture_rows
        shell('after_thermal_gpu', 'cat /sys/class/kgsl/kgsl-3d0/gpubusy; '
              'cat /proc/meminfo | head -n 5; dumpsys battery | grep -E "level:|temperature:"')
        report['harness_completed'] = True
    except Exception as e:
        report['harness_completed'] = False
        report['error'] = type(e).__name__ + ': ' + str(e)
        raise
    finally:
        report['finished_unix'] = time.time()
        (args.output / 'inference_report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')


if __name__ == '__main__':
    main()
