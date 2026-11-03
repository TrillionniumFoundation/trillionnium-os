"""Fresh, bounded host-only native compilation; never execute target programs."""
from pathlib import Path
import hashlib
import json
import os
import resource
import shlex
import signal
import stat
import subprocess
import time

B = Path('/home/alex/razr-flash-validation-canonical-20261014')
S = B / 'staging/rog-r57-count8-source-and-build'
C = S / 'inputs/source_3'
CL = S / 'inputs/source_11/linux-x86/clang-r584948b'
N = S / 'inputs/lower_count5_completed_current_upper/host/linux-x86'
SRC = B / 'tools/r11r4-native-source-review-r4/native'
OLD = B / 'evidence/r11r4-native-module-build-4182116d-d7f0-4165-a81a-2c30adf0126d'
STOCK = Path('/home/alex/codex-stock16-hepta-link-preflight-20261102-root-r1/stock-libs')
OUT = Path('/home/alex/codex-stock16-hepta-native-api36-build-c-v142-r1')
MEMORY = 8 * 1024**3
SECONDS = 50
MODULES = ('trillionnium-owner-open-bootstrap', 'trillionnium-owner-open-ingress')
CONFIG = __build_config__
INPUTS = {}
RECEIPT = {'scope': 'Host-only compiler/linker/readelf results; no target binary execution or phone access.',
           'actor_sha256': __actor_sha256__, 'commands': [], 'modules': {},
           'headers': 'Original AOSP17 platform headers retained, including for API36 retarget.',
           'stock_library_inputs_sha256': CONFIG['stock_inputs_sha256'],
           'stock_host_metadata_sha256': CONFIG['stock_input_host_sha256'],
           'phone_operations': 0, 'target_binary_executions': 0, 'pass': False}


class CompilerFailure(RuntimeError):
    """A completed compiler command failed; an independent module may still be checked."""


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def pin(path, expected=None):
    path = Path(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError('Input is not a regular file: ' + str(path))
    value = {'path': str(path), 'bytes': before.st_size, 'sha256': digest(path)}
    after = path.stat()
    keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if any(getattr(before, k) != getattr(after, k) for k in keys):
        raise RuntimeError('Input changed while measured: ' + str(path))
    if expected and any(value[k] != expected[k] for k in ('bytes', 'sha256') if k in expected):
        raise RuntimeError('Input identity mismatch: ' + str(path))
    return value


def track(path, expected=None):
    path = Path(path)
    value = pin(path, expected)
    prior = INPUTS.setdefault(str(path), value)
    if prior != value:
        raise RuntimeError('Input changed: ' + str(path))
    return value


def save(name, value):
    path = OUT / name
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    return pin(path)


def available_memory():
    return int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                    if line.startswith('MemAvailable:'))) * 1024


def capsule(argv, deps=OLD / 'deps'):
    # No network namespace access, home directories, USB devices or writable input mounts.
    cmd = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--cap-drop', 'ALL',
           '--ro-bind', '/usr', '/usr', '--ro-bind', '/bin', '/bin',
           '--ro-bind', '/lib', '/lib', '--ro-bind', '/lib64', '/lib64',
           '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--tmpfs', '/src']
    for name in ('bionic', 'external', 'frameworks', 'hardware', 'system', 'vendor'):
        cmd += ['--ro-bind', str(C / name), '/src/' + name]
    cmd += ['--tmpfs', '/src/prebuilts']
    for child in sorted((C / 'prebuilts').iterdir()):
        if child.name != 'clang':
            cmd += ['--ro-bind', str(child), '/src/prebuilts/' + child.name]
    cmd += ['--ro-bind', str(CL), '/src/prebuilts/clang/host/linux-x86/clang-r584948b',
            '--ro-bind', str(SRC), '/src/vendor/trillionnium/owner-open/native',
            '--ro-bind', str(N), '/tools', '--ro-bind', str(deps), '/src/out-native',
            '--ro-bind', str(STOCK), '/stock-libs', '--bind', str(OUT), '/work',
            '--chdir', '/src', '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin',
            '--setenv', 'LD_LIBRARY_PATH', '/tools/lib64', '--setenv', 'LANG', 'C.UTF-8',
            '--setenv', 'TMPDIR', '/tmp', '--']
    return cmd + list(argv)


def child_limits():
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY, MEMORY))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def group_rss(pgid):
    total = 0
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            if os.getpgid(int(proc.name)) == pgid:
                total += sum(int(line.split()[1]) * 1024 for line in
                             (proc / 'status').read_text().splitlines() if line.startswith('VmRSS:'))
        except (OSError, ProcessLookupError):
            pass
    return total


def run(label, argv, deps=OLD / 'deps'):
    # Allow only compiler, strip and readelf; never any produced program or old script.
    allowed = {'prebuilts/clang/host/linux-x86/clang-r584948b/bin/clang++',
               'prebuilts/clang/host/linux-x86/clang-r584948b/bin/llvm-strip',
               '/usr/bin/readelf'}
    if not argv or argv[0] not in allowed:
        raise RuntimeError('Executable outside compiler allowlist')
    cmd = capsule(argv, deps)
    so = OUT / 'logs' / (label + '.stdout')
    se = OUT / 'logs' / (label + '.stderr')
    start = time.monotonic()
    peak = 0
    failure = None
    with so.open('xb') as stdout, se.open('xb') as stderr:
        process = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                   start_new_session=True, preexec_fn=child_limits)
        try:
            while process.poll() is None:
                peak = max(peak, group_rss(process.pid))
                if time.monotonic() - start >= SECONDS:
                    failure = '50-second command deadline'
                elif peak > MEMORY or available_memory() < MEMORY:
                    failure = '8GiB memory boundary'
                elif so.stat().st_size + se.stat().st_size > 32 * 1024**2:
                    failure = '32MiB log boundary'
                if failure:
                    os.killpg(process.pid, signal.SIGKILL)
                    break
                time.sleep(0.1)
            code = process.wait(timeout=3)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
            stdout.flush()
            stderr.flush()
            os.fsync(stdout.fileno())
            os.fsync(stderr.fileno())
    row = {'label': label, 'argv': cmd, 'returncode': code, 'failure': failure,
           'elapsed_seconds': time.monotonic() - start, 'peak_group_RSS': peak,
           'stdout': pin(so), 'stderr': pin(se)}
    RECEIPT['commands'].append(row)
    print(json.dumps({k: row[k] for k in ('label', 'returncode', 'failure', 'elapsed_seconds')}), flush=True)
    if failure:
        raise RuntimeError(failure)
    if code:
        tail = se.read_text(errors='replace')[-10000:]
        raise CompilerFailure(label + ': ' + tail)


def compile_args(line, obj, api36):
    args = shlex.split(line)
    if args and args[0].startswith('PWD='):
        args.pop(0)
    out = []
    i = 0
    counts = {'target': 0, 'libc': 0, 'libm': 0, 'libdl': 0}
    while i < len(args):
        arg = args[i]
        if arg in ('-o', '-MF'):
            i += 2
            continue
        if arg in ('-MD', '-MMD'):
            i += 1
            continue
        if api36 and arg == '-target':
            if args[i + 1] != 'aarch64-linux-android10000':
                raise RuntimeError('Unexpected original compile target')
            out += [arg, 'aarch64-linux-android36']
            counts['target'] += 1
            i += 2
            continue
        for key in ('libc', 'libm', 'libdl'):
            if api36 and arg == '-D__' + key.upper() + '_API__=10000':
                arg = '-D__' + key.upper() + '_API__=36'
                counts[key] += 1
        out.append(arg)
        i += 1
    if api36 and any(v != 1 for v in counts.values()):
        raise RuntimeError('Retarget operand count mismatch: ' + repr(counts))
    return out + ['-o', obj]


def link_args(line, rsp, binary, api36):
    args = shlex.split(line)
    out = []
    replacements = 0
    targets = 0
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == '-o':
            i += 2
            continue
        if arg.startswith('@out-native/'):
            out.append('@' + rsp)
            replacements += 1
        elif api36 and arg == '-target':
            if args[i + 1] != 'aarch64-linux-android10000':
                raise RuntimeError('Unexpected original link target')
            out += [arg, 'aarch64-linux-android36']
            targets += 1
            i += 2
            continue
        else:
            out.append(arg)
        i += 1
    if replacements != 1 or (api36 and targets != 1) or '-Wl,--no-undefined' not in out:
        raise RuntimeError('Link identity/security operand mismatch')
    return out + ['-o', binary]


def one(module, source, compile_line, link_line, flags, variant, deps=OLD / 'deps'):
    api36 = variant.startswith('api36')
    directory = OUT if variant == 'baseline' else OUT / variant
    directory.mkdir(exist_ok=True)
    prefix = '/work' if variant == 'baseline' else '/work/' + variant
    obj = prefix + '/' + module + '.o'
    rsp_name = module + '.new.rsp'
    libargs = shlex.split(flags)
    stock_used = []
    for i, value in enumerate(libargs):
        if value.endswith('.so'):
            track(deps / value.removeprefix('out-native/'))
            if api36:
                name = Path(value).name
                if name not in STOCK_PINS:
                    raise RuntimeError('No genuine stock library for ' + name)
                libargs[i] = '/stock-libs/' + name
                stock_used.append(name)
    if api36 and not stock_used:
        raise RuntimeError('No stock shared libraries selected')
    rsp = directory / rsp_name
    with rsp.open('x') as stream:
        stream.write(obj + ' ' + shlex.join(libargs) + '\n')
    run(variant + '-compile-' + module, compile_args(compile_line, obj, api36), deps)
    run(variant + '-link-' + module,
        link_args(link_line, prefix + '/' + rsp_name, prefix + '/' + module + '.unstripped', api36), deps)
    run(variant + '-strip-' + module,
        ['prebuilts/clang/host/linux-x86/clang-r584948b/bin/llvm-strip', '--strip-debug',
         '-o', prefix + '/' + module, prefix + '/' + module + '.unstripped'], deps)
    binary = pin(directory / module)
    if variant == 'baseline' and binary['sha256'] != CONFIG['baseline_outputs'][module]:
        raise RuntimeError('Baseline binary differs from actual prior build: ' + repr(binary))
    run(variant + '-readelf-' + module,
        ['/usr/bin/readelf', '-h', '-l', '-d', '--wide', prefix + '/' + module], deps)
    RECEIPT['modules'][variant + '/' + module] = {
        'source': track(SRC / source), 'binary': binary, 'response_file': pin(rsp),
        'stock_libraries': stock_used, 'api36_retarget': api36,
        'runtime_qualified': False, 'baseline_byte_identity_verified': variant == 'baseline'}


def main():
    global STOCK_PINS
    if hashlib.sha256(__actor_source_bytes__).hexdigest() != __actor_sha256__:
        raise RuntimeError('Executing actor differs from captured source')
    os.umask(0o077)
    os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:4])
    if available_memory() < MEMORY:
        raise RuntimeError('Less than 8GiB host memory available')
    OUT.mkdir(mode=0o700)  # Existing run is never overwritten or replayed.
    (OUT / 'logs').mkdir(mode=0o700)
    with (OUT / 'ACTOR.py').open('xb') as stream:
        stream.write(__actor_source_bytes__)
    with (OUT / 'BUILD-CONFIG.json').open('xb') as stream:
        stream.write(__config_source_bytes__)
    RECEIPT['affinity'] = sorted(os.sched_getaffinity(0))
    RECEIPT['limits'] = {'cpus': 4, 'per_process_AS': MEMORY, 'monitored_group_RSS': MEMORY,
                         'command_seconds': SECONDS, 'cleanup_wait_seconds': 3}
    try:
        metadata = STOCK.parent / 'STOCK-LIBRARY-INPUTS.json'
        track(metadata, {'sha256': CONFIG['stock_input_host_sha256']})
        stock = json.loads(metadata.read_text())
        if stock != CONFIG['stock_inputs']:
            raise RuntimeError('Stock input metadata differs from Root-provided snapshot')
        STOCK_PINS = {}
        for name, row in stock['reads'].items():
            if not name.endswith('.so'):
                continue
            path = Path(row['host_path'])
            if path.parent != STOCK or path.is_symlink() or not row['available']:
                raise RuntimeError('Unexpected stock library selection')
            STOCK_PINS[path.name] = track(path, row)
        if len(STOCK_PINS) != 8:
            raise RuntimeError('Expected exactly eight genuine stock libraries')
        for path, expected in CONFIG['source_pins'].items():
            track(path, expected)
        track(OLD / 'receipt.json', {'sha256': CONFIG['pass_receipt_sha256']})
        prior = json.loads((OLD / 'receipt.json').read_text())
        if prior.get('pass') is not True:
            raise RuntimeError('Original baseline build did not pass')
        for path, row in prior['inputs_before'].items():
            if path.startswith(str(CL) + '/') or path.startswith(str(OLD / 'deps') + '/'):
                track(path, row)
        jobs = []
        for module in MODULES:
            source = 'owner_open_bootstrap.cpp' if module.endswith('bootstrap') else 'owner_open_ingress_proxy.cpp'
            paths = [OLD / (module + suffix) for suffix in ('.original-compile.txt', '.original-link.txt')]
            for p in paths:
                track(p)
            for p, key in zip(paths, ('original_compile_line_sha256', 'original_link_line_sha256')):
                observed = hashlib.sha256(p.read_text().removesuffix('\n').encode()).hexdigest()
                if observed != prior['modules'][module][key]:
                    raise RuntimeError('Original command differs from measured pass receipt: ' + str(p))
            for row in prior['modules'][module]['actual_preprocessor_header_inputs']:
                track(row['path'], row)
            flags = prior['modules'][module]['frozen_rule_library_flags']
            jobs.append((module, source, paths[0].read_text(), paths[1].read_text(), flags))
        for job in jobs:
            one(*job, 'baseline')
        for job in jobs:
            try:
                one(*job, 'api36')
            except CompilerFailure as error:
                RECEIPT['modules']['api36/' + job[0]] = {'failure': str(error), 'runtime_qualified': False}
        # A new small-module compile check, not an assertion about its historical output.
        # Its real Android.bp has the common C++20 runtime and no extra shared libraries.
        original = 'vendor/trillionnium/owner-open/native/owner_open_bootstrap.cpp'
        replacement = 'vendor/trillionnium/owner-open/native/owner_open_emergency_stop.cpp'
        if jobs[0][2].count(original) != 1:
            raise RuntimeError('Cannot derive unambiguous emergency source argument')
        emergency_compile = jobs[0][2].replace(original, replacement)
        common = {'libc++.so', 'libc.so', 'libm.so', 'libdl.so'}
        emergency_flags = shlex.join(token for token in shlex.split(jobs[0][4])
                                     if not token.endswith('.so') or Path(token).name in common)
        RECEIPT['emergency_stop'] = {
            'scope': 'Fresh API36 compile/link using genuine source and Android.bp common runtime.',
            'original_binary_identity_claimed': False,
            'compile_flag_basis': 'Measured bootstrap C++20 flags; exact source operand replaced.',
            'link_flag_basis': 'Measured linker/CRT flags plus actual Android.bp common runtime libraries only.'}
        try:
            one('trillionnium-owner-open-emergency-stop', 'owner_open_emergency_stop.cpp',
                emergency_compile, jobs[0][3], emergency_flags, 'api36-emergency')
        except CompilerFailure as error:
            RECEIPT['modules']['api36-emergency/trillionnium-owner-open-emergency-stop'] = {
                'failure': str(error), 'runtime_qualified': False}
        RECEIPT['pass'] = all('failure' not in v for v in RECEIPT['modules'].values())
    except BaseException as error:
        RECEIPT['failure'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        changes = []
        for path, before in INPUTS.items():
            try:
                if pin(Path(path)) != before:
                    changes.append(path)
            except Exception:
                changes.append(path)
        RECEIPT['inputs_unchanged'] = not changes
        RECEIPT['changed_inputs'] = changes
        if changes:
            RECEIPT['pass'] = False
        RECEIPT['inputs'] = INPUTS
        receipt = save('RECEIPT.json', RECEIPT)
        print(json.dumps({'final': receipt, 'pass': RECEIPT['pass'],
                          'failure': RECEIPT.get('failure'),
                          'module_status': {k: ('failure' if 'failure' in v else 'pass')
                                            for k, v in RECEIPT['modules'].items()}}), flush=True)


if __name__ == '__main__':
    main()
