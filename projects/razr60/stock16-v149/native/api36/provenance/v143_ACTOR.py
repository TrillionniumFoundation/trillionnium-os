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
OUT = Path('/home/alex/codex-stock16-hepta-backend-api36-candidate-c-v143-r1')
WORK = OUT / 'work'
SOURCE_OVERRIDE = OUT / 'source/owner_open_bootstrap.cpp'
PRIOR = Path('/home/alex/codex-stock16-hepta-native-api36-build-c-v142-r1/RECEIPT.json')
MEMORY = 8 * 1024**3
SECONDS = 50
MODULES = ('trillionnium-owner-open-bootstrap',)
CONFIG = __build_config__
INPUTS = {}
RECEIPT = {'scope': 'Host-only compiler/linker/readelf results; no target binary execution or phone access.',
           'actor_sha256': __actor_sha256__, 'commands': [], 'modules': {},
           'headers': 'Original AOSP17 platform headers retained, including for API36 retarget.',
           'stock_library_inputs_sha256': CONFIG['stock_inputs_sha256'],
           'stock_host_metadata_sha256': CONFIG['stock_input_host_sha256'],
           'phone_operations': 0, 'target_binary_executions': 0, 'pass': False}
RECEIPT['source_delta'] = 'Retain set compatibility; API36 outer profile revision and fixed startup-source audit-copy measurement.'
RECEIPT['not_implemented'] = ['actual init/security/identity deployment and observations', 'Root explicit enable', 'phone runtime/communication']
RECEIPT['candidate_ready'] = False


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


def stage_copy(source, relative, expected, executable=False):
    # No symlinks/hard links and no writes outside the new candidate directory.
    relative_path = Path(relative)
    if relative_path.is_absolute() or '..' in relative_path.parts:
        raise RuntimeError('Invalid candidate output path')
    before = track(source, expected)
    target = OUT / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    with Path(source).open('rb') as incoming, target.open('xb') as output:
        for chunk in iter(lambda: incoming.read(1024 * 1024), b''):
            output.write(chunk)
        output.flush()
        os.fsync(output.fileno())
    target.chmod(0o555 if executable else 0o444)
    after = pin(target, expected)
    if track(source) != before:
        raise RuntimeError('Candidate source changed while copied')
    return after


def stage_candidate():
    profile_key = 'payload/system_ext/etc/trillionnium/owner-open/profile-codex-host-relay-v1.json'
    init_key = 'payload/system_ext/etc/trillionnium/owner-open/stock16-backend-init.source.rc'
    expected_keys = {profile_key, init_key, 'policy-input/property_contexts',
                     'payload/system_ext/app/TrillionniumOwnerOpenShell/TrillionniumOwnerOpenShell.apk'}
    if set(__public_stage_bytes__) != expected_keys or set(CONFIG['public_stage_files']) != expected_keys:
        raise RuntimeError('Public candidate file allowlist differs')
    rows = []
    for relative, data in __public_stage_bytes__.items():
        expected = CONFIG['public_stage_files'][relative]
        if len(data) != expected['bytes'] or hashlib.sha256(data).hexdigest() != expected['sha256']:
            raise RuntimeError('Public candidate input changed')
        target = OUT / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        target.chmod(0o444)
        rows.append(pin(target, expected))
    profile = json.loads(__public_stage_bytes__[profile_key])
    if profile['component_measurement']['component_count'] != 8:
        raise RuntimeError('Eight-component measurement contract lost')
    binding = profile['startup_source_binding']
    init_sha = hashlib.sha256(__public_stage_bytes__[init_key]).hexdigest()
    if binding['boot_overlay_input_sha256'] != init_sha or binding['copy_sha256'] != init_sha:
        raise RuntimeError('Boot overlay source and measured audit copy are not bound')
    if binding['effective_init_execution_proven'] is not False or binding['automatic_enable'] is not False:
        raise RuntimeError('Candidate cannot assert effective init or enable services')
    bootstrap = RECEIPT['modules']['api36/trillionnium-owner-open-bootstrap']['binary']
    rows.append(stage_copy(Path(bootstrap['path']),
                           'payload/system_ext/bin/trillionnium-owner-open-bootstrap', bootstrap, True))
    prior_run = json.loads(PRIOR.read_text())
    for name, ref in CONFIG['reused_api36_elfs'].items():
        key = ('api36/' if name.endswith('ingress') else 'api36-emergency/') + name
        recorded = prior_run['modules'][key]['binary']
        if any(recorded[k] != ref[k] for k in ('path', 'sha256', 'bytes')):
            raise RuntimeError('Reused API36 executable does not match actual prior receipt')
        rows.append(stage_copy(Path(ref['path']), 'payload/system_ext/bin/' + name, ref, True))
    reuse = CONFIG['rootfs_reuse']
    for name, expected in reuse['files'].items():
        rows.append(stage_copy(Path(reuse['source_base']) / name,
                               'payload/system_ext/etc/trillionnium/rootlinux/' + name, expected))
    root = OUT / 'payload/system_ext/etc/trillionnium/rootlinux'
    manifest = json.loads((root / 'owner-open-rootfs.image-manifest.json').read_text())
    image = CONFIG['rootfs_reuse']['files']['owner-open-rootfs.erofs']
    if manifest['image_sha256'] != image['sha256'] or manifest['entry_count'] != 931:
        raise RuntimeError('Rootfs image/manifest source identity differs')
    inner = [v for v in manifest['entries']
             if v['destination'] == '/etc/trillionnium/owner-open/rootlinux-supervisor.json']
    if len(inner) != 1 or inner[0]['sha256'] != CONFIG['inner_supervisor_sha256']:
        raise RuntimeError('Unchanged inner supervisor config not measured by reused rootfs')
    if (root / 'owner-open-rootfs.erofs.sha256').read_text().strip() != image['sha256']:
        raise RuntimeError('Rootfs digest file differs')
    candidate = {'schema': 'stock16.hepta.inert.backend-candidate.v1', 'files': rows,
                 'candidate_ready': False, 'rootfs_byte_reused': True,
                 'no_installer_or_activation_script': True,
                 'unproven': RECEIPT['not_implemented'],
                 'policy_binding': 'UNKNOWN_PENDING_NEW_MAGISK_MODULE_POLICY_BINDING',
                 'measurement': 'Audit-copy bytes only; no effective-init or hardware attestation.'}
    RECEIPT['candidate_payload'] = save('CANDIDATE-PAYLOAD.json', candidate)


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
            '--ro-bind', str(SOURCE_OVERRIDE), '/src/vendor/trillionnium/owner-open/native/owner_open_bootstrap.cpp',
            '--ro-bind', str(N), '/tools', '--ro-bind', str(deps), '/src/out-native',
            '--ro-bind', str(STOCK), '/stock-libs', '--bind', str(WORK), '/work',
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
    if module != MODULES[0] or source != 'owner_open_bootstrap.cpp' or variant != 'api36':
        raise RuntimeError('This actor only builds the modified API36 bootstrap')
    api36 = True
    directory = WORK / variant
    directory.mkdir(exist_ok=True)
    prefix = '/work/' + variant
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
    run(variant + '-readelf-' + module,
        ['/usr/bin/readelf', '-h', '-l', '-d', '--wide', prefix + '/' + module], deps)
    RECEIPT['modules'][variant + '/' + module] = {
        'source': track(SOURCE_OVERRIDE), 'original_source': track(SRC / source),
        'binary': binary, 'response_file': pin(rsp),
        'stock_libraries': stock_used, 'api36_retarget': api36,
        'runtime_qualified': False, 'baseline_byte_identity_verified': False}


def main():
    global STOCK_PINS
    if hashlib.sha256(__actor_source_bytes__).hexdigest() != __actor_sha256__:
        raise RuntimeError('Executing actor differs from captured source')
    if hashlib.sha256(__bootstrap_source_bytes__).hexdigest() != CONFIG['bootstrap_source_after_sha256']:
        raise RuntimeError('Modified bootstrap differs from captured API36 candidate source')
    os.umask(0o077)
    os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:4])
    if available_memory() < MEMORY:
        raise RuntimeError('Less than 8GiB host memory available')
    OUT.mkdir(mode=0o700)  # Existing run is never overwritten or replayed.
    (OUT / 'logs').mkdir(mode=0o700)
    WORK.mkdir(mode=0o700)
    SOURCE_OVERRIDE.parent.mkdir(mode=0o700)
    with SOURCE_OVERRIDE.open('xb') as stream:
        stream.write(__bootstrap_source_bytes__)
    SOURCE_OVERRIDE.chmod(0o444)
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
        track(SOURCE_OVERRIDE, {'sha256': CONFIG['bootstrap_source_after_sha256'],
                                'bytes': CONFIG['bootstrap_source_bytes']})
        track(PRIOR, {'sha256': CONFIG['prior_r1_receipt_sha256']})
        prior_run = json.loads(PRIOR.read_text())
        if prior_run.get('inputs_unchanged') is not True:
            raise RuntimeError('Prior baseline inputs were not stable')
        for module, wanted in CONFIG['baseline_outputs'].items():
            done = prior_run['modules']['baseline/' + module]
            if done['binary']['sha256'] != wanted or done['baseline_byte_identity_verified'] is not True:
                raise RuntimeError('Prior two-native baseline byte identity is not established')
        RECEIPT['prior_baselines_verified_without_rebuild'] = track(PRIOR)
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
            try:
                one(*job, 'api36')
            except CompilerFailure as error:
                RECEIPT['modules']['api36/' + job[0]] = {'failure': str(error), 'runtime_qualified': False}
        RECEIPT['pass'] = len(RECEIPT['modules']) == 1 and all(
            'failure' not in v for v in RECEIPT['modules'].values())
        if RECEIPT['pass']:
            stage_candidate()
    except BaseException as error:
        RECEIPT['pass'] = False
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
