#!/usr/bin/env python3
"""One bounded kernel-only historical AVC query, with private phone-side filtering.

Only complete original logcat lines within the fixed six-second epoch window,
for the fixed worker subject context and app_process comm, may leave this
observer. No historical worker is launched or replayed. Query failures and
empty results never establish absence of an AVC or the discarded Java reason.
"""
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import time

BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
NONCE = '902e851c3ca1f90deab3d880ab993774'
LABEL = 'root-r10-neg01-7c907661-01'
ACTION_ID = '5a952602788122f47ff1370cfa38dffe'
WORKER_CONTEXT = 'u:r:trillionnium_owner_open_phone_worker:s0'
FROM_SECONDS = 1793879034
TO_SECONDS = 1793879040
MAX_COUNT = 128
MAX_STDOUT = 2 * 1024 * 1024
MAX_STDERR = 16384
MAX_LINE = 16384
MAX_SELECTED_BYTES = 262144
MAX_REPORT = 524288
WAIT_SECONDS = 25.0
HELP_PIN = {'bytes': 5973, 'sha256': 'c7ae77a8e575b64a2268c8a22a5612a55a3c4a9ef9d9a4b1a417f80789858adf'}
ACTION_PIN = {'bytes': 1512, 'sha256': '997f41e4992c2d604e2be2a8c3aaaac9a4f4b94dd0c9304aa4664ae44c79a01a'}
HISTORY_ANALYSIS_PIN = {'bytes': 10846, 'sha256': '3eb56cb06bd363ffc42233ccb0154551962039362eb65f414f66e584a4c11d8e'}

# Elementary ECMAScript alternation covers either order of the two audit
# fields. Native filtering precedes all output; Python checks every line again.
COMM_PATTERN = r'comm="app_process(32|64)?"'
CONTEXT_PATTERN = r'scontext=u:r:trillionnium_owner_open_phone_worker:s0([ \t]|$)'
NATIVE_REGEX = (r'avc:[ \t]+denied[^\n]*' + COMM_PATTERN + r'[^\n]*' + CONTEXT_PATTERN
    + r'|avc:[ \t]+denied[^\n]*' + CONTEXT_PATTERN + r'[^\n]*' + COMM_PATTERN)
ARGV = ['/system/bin/logcat', '-d', '-b', 'kernel', '-t', '1793879034.000000',
        '-v', 'threadtime,epoch,UTC,usec,printable', '--regex', NATIVE_REGEX,
        '*:V']
ENV = {'PATH': '/system/bin:/system/xbin', 'ANDROID_ROOT': '/system',
       'ANDROID_DATA': '/data', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'}
EPOCH = re.compile(rb'^[ \t]*([0-9]{10})\.([0-9]{6})[ \t]+')
AVC = re.compile(rb'avc:[ \t]+denied(?:[ \t]|$)')
COMM = re.compile(rb'(?:^|[ \t])comm="app_process(?:32|64)?"(?:[ \t]|$)')
CONTEXT = re.compile(rb'(?:^|[ \t])scontext=u:r:trillionnium_owner_open_phone_worker:s0(?:[ \t]|$)')


def need(value, why):
    if not value:
        raise ValueError(why)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False,
                       separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')


def small_proc(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        need(stat.S_ISREG(os.fstat(fd).st_mode), 'regular proc observation required')
        parts = []
        total = 0
        while True:
            block = os.read(fd, min(4096, maximum + 1 - total))
            if not block:
                break
            total += len(block)
            need(total <= maximum, 'proc observation bound')
            parts.append(block)
        return b''.join(parts)
    finally:
        os.close(fd)


def boot():
    raw = small_proc('/proc/sys/kernel/random/boot_id', 128)
    need(raw.decode('ascii').strip() == BOOT, 'fixed original boot differs')
    return {'value': BOOT, **pin(raw), 'observed_monotonic_ns': time.monotonic_ns()}


class WindowFilter:
    def __init__(self):
        self.pending = b''
        self.records = []
        self.selected_bytes = 0
        self.header_lines = 0
        self.data_lines = 0
        self.before_window = 0
        self.after_window = 0
        self.unparseable = 0
        self.predicate_rejected = 0
        self.incomplete_final_line = False
        self.overflow = None

    def line(self, raw):
        need(raw.endswith(b'\n'), 'one complete original line required')
        if len(raw) > MAX_LINE:
            self.overflow = 'LOGCAT_LINE_BYTE_BOUND'
            return
        if raw.rstrip(b'\r\n') == b'--------- beginning of kernel':
            self.header_lines += 1
            return
        self.data_lines += 1
        match = EPOCH.match(raw)
        if match is None:
            self.unparseable += 1
            return
        # All predicates are independently checked even though native logcat
        # was required to filter. Rejected raw lines are never retained.
        if not (AVC.search(raw) and COMM.search(raw) and CONTEXT.search(raw)):
            self.predicate_rejected += 1
            return
        seconds, fraction = (int(x) for x in match.groups())
        if seconds < FROM_SECONDS:
            self.before_window += 1
            return
        if seconds >= TO_SECONDS:
            self.after_window += 1
            return
        if (len(self.records) >= MAX_COUNT
                or self.selected_bytes + len(raw) > MAX_SELECTED_BYTES):
            self.overflow = 'SELECTED_ORIGINAL_BYTE_OR_COUNT_BOUND'
            return
        self.records.append({'epoch_microseconds': seconds * 1000000 + fraction,
            **pin(raw), 'original_line_base64': base64.b64encode(raw).decode('ascii')})
        self.selected_bytes += len(raw)

    def feed(self, block):
        need(type(block) is bytes, 'raw native bytes required')
        self.pending += block
        while b'\n' in self.pending and self.overflow is None:
            raw, self.pending = self.pending.split(b'\n', 1)
            self.line(raw + b'\n')
        if len(self.pending) > MAX_LINE and self.overflow is None:
            self.overflow = 'UNTERMINATED_LOGCAT_LINE_BYTE_BOUND'

    def finish(self):
        if self.pending:
            self.incomplete_final_line = True
        # An incomplete final line is not reconstructed or emitted as an original.
        self.pending = b''

    def summary(self):
        return {'selected_originals': self.records, 'selected_original_count': len(self.records),
            'selected_original_bytes': self.selected_bytes, 'kernel_header_lines': self.header_lines,
            'native_data_lines_observed': self.data_lines, 'before_window_discarded': self.before_window,
            'after_window_discarded': self.after_window, 'unparseable_discarded': self.unparseable,
            'independent_predicate_rejected_discarded': self.predicate_rejected,
            'incomplete_final_line_discarded': self.incomplete_final_line,
            'filter_overflow': self.overflow,
            'native_count_limit_configured': False,
            'discarded_raw_lines_or_samples_retained': False,
            'complete_native_stdout_retained': False}


def poll_owned_child(child):
    if child['pid'] is None or child['joined']:
        return
    pid, status = os.waitpid(child['pid'], os.WNOHANG)
    if pid == 0:
        return
    need(pid == child['pid'], 'owned waitpid result differs')
    child.update(joined=True, wait_status=status,
                 return_code=os.waitstatus_to_exitcode(status),
                 observed_monotonic_ns=time.monotonic_ns())


def query_once():
    filters = WindowFilter()
    child = {'pid': None, 'joined': False, 'return_code': None, 'wait_status': None}
    streams = {'stdout': {'bytes_read': 0, 'eof': False},
               'stderr': {'bytes_read': 0, 'eof': False}}
    stderr = bytearray()
    owned = set()
    fd_registration_incomplete = False
    fork_attempted = False
    selector = None
    reason = None
    errors = []
    first_boot = last_boot = None
    started = time.monotonic()
    clock_before = {'unix_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns()}
    phase = 'same_boot_and_root_identity'
    native_context = None
    try:
        first_boot = boot()
        need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
             'root credentials required for the authorized kernel query')
        native_context = small_proc('/proc/self/attr/current', 256).rstrip(b'\0\n').decode('ascii')
        need(native_context == 'u:r:magisk:s0', 'ordinary native root domain required')
        need(os.readlink('/proc/1/exe') == '/system/bin/init', 'native init anchor differs')
        native_root = os.stat('/proc/1/root')
        need(stat.S_ISDIR(native_root.st_mode), 'native Android root anchor differs')
        phase = 'one_new_readonly_logcat_child'
        # An interruption during resource creation/registration must not
        # become a false complete-cleanup statement. No unknown FD is guessed.
        fd_registration_incomplete = True
        out_r, out_w = os.pipe2(os.O_CLOEXEC)
        owned.update((out_r, out_w))
        fd_registration_incomplete = False
        fd_registration_incomplete = True
        err_r, err_w = os.pipe2(os.O_CLOEXEC)
        owned.update((err_r, err_w))
        fd_registration_incomplete = False
        fd_registration_incomplete = True
        null = os.open('/dev/null', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        owned.add(null)
        fd_registration_incomplete = False
        ns = os.fstat(null)
        need(stat.S_ISCHR(ns.st_mode) and os.major(ns.st_rdev) == 1 and os.minor(ns.st_rdev) == 3,
             'fixed null input required')
        inherited = {int(x) for x in os.listdir('/proc/self/fd') if x.isdecimal() and int(x) > 2}
        deadline = time.monotonic() + WAIT_SECONDS
        # If fork returns but parent identity registration is interrupted,
        # retain unknown child state instead of asserting no child existed.
        fork_attempted = True
        pid = os.fork()
        if pid == 0:
            try:
                os.dup2(null, 0)
                os.dup2(out_w, 1)
                os.dup2(err_w, 2)
                for fd in inherited:
                    try:
                        os.close(fd)
                    except OSError as error:
                        if error.errno != errno.EBADF:
                            raise
                # The parent remains in its original GNU root. Only this new
                # child enters the original native Android root and executes
                # the one fixed read-only logcat command.
                os.chroot('/proc/1/root')
                os.chdir('/')
                os.execve(ARGV[0], ARGV, ENV)
            except BaseException as error:
                text = ('FIXED_LOGCAT_CHILD_EXEC_FAILED ' + type(error).__name__
                        + ': ' + str(error)[:1024] + '\n').encode('utf-8', 'backslashreplace')
                try:
                    os.write(2, text)
                finally:
                    os._exit(126)
        child['pid'] = pid
        child['fork_returned_monotonic_ns'] = time.monotonic_ns()
        for fd in (out_w, err_w, null):
            os.close(fd)
            owned.remove(fd)
        selector = selectors.DefaultSelector()
        for fd, name in ((out_r, 'stdout'), (err_r, 'stderr')):
            os.set_blocking(fd, False)
            selector.register(fd, selectors.EVENT_READ, name)
        phase = 'bounded_two_stream_capture_and_phone_side_window_filter'
        while selector.get_map() or not child['joined']:
            poll_owned_child(child)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reason = 'QUERY_WAIT_LIMIT_REACHED_WITHOUT_SIGNAL_OR_RETRY'
                break
            if not selector.get_map() and child['joined']:
                break
            events = selector.select(min(0.1, remaining))
            for key, _mask in events:
                name = key.data
                state = streams[name]
                maximum = MAX_STDOUT if name == 'stdout' else MAX_STDERR
                remaining_bytes = maximum - state['bytes_read']
                raw = os.read(key.fd, min(65536, remaining_bytes + 1))
                if not raw:
                    state['eof'] = True
                    selector.unregister(key.fd)
                    os.close(key.fd)
                    owned.remove(key.fd)
                    continue
                state['bytes_read'] += len(raw)
                admitted = raw[:max(0, remaining_bytes)]
                if name == 'stdout':
                    filters.feed(admitted)
                else:
                    stderr.extend(admitted)
                if state['bytes_read'] > maximum:
                    reason = name.upper() + '_READ_BYTE_BOUND_EXCEEDED'
                    break
                if filters.overflow is not None:
                    reason = filters.overflow
                    break
            if reason is not None:
                break
        poll_owned_child(child)
    except BaseException as error:
        errors.append({'phase': phase, 'type': type(error).__name__, 'detail': str(error)[:1024]})
    finally:
        # No kill, killpg, alarm or timeout-triggered signal is sent. Closing a
        # read endpoint can cause EPIPE/SIGPIPE in the new query child; that is
        # explicitly not a proof that an unjoined child has terminated.
        if selector is not None:
            selector.close()
        for fd in sorted(owned):
            try:
                os.close(fd)
            except OSError as error:
                errors.append({'phase': 'owned_fd_close', 'fd': fd,
                    'type': type(error).__name__, 'detail': str(error)[:256]})
        owned.clear()
        try:
            poll_owned_child(child)
        except BaseException as error:
            errors.append({'phase': 'final_owned_waitpid', 'type': type(error).__name__,
                           'detail': str(error)[:256]})
        try:
            last_boot = boot()
        except BaseException as error:
            errors.append({'phase': 'final_boot', 'type': type(error).__name__,
                           'detail': str(error)[:256]})
        filters.finish()
    result_filter = filters.summary()
    read_complete = (child['joined'] and child['return_code'] == 0
        and all(row['eof'] for row in streams.values()) and reason is None and not errors
        and first_boot is not None and last_boot is not None
        and filters.unparseable == 0 and filters.predicate_rejected == 0
        and not filters.incomplete_final_line and filters.overflow is None)
    if not read_complete:
        state = 'HISTORICAL_AUDIT_QUERY_FAILED_OR_INCOMPLETE_OR_UNKNOWN'
    elif filters.records:
        state = 'FIXED_WINDOW_AVC_ORIGINALS_RETAINED_CORRELATION_ONLY'
    else:
        state = 'NO_MATCHING_FIXED_WINDOW_AVC_RETAINED_AVAILABILITY_UNKNOWN'
    report = {'schema': 'hepta.codec72.fixed-kernel-audit-observation.v1', 'state': state,
        'original_label': LABEL, 'original_nonce': NONCE, 'original_action_id': ACTION_ID,
        'actual_help_pin': HELP_PIN, 'historical_receipt_pin': ACTION_PIN,
        'historical_analysis_pin': HISTORY_ANALYSIS_PIN,
        'fixed_boot': BOOT, 'boot_before': first_boot, 'boot_after': last_boot,
        'root_query_parent_context': native_context, 'query_argv': ARGV, 'query_environment': ENV,
        'native_buffer': 'kernel', 'native_time_filter_has_upper_bound': False,
        'phone_side_epoch_window': {'from_inclusive': FROM_SECONDS, 'to_exclusive': TO_SECONDS,
            'utc_from': '2026-11-05T11:43:54.000000Z', 'utc_to': '2026-11-05T11:44:00.000000Z'},
        'worker_subject_context': WORKER_CONTEXT,
        'comm_focus': ['app_process', 'app_process32', 'app_process64'],
        'historical_parent_pid_hint_not_used_as_filter': 19097,
        'historical_java_child_pid_or_startticks_known': False,
        'query_child': child, 'native_streams': streams, 'native_read_complete': read_complete,
        'stderr_original_prefix_base64': base64.b64encode(stderr).decode('ascii'),
        'stderr_original_prefix': pin(stderr),
        'stderr_complete': streams['stderr']['eof'] and streams['stderr']['bytes_read'] <= MAX_STDERR,
        'filter': result_filter, 'capture_limit_reason': reason, 'errors': errors,
        'clock_before': clock_before,
        'clock_after': {'unix_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns()},
        'elapsed_seconds': time.monotonic() - started,
        'fd_creation_or_registration_incomplete': fd_registration_incomplete,
        'owned_pipe_fds_closed': not fd_registration_incomplete
            and not any(x.get('phase') == 'owned_fd_close' for x in errors),
        'query_fork_attempted': fork_attempted,
        'query_child_identity_registered': child['pid'] is not None,
        'unjoined_query_child_state_remains_unknown': fork_attempted and not child['joined'],
        'pipe_close_may_cause_child_EPIPE_or_SIGPIPE': True,
        'explicit_signal_calls': 0, 'signal_handlers_or_timers_installed': 0,
        'additional_logcat_calls_or_scope_expansion': 0,
        'log_buffer_clear_resize_prune_or_policy_changes': 0,
        'phone_files_written': 0, 'new_worker_or_app_process': 0,
        'old_native_action_replayed': False, 'case_pass': False,
        'complete_historical_window_or_audit_retention_proven': False,
        'absence_of_AVC_proven': False, 'exact_original_Java_failure_reason_proven': False,
        'matched_records_are_correlations_not_unique_Java_attribution': True,
        'caps': {'native_max_count': None, 'selected_original_count': MAX_COUNT,
            'stdout_read': MAX_STDOUT,
            'stderr_read': MAX_STDERR, 'original_line': MAX_LINE,
            'selected_original_bytes': MAX_SELECTED_BYTES, 'report': MAX_REPORT,
            'cooperative_wait_seconds': WAIT_SECONDS,
            'whole_operation_hard_preemptive_deadline': False}}
    return report, 0 if read_complete else 1


def main():
    report, rc = query_once()
    raw = encoded(report)
    if len(raw) > MAX_REPORT:
        raw = encoded({'schema': 'hepta.codec72.fixed-kernel-audit-observation.v1',
            'state': 'OBSERVATION_REPORT_BYTE_BOUND_REJECTED',
            'unreturned_full_report': pin(raw), 'selected_originals_retained': False,
            'query_child': report['query_child'], 'native_streams': report['native_streams'],
            'boot_before': report['boot_before'], 'boot_after': report['boot_after'],
            'explicit_signal_calls': 0, 'phone_files_written': 0,
            'case_pass': False, 'absence_of_AVC_proven': False,
            'exact_original_Java_failure_reason_proven': False})
        rc = 1
    offset = 0
    while offset < len(raw):
        count = os.write(1, raw[offset:])
        need(count > 0, 'stdout writer made no progress')
        offset += count
    return rc


if __name__ == '__main__':
    raise SystemExit(main())
