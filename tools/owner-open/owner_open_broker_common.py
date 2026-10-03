"""Strict mechanical helpers for the owner-open multi-connection broker."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import functools
import threading
import time
from typing import Any, BinaryIO

MAX_LINE_BYTES = 1024 * 1024
MAX_DESCRIPTOR_BYTES = 1024 * 1024
MAX_TOKEN_BYTES = 256
MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
MAX_ARGV_ITEMS = 4096
MAX_ARGUMENT_BYTES = 64 * 1024
MAX_TOTAL_ARGV_BYTES = 1024 * 1024
ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,256}$")
TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")

# Evidence only: off until explicitly configured by the service entrypoint.
# Hooks never do file I/O and never wait behind a product/trace lock. Export is
# a separate outer operation after workers stopped; loss/open spans reject it
# as complete evidence. No semantic success or installed qualification is minted.
TRACE_STAGES = frozenset({
    "broker_accept", "broker_auth", "broker_queue_wait", "broker_forward",
    "host_decode", "host_capacity_wait", "journal_append", "journal_fsync",
    "provider_spawn", "provider_first_event", "provider_wait", "callback_admission",
    "tool_spawn", "tool_output", "tool_exit", "tool_cleanup", "terminal_persistence",
    "delivery_queue_wait", "client_delivery",
})
TRACE_MAX_RECORDS = 8192
TRACE_MAX_EXPORT_BYTES = 8 * 1024 * 1024
_PERFORMANCE_TRACE = None


class PerformanceTrace:
    def __init__(self, sample_id: str, role: str, capacity: int = TRACE_MAX_RECORDS):
        pattern = r"[A-Za-z0-9_.:/-]{1,128}"
        if (not isinstance(sample_id, str) or not re.fullmatch(pattern, sample_id)
                or not isinstance(role, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", role) or role in {".", ".."}
                or type(capacity) is not int or not 1 <= capacity <= TRACE_MAX_RECORDS):
            raise ValueError("trace identifier/capacity outside fixed bounds")
        self.sample_id, self.role, self.capacity = sample_id, role, capacity
        self.records = []
        self.open = self.next = 0
        self.loss_observed = False
        self.lock = threading.Lock()

    def start(self, stage: str, key: str, deferred: bool = False):
        if stage not in TRACE_STAGES or not isinstance(key, str) or len(key) > 4096:
            self.loss_observed = True
            return _NO_PERFORMANCE_SPAN
        try:
            encoded = key.encode()
        except UnicodeError:
            self.loss_observed = True
            return _NO_PERFORMANCE_SPAN
        if len(encoded) > 4096:
            self.loss_observed = True
            return _NO_PERFORMANCE_SPAN
        start = time.monotonic_ns()
        pid, tid = os.getpid(), threading.get_native_id()
        if not (0 <= start < (1 << 64) and 0 < pid < (1 << 32) and 0 < tid < (1 << 63)):
            self.loss_observed = True
            return _NO_PERFORMANCE_SPAN
        scope = hashlib.sha256(encoded).hexdigest()
        if not self.lock.acquire(blocking=False):
            self.loss_observed = True
            return _NO_PERFORMANCE_SPAN
        try:
            if self.next >= (1 << 64) - 1 or self.open + len(self.records) >= self.capacity:
                self.loss_observed = True
                return _NO_PERFORMANCE_SPAN
            sequence = self.next; self.next += 1; self.open += 1
        finally:
            self.lock.release()
        return PerformanceSpan(self, {
            "sequence": sequence, "stage": stage, "scope_sha256": scope,
            "pid": pid, "tid": tid,
            "start_ns": start, "end_ns": None, "end": "unfinished",
        }, deferred)

    def snapshot(self):
        if not self.lock.acquire(blocking=False):
            raise ValueError("trace snapshot busy")
        try:
            return {
                "schema": "org.trillionnium.actual-monotonic-stage-trace.v1",
                "sample_id": self.sample_id, "producer_role": self.role,
                "clock": "CLOCK_MONOTONIC", "capacity_records": self.capacity,
                "loss_observed": self.loss_observed, "lost_records": None,
                "lost_count_semantics": "unavailable", "open_spans": self.open,
                "snapshot_without_observed_loss": not self.loss_observed and self.open == 0,
                "snapshot_only": True, "producer_quiescence_proven": False,
                "trace_complete": False,
                "installed_qualified": False,
                "records": [dict(record) for record in self.records],
            }
        finally:
            self.lock.release()


class PerformanceSpan:
    def __init__(self, recorder=None, record=None, deferred=False):
        self.recorder, self.record, self.deferred = recorder, record, deferred

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        self.finish("exception" if kind else "scope_exit_unclassified")
        return False

    def finish(self, end="observed_boundary"):
        recorder, record = self.recorder, self.record
        self.recorder = self.record = None
        if recorder is None:
            return
        if end not in {"observed_boundary", "abandoned", "exception", "scope_exit_unclassified"}:
            end = "abandoned"
        now = time.monotonic_ns()
        if end == "abandoned" or not record["start_ns"] <= now < (1 << 64):
            recorder.loss_observed = True
        if not record["start_ns"] <= now < (1 << 64):
            now = record["start_ns"]
        record["end_ns"], record["end"] = now, end
        if not recorder.lock.acquire(blocking=False):
            # Open count is intentionally not guessed down after loss.
            recorder.loss_observed = True
            return
        try:
            recorder.open -= 1
            if len(recorder.records) >= recorder.capacity:
                recorder.loss_observed = True
            else:
                recorder.records.append(record)
        finally:
            recorder.lock.release()


class _NoPerformanceSpan:
    __slots__ = ()

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        return False

    def finish(self, end="observed_boundary"):
        pass


_NO_PERFORMANCE_SPAN = _NoPerformanceSpan()


def performance_span(stage: str, key: str = "", deferred: bool = False):
    recorder = _PERFORMANCE_TRACE
    return _NO_PERFORMANCE_SPAN if recorder is None else recorder.start(stage, key, deferred)


def performance_trace_enabled():
    return _PERFORMANCE_TRACE is not None


def performance_stage(stage: str):
    def decorate(function):
        @functools.wraps(function)
        def call(*args, **kwargs):
            # Disabled hooks do not inspect caller properties or arguments.
            if _PERFORMANCE_TRACE is None:
                return function(*args, **kwargs)
            key = kwargs.get("label", function.__qualname__)
            for arg in args:
                digest = getattr(arg, "request_sha256", None)
                if isinstance(digest, str):
                    key = digest; break
            with performance_span(stage, key):
                return function(*args, **kwargs)
        return call
    return decorate


def configure_performance_trace(sample_id: str, role: str, capacity=TRACE_MAX_RECORDS):
    global _PERFORMANCE_TRACE
    if _PERFORMANCE_TRACE is not None:
        raise ValueError("trace already configured")
    mode = os.environ.get('TRILLIONNIUM_OWNER_TRACE_MODE')
    output = os.environ.get('TRILLIONNIUM_OWNER_TRACE_STREAM_OUTPUT')
    if mode not in {None, 'snapshot', 'streaming-completion'}:
        raise ValueError('invalid explicit trace mode')
    if output is not None and mode != 'streaming-completion':
        raise ValueError('stream output requires explicit streaming mode')
    if mode == 'streaming-completion':
        if output is None or capacity != TRACE_MAX_RECORDS:
            raise ValueError('streaming requires dedicated output and fixed bank contract')
        _PERFORMANCE_TRACE = _TraceCompletionStreamRecorder(sample_id, role, output)
    else:
        _PERFORMANCE_TRACE = PerformanceTrace(sample_id, role, capacity)
    return _PERFORMANCE_TRACE

def drain_performance_stream_at_caller_boundary():
    recorder = _PERFORMANCE_TRACE
    if recorder is None or isinstance(recorder, PerformanceTrace): return
    # A prior product operation returned and released its locks. Preserve
    # sticky evidence failure until the outer final export, not an effect retry.
    try: recorder.drain()
    except (ValueError, OSError): pass # recorder retained the first precise failure


def export_performance_trace_from_env():
    if _PERFORMANCE_TRACE is not None and not isinstance(_PERFORMANCE_TRACE, PerformanceTrace):
        failure = None
        try: _PERFORMANCE_TRACE.drain(final=True)
        except BaseException as error: failure = error
        try: _PERFORMANCE_TRACE.output.close()
        except BaseException as error: failure = failure or error
        if failure: raise failure
        return
    if _PERFORMANCE_TRACE is None or "TRILLIONNIUM_OWNER_TRACE_OUTPUT" not in os.environ:
        return
    deadline = time.monotonic_ns() + 5_000_000_000
    def budget():
        if time.monotonic_ns() >= deadline:
            raise ValueError("trace export deadline exceeded")
    path = Path(os.environ["TRILLIONNIUM_OWNER_TRACE_OUTPUT"] + "." + _PERFORMANCE_TRACE.role)
    if not path.is_absolute() or '..' in path.parts or len(os.fsencode(path)) > 4096 or len(path.parts) > 64:
        raise ValueError("trace output must be a bounded physical absolute path")
    payload = json.dumps(_PERFORMANCE_TRACE.snapshot(), allow_nan=False, separators=(",", ":")).encode()
    if len(payload) > TRACE_MAX_EXPORT_BYTES:
        raise ValueError("trace export exceeds fixed cap")
    parents = [os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)]
    names = []
    def fixed(metadata):
        return metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid
    try:
        for part in path.parts[1:-1]:
            budget()
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parents[-1])
            parents.append(child); names.append(part)
        parent = parents[-1]
        metadata = os.fstat(parent)
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise ValueError("trace parent must be private and owned")
        import io
        budget()
        with io.FileIO(os.open(path.name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent), 'wb', closefd=True) as output:
            if output.write(payload) != len(payload):
                raise OSError("trace export short write")
            output.flush(); os.fsync(output.fileno())
            actual = os.fstat(output.fileno())
            entry = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (fixed(actual) != fixed(entry) or not stat.S_ISREG(actual.st_mode)
                    or actual.st_nlink != 1 or actual.st_size != len(payload)
                    or actual.st_mode & 0o777 != 0o600):
                raise ValueError("trace output identity/size changed")
            for index, name in enumerate(names):
                budget()
                held = os.fstat(parents[index + 1])
                entry = os.stat(name, dir_fd=parents[index], follow_symlinks=False)
                if fixed(held) != fixed(entry):
                    raise ValueError("trace parent entry changed")
    finally:
        # Attempt each raw directory FD once, never retry a released number.
        first_error = None
        while parents:
            fd = parents.pop()
            try:
                os.close(fd)
            except OSError as error:
                first_error = first_error or error
        if first_error:
            raise first_error
    budget()


"""Off-default two-bank evidence. No hook I/O, background thread or v1 snapshot."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import time

TRACE_STREAM_SLOTS=512
TRACE_STREAM_MAX_EPOCHS=256
TRACE_STREAM_MAX_STARTED=65536
TRACE_STREAM_RESIDENT_CREDITS=1024
TRACE_STREAM_MAX_FILES=514
TRACE_STREAM_MAX_DISK_BYTES=16*1024*1024
TRACE_STREAM_MAX_CHUNK_BYTES=512*1024
TRACE_STREAM_MAX_DESCRIPTOR_BYTES=4096
TRACE_STREAM_STAGES=frozenset({'broker_accept','broker_auth','broker_queue_wait','broker_forward',
 'host_decode','host_capacity_wait','journal_append','journal_fsync','provider_spawn',
 'provider_first_event','provider_wait','callback_admission','tool_spawn','tool_output',
 'tool_exit','tool_cleanup','terminal_persistence','delivery_queue_wait','client_delivery'})

def _trace_stream_fd9(m):
    return [m.st_dev,m.st_ino,m.st_mode,m.st_nlink,m.st_uid,m.st_gid,m.st_size,m.st_mtime_ns,m.st_ctime_ns]
def _trace_stream_fixed(m):return m.st_dev,m.st_ino,m.st_mode,m.st_uid,m.st_gid
def _trace_stream_encoded(value):return json.dumps(value,allow_nan=False,separators=(',',':')).encode()

def _trace_stream_generation():
    with open('/proc/self/stat','rb') as f:raw=f.read(8193)
    if len(raw)>8192:raise ValueError('trace _trace_stream_generation stat bound')
    fields=raw[raw.rfind(b')')+1:].split();start=int(fields[19])
    with open('/proc/sys/kernel/random/boot_id','rb') as f:boot=f.read(65).strip()
    if start<=0 or not re.fullmatch(rb'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',boot):
        raise ValueError('trace _trace_stream_generation identity shape')
    return {'pid':os.getpid(),'start_time_ticks':start,'boot_id_sha256':hashlib.sha256(boot).hexdigest()}

class _TraceStreamOutput:
    def __init__(self,prefix,role,g):
        prefix=Path(prefix)
        if not prefix.is_absolute() or '..' in prefix.parts or len(os.fsencode(prefix))>4096 or len(prefix.parts)>64:
            raise ValueError('stream physical output bound')
        if not re.fullmatch('[A-Za-z0-9_.:-]{1,128}',prefix.name):raise ValueError('stream stem bound')
        self.owners=[os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)];self.names=[]
        self.base=f'{prefix.name}.{role}.{g["pid"]}.{g["start_time_ticks"]}.{g["boot_id_sha256"][:16]}'
        if len(self.base)>200:self.close();raise ValueError('generated stream leaf bound')
        try:
            for name in prefix.parts[1:-1]:
                self.owners.append(os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.owners[-1]));self.names.append(name)
            m=os.fstat(self.owners[-1])
            if m.st_uid!=os.geteuid() or m.st_mode&0o077:raise ValueError('stream parent private owned required')
        except BaseException:self.close();raise
        self.parent_fixed=[_trace_stream_fixed(os.fstat(fd)) for fd in self.owners]
        self.bytes=self.files=0;self.previous_ack='';self._first_failure={};self.phase='context.configure'
    @property
    def failure(self):return self._first_failure.get('first')
    def retain_failure(self,phase,message):
        # One bounded entry. CPython dict.setdefault admits the first retained
        # diagnostic without waiting on the occupied exporter/product locks.
        self._first_failure.setdefault('first',phase+': '+str(message)[:512])
    def close(self):
        first=None
        while self.owners:
            try:os.close(self.owners.pop())
            except OSError as e:first=first or e
        if first:raise first
    def custody(self):
        for fd,expected in zip(self.owners,self.parent_fixed):
            if _trace_stream_fixed(os.fstat(fd))!=expected:raise ValueError('stream held parent identity changed')
        for i,name in enumerate(self.names):
            if _trace_stream_fixed(os.fstat(self.owners[i+1]))!=_trace_stream_fixed(os.stat(name,dir_fd=self.owners[i],follow_symlinks=False)):
                raise ValueError('stream parent custody changed')
    def write(self,kind,name,raw,maximum,deadline):
        self.phase=kind+'.bounds'
        if self.failure is not None or len(raw)>maximum or time.monotonic_ns()>=deadline:raise ValueError('stream write bound/failure/deadline')
        self.bytes+=len(raw);self.files+=1
        if self.bytes>TRACE_STREAM_MAX_DISK_BYTES or self.files>TRACE_STREAM_MAX_FILES:raise ValueError('stream lifetime disk bound')
        self.phase=kind+'.parent_before';self.custody();parent=self.owners[-1]
        import io
        self.phase=kind+'.open_exclusive'
        with io.FileIO(os.open(name,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent),'wb+',closefd=True) as f:
            self.phase=kind+'.write';view=memoryview(raw)
            while view:
                if time.monotonic_ns()>=deadline:raise ValueError('stream write elapsed deadline')
                n=f.write(view)
                if type(n)is not int or n<=0:raise OSError('stream short write')
                view=view[n:]
            f.flush();self.phase=kind+'.file_fsync';os.fsync(f.fileno());self.phase=kind+'.fd_verify';before=os.fstat(f.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=os.geteuid() or before.st_mode&0o777!=0o600 or before.st_size!=len(raw):
                raise ValueError('stream output custody invalid')
            f.seek(0);digest=hashlib.sha256();left=len(raw)
            while left:
                if time.monotonic_ns()>=deadline:raise ValueError('stream verify deadline')
                b=f.read(min(left,8192))
                if not b:raise ValueError('stream verify short read')
                digest.update(b);left-=len(b)
            after=os.fstat(f.fileno());entry=os.stat(name,dir_fd=parent,follow_symlinks=False)
            if _trace_stream_fd9(before)!=_trace_stream_fd9(after) or _trace_stream_fd9(after)!=_trace_stream_fd9(entry) or digest.digest()!=hashlib.sha256(raw).digest():
                raise ValueError('stream output identity/hash changed')
            self.phase=kind+'.parent_fsync';os.fsync(parent);self.phase=kind+'.parent_after';self.custody()
            if time.monotonic_ns()>=deadline:raise ValueError('stream publication late')
            return _trace_stream_fd9(after)

class _TraceCompletionStreamRecorder:
    def __init__(self,sample_id,role,prefix):
        if not isinstance(sample_id,str) or not re.fullmatch('[A-Za-z0-9_.:/-]{1,128}',sample_id) or not isinstance(role,str) or not re.fullmatch('[A-Za-z0-9_.-]{1,128}',role) or role in {'.','..'}:
            raise ValueError('stream sample/role bounds')
        self.sample_id,self.role=sample_id,role;self.generation=_trace_stream_generation()
        self.banks=[self.bank(0),None];self.active=0;self.next_epoch=1
        self.lock=threading.Lock();self.export_lock=threading.Lock()
        self.started=self.pending=self.resident=self.published=self.acked=0
        self.loss_observed=False;self.closed=False;self.output=_TraceStreamOutput(prefix,role,self.generation)
        try:
            context={'schema':'org.trillionnium.actual-monotonic-completion-stream-context.v2','sample_id':sample_id,'producer_role':role,'generation':self.generation,
                     'bank_count':2,'slots_per_bank':512,'lifetime_epochs':TRACE_STREAM_MAX_EPOCHS,'lifetime_files':TRACE_STREAM_MAX_FILES,
                     'lifetime_disk_bytes':TRACE_STREAM_MAX_DISK_BYTES,'lifetime_started':TRACE_STREAM_MAX_STARTED,'resident_credits':TRACE_STREAM_RESIDENT_CREDITS,
                     'completion_order':'closed_publication_admission','lost_count_semantics':'unavailable','trace_complete':False,'installed_qualified':False}
            self.output.write('context',self.output.base+'.context.json',_trace_stream_encoded(context),4096,time.monotonic_ns()+5_000_000_000)
        except BaseException as error:
            self.output.retain_failure(self.output.phase,error);self.output.close();raise ValueError(self.output.failure) from error
    @staticmethod
    def bank(epoch):return {'epoch':epoch,'claimed':0,'sealed':False,'slots':[None]*512}
    def start(self,stage,key,deferred=False):
        if stage not in TRACE_STREAM_STAGES or not isinstance(key,str) or len(key)>4096:
            self.loss_observed=True;return _TraceCompletionStreamSpan()
        try:raw=key.encode()
        except UnicodeError:self.loss_observed=True;return _TraceCompletionStreamSpan()
        start=time.monotonic_ns();pid=os.getpid();tid=threading.get_native_id()
        if len(raw)>4096 or not 0<=start<1<<64 or not 0<pid<1<<32 or not 0<tid<1<<63:
            self.loss_observed=True;return _TraceCompletionStreamSpan()
        # Hash and allocation occur outside the short metadata grant. The closed
        # bit, start ID and both resident/pending counters share this one gate.
        record={'start_claim_id':None,'completion_sequence':None,'stage':stage,'scope_sha256':hashlib.sha256(raw).hexdigest(),
                'pid':pid,'tid':tid,'start_ns':start,'end_ns':None,'end':'unfinished'}
        if not self.lock.acquire(False):self.loss_observed=True;return _TraceCompletionStreamSpan()
        try:
            if self.closed or self.started>=TRACE_STREAM_MAX_STARTED or self.resident>=TRACE_STREAM_RESIDENT_CREDITS:
                self.loss_observed=True;return _TraceCompletionStreamSpan()
            record['start_claim_id']=self.started;self.started+=1;self.resident+=1;self.pending+=1
        finally:self.lock.release()
        return _TraceCompletionStreamSpan(self,record,deferred)
    def publish(self,record):
        if not self.lock.acquire(False):self.loss_observed=True;return # retained pending/credit is never guessed down
        try:
            bank=self.banks[self.active]
            self.pending-=1
            if bank is None or bank['sealed'] or bank['claimed']>=512:
                self.loss_observed=True;return
            slot=bank['claimed'];bank['claimed']+=1
            record['completion_sequence']=bank['epoch']*512+slot
            bank['slots'][slot]=record;self.published+=1
        finally:self.lock.release()
    def snapshot(self):raise ValueError('completion streaming evidence is not snapshot v1')
    def drain(self,final=False):
        if not self.export_lock.acquire(False):
            if final:
                self.output.retain_failure('exporter.acquire','final busy');self.loss_observed=True
                raise ValueError(self.output.failure)
            return
        try:
            if self.output.failure is not None:raise ValueError('stream retains first failure: '+self.output.failure)
            try:self._drain(final)
            except BaseException as error:
                self.output.retain_failure(self.output.phase,error)
                raise ValueError(self.output.failure) from error
        finally:self.export_lock.release()
    def activate(self,index):
        if self.next_epoch>=TRACE_STREAM_MAX_EPOCHS:raise ValueError('stream lifetime epoch bound')
        self.banks[index]=self.bank(self.next_epoch);self.next_epoch+=1;self.active=index
    def _drain(self,final):
        self.output.phase='drain.seal'
        if not self.lock.acquire(False):
            if final:raise ValueError('stream final metadata busy')
            return # no I/O/ACK attempted, a later caller boundary may drain
        try:
            if final:self.closed=True
            bank=self.banks[self.active]
            if bank is not None and (final or bank['claimed']>=256):
                bank['sealed']=True
                if not final and self.banks[1-self.active] is None:self.activate(1-self.active)
            ready=sorted((b for b in self.banks if b is not None and b['sealed']),key=lambda b:b['epoch'])
        finally:self.lock.release()
        deadline=time.monotonic_ns()+5_000_000_000
        for bank in ready:
            self.output.phase='drain.closed_slots'
            if any(b is not None and b['epoch']<bank['epoch'] for b in self.banks):continue
            if self.loss_observed or any(r is None for r in bank['slots'][:bank['claimed']]):raise ValueError('stream loss/publication hole prevents ACK')
            count=bank['claimed'];epoch=bank['epoch'];start=epoch*512
            chunk={'schema':'org.trillionnium.actual-monotonic-completion-stream-chunk.v2','sample_id':self.sample_id,'producer_role':self.role,'generation':self.generation,'epoch':epoch,
                   'claimed_start':start,'claimed_end_exclusive':start+count,'declared_unused_tail_start':start+count,'declared_unused_tail_end_exclusive':start+512,
                   'loss_observed':False,'lost_records_lower_bound':None,'lost_count_semantics':'unavailable','records':bank['slots'][:count],
                   'previous_ack_sha256':self.output.previous_ack,'trace_complete':False,'installed_qualified':False}
            self.output.phase='chunk.serialize';raw=_trace_stream_encoded(chunk);name=f'{self.output.base}.e{epoch}.chunk.json'
            custody=self.output.write('chunk',name,raw,TRACE_STREAM_MAX_CHUNK_BYTES,deadline)
            ack={'schema':'org.trillionnium.actual-monotonic-completion-stream-ack.v2','sample_id':self.sample_id,'producer_role':self.role,'generation':self.generation,'epoch':epoch,
                 'chunk_file':name,'chunk_bytes':len(raw),'chunk_sha256':hashlib.sha256(raw).hexdigest(),'chunk_fd9':custody,'claimed_start':start,'claimed_end_exclusive':start+count,
                 'previous_ack_sha256':self.output.previous_ack,'trace_complete':False,'installed_qualified':False}
            self.output.phase='ack.serialize'
            if self.loss_observed:raise ValueError('concurrent stream loss prevents ACK')
            ack_raw=_trace_stream_encoded(ack);self.output.write('ack',f'{self.output.base}.e{epoch}.ack.json',ack_raw,4096,deadline)
            self.output.phase='ack.release_credits'
            if self.loss_observed:raise ValueError('late stream loss retains bank')
            if not self.lock.acquire(False):raise ValueError('ACKed bank retained on metadata contention')
            try:
                index=next(i for i,b in enumerate(self.banks) if b is bank)
                if self.resident<count:raise ValueError('resident credit accounting invalid')
                self.output.previous_ack=hashlib.sha256(ack_raw).hexdigest();self.banks[index]=None
                self.resident-=count;self.acked+=count
            finally:self.lock.release()
        self.output.phase='drain.reactivate'
        if not self.lock.acquire(False):raise ValueError('stream post-drain metadata busy')
        try:
            if not final and self.banks[self.active] is None:self.activate(self.active)
            if final:
                self.output.phase='terminator.closure'
                if self.loss_observed or self.pending!=0 or self.resident!=0 or any(b is not None for b in self.banks) or not self.started==self.published==self.acked:
                    raise ValueError('stream final pending/lost/unACKed/start closure')
                counts=(self.started,self.published,self.acked,self.pending,self.resident)
                end={'schema':'org.trillionnium.actual-monotonic-completion-stream-terminator.v2','sample_id':self.sample_id,'producer_role':self.role,'generation':self.generation,
                     'last_ack_sha256':self.output.previous_ack,'epochs':self.next_epoch,'files_before_terminator':self.output.files,'bytes_before_terminator':self.output.bytes,
                     'started_count':self.started,'published_count':self.published,'acknowledged_count':self.acked,'pending_count':0,'resident_count':0,
                     'source_stream_closed':True,'producer_quiescence_proven':False,'trace_complete':False,'installed_qualified':False}
            else:end=None
        finally:self.lock.release()
        if end is not None:
            self.output.phase='terminator.serialize';self.output.write('terminator',self.output.base+'.terminator.json',_trace_stream_encoded(end),4096,deadline)
            self.output.phase='terminator.late_closure'
            if not self.lock.acquire(False):raise ValueError('final late metadata busy')
            try:
                if self.loss_observed or counts!=(self.started,self.published,self.acked,self.pending,self.resident):raise ValueError('source changed during final publication')
            finally:self.lock.release()

class _TraceCompletionStreamSpan:
    __slots__=('recorder','record','deferred')
    def __init__(self,recorder=None,record=None,deferred=False):self.recorder,self.record,self.deferred=recorder,record,deferred
    def __enter__(self):return self
    def __exit__(self,kind,value,tb):self.finish('exception' if kind else 'scope_exit_unclassified');return False
    def finish(self,end='observed_boundary'):
        r,record=self.recorder,self.record;self.recorder=self.record=None
        if r is None:return
        if end not in {'observed_boundary','scope_exit_unclassified','abandoned','exception'}:end='abandoned'
        now=time.monotonic_ns()
        if end=='abandoned' or not record['start_ns']<=now<1<<64:r.loss_observed=True
        record['end_ns']=now if record['start_ns']<=now<1<<64 else record['start_ns'];record['end']=end
        r.publish(record)


class DuplicateMember(ValueError):
    pass


class BrokerError(ValueError):
    pass


def _reject_nonfinite_json(value: str) -> None:
    """Keep protocol JSON in the RFC-8259 finite-number subset."""

    raise ValueError(f"non-finite JSON number {value}")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateMember(f"duplicate key {key}")
        result[key] = value
    return result


def strict_json(raw: bytes, *, label: str, maximum: int = MAX_LINE_BYTES) -> Any:
    if not raw or len(raw) > maximum:
        raise BrokerError(f"{label} is empty or exceeds {maximum} bytes")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_reject_nonfinite_json,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise BrokerError(f"invalid {label}: {error}") from error


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None:
        raise BrokerError(f"{label} is empty, oversized or malformed")
    return value


def require_token(value: Any) -> str:
    if not isinstance(value, str) or TOKEN_RE.fullmatch(value) is None:
        raise BrokerError("broker token must be 32 random bytes encoded as lowercase hex")
    return value


def compare_token(first: str, second: str) -> bool:
    return hmac.compare_digest(first.encode("ascii"), second.encode("ascii"))


def read_line(stream: BinaryIO, *, label: str, maximum: int = MAX_LINE_BYTES) -> bytes | None:
    raw = stream.readline(maximum + 2)
    if not raw:
        return None
    if not raw.endswith(b"\n") or len(raw) > maximum + 1:
        raise BrokerError(f"{label} is oversized or not newline terminated")
    raw = raw[:-1]
    if not raw:
        raise BrokerError(f"{label} is empty")
    return raw


def _executable_stat_tuple(metadata: os.stat_result) -> tuple[int, ...]:
    """Return the metadata that must remain stable while hashing an executable."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_executable_metadata(metadata: os.stat_result, label: str) -> None:
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise BrokerError(f"{label} must be a non-symlink regular file")
    if (
        metadata.st_nlink != 1
        or metadata.st_size == 0
        or metadata.st_size > MAX_EXECUTABLE_BYTES
    ):
        raise BrokerError(f"{label} must be one non-empty file within the executable byte bound")
    if metadata.st_mode & 0o022:
        raise BrokerError(f"{label} must not be group/world writable")
    # Checking the mode bits on the opened inode avoids an additional path
    # lookup (and therefore another pathname race) during startup.
    if metadata.st_mode & 0o111 == 0:
        raise BrokerError(f"{label} is not executable")


def open_validated_executable(
    path: Path,
    label: str,
    *,
    expected_identity: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Open and validate an executable, returning a pinned descriptor.

    The descriptor is intentionally returned to the caller instead of being
    closed here.  A broker can then execute ``/proc/self/fd/<descriptor>``
    while passing that descriptor to the child, so a replacement or symlink
    swap of ``path`` between validation and ``Popen`` cannot redirect startup
    to another inode.  ``expected_identity`` binds a later startup validation
    to the identity captured when the broker was constructed.
    """

    if not path.is_absolute():
        raise BrokerError(f"{label} must be absolute")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise BrokerError(f"{label} cannot be inspected: {error}") from error
    _validate_executable_metadata(metadata, label)
    before = _executable_stat_tuple(metadata)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BrokerError(f"{label} cannot be opened: {error}") from error

    try:
        opened = os.fstat(descriptor)
        _validate_executable_metadata(opened, label)
        if _executable_stat_tuple(opened) != before:
            raise BrokerError(f"{label} changed before open")
        digest = hashlib.sha256()
        read = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            read += len(chunk)
            if read > MAX_EXECUTABLE_BYTES:
                raise BrokerError(f"{label} exceeds the executable byte bound")
        after = os.fstat(descriptor)
        if _executable_stat_tuple(after) != before or read != metadata.st_size:
            raise BrokerError(f"{label} changed while being measured")
        identity = {
            "path": str(path),
            "sha256": digest.hexdigest(),
            "bytes": read,
            "uid": after.st_uid,
            "gid": after.st_gid,
            "mode": f"{stat.S_IMODE(after.st_mode):04o}",
            "device": after.st_dev,
            "inode": after.st_ino,
        }
        if expected_identity is not None:
            identity_fields = (
                "sha256",
                "bytes",
                "uid",
                "gid",
                "mode",
                "device",
                "inode",
            )
            if any(identity.get(field) != expected_identity.get(field) for field in identity_fields):
                raise BrokerError(f"{label} changed since initial validation")
        return descriptor, identity
    except Exception:
        os.close(descriptor)
        raise


def validate_executable(path: Path, label: str) -> dict[str, Any]:
    descriptor, identity = open_validated_executable(path, label)
    os.close(descriptor)
    return identity



def validate_argv(argv: list[str], label: str = "upstream argv") -> None:
    if not argv or len(argv) > MAX_ARGV_ITEMS:
        raise BrokerError(f"{label} is empty or has too many elements")
    total = 0
    for item in argv:
        if not isinstance(item, str):
            raise BrokerError(f"{label} elements must be strings")
        encoded = item.encode("utf-8")
        if b"\x00" in encoded or len(encoded) > MAX_ARGUMENT_BYTES:
            raise BrokerError(f"{label} contains NUL or an oversized argument")
        total += len(encoded)
        if total > MAX_TOTAL_ARGV_BYTES:
            raise BrokerError(f"{label} exceeds the total byte bound")


def validate_private_parent(path: Path, label: str) -> None:
    if not path.is_absolute() or not path.parent.is_dir() or path.parent.is_symlink():
        raise BrokerError(f"{label} path must be absolute with an existing real parent")
    metadata = path.parent.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise BrokerError(f"{label} parent must be a stable real directory")
    mode = stat.S_IMODE(metadata.st_mode)
    effective_uid = os.geteuid()
    trusted_owner = metadata.st_uid in {0, effective_uid}
    root_sticky = metadata.st_uid == 0 and bool(mode & stat.S_ISVTX)
    if not trusted_owner or (mode & 0o022 and not root_sticky):
        raise BrokerError(
            f"{label} parent is not owner-controlled: uid={metadata.st_uid} mode={mode:04o}"
        )


def validate_socket_path(path: Path) -> None:
    if not path.is_absolute():
        raise BrokerError("broker Unix socket path must be absolute")
    encoded = os.fsencode(path)
    if len(encoded) > 100:
        raise BrokerError("broker Unix socket path exceeds the portable byte bound")
    if encoded.startswith(b"@"):  # abstract sockets remain an Android/W6 carrier concern
        raise BrokerError("foundation broker requires a filesystem Unix socket")
    parent = path.parent
    metadata = parent.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise BrokerError("broker socket parent must be a stable real directory")
    mode = stat.S_IMODE(metadata.st_mode)
    effective_uid = os.geteuid()
    trusted_owner = metadata.st_uid in {0, effective_uid}
    root_sticky = metadata.st_uid == 0 and bool(mode & stat.S_ISVTX)
    if not trusted_owner or (mode & 0o022 and not root_sticky):
        raise BrokerError(
            f"broker socket parent is not owner-controlled: uid={metadata.st_uid} mode={mode:04o}"
        )


def _validate_private_metadata(metadata: os.stat_result, label: str) -> None:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise BrokerError(f"{label} must be one regular file")
    if metadata.st_uid != os.geteuid():
        raise BrokerError(f"{label} must be owned by the effective service UID")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise BrokerError(f"{label} must have mode 0600")


def read_private_bytes(path: Path, *, label: str, maximum: int) -> bytes:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or metadata.st_size <= 0 or metadata.st_size > maximum:
        raise BrokerError(f"{label} is absent, symlinked, empty or oversized")
    _validate_private_metadata(metadata, label)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        _validate_private_metadata(opened, label)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise BrokerError(f"{label} changed before open")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(raw) != metadata.st_size or len(raw) > maximum:
        raise BrokerError(f"{label} changed while being read")
    if (after.st_mtime_ns, after.st_ctime_ns, after.st_size) != (
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_size,
    ):
        raise BrokerError(f"{label} changed while being read")
    return raw


def read_private_json(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    raw = read_private_bytes(path, label=label, maximum=MAX_DESCRIPTOR_BYTES)
    value = strict_json(raw, label=label, maximum=MAX_DESCRIPTOR_BYTES)
    if not isinstance(value, dict):
        raise BrokerError(f"{label} must contain an object")
    return value, raw


def atomic_write_private(path: Path, raw: bytes, *, label: str) -> None:
    validate_private_parent(path, label)
    if path.is_symlink():
        raise BrokerError(f"{label} path must not be a symlink")
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load_or_create_token(path: Path) -> str:
    try:
        raw = read_private_bytes(path, label="broker token", maximum=MAX_TOKEN_BYTES)
    except FileNotFoundError:
        raw = b""
    if raw:
        try:
            value = raw.decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise BrokerError("broker token is not ASCII") from error
        return require_token(value)

    validate_private_parent(path, "broker token")
    if path.is_symlink():
        raise BrokerError("broker token path must not be a symlink")
    token = secrets.token_hex(32)
    encoded = (token + "\n").encode("ascii")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        raw = read_private_bytes(path, label="broker token", maximum=MAX_TOKEN_BYTES)
        try:
            return require_token(raw.decode("ascii").strip())
        except UnicodeDecodeError as error:
            raise BrokerError("broker token is not ASCII") from error
    try:
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return token


def descriptor_preimage(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result.pop("descriptor_sha256", None)
    return result


def descriptor_sha256(value: dict[str, Any]) -> str:
    return sha256_bytes(canonical(descriptor_preimage(value)))


def finalize_descriptor(value: dict[str, Any]) -> dict[str, Any]:
    result = descriptor_preimage(value)
    result["descriptor_sha256"] = descriptor_sha256(result)
    return result


def validate_descriptor(value: dict[str, Any]) -> None:
    supplied = value.get("descriptor_sha256")
    if not isinstance(supplied, str) or supplied != descriptor_sha256(value):
        raise BrokerError("broker descriptor SHA-256 does not bind its canonical preimage")
    if value.get("schema") != "org.trillionnium.owner-open.connection-broker.v1":
        raise BrokerError("unsupported broker descriptor schema")
    require_id(value.get("broker_id"), "broker_id")
    socket_path = value.get("socket_path")
    token_file = value.get("token_file")
    if not isinstance(socket_path, str) or not Path(socket_path).is_absolute():
        raise BrokerError("broker descriptor socket_path is invalid")
    if not isinstance(token_file, str) or not Path(token_file).is_absolute():
        raise BrokerError("broker descriptor token_file is invalid")
    if value.get("response_model") != (
        "broker_correlated_result_owner_with_broadcast_observation"
    ):
        raise BrokerError("broker descriptor response model is incompatible")
    for field in (
        "max_clients",
        "client_queue_frames",
        "client_queue_bytes",
        "max_pending_requests",
    ):
        item = value.get(field)
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            raise BrokerError(f"broker descriptor {field} is not a positive integer")
