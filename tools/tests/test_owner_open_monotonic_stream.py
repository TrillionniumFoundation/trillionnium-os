"""Actual two-bank source mechanisms, not installed or full workload evidence."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import socket
import threading
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
def raw_module(name,path):
    m=types.ModuleType(name);m.__file__=str(path);exec(compile(path.read_bytes(),str(path),'exec'),m.__dict__);return m
C=raw_module('_own_stream_test_common',ROOT/'tools/owner-open/owner_open_broker_common.py')
V=raw_module('_own_stream_test_consumer',ROOT/'tools/perf/inspect_monotonic_stream.py')

class ActualStreamTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);os.chmod(self.root,0o700);self.owned=[]
    def tearDown(self):
        C._PERFORMANCE_TRACE=None
        for r in self.owned:r.output.close()
        self.temp.cleanup()
    def recorder(self):
        r=C._TraceCompletionStreamRecorder('real-sample','broker',str(self.root/'trace'));self.owned.append(r);return r
    def report(self,r):return V.inspect_context(self.root/(r.output.base+'.context.json'))
    def span(self,r):r.start('broker_auth','bounded ordinary physical hook').finish()
    def test_same_lifetime_13000_acknowledged_real_records_and_unused_tail(self):
        r=self.recorder()
        for i in range(13000):
            self.span(r)
            if (i+1)%200==0:r.drain()
        r.drain(final=True);v=self.report(r)
        self.assertEqual(v['acknowledged_records'],13000);self.assertEqual(v['stage_counts'],{'broker_auth':13000})
        self.assertEqual(v['context']['lost_count_semantics'],'unavailable')
        self.assertFalse(v['installed_qualified']);self.assertFalse(v['l2_qualified']);self.assertFalse(v['whole_family_budget_qualified'])
        self.assertLessEqual(v['observed_files'],514);self.assertLessEqual(v['observed_bytes'],16*1024*1024)
        with self.assertRaises(ValueError):r.snapshot()
    def test_long_span_keeps_credit_and_start_id_but_does_not_pin_bank(self):
        r=self.recorder();long=r.start('broker_forward','long physical hook',True)
        for i in range(2000):
            self.span(r)
            if (i+1)%256==0:r.drain()
        self.assertEqual(r.pending,1);self.assertFalse(r.loss_observed);self.assertTrue(list(self.root.glob('*.ack.json')))
        long.finish();r.drain(final=True);self.assertEqual(self.report(r)['acknowledged_records'],2001)
        chunks=sorted((json.loads(p.read_bytes()) for p in self.root.glob('*.chunk.json')),key=lambda v:v['epoch'])
        self.assertEqual(chunks[-1]['records'][-1]['start_claim_id'],0)
    def test_pending_and_completed_share1024_resident_limit(self):
        r=self.recorder();pending=[r.start('broker_forward','pending',True) for _ in range(1024)]
        self.assertEqual(r.resident,1024);self.span(r);self.assertTrue(r.loss_observed)
        for span in pending:span.finish()
        with self.assertRaisesRegex(ValueError,'loss'):r.drain(final=True)
        self.assertFalse(list(self.root.glob('*.ack.json')));self.assertIsNotNone(r.output.failure);self.assertEqual(r.resident,1024)
    def test_actual_single_listener_accept_completes_after2000_closed_burst(self):
        r=self.recorder();C._PERFORMANCE_TRACE=r
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        path=self.root/'listener.sock';listener.bind(str(path));listener.listen(1);listener.settimeout(2)
        ready=threading.Event();errors=[]
        def accept_once():
            try:
                with C.performance_span('broker_accept','listener.accept'):
                    ready.set();connection,_=listener.accept();connection.close()
            except BaseException as error:errors.append(error)
        worker=threading.Thread(target=accept_once);worker.start()
        try:
            self.assertTrue(ready.wait(1))
            for i in range(2000):
                self.span(r)
                if (i+1)%256==0:r.drain()
            self.assertEqual(r.pending,1);self.assertFalse(r.loss_observed);self.assertTrue(list(self.root.glob('*.ack.json')))
            connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);connection.connect(str(path));connection.close()
            worker.join(2);self.assertFalse(worker.is_alive());self.assertFalse(errors)
            r.drain(final=True);report=self.report(r);self.assertEqual(report['acknowledged_records'],2001);self.assertEqual(report['stage_counts']['broker_accept'],1)
        finally:
            if worker.is_alive():
                connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                try:connection.connect(str(path))
                finally:connection.close()
                worker.join(2)
            listener.close();path.unlink(missing_ok=True)
    def test_final_close_with_pending_and_later_start_refuses_complete(self):
        r=self.recorder();span=r.start('broker_forward','pending',True)
        with self.assertRaisesRegex(ValueError,'pending'):r.drain(final=True)
        before=r.started;self.span(r);self.assertEqual(r.started,before);self.assertTrue(r.loss_observed)
        span.finish()
        with self.assertRaises(ValueError):r.drain(final=True)
        self.assertFalse(list(self.root.glob('*.terminator.json')))
    def test_actual_ack_file_collision_retains_credit_and_first_phase(self):
        r=self.recorder()
        for _ in range(256):self.span(r)
        collision=self.root/(r.output.base+'.e0.ack.json');collision.write_bytes(b'actual exclusive collision');os.chmod(collision,0o600)
        with self.assertRaisesRegex(ValueError,'ack.open_exclusive'):r.drain()
        first=r.output.failure;self.assertEqual(r.resident,256);self.assertTrue(any(b and b['claimed']==256 for b in r.banks))
        with self.assertRaisesRegex(ValueError,'first failure'):r.drain()
        self.assertEqual(r.output.failure,first)
    def test_real_parent_mode_change_fails_and_keeps_bank(self):
        r=self.recorder()
        for _ in range(256):self.span(r)
        os.chmod(self.root,0o750)
        with self.assertRaisesRegex(ValueError,'parent'):r.drain()
        self.assertIsNotNone(r.output.failure);self.assertTrue(any(b for b in r.banks));self.assertFalse(list(self.root.glob('*.ack.json')))
    def test_real_parent_rename_keeps_old_fd_and_rejects_new_empty_directory(self):
        parent=self.root/'owned';parent.mkdir(mode=0o700)
        r=C._TraceCompletionStreamRecorder('real-sample','broker',str(parent/'trace'));self.owned.append(r)
        for _ in range(256):self.span(r)
        parent.rename(self.root/'retained');parent.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError,'parent'):r.drain()
        self.assertFalse(list(parent.iterdir()));self.assertIsNotNone(r.output.failure)
        with self.assertRaises(ValueError):r.drain()
    def test_fsync_error_does_not_ack_clear_or_silently_resume(self):
        r=self.recorder()
        for _ in range(256):self.span(r)
        with patch.object(C.os,'fsync',side_effect=OSError(28,'injected syscall ENOSPC')):
            with self.assertRaisesRegex(ValueError,'chunk.file_fsync'):r.drain()
        self.assertIsNotNone(r.output.failure);self.assertFalse(list(self.root.glob('*.ack.json')))
        self.assertTrue(any(b and b['claimed']==256 for b in r.banks))
        with self.assertRaises(ValueError):r.drain()
    def test_consumer_rejects_extra_member_missing_terminator_and_changed_chunk(self):
        r=self.recorder();self.span(r);r.drain(final=True);v=self.report(r)
        self.assertEqual(v['acknowledged_records'],1)
        context=self.root/(r.output.base+'.context.json');original=context.read_bytes()
        value=json.loads(original);value['unregistered_extension']=0;context.write_bytes(json.dumps(value).encode());os.chmod(context,0o600)
        with self.assertRaises(V.StreamError):self.report(r)
        context.write_bytes(original)
        term=self.root/(r.output.base+'.terminator.json');saved=term.read_bytes();term.unlink()
        with self.assertRaises(OSError):self.report(r)
        term.write_bytes(saved);os.chmod(term,0o600)
        chunk=next(self.root.glob('*.chunk.json'));chunk.write_bytes(chunk.read_bytes().replace(b'broker_auth',b'host_decode'))
        with self.assertRaises(V.StreamError):self.report(r)
    def test_v1_snapshot_and_mixed_context_rejected(self):
        r=self.recorder();self.span(r);r.drain(final=True)
        context=self.root/(r.output.base+'.context.json');value=json.loads(context.read_bytes())
        for schema in ('org.trillionnium.actual-monotonic-stream-context.v1','org.trillionnium.actual-monotonic-trace.v1'):
            value['schema']=schema;context.write_bytes(json.dumps(value).encode())
            with self.assertRaises(V.StreamError):self.report(r)
    def test_consumer_start_identity_duplicate_or_hole_rejected_even_with_rebound_ack(self):
        r=self.recorder();self.span(r);self.span(r);r.drain(final=True)
        chunk=next(self.root.glob('*.chunk.json'));ack=next(self.root.glob('*.ack.json'));term=next(self.root.glob('*.terminator.json'))
        original=json.loads(chunk.read_bytes())
        for ident in (0,2):
            value=json.loads(json.dumps(original));value['records'][1]['start_claim_id']=ident;raw=json.dumps(value,separators=(',',':')).encode();chunk.write_bytes(raw)
            a=json.loads(ack.read_bytes());a['chunk_bytes']=len(raw);a['chunk_sha256']=hashlib.sha256(raw).hexdigest();a['chunk_fd9']=V.fd9(chunk.stat());araw=json.dumps(a,separators=(',',':')).encode();ack.write_bytes(araw)
            t=json.loads(term.read_bytes());t['last_ack_sha256']=hashlib.sha256(araw).hexdigest();t['bytes_before_terminator']=sum(p.stat().st_size for p in self.root.iterdir() if p!=term);term.write_bytes(json.dumps(t,separators=(',',':')).encode())
            with self.assertRaises(V.StreamError):self.report(r)
    def test_generation_is_real_and_two_processes_same_prefix_do_not_collide(self):
        common=ROOT/'tools/owner-open/owner_open_broker_common.py'
        code='import types,pathlib,sys; p=pathlib.Path(sys.argv[1]);m=types.ModuleType("measured");exec(compile(p.read_bytes(),str(p),"exec"),m.__dict__);r=m._TraceCompletionStreamRecorder("physical","broker",sys.argv[2]);r.start("broker_auth","ordinary").finish();r.drain(final=True);r.output.close()'
        for _ in range(2):
            op=subprocess.run([sys.executable,'-B','-c',code,str(common),str(self.root/'same')],capture_output=True,timeout=10)
            self.assertEqual(op.returncode,0,op.stderr)
        contexts=list(self.root.glob('*.context.json'));self.assertEqual(len(contexts),2)
        reports=[V.inspect_context(p) for p in contexts]
        self.assertNotEqual(reports[0]['context']['generation']['pid'],reports[1]['context']['generation']['pid'])
        self.assertEqual([r['acknowledged_records'] for r in reports],[1,1])
    def test_strict_env_does_not_silently_fallback_and_default_off_uses_no_clock(self):
        with patch.dict(os.environ,{'TRILLIONNIUM_OWNER_TRACE_MODE':'typo'},clear=True):
            with self.assertRaises(ValueError):C.configure_performance_trace('id','broker')
        with patch.dict(os.environ,{'TRILLIONNIUM_OWNER_TRACE_STREAM_OUTPUT':str(self.root/'x')},clear=True):
            with self.assertRaises(ValueError):C.configure_performance_trace('id','broker')
        with patch.dict(os.environ,{'TRILLIONNIUM_OWNER_TRACE_MODE':'streaming-completion'},clear=True):
            with self.assertRaises(ValueError):C.configure_performance_trace('id','broker')
        C._PERFORMANCE_TRACE=None
        with patch.object(C.time,'monotonic_ns',side_effect=AssertionError('disabled hook touched clock')):
            C.performance_span('broker_auth','ordinary').finish()
        entry=ROOT/'tools/owner-open/owner_open_connection_broker_v2.py'
        env=dict(os.environ);env.pop('TRILLIONNIUM_OWNER_TRACE_SAMPLE',None);env['TRILLIONNIUM_OWNER_TRACE_MODE']='streaming-completion';env['TRILLIONNIUM_OWNER_TRACE_STREAM_OUTPUT']=str(self.root/'inert')
        op=subprocess.run([sys.executable,'-B',str(entry),'--help'],env=env,capture_output=True,timeout=10)
        self.assertEqual(op.returncode,2);self.assertIn(b'requires sample',op.stderr);self.assertFalse(list(self.root.iterdir()))
    def test_final_busy_exporter_preserves_first_phase_without_later_ack(self):
        r=self.recorder();r.export_lock.acquire()
        try:
            with self.assertRaisesRegex(ValueError,'exporter.acquire: final busy'):r.drain(final=True)
        finally:r.export_lock.release()
        self.assertEqual(r.output.failure,'exporter.acquire: final busy')
        with self.assertRaisesRegex(ValueError,'exporter.acquire: final busy'):r.drain()
        self.assertFalse(list(self.root.glob('*.ack.json')))
    def test_initial_context_collision_reports_precise_exclusive_phase(self):
        self.recorder()
        with self.assertRaisesRegex(ValueError,'context.open_exclusive'):
            C._TraceCompletionStreamRecorder('real-sample','broker',str(self.root/'trace'))
    def test_empty_source_scope_terminates_without_fabricated_record(self):
        r=self.recorder();r.drain(final=True);self.assertEqual(self.report(r)['acknowledged_records'],0)

class StreamReaderLeafAdmissionTests(unittest.TestCase):
    """Owned local-file probes; never product/native or installed evidence."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)

    def tearDown(self):
        self.temp.cleanup()

    def reader(self):
        return V.Reader(self.root / 'fixture.context.json', 1)

    def regular(self, name='fixture.context.json', raw=b'{"source_only":true}'):
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def test_writerless_fifo_rejects_before_reader_deadline_for_every_leaf_kind(self):
        for suffix in ('context', 'terminator', 'e0.chunk', 'e0.ack'):
            with self.subTest(suffix=suffix):
                name = 'fixture.' + suffix + '.json'
                fifo = self.root / name
                # Do not replace a denied IPC operation with another route.
                os.mkfifo(fifo, 0o600)
                reader = self.reader()
                finished = threading.Event()
                errors = []

                def read_fifo():
                    try:
                        reader.read(name, V.MAX_META)
                    except BaseException as error:
                        errors.append(error)
                    finally:
                        finished.set()

                worker = threading.Thread(target=read_fifo, daemon=True)
                writer = None
                try:
                    worker.start()
                    # Reader has a one-second budget. A FIFO without a writer
                    # must be rejected without waiting for another participant.
                    returned = finished.wait(1.25)
                finally:
                    if not finished.is_set():
                        # Release only this test-owned FIFO on the red path.
                        # O_RDWR|NONBLOCK also avoids a race with reader entry.
                        writer = os.open(fifo, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
                    worker.join(2)
                    if writer is not None:
                        os.close(writer)
                    reader.close()
                    fifo.unlink()
                self.assertFalse(worker.is_alive(), 'test-owned FIFO reader did not retire')
                self.assertTrue(returned, 'FIFO acquisition outlived the reader deadline')
                self.assertEqual(len(errors), 1)
                self.assertIsInstance(errors[0], V.StreamError)
                self.assertIn('stream regular owner leaf bound', str(errors[0]))

    def test_regular_private_leaf_preserves_exact_bytes_hash_and_custody(self):
        raw = b'{"source_only":true}'
        path = self.regular(raw=raw)
        reader = self.reader()
        try:
            value, descriptor = reader.read(path.name, V.MAX_META)
            self.assertEqual(value, {'source_only': True})
            self.assertEqual(descriptor['bytes'], len(raw))
            self.assertEqual(descriptor['sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(descriptor['fd9'], V.fd9(path.stat()))
            reader.custody()
        finally:
            reader.close()

    def test_directory_and_symlink_leaves_are_still_rejected(self):
        directory = self.root / 'directory.context.json'
        directory.mkdir(mode=0o700)
        target = self.regular('target.json')
        link = self.root / 'link.context.json'
        link.symlink_to(target.name)
        for path, error in ((directory, V.StreamError), (link, OSError)):
            with self.subTest(name=path.name):
                reader = self.reader()
                try:
                    with self.assertRaises(error):
                        reader.read(path.name, V.MAX_META)
                finally:
                    reader.close()

    def test_hardlinked_and_nonprivate_leaves_are_still_rejected(self):
        linked = self.regular('linked.context.json')
        os.link(linked, self.root / 'second-name')
        exposed = self.regular('exposed.context.json')
        exposed.chmod(0o640)
        for path in (linked, exposed):
            with self.subTest(name=path.name):
                reader = self.reader()
                try:
                    with self.assertRaisesRegex(V.StreamError, 'regular owner leaf bound'):
                        reader.read(path.name, V.MAX_META)
                finally:
                    reader.close()

    def test_leaf_replacement_during_read_is_still_rejected(self):
        path = self.regular()
        reader = self.reader()
        real_read = os.read
        changed = False

        def replace_after_read(fd, count):
            nonlocal changed
            raw = real_read(fd, count)
            if not changed:
                changed = True
                path.rename(self.root / 'retained-original')
                self.regular()
            return raw

        try:
            with patch.object(V.os, 'read', side_effect=replace_after_read):
                with self.assertRaisesRegex(V.StreamError, 'leaf changed during read'):
                    reader.read(path.name, V.MAX_META)
        finally:
            reader.close()

    def test_expired_deadline_rejects_before_open(self):
        path = self.regular()
        reader = self.reader()
        reader.deadline = 0
        try:
            with patch.object(V.os, 'open') as opened:
                with self.assertRaisesRegex(V.StreamError, 'whole reader deadline'):
                    reader.read(path.name, V.MAX_META)
                opened.assert_not_called()
        finally:
            reader.close()

    def test_oversized_regular_leaf_is_rejected_before_read(self):
        path = self.regular(raw=b'x' * (V.MAX_META + 1))
        reader = self.reader()
        try:
            with patch.object(V.os, 'read') as read:
                with self.assertRaisesRegex(V.StreamError, 'regular owner leaf bound'):
                    reader.read(path.name, V.MAX_META)
                read.assert_not_called()
        finally:
            reader.close()

if __name__=='__main__':unittest.main()
