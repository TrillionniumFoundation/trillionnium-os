#!/usr/bin/env python3
"""Read-only complete P4 sender census for physical NEG04/05/07; no phone call."""
import argparse,base64,errno,gzip,hashlib,io,json,os,re,stat,sys,tarfile,time
from pathlib import Path
FINAL_DEPENDENCIES=None
P4='/home/alex/razr60-local-model-v150'
INPUT_BASE=P4+'/fault-p4-capture-inputs-r1'
OUTPUT_BASE=P4+'/fault-p4-original-captures-r1'
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
MAX_FILE=16*1024*1024
MAX_TOTAL=64*1024*1024
MAX_FILES=2048
MAX_DIRECTORY_FILES=1024
MAX_SECONDS=60.0
O_DIRECTORY=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
def need(value, message):
    if not value:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
        separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')

def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))

def metadata(value):
    return {key: getattr(value, key) for key in META}

def canonical(path):
    need(type(path) is str and path.startswith('/') and '\x00' not in path,
         'explicit absolute path required')
    parts = path[1:].split('/')
    need(parts and all(part not in ('', '.', '..') for part in parts),
         'noncanonical path')
    need(str(Path(path)) == path, 'canonical path spelling differs')
    return path

def under(path, root):
    canonical(path)
    need(path.startswith(root + '/'), 'path outside the one explicit input namespace')
    return path

def parent_fd(path):
    canonical(path)
    parts = path[1:].split('/')
    fd = os.open('/', O_DIRECTORY)
    try:
        for part in parts[:-1]:
            nxt = os.open(part, O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise

def exact3(value, cap=MAX_FILE):
    need(type(value) is dict and set(value) == {'path','bytes','sha256'},
         'exact three-field descriptor required')
    canonical(value['path'])
    need(type(value['bytes']) is int and 0 <= value['bytes'] <= cap
         and type(value['sha256']) is str
         and re.fullmatch('[0-9a-f]{64}', value['sha256']) is not None,
         'descriptor byte pin differs')
    return value

def read_regular(path, cap, check_time):
    parent, leaf = parent_fd(path)
    fd = -1
    try:
        before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= cap, 'bounded regular single-link file required')
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=parent)
        need(metadata(os.fstat(fd)) == metadata(before), 'original changed at open')
        chunks = []
        count = 0
        while True:
            check_time()
            chunk = os.read(fd, min(65536, cap + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
            need(count <= cap, 'original exceeds byte limit')
        raw = b''.join(chunks)
        need(len(raw) == before.st_size
             and metadata(os.fstat(fd)) == metadata(before)
             == metadata(os.stat(leaf, dir_fd=parent, follow_symlinks=False)),
             'original file bookends differ')
        return raw, metadata(before)
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent)

def observe_absence(path):
    """Only real ENOENT from a canonical held ancestor proves absence."""
    canonical(path)
    parts = path[1:].split('/')
    fd = os.open('/', O_DIRECTORY)
    walked = '/'
    try:
        for index, part in enumerate(parts):
            before = metadata(os.fstat(fd))
            try:
                st = os.stat(part, dir_fd=fd, follow_symlinks=False)
            except OSError as error:
                need(error.errno == errno.ENOENT, 'absence is unknown, not ENOENT')
                need(metadata(os.fstat(fd)) == before, 'absence ancestor changed')
                return {'ancestor': walked, 'metadata': before,
                    'missing_component': part, 'unresolved_suffix': parts[index:],
                    'errno': errno.ENOENT}
            if index == len(parts) - 1:
                raise ValueError('expected absent path exists')
            need(stat.S_ISDIR(st.st_mode), 'absence walk encountered non-directory or link')
            nxt = os.open(part, O_DIRECTORY, dir_fd=fd)
            need(metadata(os.fstat(nxt)) == metadata(st), 'absence ancestor changed at open')
            os.close(fd)
            fd = nxt
            walked = (walked.rstrip('/') + '/' + part)
        raise ValueError('absence path has no missing component')
    finally:
        os.close(fd)

def new_directory(path):
    parent, leaf = parent_fd(path)
    try:
        parent_stat = os.fstat(parent)
        need(parent_stat.st_uid == os.geteuid() and stat.S_IMODE(parent_stat.st_mode) == 0o700,
             'existing output parent must already be private and owned')
        os.mkdir(leaf, 0o700, dir_fd=parent)
        fd = os.open(leaf, O_DIRECTORY, dir_fd=parent)
        try:
            st = os.fstat(fd)
            need(st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o700,
                 'new private output directory differs')
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)

def put(path, raw):
    parent, leaf = parent_fd(path)
    fd = -1
    try:
        fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            need(count > 0, 'output write stopped')
            view = view[count:]
        os.fsync(fd)
        os.fsync(parent)
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent)
    actual, _ = read_regular(path, max(len(raw), 1), lambda: None)
    need(actual == raw, 'new output readback differs')
    return {'path': path, 'bytes': len(raw), 'sha256': sha(raw)}

class Capture:
    def __init__(self):
        self.started = time.monotonic()
        self.originals = {}
        self.retained = {}
        self.directories = []
        self.absences = []
        self.total = 0
        self.retained_total = 0

    def clock(self):
        need(time.monotonic() - self.started <= MAX_SECONDS, 'capture time bound exceeded')

    def file(self, path, relative, pin=None, cap=MAX_FILE):
        self.clock()
        need(type(relative) is str and not relative.startswith('/')
             and all(x not in ('', '.', '..') for x in relative.split('/')),
             'retained relative name differs')
        raw, info = read_regular(path, cap, self.clock)
        if pin is not None:
            exact3(pin, cap)
            need(path == pin['path'] and (len(raw), sha(raw)) == (pin['bytes'], pin['sha256']),
                 'explicit original byte pin differs')
        original = {'source': path, 'bytes': len(raw), 'sha256': sha(raw), 'metadata': info}
        if path in self.originals:
            old, old_raw = self.originals[path]
            need(old == original and old_raw == raw, 'repeated original differs')
        else:
            self.total += len(raw)
            need(self.total <= MAX_TOTAL and len(self.originals) < MAX_FILES,
                 'complete original pool exceeds bound')
            self.originals[path] = (original, raw)
        need(relative not in self.retained, 'retained archive name reused')
        self.retained_total += len(raw)
        need(self.retained_total <= MAX_TOTAL, 'all retained copies exceed complete byte bound')
        self.retained[relative] = raw
        return {**original, 'retained': {'path': relative, 'bytes': len(raw), 'sha256': sha(raw)}}

    def absence(self, path):
        first, second = observe_absence(path), observe_absence(path)
        need(first == second, 'double absence observations differ')
        result = {'schema': 'hepta.canonical-path-absence.v1', 'source': path,
            'canonical_ancestor': {'source': first['ancestor'],
                'metadata_before': first['metadata'], 'metadata_after': second['metadata']},
            'missing_component': first['missing_component'],
            'unresolved_suffix': first['unresolved_suffix'],
            'observations': [{'errno': errno.ENOENT}, {'errno': errno.ENOENT}],
            'final_observations': []}
        self.absences.append((result, first))
        return result

    def directory(self, path, prefix):
        try:
            parent, leaf = parent_fd(path)
        except OSError as error:
            need(error.errno == errno.ENOENT, 'directory ancestor read is unknown, not absent')
            return None, {}, self.absence(path)
        fd = -1
        try:
            try:
                fd = os.open(leaf, O_DIRECTORY, dir_fd=parent)
            except OSError as error:
                need(error.errno == errno.ENOENT, 'directory is neither real nor proven absent')
                return None, {}, self.absence(path)
            before = metadata(os.fstat(fd))
            need(stat.S_ISDIR(before['st_mode']) and before['st_uid'] == os.geteuid()
                 and not (before['st_mode'] & 0o022), 'original directory identity or writer permissions differ')
            names = sorted(os.listdir(fd))
            need(len(names) <= MAX_DIRECTORY_FILES and len(names) == len(set(names))
                 and all(re.fullmatch('[A-Za-z0-9._-]{1,192}', n) is not None
                         and n not in ('.','..') for n in names), 'directory name/count bound differs')
            rows = {}
            for name in names:
                self.clock()
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1,
                     'unreviewed nested directory, link or special file in complete census')
                rows[name] = self.file(path + '/' + name, prefix + '/' + name)
            after = metadata(os.fstat(fd))
            need(before == after == metadata(os.stat(leaf, dir_fd=parent, follow_symlinks=False))
                 and names == sorted(os.listdir(fd)), 'complete directory bookends differ')
            row = {'source': path, 'metadata_before': before, 'metadata_after': after,
                   'names_before': names, 'names_after': list(names)}
            self.directories.append(row)
            return row, rows, None
        finally:
            if fd >= 0:
                os.close(fd)
            os.close(parent)

    def optional_file(self, path, relative, cap=MAX_FILE):
        try:
            return self.file(path, relative, cap=cap), None
        except OSError as error:
            need(error.errno == errno.ENOENT, 'optional file read is unknown, not absent')
            return None, self.absence(path)

    def recheck(self):
        for original, raw in self.originals.values():
            self.clock()
            current, info = read_regular(original['source'], MAX_FILE, self.clock)
            need(current == raw and info == original['metadata'],
                 'original bytes or full9 changed at final bookend')
        for row in self.directories:
            parent, leaf = parent_fd(row['source'])
            fd = -1
            try:
                fd = os.open(leaf, O_DIRECTORY, dir_fd=parent)
                need(metadata(os.fstat(fd)) == row['metadata_before']
                     == metadata(os.stat(leaf, dir_fd=parent, follow_symlinks=False))
                     and sorted(os.listdir(fd)) == row['names_before'],
                     'complete directory final census differs')
                row['metadata_after'] = metadata(os.fstat(fd))
                row['names_after'] = sorted(os.listdir(fd))
            finally:
                if fd >= 0:
                    os.close(fd)
                os.close(parent)
        for row, first in self.absences:
            a, b = observe_absence(row['source']), observe_absence(row['source'])
            need(first == a == b, 'canonical final double absence differs')
            row['canonical_ancestor']['metadata_after'] = b['metadata']
            row['final_observations'] = [{'errno': errno.ENOENT}, {'errno': errno.ENOENT}]

def write_retained(out, values):
    directories = set()
    for relative, raw in sorted(values.items()):
        parts = relative.split('/')
        current = out + '/retained'
        if current not in directories:
            new_directory(current)
            directories.add(current)
        for part in parts[:-1]:
            current += '/' + part
            if current not in directories:
                new_directory(current)
                directories.add(current)
        put(current + '/' + parts[-1], raw)

def archive(out, values, report_raw, check_time):
    path = out + '/ORIGINALS.tar.gz'
    parent, leaf = parent_fd(path)
    fd = -1
    try:
        fd = os.open(leaf, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        with os.fdopen(fd,'wb',closefd=False) as stream:
            with gzip.GzipFile(fileobj=stream,mode='wb',mtime=0) as zipped:
                with tarfile.open(fileobj=zipped,mode='w',format=tarfile.GNU_FORMAT) as tf:
                    members = dict(values)
                    members['CAPTURE.original.json'] = report_raw
                    for name, raw in sorted(members.items()):
                        check_time()
                        item = tarfile.TarInfo(name)
                        item.size = len(raw); item.mode = 0o600
                        item.uid = item.gid = 0; item.mtime = 0
                        tf.addfile(item,io.BytesIO(raw))
            stream.flush()
            os.fsync(fd)
        need(os.fstat(fd).st_size <= MAX_TOTAL, 'archive byte bound exceeded')
        os.fsync(parent)
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent)
    raw, _ = read_regular(path,MAX_TOTAL,check_time)
    return {'path':path,'bytes':len(raw),'sha256':sha(raw)}

def final_dependencies():
    need(type(FINAL_DEPENDENCIES) is dict and set(FINAL_DEPENDENCIES)=={'sender_sha256'} and
         FINAL_DEPENDENCIES['sender_sha256']=='5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281',
         'future_reviewed_sender_dependency_is_unfrozen')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--plan');p.add_argument('--plan-sha256');p.add_argument('--self-sha256')
    p.add_argument('--execute-read-once',action='store_true');args=p.parse_args()
    if not args.execute_read_once:
        print(encoded({'state':'SOURCE_PREVIEW_NO_PRIVATE_READ','phone_calls':0,'process_starts':0,
            'physical_case_pass':False,'final_dependencies_frozen':FINAL_DEPENDENCIES is not None}).decode(),end='')
        return 0
    final_dependencies()
    c=Capture();selfrow=c.file(os.path.abspath(__file__),'SOURCE.original.py',cap=65536)
    need(selfrow['sha256']==args.self_sha256,'actual_P4_capture_source_differs')
    row=c.file(args.plan,'PLAN.original.json',cap=65536)
    need(row['sha256']==args.plan_sha256,'actual_P4_capture_plan_differs')
    plan=strict(c.retained['PLAN.original.json'])
    need(type(plan) is dict and set(plan)=={'schema','case_id','nonce','sender_label','owner_request_sha256',
        'scope','out'} and plan['schema']=='hepta.physical-fault.p4-sender-capture-plan.v1' and
        plan['case_id'] in ('NEG-04','NEG-05','NEG-07') and re.fullmatch('[0-9a-f]{32}',plan['nonce']) and
        re.fullmatch('[a-z0-9][a-z0-9-]{5,69}',plan['sender_label']) and
        re.fullmatch('[0-9a-f]{64}',plan['owner_request_sha256']),'actual_fixed_fault_capture_plan')
    need(args.plan==INPUT_BASE+'/'+plan['nonce']+'/PLAN.json' and
         plan['out']==OUTPUT_BASE+'/'+plan['nonce'],'exact_new_P4_capture_namespace')
    out=plan['out'];new_directory(out)
    intent=put(out+'/INTENT.json',encoded({'schema':'hepta.physical-fault.p4-capture-intent.v1',
        'source':selfrow,'plan':row,'case_id':plan['case_id'],'maximum_capture_attempts':1,
        'phone_calls':0,'automatic_retry':False}))
    written=False
    try:
        source='/home/alex/codex-hepta-natural-'+plan['sender_label']+'-root-v150'
        directory,rows,absent=c.directory(source,'sender')
        need(directory is not None and absent is None,'actual_complete_sender_directory_required')
        required={'SEND.once.json','SEND-NATIVE-LATENCY.json','DRAFT-RESTORE-RESULT.json'}
        # Draft receipts are validated by the independent closer. Different
        # reviewed sender revisions may name the final receipt differently;
        # no member is omitted from this complete directory census.
        need({'SEND.once.json','SEND-NATIVE-LATENCY.json'}<=set(rows) and
             'ACTOR-FAILURE.json' not in rows,'actual_sender_did_not_finish_safely')
        once=strict(c.retained['sender/SEND.once.json'])
        need(once.get('prompt_sha256')==plan['owner_request_sha256'] and
             type(once.get('prompt')) is str and sha(once['prompt'].encode())==plan['owner_request_sha256'],
             'actual_sender_owner_binding')
        latency=strict(c.retained['sender/SEND-NATIVE-LATENCY.json'])
        need(latency.get('scope')==plan['scope'] and latency.get('owner_request_utf8_sha256')==
             plan['owner_request_sha256'],'actual_sender_scope_binding')
        c.recheck()
        report={'schema':'hepta.physical-fault.p4-sender-original-capture.v1',
            'state':'COMPLETE_P4_SENDER_ORIGINALS_CAPTURED_UNQUALIFIED','source':selfrow,'plan':row,
            'intent':intent,'case_id':plan['case_id'],'nonce':plan['nonce'],
            'sender_label':plan['sender_label'],'scope':plan['scope'],
            'owner_request_sha256':plan['owner_request_sha256'],
            'sender_directory':directory,'sender_originals':rows,
            'original_file_count':len(c.originals),'original_raw_bytes':c.total,
            'retained_member_count':len(c.retained),'all_original_full9_and_bytes_rechecked':True,
            'complete_directory_census_bookends_equal':True,'phone_calls':0,'signals':0,
            'physical_case_pass':False,'automatic_retry':False}
        body=encoded(report);need(len(body)<=4*1024*1024,'P4_capture_report_bound')
        written=True;write_retained(out,c.retained);c.recheck()
        capture=put(out+'/CAPTURE.original.json',body)
        packed=archive(out,c.retained,body,c.clock);c.recheck()
        result={'schema':'hepta.physical-fault.p4-capture-result.v1','state':report['state'],
            'capture':capture,'archive':packed,'archive_member_count':len(c.retained)+1,
            'originals_rechecked_after_archive':True,'phone_calls':0,'physical_case_pass':False,
            'automatic_retry':False}
        final=put(out+'/RESULT.json',encoded(result))
        print(encoded({'result':final,**result}).decode(),end='');return 0
    except BaseException as error:
        if not written:
            written=True
            try:write_retained(out,c.retained)
            except BaseException:pass
        put(out+'/FAILURE.json',encoded({'state':'INCOMPLETE_ORIGINAL_CAPTURE_NO_RETRY',
            'error_type':type(error).__name__,'error':str(error)[:1024],'physical_case_pass':False,
            'automatic_retry':False,'phone_calls':0}))
        raise

if __name__=='__main__':raise SystemExit(main())
