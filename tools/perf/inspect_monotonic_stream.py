#!/usr/bin/env python3
"""Read immutable acknowledged stream bytes; never admit installed/L2 evidence.

A terminator closes this source recorder, not its whole process family. The
caller must separately bind source, actual execution, producer set and custody.
Snapshot v1 and begin-order streaming v1 are never accepted here.
Completion sequence is closed-publication admission order, not timestamp order.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

STAGES = frozenset(('broker_accept broker_auth broker_queue_wait broker_forward '
 'host_decode host_capacity_wait journal_append journal_fsync provider_spawn '
 'provider_first_event provider_wait callback_admission tool_spawn tool_output '
 'tool_exit tool_cleanup terminal_persistence delivery_queue_wait client_delivery').split())
PREFIX = 'org.trillionnium.actual-monotonic-completion-stream-'
SHA = re.compile('[0-9a-f]{64}\\Z')
MAX_FILES, MAX_BYTES, MAX_CHUNK, MAX_META = 514, 16*1024*1024, 512*1024, 4096

class StreamError(ValueError): pass

def need(condition, message):
    if not condition: raise StreamError(message)

def number(value, label, maximum=(1<<64)-1, minimum=0):
    need(type(value) is int and minimum <= value <= maximum, label+' integer bound')
    return value

def keys(value, expected, label):
    need(type(value) is dict and set(value) == set(expected.split()), label+' closed keys')

def strict(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON member'); result[key] = value
        return result
    def constant(_): raise StreamError('nonfinite JSON')
    try: return json.loads(raw.decode(), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError) as error: raise StreamError('invalid JSON') from error

def fd9(m):
    return [m.st_dev,m.st_ino,m.st_mode,m.st_nlink,m.st_uid,m.st_gid,m.st_size,m.st_mtime_ns,m.st_ctime_ns]

def fixed(m): return m.st_dev,m.st_ino,m.st_mode,m.st_uid,m.st_gid

class Reader:
    def __init__(self, context_path, seconds):
        number(seconds, 'seconds', 120, 1)
        p = Path(context_path)
        need(p.is_absolute() and '..' not in p.parts and len(os.fsencode(p))<=4096 and len(p.parts)<=64, 'physical context path')
        need(p.name.endswith('.context.json'), 'context suffix')
        self.deadline=time.monotonic_ns()+seconds*1_000_000_000
        self.parents=[]; self.names=[]; self.files=[]; self.total=0; self.path=p
        try:
            self.parents.append(os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC))
            for part in p.parts[1:-1]:
                self.budget()
                self.parents.append(os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.parents[-1]));self.names.append(part)
            m=os.fstat(self.parents[-1]);need(m.st_uid==os.geteuid() and not m.st_mode&0o077,'private owner parent')
            self.parent_fixed=[fixed(os.fstat(fd)) for fd in self.parents]
            self.custody()
        except BaseException: self.close();raise
    def budget(self): need(time.monotonic_ns()<self.deadline,'whole reader deadline')
    def custody(self):
        self.budget()
        for i, fd in enumerate(self.parents):
            need(fixed(os.fstat(fd))==self.parent_fixed[i], 'held parent changed')
        for i,name in enumerate(self.names):
            need(fixed(os.stat(name,dir_fd=self.parents[i],follow_symlinks=False))==self.parent_fixed[i+1],'parent entry changed')
        for fd,name,record in self.files:
            need(fd9(os.fstat(fd))==record['fd9']==fd9(os.stat(name,dir_fd=self.parents[-1],follow_symlinks=False)),'retained leaf changed')
    def read(self,name,cap):
        need(len(self.files)<MAX_FILES and '/' not in name and len(os.fsencode(name))<=255,'file name/count bound')
        self.custody(); fd=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.parents[-1])
        try:
            m=os.fstat(fd); need(stat.S_ISREG(m.st_mode) and m.st_nlink==1 and stat.S_IMODE(m.st_mode)==0o600 and m.st_uid==os.geteuid() and 0<m.st_size<=cap,'stream regular owner leaf bound')
            need(fd9(m)==fd9(os.stat(name,dir_fd=self.parents[-1],follow_symlinks=False)), 'leaf entry before')
            self.total+=m.st_size;need(self.total<=MAX_BYTES,'stream lifetime byte bound')
            raw=bytearray()
            while len(raw)<m.st_size:
                self.budget();chunk=os.read(fd,min(8192,m.st_size-len(raw)));need(bool(chunk),'short stream read');raw.extend(chunk)
            need(fd9(m)==fd9(os.fstat(fd))==fd9(os.stat(name,dir_fd=self.parents[-1],follow_symlinks=False)),'leaf changed during read')
            record={'name':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'fd9':fd9(m)}
            self.files.append((fd,name,record));fd=None
            return strict(raw),record
        finally:
            if fd is not None:os.close(fd)
    def close(self):
        first=None
        for fd in [r[0] for r in self.files]+list(reversed(self.parents)):
            try:os.close(fd)
            except OSError as e:first=first or e
        self.files=[];self.parents=[]
        if first:raise first

COMMON='schema sample_id producer_role generation trace_complete installed_qualified'
def identity(value, schema, context, extra):
    keys(value,COMMON+' '+extra,schema)
    need(value['schema']==PREFIX+schema+'.v2',schema+' schema')
    for name in ('sample_id','producer_role','generation'):
        need(value[name]==context[name],schema+' identity')
    need(value['trace_complete'] is False and value['installed_qualified'] is False,'qualification flags must remain false')

def inspect_context(path, *, seconds=120):
    reader=Reader(path,seconds)
    try:
        context,cdesc=reader.read(reader.path.name,MAX_META)
        keys(context,COMMON+' bank_count slots_per_bank lifetime_epochs lifetime_files lifetime_disk_bytes lifetime_started resident_credits completion_order lost_count_semantics','context')
        need(context['schema']==PREFIX+'context.v2' and context['trace_complete'] is False and context['installed_qualified'] is False,'context protocol')
        need(type(context['sample_id']) is str and re.fullmatch('[A-Za-z0-9_.:/-]{1,128}',context['sample_id']),'sample identifier')
        need(type(context['producer_role']) is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}',context['producer_role']) and context['producer_role'] not in {'.','..'},'role identifier')
        g=context['generation'];keys(g,'pid start_time_ticks boot_id_sha256','generation')
        number(g['pid'],'pid',(1<<32)-1,1);number(g['start_time_ticks'],'startticks',minimum=1)
        need(type(g['boot_id_sha256']) is str and SHA.fullmatch(g['boot_id_sha256']),'boot SHA')
        for name,value in {'bank_count':2,'slots_per_bank':512,'lifetime_epochs':256,'lifetime_files':514,'lifetime_disk_bytes':MAX_BYTES,'lifetime_started':65536,'resident_credits':1024}.items():
            need(type(context[name]) is int and context[name]==value,'context fixed bound '+name)
        need(context['completion_order']=='closed_publication_admission','closed completion assignment')
        need(context['lost_count_semantics'] in {'saturating_lower_bound','unavailable'},'closed loss semantics')
        base=reader.path.name[:-len('.context.json')]
        suffix=f'.{context["producer_role"]}.{g["pid"]}.{g["start_time_ticks"]}.{g["boot_id_sha256"][:16]}'
        need(base.endswith(suffix) and len(base)<=200,'physical generation filename')
        stem=base[:-len(suffix)]
        need(re.fullmatch('[A-Za-z0-9_.:-]{1,128}',stem),'stream stem')
        end,edesc=reader.read(base+'.terminator.json',MAX_META)
        identity(end,'terminator',context,'last_ack_sha256 epochs files_before_terminator bytes_before_terminator source_stream_closed producer_quiescence_proven started_count published_count acknowledged_count pending_count resident_count')
        epochs=number(end['epochs'],'epochs',256,1)
        need(end['source_stream_closed'] is True and end['producer_quiescence_proven'] is False,'source closure only')
        number(end['files_before_terminator'],'pre-terminator files',513,1);number(end['bytes_before_terminator'],'pre-terminator bytes',MAX_BYTES,1)
        for key in ('started_count','published_count','acknowledged_count'):number(end[key],key,65536)
        for key in ('pending_count','resident_count'):need(type(end[key]) is int and end[key]==0,'final '+key)
        starts=bytearray(8192) # finite exact ID set, no producer reset or renumbering
        previous=''; total_records=0; stages={}; names={reader.path.name,base+'.terminator.json'}
        for epoch in range(epochs):
            reader.budget();name=f'{base}.e{epoch}.chunk.json';aname=f'{base}.e{epoch}.ack.json'
            chunk,desc=reader.read(name,MAX_CHUNK);ack,adesc=reader.read(aname,MAX_META);names.update((name,aname))
            identity(chunk,'chunk',context,'epoch claimed_start claimed_end_exclusive declared_unused_tail_start declared_unused_tail_end_exclusive loss_observed lost_records_lower_bound lost_count_semantics records previous_ack_sha256')
            identity(ack,'ack',context,'epoch chunk_file chunk_bytes chunk_sha256 chunk_fd9 claimed_start claimed_end_exclusive previous_ack_sha256')
            for obj in (chunk,ack):
                need(type(obj['epoch']) is int and obj['epoch']==epoch and obj['previous_ack_sha256']==previous,'epoch/ACK order')
                need(type(obj['claimed_start']) is int and obj['claimed_start']==epoch*512,'claimed range start')
            records=chunk['records'];need(type(records) is list and len(records)<=512,'records bank bound')
            count=len(records);stop=epoch*512+count
            need(chunk['loss_observed'] is False and chunk['lost_count_semantics']==context['lost_count_semantics'],'observed loss denies scope')
            if context['lost_count_semantics']=='unavailable':need(chunk['lost_records_lower_bound'] is None,'Python does not fabricate count')
            else:need(type(chunk['lost_records_lower_bound']) is int and chunk['lost_records_lower_bound']==0,'Rust observed count')
            for obj in (chunk,ack):need(type(obj['claimed_end_exclusive']) is int and obj['claimed_end_exclusive']==stop,'claimed end')
            need(type(chunk['declared_unused_tail_start']) is int and chunk['declared_unused_tail_start']==stop and type(chunk['declared_unused_tail_end_exclusive']) is int and chunk['declared_unused_tail_end_exclusive']==(epoch+1)*512,'explicit unused tail')
            need(ack['chunk_file']==name and type(ack['chunk_bytes']) is int and ack['chunk_bytes']==desc['bytes'] and ack['chunk_sha256']==desc['sha256'] and type(ack['chunk_fd9']) is list and len(ack['chunk_fd9'])==9 and all(type(n) is int for n in ack['chunk_fd9']) and ack['chunk_fd9']==desc['fd9'],'ACK binds physical chunk')
            for slot,record in enumerate(records):
                keys(record,'start_claim_id completion_sequence stage scope_sha256 pid tid start_ns end_ns end','record')
                need(type(record['completion_sequence']) is int and record['completion_sequence']==epoch*512+slot,'completion publication sequence')
                ident=number(record['start_claim_id'],'start_claim_id',65535)
                byte,bit=divmod(ident,8);need(not starts[byte]&(1<<bit),'duplicate start claim identity');starts[byte]|=1<<bit
                need(type(record['stage']) is str and record['stage'] in STAGES,'stage enum')
                need(type(record['scope_sha256']) is str and SHA.fullmatch(record['scope_sha256']),'scope SHA')
                need(type(record['pid']) is int and record['pid']==g['pid'],'record physical PID')
                number(record['tid'],'tid',(1<<63)-1,1)
                start=number(record['start_ns'],'start_ns');stop_ns=number(record['end_ns'],'end_ns');need(start<=stop_ns,'monotonic duration')
                need(record['end'] in {'observed_boundary','scope_exit_unclassified','exception'},'no unfinished/abandoned claim')
                stages[record['stage']]=stages.get(record['stage'],0)+1
            total_records+=count;previous=adesc['sha256']
        need(total_records==end['started_count']==end['published_count']==end['acknowledged_count'],'complete start/publication/ACK cardinality')
        for ident in range(65536):
            reader.budget()
            need(bool(starts[ident//8]&(1<<(ident%8)))==(ident<total_records),'exact closed start ID set')
        need(end['last_ack_sha256']==previous,'terminator ACK chain')
        need(end['files_before_terminator']==len(reader.files)-1 and end['bytes_before_terminator']==reader.total-edesc['bytes'],'terminator whole file/byte accounting')
        observed=set()
        with os.scandir(reader.parents[-1]) as entries:
            count=0
            for entry in entries:
                reader.budget();count+=1;need(count<=4096,'parent enumeration bound')
                if entry.name.startswith(base+'.'):observed.add(entry.name)
        need(observed==names,'missing/extra generation evidence')
        reader.custody()
        return {'schema':'org.trillionnium.inspected-acknowledged-monotonic-completion-stream.v2','context':context,
                'acknowledged_records':total_records,'started_count':end['started_count'],
                'start_identity_set_closed':True,'completion_order':'closed_publication_admission','epochs':epochs,'stage_counts':stages,
                'observed_files':len(reader.files),'observed_bytes':reader.total,
                'files':[row[2] for row in reader.files], 'source_stream_closed':True,
                'producer_quiescence_proven':False,'source_qualification_proven':False,
                'installed_qualified':False,'whole_family_budget_qualified':False,'l2_qualified':False}
    finally:reader.close()

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('context',type=Path);parser.add_argument('--seconds',type=int,default=120);args=parser.parse_args()
    try:report=inspect_context(args.context,seconds=args.seconds)
    except (StreamError,OSError) as error:parser.exit(2,str(error)+'\n')
    print(json.dumps(report,sort_keys=True,allow_nan=False))

if __name__=='__main__':main()
