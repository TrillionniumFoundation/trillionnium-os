#!/usr/bin/env python3
"""Extract actual ownership/read methods and exercise them with explicit Android IO stand-ins."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def pin(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def block(text, start):
    assert text.count(start) == 1, start
    begin = text.index(start)
    opening = text.index('{', begin)
    depth = 1
    quote = None
    escaped = False
    line = False
    comment = False
    i = opening + 1
    while i < len(text):
        c = text[i]
        n = text[i + 1:i + 2]
        if line:
            if c == '\n':
                line = False
        elif comment:
            if c == '*' and n == '/':
                comment = False
                i += 1
        elif quote:
            if escaped:
                escaped = False
            elif c == '\\':
                escaped = True
            elif c == quote:
                quote = None
        elif c in ('"', "'"):
            quote = c
        elif c == '/' and n == '/':
            line = True
            i += 1
        elif c == '/' and n == '*':
            comment = True
            i += 1
        elif c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return text[begin:i + 1] + '\n'
        i += 1
    raise AssertionError('unclosed actual source block')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--java', default='java')
    parser.add_argument('--compiler-contract', choices=('release8', 'local-source8-target8'), default='release8')
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    root = here.parents[1]
    service = root / 'src/org/trillionnium/hepta/local/HeptaAccessibilityService.java'
    test = here / 'FlightObservationWorkerHostTest.java'
    inputs = [pin(service), pin(test), pin(Path(__file__).resolve())]
    source = service.read_text()
    anchors = [
        '    static final class FlightObservationSnapshot implements AutoCloseable {',
        '    private final class FlightObservationRead<T> implements Runnable {',
        '    private <T>T readFlightObservationOnWorker(',
    ]
    chunks = [block(source, anchor) for anchor in anchors]
    close = block(block(source, '    private static final class Graph {'),
                  '        void close(){for(NodeRef n:refs.values())n.node.recycle();refs.clear();}')
    # These are explicit fake Android/queue boundary types. The real source blocks
    # above retain their bodies, synchronization, exception and cleanup behavior.
    fixture = '''package org.trillionnium.hepta.local;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
final class HeptaAccessibilityService {
 interface Cancellation { boolean isCancelled(); }
 static ExecutorService observationIo;
 static final AtomicBoolean observationIoBusy=new AtomicBoolean();
 static final class SystemClock { static long elapsedRealtime(){return System.nanoTime()/1000000;} }
 static final class Looper {
  static final Looper MAIN=new Looper();static Thread mainThread;
  static Looper getMainLooper(){return MAIN;}
  static Looper myLooper(){return Thread.currentThread()==mainThread?MAIN:null;}
 }
 static final class WebFlightSession {}
 static final class BackgroundSession {}
 static final class QualificationScopeConfig {static final class Bound {}}
 static final class TaskAuthorization {static final class Gate {}}
 static final class PhoneObservation {}
 static final class FakeNode {
  final AtomicBoolean recycled=new AtomicBoolean();final AtomicInteger recycles=new AtomicInteger();
  void recycle(){if(!recycled.compareAndSet(false,true))throw new AssertionError("double node recycle");recycles.incrementAndGet();}
 }
 static final class NodeRef {final FakeNode node;NodeRef(FakeNode n){node=n;}}
 static final class Graph {
  final Map<String,NodeRef> refs=new HashMap<String,NodeRef>();
  String flightNativeSnapshotRaw="[]",backgroundOwnerSha="synthetic",backgroundSelectionRaw="{}";
''' + close + '}\n' + '\n'.join(chunks) + '''
 static void fixtureReset(){observationIo=Executors.newSingleThreadExecutor();observationIoBusy.set(false);Looper.mainThread=null;}
 static void fixtureShutdown()throws Exception{observationIo.shutdownNow();if(!observationIo.awaitTermination(2,TimeUnit.SECONDS))throw new AssertionError("worker did not actually drain");}
 static void fixtureReject(){observationIo.shutdown();}
 static void fixtureQueue(Runnable r){observationIo.execute(r);}
 static long fixtureNow(){return SystemClock.elapsedRealtime();}
 static boolean fixtureBusy(){return observationIoBusy.get();}
 static void fixtureMain(boolean value){Looper.mainThread=value?Thread.currentThread():null;}
 static boolean fixtureClosed(FlightObservationSnapshot s){return s.closed;}
 static void fixtureBorrow(FlightObservationSnapshot s){s.borrow();}
 static void fixtureRelease(FlightObservationSnapshot s){s.releaseBorrow();}
 FlightObservationSnapshot fixtureSnapshot(FakeNode n){
  Graph owned=new Graph();owned.refs.put("n0",new NodeRef(n));
  return new FlightObservationSnapshot(this,new WebFlightSession(),new BackgroundSession(),new QualificationScopeConfig.Bound(),
   new TaskAuthorization.Gate(),new PhoneObservation(),owned,new Graph(),"n0","0","{}",fixtureNow());
 }
 <T>T fixtureRead(Callable<T> read,final AtomicBoolean cancel,long deadline,FlightObservationSnapshot source)throws Exception{
  return readFlightObservationOnWorker(read,new Cancellation(){public boolean isCancelled(){return cancel.get();}},deadline,source);
 }
}
'''
    out = args.out.resolve()
    out.mkdir(exist_ok=False)
    generated = out / 'HeptaAccessibilityService.java'
    generated.write_text(fixture)
    classes = out / 'classes'
    classes.mkdir()
    empty = out / 'empty-sourcepath'
    empty.mkdir()
    commands = []

    def run(name, argv):
        value = subprocess.run(list(map(str, argv)), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=30, check=False,
                               env=dict(os.environ, LANG='C', LC_ALL='C'))
        stdout = out / (name + '.stdout')
        stderr = out / (name + '.stderr')
        stdout.write_bytes(value.stdout)
        stderr.write_bytes(value.stderr)
        row = {'name': name, 'argv': list(map(str, argv)), 'exit_code': value.returncode,
               'stdout': pin(stdout), 'stderr': pin(stderr)}
        commands.append(row)
        return value.returncode

    flags = ['--release', '8', '-Xlint:all'] if args.compiler_contract == 'release8' else ['-source', '8', '-target', '8', '-Xlint:all,-options']
    compiled = run('compile', [args.java, '-m', 'jdk.compiler/com.sun.tools.javac.Main', *flags,
        '-encoding', 'UTF-8', '-Werror', '-proc:none', '-implicit:none', '-sourcepath', empty,
        '-d', classes, generated, test])
    cases = out / 'CASES.json'
    if compiled == 0:
        run('ownership-cases', [args.java, '-cp', classes, 'org.trillionnium.hepta.local.FlightObservationWorkerHostTest', cases])
    assert inputs == [pin(service), pin(test), pin(Path(__file__).resolve())]
    result = {'schema': 'hepta.flight-observation-worker-host-result.v1',
              'all_pass': compiled == 0 and len(commands) == 2 and commands[1]['exit_code'] == 0,
              'scope': 'synthetic_android_io_actual_extracted_service_lifecycle',
              'compiler_contract': args.compiler_contract,
              'source_inputs': inputs, 'source_inputs_before_after_equal': True, 'commands': commands,
              'extracted_blocks': [{'anchor': anchor, 'bytes': len(chunk.encode()),
                 'sha256': hashlib.sha256(chunk.encode()).hexdigest()} for anchor, chunk in zip(anchors, chunks)],
              'generated_fixture': pin(generated), 'original_graph_close_byte_preserved': True,
              'full_android_service_compiled': False, 'phone_operations': 0, 'business_verified': False,
              'cases': json.loads(cases.read_bytes()) if cases.is_file() else None}
    target = out / 'RESULT.json'
    target.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'result': pin(target), 'all_pass': result['all_pass'], 'cases': result['cases']}))
    raise SystemExit(0 if result['all_pass'] else 1)


if __name__ == '__main__':
    main()
