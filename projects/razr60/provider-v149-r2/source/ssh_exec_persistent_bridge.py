#!/usr/bin/env python3
"""Multiplexed opaque loopback transport over ordinary SSH exec, never SSH -R.

A lost generation closes every admitted stream. Only future TCP connections get
new channels; no accepted bytes, turn or CLI request are replayed or resumed.
"""
import argparse
import asyncio
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

VERSION = 1
HEADER = struct.Struct('!BII')
OPEN, DATA, EOF, CLOSE, READY, PING, PONG = range(1, 8)
MAX_DATA = 65536
MAX_ACTIVE = 4
MAX_CHANNELS = 4096
SSH_BASE = ['/usr/bin/ssh', '-T', '-J', 'ai395-usb4', '-o', 'HostName=10.77.0.4', '-p', '22',
            '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=5',
            '-o', 'ClearAllForwardings=yes', '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
            '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2', 'pocket4-usb4-fast']


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


async def bounded_close(writer):
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 2)
    except (ConnectionError, OSError):
        actual_socket = writer.get_extra_info('socket')
        require(actual_socket is not None and actual_socket.fileno() == -1,
                'writer cleanup failed without actual closed-socket receipt')


class Channel:
    def __init__(self, mux, number, reader, writer):
        self.mux, self.number, self.reader, self.writer = mux, number, reader, writer
        self.sent_eof = self.received_eof = self.closed = False
        self.read_bytes = self.written_bytes = 0
        self.task = None
        self.expiry_task = None
        self.cleanup_complete = False
        self.close_lock = asyncio.Lock()

    async def pump(self):
        try:
            async with asyncio.timeout(900):
                while not self.closed:
                    data = await self.reader.read(MAX_DATA)
                    if not data:
                        self.sent_eof = True
                        await self.mux.send(EOF, self.number)
                        if self.received_eof:
                            await self.close(notify=True)
                        return
                    self.read_bytes += len(data)
                    await self.mux.send(DATA, self.number, data)
        except asyncio.CancelledError:
            raise
        except Exception:
            await self.close(notify=True)

    async def receive(self, kind, data):
        if self.closed:
            return
        if kind == DATA:
            require(not self.received_eof, 'data followed channel EOF')
            self.writer.write(data)
            await asyncio.wait_for(self.writer.drain(), 10)
            self.written_bytes += len(data)
        elif kind == EOF:
            require(not self.received_eof, 'duplicate channel EOF')
            self.received_eof = True
            if self.writer.can_write_eof():
                self.writer.write_eof()
                await asyncio.wait_for(self.writer.drain(), 10)
            else:
                raise RuntimeError('TCP writer cannot half-close')
            if self.sent_eof:
                await self.close(notify=True)
        elif kind == CLOSE:
            await self.close(notify=False)
        else:
            raise RuntimeError('invalid channel frame')

    async def close(self, notify):
        async with self.close_lock:
            if self.cleanup_complete:
                return
            self.closed = True  # Revoke continuation immediately; keep ownership until cleanup.
            self.mux.closed.add(self.number)
            if self.task is not None and self.task is not asyncio.current_task():
                self.task.cancel()
            if self.expiry_task is not None and self.expiry_task is not asyncio.current_task():
                self.expiry_task.cancel()
            await bounded_close(self.writer)
            if notify and not self.mux.closing:
                await self.mux.send(CLOSE, self.number)
            self.mux.channels.pop(self.number, None)
            self.cleanup_complete = True
            if self.mux.remote and self.mux.last_id >= MAX_CHANNELS and not self.mux.channels:
                self.mux.writer.close()  # Rotate only after all admitted streams closed.


class Mux:
    def __init__(self, reader, writer, remote, nonce, provider_check=None):
        self.reader, self.writer = reader, writer
        self.remote, self.nonce, self.provider_check = remote, nonce, provider_check
        self.channels, self.closed = {}, set()
        self.write_lock = asyncio.Lock()
        self.closing = False
        self.last_id = 0
        self.ready = remote
        self.server = None
        self.heartbeat_task = None
        self.channel_tasks = set()
        self.accept_tasks = set()

    async def send(self, kind, number=0, data=b''):
        require(len(data) <= MAX_DATA, 'SSH frame exceeds bound')
        async with self.write_lock:
            self.writer.write(HEADER.pack(kind, number, len(data))+data)
            await asyncio.wait_for(self.writer.drain(), 10)

    def begin_pump(self, channel):
        task = asyncio.create_task(channel.pump())
        channel.task = task
        self.channel_tasks.add(task)
        task.add_done_callback(self.channel_tasks.discard)
        async def expire():
            await asyncio.sleep(900)
            await channel.close(notify=True)
        channel.expiry_task = asyncio.create_task(expire())
        self.channel_tasks.add(channel.expiry_task)
        channel.expiry_task.add_done_callback(self.channel_tasks.discard)

    async def accept(self, reader, writer):
        current = asyncio.current_task()
        self.accept_tasks.add(current)  # Before any await, keep an actual accepted socket owner.
        channel = None
        try:
            if self.closing or len(self.channels) >= MAX_ACTIVE or self.last_id >= MAX_CHANNELS:
                await bounded_close(writer)
                return
            self.last_id += 1
            channel = Channel(self, self.last_id, reader, writer)
            self.channels[channel.number] = channel
            await self.send(OPEN, channel.number)
            if self.closing or channel.closed or self.channels.get(channel.number) is not channel:
                await channel.close(notify=False)
                return
            self.begin_pump(channel)
        except BaseException:
            if channel is not None:
                await channel.close(notify=False)
            else:
                await bounded_close(writer)
            raise
        finally:
            self.accept_tasks.discard(current)

    async def heartbeat(self):
        while not self.closing:
            await asyncio.sleep(15)
            await self.send(PING)

    async def run(self):
        self.heartbeat_task = asyncio.create_task(self.heartbeat())
        body_error = None
        try:
            while not self.closing:
                header = await asyncio.wait_for(self.reader.readexactly(HEADER.size), 50)
                kind, number, size = HEADER.unpack(header)
                require(kind in range(1, 8) and size <= MAX_DATA, 'invalid bridge frame')
                data = await asyncio.wait_for(self.reader.readexactly(size), 10)
                if kind == READY:
                    value = json.loads(data)
                    require(not self.remote and not self.ready and number == 0 and
                            value == {'version': VERSION, 'nonce': self.nonce, 'port': 18084},
                            'remote bridge ready identity differs')
                    self.ready = True
                    print(json.dumps({'event': 'bridge-ready', 'remote_port': 18084,
                                      'nonce': self.nonce}), flush=True)
                    continue
                require(self.ready, 'channel frame arrived before READY')
                if kind in [PING, PONG]:
                    require(number == 0 and size == 0, 'invalid heartbeat')
                    if kind == PING:
                        await self.send(PONG)
                    continue
                require(0 < number <= MAX_CHANNELS and (kind == DATA or size == 0), 'invalid channel id/length')
                if kind == OPEN:
                    require(not self.remote and number == self.last_id+1 and
                            sum(not ch.closed for ch in self.channels.values()) < MAX_ACTIVE,
                            'remote channel admission invalid')
                    self.last_id = number
                    try:
                        self.provider_check()
                        reader, writer = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', 18082,
                                                               limit=65536), 3)
                    except Exception:
                        self.closed.add(number)
                        await self.send(CLOSE, number)
                        continue
                    channel = Channel(self, number, reader, writer)
                    self.channels[number] = channel
                    self.begin_pump(channel)
                elif number in self.channels:
                    await self.channels[number].receive(kind, data)
                elif number not in self.closed:
                    raise RuntimeError('frame for channel never admitted')
                # Late frames for a closed channel are discarded, never re-opened.
        except BaseException as error:
            body_error = error
            raise
        finally:
            self.closing = True
            first = None
            async def cleanup(operation):
                nonlocal first
                try:
                    await operation
                except BaseException as error:
                    first = first or error
            if self.server is not None:
                self.server.close()  # Stop accept first; wait_closed is AFTER actual client close.
            accepts = list(self.accept_tasks)
            for task in accepts:
                task.cancel()
            results = await asyncio.gather(*accepts, return_exceptions=True)
            for result in results:
                if isinstance(result, BaseException) and not isinstance(result, asyncio.CancelledError):
                    first = first or result
            self.heartbeat_task.cancel()
            await asyncio.gather(self.heartbeat_task, return_exceptions=True)
            for channel in list(self.channels.values()):
                await cleanup(channel.close(notify=False))
            tasks = list(self.channel_tasks)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if self.server is not None:
                await cleanup(asyncio.wait_for(self.server.wait_closed(), 3))
            await cleanup(bounded_close(self.writer))
            if first is not None:
                if body_error is not None:
                    body_error.add_note('transport cleanup also failed: '+type(first).__name__)
                else:
                    raise first



class PipeWriterProtocol(asyncio.streams.FlowControlMixin):
    def __init__(self, loop):
        super().__init__(loop=loop)
        self.closed = loop.create_future()

    def connection_lost(self, error):
        super().connection_lost(error)
        if not self.closed.done():
            if error is None:
                self.closed.set_result(None)
            else:
                self.closed.set_exception(error)

    def _get_close_waiter(self, stream):
        return self.closed


async def stdio_streams():
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=65536)
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)
    transport, writer_protocol = await loop.connect_write_pipe(lambda: PipeWriterProtocol(loop), sys.stdout.buffer)
    writer = asyncio.StreamWriter(transport, writer_protocol, reader, loop)
    return reader, writer


async def remote(nonce):
    require(len(nonce) == 32 and all(x in '0123456789abcdef' for x in nonce), 'bad nonce')
    reader, writer = await stdio_streams()
    mux = Mux(reader, writer, True, nonce)
    mux.server = await asyncio.start_server(mux.accept, '127.0.0.1', 18084, limit=65536)
    await mux.send(READY, data=json.dumps({'version': VERSION, 'nonce': nonce, 'port': 18084}).encode())
    await mux.run()


def passive_provider(args):
    raw = (args.provider_state/'ready.json').read_bytes()
    require(len(raw) < 8192, 'provider ready oversized')
    ready = json.loads(raw)
    require(ready.get('schema') == 'hepta.daily-provider.ready.v1' and ready.get('accepting') is True and
            ready.get('source_sha256') == args.provider_sha256 and ready.get('port') == 18082,
            'daily provider readiness differs')
    process = subprocess.run(['/bin/ps', '-p', str(ready['pid']), '-o', 'args='],
                             capture_output=True, text=True, timeout=2)
    require(process.returncode == 0 and str(args.provider_source) in process.stdout and
            '--state '+str(args.provider_state) in process.stdout, 'provider process identity differs')
    require(hashlib.sha256(args.provider_source.read_bytes()).hexdigest() == args.provider_sha256,
            'daily provider source changed')


async def local(args):
    args.state.mkdir(mode=0o700, exist_ok=True)
    info = args.state.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
            'private bridge state required')
    lock = os.open(args.state/'bridge.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for number in [signal.SIGINT, signal.SIGTERM, signal.SIGHUP]:
        loop.add_signal_handler(number, stop.set)
    delay = 1
    while not stop.is_set():
        process = None
        wait_stop = mux_task = stderr_task = None
        began = time.monotonic()
        try:
            # Metadata only: never connect to the provider to test readiness.
            passive_provider(args)
            nonce = secrets.token_hex(16)
            bootstrap = ("import hashlib,pathlib,sys; p=pathlib.Path("+repr(str(args.remote_source))+"); "
                         "b=p.read_bytes(); assert hashlib.sha256(b).hexdigest()=="+repr(args.remote_sha256)+"; "
                         "sys.argv=[str(p),'--remote','--nonce',"+repr(nonce)+"]; "
                         "exec(compile(b,str(p),'exec'),{'__name__':'__main__','__file__':str(p)})")
            command = 'python3 -B -u -c '+shlex.quote(bootstrap)
            process = await asyncio.create_subprocess_exec(*SSH_BASE, command,
                        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE, start_new_session=True, limit=65536)
            async def drain_stderr():
                # Do not retain SSH messages which may contain account metadata.
                total = 0
                while True:
                    data = await process.stderr.read(4096)
                    if not data:
                        return
                    total += len(data)
                    require(total <= 1024*1024, 'SSH stderr exceeds per-generation bound')
            stderr_task = asyncio.create_task(drain_stderr())
            mux = Mux(process.stdout, process.stdin, False, nonce, lambda: passive_provider(args))
            mux_task = asyncio.create_task(mux.run())
            wait_stop = asyncio.create_task(stop.wait())
            done, _pending = await asyncio.wait([mux_task, wait_stop, stderr_task], return_when=asyncio.FIRST_COMPLETED)
            if mux_task in done:
                await mux_task
            elif stderr_task in done:
                await stderr_task
                raise RuntimeError('SSH stderr ended; generation closed')
        except asyncio.CancelledError:
            raise
        except Exception as error:
            print(json.dumps({'event': 'transport-generation-ended', 'error_class': type(error).__name__,
                              'accepted_streams_replayed': False}), flush=True)
        finally:
            for task in [mux_task, wait_stop, stderr_task]:
                if task is not None:
                    task.cancel()
            await asyncio.gather(*(t for t in [mux_task, wait_stop, stderr_task] if t is not None), return_exceptions=True)
            if process is not None:
                if process.returncode is None:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGTERM)
                    try:
                        await asyncio.wait_for(process.wait(), 3)
                    except asyncio.TimeoutError:
                        with contextlib.suppress(ProcessLookupError):
                            os.killpg(process.pid, signal.SIGKILL)
                        await process.wait()
        if stop.is_set():
            break
        delay = 1 if time.monotonic()-began >= 60 else min(delay*2, 60)
        try:
            await asyncio.wait_for(stop.wait(), delay)
        except asyncio.TimeoutError:
            pass
    os.close(lock)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--remote', action='store_true')
    p.add_argument('--nonce')
    p.add_argument('--state', type=Path)
    p.add_argument('--provider-state', type=Path)
    p.add_argument('--provider-source', type=Path)
    p.add_argument('--provider-sha256')
    p.add_argument('--remote-source', type=Path)
    p.add_argument('--remote-sha256')
    args = p.parse_args()
    if args.remote:
        asyncio.run(remote(args.nonce))
    else:
        require(all([args.state, args.provider_state, args.provider_source, args.provider_sha256,
                     args.remote_source, args.remote_sha256]), 'local bridge configuration incomplete')
        asyncio.run(local(args))


if __name__ == '__main__':
    main()
