#!/usr/bin/env python3
"""Selected Root Linux squashfs builder with bounded subprocess retirement."""
from __future__ import annotations

import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import time

import build_owner_open_rootfs_image_release as base

POLL_SECONDS = 0.02
TERM_GRACE = 1.0
KILL_GRACE = 2.0
DRAIN_SECONDS = 1.0
READ_BYTES = 64 * 1024
MAX_PROC_ENTRIES = 65536
MAX_PROC_STAT_BYTES = 8192


def _observe_exit(process: subprocess.Popen[bytes]) -> int | None:
    """Keep the direct child waitable until all original-group signals finish."""
    if process.returncode is not None:
        raise base.ImageError("image tool process-group anchor was already reaped")
    result = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if result is None:
        return None
    if result.si_pid != process.pid:
        raise base.ImageError("image tool wait identity differs")
    if result.si_code == os.CLD_EXITED:
        return result.si_status
    if result.si_code in (os.CLD_KILLED, os.CLD_DUMPED):
        return -result.si_status
    raise base.ImageError("image tool wait returned a non-exit event")


def _quiet_group(pid: int, deadline: float) -> bool:
    """Observe only the original process group, never escaped descendants."""
    anchor_seen, quiet = False, True
    with os.scandir("/proc") as entries:
        for count, entry in enumerate(entries, 1):
            if count > MAX_PROC_ENTRIES or time.monotonic() >= deadline:
                raise base.ImageError("image tool process observation budget exhausted")
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            try:
                with open(f"/proc/{entry.name}/stat", "rb") as source:
                    raw = source.read(MAX_PROC_STAT_BYTES + 1)
            except (FileNotFoundError, ProcessLookupError):
                continue
            if len(raw) > MAX_PROC_STAT_BYTES:
                raise base.ImageError("image tool procfs stat exceeds its bound")
            fields = raw.rsplit(b")", 1)[1].split()
            group, session = int(fields[2]), int(fields[3])
            if int(entry.name) == pid:
                if group != pid or session != pid:
                    raise base.ImageError("image tool process-group identity changed")
                anchor_seen = True
            if group == pid and fields[0] not in (b"Z", b"X"):
                quiet = False
    if not anchor_seen:
        raise base.ImageError("image tool waitable anchor is not visible in procfs")
    return quiet


def terminate_group(process: subprocess.Popen[bytes]) -> None:
    """Retire even an exited leader's original group before reaping it.

    Exclusive direct-child reaping and a complete same-namespace /proc are
    required. No signals follow loss or consumption of the waitable anchor.
    Cleanup failure must prevent the caller from publishing an image receipt.
    A TERM-phase scan-budget expiry may be superseded only by complete later
    SIGKILL-phase confirmation; signal, identity and other observation errors
    remain terminal cleanup errors.
    """
    try:
        _observe_exit(process)
    except Exception as error:
        raise base.ImageError("image tool process-group anchor unavailable") from error
    hard_errors: list[str] = []
    final_budget_error: str | None = None
    settled = False
    for sig, grace in ((signal.SIGTERM, TERM_GRACE), (signal.SIGKILL, KILL_GRACE)):
        # A failed signal does not skip escalation; a lost anchor does.
        try:
            _observe_exit(process)
        except Exception as error:
            raise base.ImageError("image tool process-group anchor lost during retirement") from error
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        except OSError as error:
            hard_errors.append(f"signal {sig}: {str(error)[:256]}")
        deadline = time.monotonic() + grace
        quiet_once = False
        phase_budget_error: str | None = None
        while time.monotonic() < deadline:
            try:
                exited = _observe_exit(process) is not None
                quiet = _quiet_group(process.pid, min(deadline, time.monotonic() + 1.0))
            except Exception as error:
                detail = f"observation: {str(error)[:256]}"
                if str(error) == "image tool process observation budget exhausted":
                    phase_budget_error = detail
                else:
                    hard_errors.append(detail)
                break
            if exited and quiet and quiet_once:
                if sig == signal.SIGKILL:
                    settled = True
                break
            quiet_once = exited and quiet
            time.sleep(min(0.005, max(0, deadline - time.monotonic())))
        if sig == signal.SIGKILL:
            final_budget_error = phase_budget_error
    try:
        # All group signals are over. Even unconfirmed cleanup still attempts
        # bounded reaping, but it can never become a successful build result.
        exited = _observe_exit(process) is not None
        process.wait(timeout=0 if exited else KILL_GRACE)
    except Exception as error:
        raise base.ImageError("image tool process group could not be reaped") from error
    if hard_errors or not settled:
        details = list(hard_errors)
        if not settled:
            details.append(final_budget_error or "deadline")
        raise base.ImageError("image tool original-group cleanup unconfirmed: "
                              + "; ".join(details)[:1536])


def bounded_command(argv: list[str], timeout: float):
    if (type(timeout) not in (int, float) or not 0.001 <= timeout <= 1800
            or type(base.MAX_OUTPUT_BYTES) is not int
            or not 0 < base.MAX_OUTPUT_BYTES <= 16 * 1024 * 1024):
        raise base.ImageError("image command timeout/output budget is invalid or non-finite")
    if (not sys.platform.startswith("linux") or not callable(getattr(os, "waitid", None))
            or not hasattr(os, "WNOWAIT") or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL):
        raise base.ImageError("image command requires Linux WNOWAIT and exclusive default-SIGCHLD reaping")
    started = time.monotonic()
    process = subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True, close_fds=True, bufsize=0,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "TZ": "UTC"},
    )
    selector = None
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    captured = 0
    retirement_attempted = False
    drain_deadline = None
    failure = None
    timed_out = False
    try:
        # Initialization errors receive exactly the same cleanup as pump errors.
        selector = selectors.DefaultSelector()
        for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe.fileno(), selectors.EVENT_READ, name)
        while True:
            if not retirement_attempted:
                if _observe_exit(process) is not None:
                    retirement_attempted = True
                    terminate_group(process)
                    drain_deadline = time.monotonic() + DRAIN_SECONDS
                elif time.monotonic() >= started + timeout:
                    timed_out = True
                    raise base.ImageError("image command execution deadline expired")
            if retirement_attempted and not selector.get_map():
                break
            deadline = drain_deadline if retirement_attempted else started + timeout
            if retirement_attempted and time.monotonic() >= deadline:
                raise base.ImageError("image command pipe drain deadline exceeded; escaped writers may remain")
            delay = min(POLL_SECONDS, max(0.0, deadline - time.monotonic()))
            if not selector.get_map():
                time.sleep(delay)
                continue
            for key, _mask in selector.select(delay):
                # A sentinel byte distinguishes exact-boundary EOF from excess.
                # Never collect unbounded output and check its length afterwards.
                size = min(READ_BYTES, base.MAX_OUTPUT_BYTES - captured + 1)
                try:
                    chunk = os.read(key.fd, size)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                if captured + len(chunk) > base.MAX_OUTPUT_BYTES:
                    raise base.ImageError(f"command output exceeds byte bound: {argv[0]}")
                streams[key.data].extend(chunk)
                captured += len(chunk)
    except Exception as error:
        failure = f"{type(error).__name__}: {str(error)[:1536]}"
    finally:
        if not retirement_attempted:
            retirement_attempted = True
            try:
                terminate_group(process)
                if timed_out:
                    failure = f"command timed out and was reaped: {argv[0]}"
            except Exception as error:
                failure = f"image cleanup failed: {str(error)[:1536]}; prior={failure or 'none'}"
        if selector is not None:
            try:
                selector.close()
            except Exception as error:
                failure = f"image selector close failed: {str(error)[:512]}; prior={failure or 'none'}"
        for pipe in (process.stdout, process.stderr):
            try:
                if pipe is not None:
                    pipe.close()
            except OSError as error:
                failure = f"image pipe close failed: {str(error)[:512]}; prior={failure or 'none'}"
    if failure is not None:
        raise base.ImageError(failure[:2048])
    stdout, stderr = bytes(streams["stdout"]), bytes(streams["stderr"])
    return {
        "returncode": process.returncode,
        "elapsed_ms": max(0, int((time.monotonic() - started) * 1000)),
        "stdout": stdout, "stderr": stderr,
        "stdout_sha256": base.hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": base.hashlib.sha256(stderr).hexdigest(),
    }


def normalize_copy(source_root: Path, destination_root: Path) -> list[str]:
    destination_root.mkdir(mode=0o755)
    files: list[str] = []
    for source in sorted(source_root.rglob("*")):
        relative = source.relative_to(source_root)
        target = destination_root / relative
        metadata = source.lstat()
        if base.stat.S_ISLNK(metadata.st_mode):
            raise base.ImageError(f"staging copy encountered symlink: {relative}")
        if base.stat.S_ISDIR(metadata.st_mode):
            target.mkdir(mode=0o755, parents=True, exist_ok=True)
            os.chmod(target, 0o755)
            continue
        if not base.stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise base.ImageError(f"staging copy encountered non-regular file: {relative}")
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        shutil.copyfile(source, target, follow_symlinks=False)
        os.chmod(target, base.stat.S_IMODE(metadata.st_mode))
        source_digest, source_bytes = base.sha256_path(source, base.MAX_FILE_BYTES)
        target_digest, target_bytes = base.sha256_path(target, base.MAX_FILE_BYTES)
        if source_digest != target_digest or source_bytes != target_bytes:
            raise base.ImageError(f"normalized staging copy drifted: {relative}")
        files.append(relative.as_posix())
    for path in sorted(destination_root.rglob("*"), reverse=True):
        os.utime(path, ns=(0, 0), follow_symlinks=False)
    os.utime(destination_root, ns=(0, 0), follow_symlinks=False)
    return sorted(files)


base.bounded_command = bounded_command
base.normalize_copy = normalize_copy


def main(argv: list[str]) -> int:
    return base.main(argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
