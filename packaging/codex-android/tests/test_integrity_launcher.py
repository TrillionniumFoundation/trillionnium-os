from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "packaging/codex-android/launcher/codex-integrity-launcher.c"
RUNTIME_SOURCE = r"""
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

int main(int argc, char **argv) {
  struct rlimit core;
  const char *expected = getenv("P01_EXPECTED_ARGV0");
  if (argc != 3 || expected == NULL || strcmp(argv[0], expected) != 0 ||
      strcmp(argv[1], "alpha") != 0 || strcmp(argv[2], "beta") != 0 ||
      getenv("P01_ENV_MARKER") == NULL ||
      strcmp(getenv("P01_ENV_MARKER"), "preserved") != 0 ||
      prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
      getrlimit(RLIMIT_CORE, &core) != 0 || core.rlim_cur != 0 ||
      core.rlim_max != 0 || fcntl(3, F_GETFD) < 0 ||
      (fcntl(3, F_GETFD) & FD_CLOEXEC) != 0) {
    return 41;
  }
  for (int descriptor = 4; descriptor < 64; descriptor++) {
    errno = 0;
    if (fcntl(descriptor, F_GETFD) >= 0 || errno != EBADF) {
      return 42;
    }
  }
  printf("p01-runtime-ok:%ld\n", (long)getpid());
  return 0;
}
"""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@unittest.skipUnless(shutil.which("cc"), "host C compiler unavailable")
class CodexIntegrityLauncherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.runtime_source = self.root / "runtime.c"
        self.runtime = self.root / "codex.real"
        self.tool = self.root / "trillionnium-agent-system-api"
        self.launcher = self.root / "codex-launcher"
        self.runtime_source.write_text(RUNTIME_SOURCE)
        subprocess.run(
            ["cc", "-std=c17", "-O2", str(self.runtime_source), "-o", str(self.runtime)],
            check=True,
        )
        self.runtime.chmod(0o755)
        self.tool.write_bytes(b"measured system api fixture\n")
        self.tool.chmod(0o755)
        definitions = [
            f'-DTRILLIONNIUM_CODEX_RUNTIME_PATH="{self.runtime}"',
            f'-DTRILLIONNIUM_SYSTEM_API_TOOL_PATH="{self.tool}"',
            f'-DTRILLIONNIUM_CODEX_RUNTIME_SHA256="{sha256(self.runtime)}"',
            f'-DTRILLIONNIUM_SYSTEM_API_TOOL_SHA256="{sha256(self.tool)}"',
            "-DTRILLIONNIUM_CODEX_REQUIRE_ACCESSIBILITY_TOOL=0",
            f"-DTRILLIONNIUM_EXPECTED_OWNER_UID={os.getuid()}",
            f"-DTRILLIONNIUM_EXPECTED_OWNER_GID={os.getgid()}",
            f"-DTRILLIONNIUM_CODEX_UID={os.getuid()}",
            f"-DTRILLIONNIUM_CODEX_GID={os.getgid()}",
            "-DTRILLIONNIUM_CODEX_REQUIRE_EMPTY_GROUPS=0",
            "-DTRILLIONNIUM_INTEGRITY_LAUNCHER_TEST=1",
        ]
        subprocess.run(
            [
                "cc",
                "-std=c17",
                "-Wall",
                "-Wextra",
                "-Werror",
                *definitions,
                str(SOURCE),
                "-o",
                str(self.launcher),
            ],
            check=True,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_launcher(self, *arguments: str, pass_fd: bool = False) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment.update(
            {
                "P01_EXPECTED_ARGV0": str(self.runtime),
                "P01_ENV_MARKER": "preserved",
            }
        )
        descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC) if pass_fd else -1
        try:
            return subprocess.run(
                [str(self.launcher), *arguments],
                env=environment,
                pass_fds=(() if descriptor < 0 else (descriptor,)),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def test_verify_only_accepts_exact_measured_files(self) -> None:
        result = self.run_launcher("--verify-only")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_exec_preserves_argv_and_environment_but_closes_untrusted_fds(self) -> None:
        result = self.run_launcher("alpha", "beta", pass_fd=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith("p01-runtime-ok:"), result.stdout)

    def test_final_runtime_preserves_launcher_pid(self) -> None:
        environment = dict(os.environ)
        environment.update(
            {
                "P01_EXPECTED_ARGV0": str(self.runtime),
                "P01_ENV_MARKER": "preserved",
            }
        )
        process = subprocess.Popen(
            [str(self.launcher), "alpha", "beta"],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        launcher_pid = process.pid
        stdout, stderr = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0, stderr)
        self.assertEqual(stdout, f"p01-runtime-ok:{launcher_pid}\n")

    def test_runtime_digest_drift_fails_before_exec(self) -> None:
        with self.runtime.open("ab") as stream:
            stream.write(b"drift")
        self.runtime.chmod(0o755)
        result = self.run_launcher("alpha", "beta")
        self.assertEqual(result.returncode, 125)
        self.assertIn("measured executable contract failed", result.stderr)

    def test_tool_symlink_and_mode_drift_are_rejected(self) -> None:
        original = self.root / "system-api.real"
        self.tool.rename(original)
        self.tool.symlink_to(original)
        symlink = self.run_launcher("--verify-only")
        self.assertEqual(symlink.returncode, 125)

        self.tool.unlink()
        original.rename(self.tool)
        self.tool.chmod(0o775)
        mode = self.run_launcher("--verify-only")
        self.assertEqual(mode.returncode, 125)


if __name__ == "__main__":
    unittest.main()
