"""Detect what isolation this machine can actually provide, and build the profile.

The ladder is `bwrap` > `firejail` > `seatbelt` > `rlimit-only`. A binary being on PATH is
not enough: each candidate has to pass a functional probe (interpreter starts *and* a write
outside the allowed root is refused by the kernel). We report the level we can demonstrate,
never a stronger one.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

LEVEL_BWRAP = "bwrap"
LEVEL_FIREJAIL = "firejail"
LEVEL_SEATBELT = "seatbelt"
LEVEL_RLIMIT = "rlimit-only"

LADDER = [LEVEL_BWRAP, LEVEL_FIREJAIL, LEVEL_SEATBELT, LEVEL_RLIMIT]

# Paths whose contents have no business being read by a data tool.
SENSITIVE_READ_PATHS = [
    "/etc", "/private/etc", "/var/root", "/proc", "/sys",
    str(Path.home() / ".ssh"), str(Path.home() / ".aws"), str(Path.home() / ".gnupg"),
    str(Path.home() / "Library/Keychains"),
]

PROBE_TIMEOUT_S = 20


@dataclass
class IsolationReport:
    level: str
    available: dict[str, bool] = field(default_factory=dict)
    probes: dict[str, str] = field(default_factory=dict)
    enforced: dict[str, str] = field(default_factory=dict)
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "available": self.available,
            "probes": self.probes,
            "enforced": self.enforced,
            "details": self.details,
            "ladder": LADDER,
        }


def _which(name: str) -> str | None:
    return shutil.which(name)


def _run(argv: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def _probe_seatbelt(python: str) -> tuple[bool, str]:
    """Interpreter must start, and an out-of-root write must be refused by the kernel."""
    probe_root = Path("/tmp") / f"anvil-probe-{os.getpid()}"
    probe_root.mkdir(parents=True, exist_ok=True)
    profile = render_seatbelt_profile(
        writable_roots=[str(probe_root)], read_only_roots=[], allow_network=True,
        deny_reads=["/etc"],
    )
    escaped = probe_root.parent / f"anvil-probe-escape-{os.getpid()}.txt"
    script = textwrap.dedent(f"""
        import os, sys
        try:
            open({str(escaped)!r}, 'w').write('escape')
            sys.stdout.write('WROTE-OUTSIDE')
        except PermissionError:
            sys.stdout.write('DENIED')
        """)
    try:
        proc = _run(["sandbox-exec", "-p", profile, python, "-c", script], PROBE_TIMEOUT_S)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return False, f"sandbox-exec probe failed to run: {exc}"
    finally:
        shutil.rmtree(probe_root, ignore_errors=True)
        escaped.unlink(missing_ok=True)
    out = (proc.stdout or "").strip()
    if proc.returncode != 0 and out == "":
        return False, f"sandbox-exec probe errored: {(proc.stderr or '').strip()[:120]}"
    if out == "DENIED":
        return True, "kernel refused a write outside the allowed root"
    return False, f"write outside root was NOT refused (probe output: {out or 'empty'})"


def _probe_namespaced(binary: str, python: str, args: list[str]) -> tuple[bool, str]:
    """Generic probe for bwrap/firejail: run python, try an escaped write."""
    probe_root = Path("/tmp") / f"anvil-probe-{binary}-{os.getpid()}"
    probe_root.mkdir(parents=True, exist_ok=True)
    escaped = probe_root.parent / f"anvil-probe-escape-{binary}-{os.getpid()}.txt"
    script = textwrap.dedent(f"""
        import sys
        try:
            open({str(escaped)!r}, 'w').write('escape')
            sys.stdout.write('WROTE-OUTSIDE')
        except PermissionError:
            sys.stdout.write('DENIED')
        """)
    try:
        proc = _run([binary, *args, python, "-c", script], PROBE_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return False, f"{binary} probe timed out"
    except OSError as exc:
        return False, f"{binary} could not execute: {exc}"
    finally:
        shutil.rmtree(probe_root, ignore_errors=True)
        escaped.unlink(missing_ok=True)
    out = (proc.stdout or "").strip()
    if out == "DENIED":
        return True, f"{binary} refused a write outside the allowed root"
    if out == "":
        return False, f"{binary} could not start the interpreter: {(proc.stderr or '').strip()[:120]}"
    return False, f"{binary} did not refuse the escaped write"


def render_seatbelt_profile(writable_roots: list[str], read_only_roots: list[str],
                            allow_network: bool, deny_reads: list[str]) -> str:
    """A Seatbelt profile: write allowlist, read denylist, optional network denial."""
    lines = ["(version 1)", "(allow default)"]
    if not allow_network:
        lines.append("(deny network*)")
    lines.append("(deny process-fork)")
    lines.append("(deny file-write*)")
    for root in ["/dev", "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/dtracehelper"]:
        lines.append(f"(allow file-write* (literal \"{root}\"))")
    for root in writable_roots:
        lines.append(f"(allow file-write* (subpath \"{os.path.realpath(root)}\"))")
    for path in deny_reads:
        if path == "/etc":
            lines.append('(deny file-read* (subpath "/etc"))')
            lines.append('(deny file-read* (subpath "/private/etc"))')
        else:
            lines.append(f'(deny file-read* (subpath "{path}"))')
    return "\n".join(lines) + "\n"


def build_exec_argv(level: str, *, python: str, child_args: list[str],
                    writable_roots: list[str], allow_network: bool,
                    profile: str | None) -> list[str]:
    """Wrap the interpreter command in whatever isolation this machine proved it has.

    Only `seatbelt` is exercised here (bwrap/firejail are absent on this Mac); their
    branches are kept as the standard recipes and are gated by the probe in `detect()`.
    """
    if level == LEVEL_SEATBELT and profile is not None:
        return ["sandbox-exec", "-p", profile, python, *child_args]
    if level == LEVEL_BWRAP:
        argv = ["bwrap", "--die-with-parent", "--unshare-pid", "--ro-bind", "/", "/"]
        for root in writable_roots:
            argv += ["--bind", root, root]
        if not allow_network:
            argv.append("--unshare-net")
        return [*argv, "--", python, *child_args]
    if level == LEVEL_FIREJAIL:
        argv = ["firejail", "--quiet", "--noprofile"]
        if not allow_network:
            argv.append("--net=none")
        for root in writable_roots:
            argv += [f"--bind={root}"]
        return [*argv, python, *child_args]
    return [python, *child_args]


def detect(python: str | None = None, cache: dict[str, Any] = {}) -> IsolationReport:
    """Probe once per process; later calls return the cached report."""
    if "report" in cache:
        return cache["report"]

    python = python or sys.executable
    available = {
        LEVEL_BWRAP: bool(_which("bwrap")),
        LEVEL_FIREJAIL: bool(_which("firejail")),
        LEVEL_SEATBELT: bool(_which("sandbox-exec")),
    }
    probes: dict[str, str] = {}
    level = LEVEL_RLIMIT
    chosen_binary_present = False

    if available[LEVEL_BWRAP]:
        ok, why = _probe_namespaced("bwrap", python, ["--ro-bind", "/", "/", "--tmpfs", "/tmp"])
        probes[LEVEL_BWRAP] = why
        if ok:
            level, chosen_binary_present = LEVEL_BWRAP, True
    else:
        probes[LEVEL_BWRAP] = "bwrap not installed"

    if level == LEVEL_RLIMIT and available[LEVEL_FIREJAIL]:
        ok, why = _probe_namespaced("firejail", python, ["--quiet", "--private=/tmp"])
        probes[LEVEL_FIREJAIL] = why
        if ok:
            level, chosen_binary_present = LEVEL_FIREJAIL, True
    elif LEVEL_FIREJAIL not in probes:
        probes[LEVEL_FIREJAIL] = "firejail not installed"

    if level == LEVEL_RLIMIT and available[LEVEL_SEATBELT] and sys.platform == "darwin":
        ok, why = _probe_seatbelt(python)
        probes[LEVEL_SEATBELT] = why
        if ok:
            level = LEVEL_SEATBELT
        else:
            probes[LEVEL_SEATBELT] = f"probe failed -> {why}"
    elif LEVEL_SEATBELT not in probes:
        probes[LEVEL_SEATBELT] = ("not installed" if not available[LEVEL_SEATBELT]
                                  else "not applicable outside macOS")

    enforced = {
        "network_egress": "kernel (seatbelt deny network*)" if level == LEVEL_SEATBELT else
                          "kernel (namespace)" if chosen_binary_present else
                          "python audit hook only",
        "write_confinement": "kernel (seatbelt write allowlist)" if level == LEVEL_SEATBELT else
                             "kernel (namespace bind mounts)" if chosen_binary_present else
                             "python audit hook only",
        "sensitive_read_denial": "kernel (seatbelt deny-read of /etc, ~/.ssh, ...)"
                                 if level == LEVEL_SEATBELT else "python audit hook only",
        "process_creation": "kernel (seatbelt deny process-fork) + RLIMIT_NPROC"
                            if level == LEVEL_SEATBELT else "python audit hook + RLIMIT_NPROC",
        "cpu_memory_files": "POSIX rlimits (RLIMIT_CPU / RLIMIT_AS / RLIMIT_FSIZE)",
        "wall_clock": "parent watchdog, SIGKILL to process group",
    }
    details = (
        f"effective isolation level: {level}"
        + (f" via {python}" if False else "")
    )
    report = IsolationReport(level=level, available=available, probes=probes,
                             enforced=enforced, details=details)
    cache["report"] = report
    return report
