"""Runs inside the sandboxed subprocess. This is the runtime enforcement layer.

Order matters: resource limits first (everything inherited is capped), then the audit hook,
then the generated tool executed exactly as returned. The hook cannot be uninstalled by the
code under test (CPython exposes no removal API), and it sees operations the AST pre-check
could not resolve, such as a path assembled at runtime.
"""

from __future__ import annotations

import json
import os
import resource
import signal
import sys
import time
from pathlib import Path
from typing import Any

BLOCKED_MARKER = "__ANVIL_BLOCKED__"
META_MARKER = "__ANVIL_META__"
FINAL_MARKER = "__ANVIL_FINAL__"


class FinalAnswerSignal(BaseException):
    """Raised when an agent code action calls `final_answer(...)`, mirroring smolagents."""

BANNED_IMPORTS = {
    "socket", "ssl", "subprocess", "multiprocessing", "pty", "ctypes", "httpx",
    "requests", "urllib", "urllib3", "aiohttp", "ftplib", "smtplib", "telnetlib",
}
NETWORK_MODULES = {"socket", "ssl", "http", "httpx", "requests", "urllib", "urllib3",
                   "aiohttp", "ftplib", "smtplib", "poplib", "imaplib", "telnetlib"}
PROCESS_EVENTS = {"os.system", "os.exec", "os.spawn", "os.fork", "subprocess.Popen"}
SOCKET_EVENTS = {
    "socket", "socket.connect", "socket.bind", "socket.listen", "socket.accept",
    "socket.sendto", "socket.getaddrinfo", "socket.gethostbyname",
}
# Deleting or renaming anything the run does not own is outside the granted blast radius.
MUTATION_EVENTS = {"os.remove", "os.rmdir", "os.rename", "os.replace", "os.chmod",
                   "os.link", "os.symlink", "os.mkdir", "os.makedirs", "os.truncate"}

_hook_active = False
ALLOW_NETWORK = False
WRITE_ROOTS: list[str] = []
SENSITIVE_READ_PREFIXES: list[str] = []
DENIED_IMPORTS: set[str] = set()
MEM_MB = 512
TOOL_PATH = ""


class SandboxBlocked(RuntimeError):
    """Raised into the code under test when runtime policy refuses an operation."""


def emit_blocked(call: str, reason: str, layer: str = "audit-hook") -> None:
    payload = {"call": call, "reason": reason, "layer": layer}
    sys.__stderr__.write(f"{BLOCKED_MARKER}{json.dumps(payload, default=str)}\n")
    sys.__stderr__.flush()


def _under(path: str, roots: list[str]) -> bool:
    real = os.path.realpath(path)
    return any(real == root or real.startswith(root.rstrip(os.sep) + os.sep) for root in roots)


def _is_write(mode, flags: int) -> bool:
    if isinstance(mode, str) and any(ch in mode for ch in ("w", "a", "x", "+")):
        return True
    base = flags & os.O_ACCMODE
    return base != os.O_RDONLY or bool(flags & getattr(os, "O_TMPFILE", 0))


def _library_roots() -> tuple[str, str]:
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    stdlib = os.path.realpath(os.path.dirname(os.__file__))
    site = os.path.realpath(str(Path(sys.executable).parent.parent / "lib" / version / "site-packages"))
    return stdlib, site


def _caller_frame():
    """The first frame that is neither importlib machinery nor a stdlib wrapper.

    `import subprocess; subprocess.run(...)` from the tool has to count as the tool acting,
    even though the audit event fires inside the stdlib's own `subprocess.py`. A call that
    originates in an installed library (matplotlib enumerating system fonts via `fc-list`,
    numpy dlopening its extensions) is that library's plumbing: the caller resolves to the
    library, so the hook allows it and the kernel policy is what guards the primitive.
    """
    stdlib, site = _library_roots()
    frame = sys._getframe(1)
    for _ in range(40):
        if frame is None:
            break
        filename = frame.f_code.co_filename or ""
        real = os.path.realpath(filename) if filename and not filename.startswith("<") else filename
        is_importlib = filename.startswith("<") or os.sep + "importlib" + os.sep in real
        is_third_party = site and (real == site or real.startswith(site + os.sep))
        is_stdlib_wrapper = (not is_third_party) and stdlib and real.startswith(stdlib + os.sep)
        if is_importlib or is_stdlib_wrapper:
            frame = frame.f_back
            continue
        return real
    return ""


def _called_from_tool() -> bool:
    return bool(TOOL_PATH) and _caller_frame() == TOOL_PATH


def audit_hook(event: str, args: tuple) -> None:
    """Refuse operations by capability, at the moment the operation actually happens."""
    if not _hook_active:
        return

    if event == "import":
        root = (str(args[0]) if args else "").split(".")[0]
        if root in DENIED_IMPORTS and _called_from_tool():
            if root in NETWORK_MODULES and not ALLOW_NETWORK:
                reason = "network denied by policy (capability not granted)"
            else:
                reason = f"{root} denied by policy"
            emit_blocked(f"import {root}", reason)
            raise SandboxBlocked(reason)
        return

    if event in SOCKET_EVENTS:
        if not ALLOW_NETWORK:
            reason = "network denied by policy (capability not granted)"
            emit_blocked("socket.socket()" if event == "socket" else event, reason)
            raise SandboxBlocked(reason)
        return

    if event in PROCESS_EVENTS:
        # Denied globally, not per-caller: CPython raises these particular audit events from
        # C with no Python caller frame, so the stack cannot be consulted reliably. The
        # trade is documented — a library's own subprocess attempt (matplotlib probing
        # `fc-list`) is refused too, which is why the font cache is pre-warmed outside.
        reason = "process creation denied by policy"
        emit_blocked(event if event != "os.exec" else "os.execv", reason)
        raise SandboxBlocked(reason)

    if event.startswith("ctypes"):
        # Libraries dlopen their own compiled extensions through ctypes; the tool may not
        # reach for arbitrary native functions. Scoped to the tool frame, like imports.
        if not _called_from_tool():
            return
        reason = "ctypes foreign-function calls denied by policy"
        emit_blocked(f"ctypes.{event.split('.', 1)[-1]}", reason)
        raise SandboxBlocked(reason)

    if event == "open":
        path = str(args[0]) if args else ""
        mode = args[1] if len(args) > 1 else None
        flags = args[2] if len(args) > 2 and isinstance(args[2], int) else 0
        if not path or path.startswith("<") or path in ("/dev/null", "/dev/stdout",
                                                        "/dev/stderr", "/dev/dtracehelper"):
            return
        if _is_write(mode, flags):
            if not _under(path, WRITE_ROOTS):
                reason = (f"write to '{path}' outside ALLOWED_WRITE_PATHS "
                          f"({', '.join(WRITE_ROOTS) or 'none'})")
                emit_blocked(f"open({path!r}, 'w')", reason)
                raise SandboxBlocked(reason)
        else:
            for prefix in SENSITIVE_READ_PREFIXES:
                if _under(path, [prefix]):
                    reason = f"sensitive path '{prefix}' not readable by policy"
                    emit_blocked(f"open({path!r})", reason)
                    raise SandboxBlocked(reason)
        return

    if event in MUTATION_EVENTS:
        target = str(args[0]) if args else ""
        follow = str(args[1]) if len(args) > 1 and isinstance(args[1], (str, bytes)) else target
        if _under(target, WRITE_ROOTS) and _under(follow, WRITE_ROOTS):
            return
        reason = (f"filesystem mutation of '{target}' outside ALLOWED_WRITE_PATHS "
                  f"({', '.join(WRITE_ROOTS) or 'none'})")
        emit_blocked(f"{event}({target!r})", reason)
        raise SandboxBlocked(reason)


def apply_limits(caps: dict) -> dict:
    """setrlimit before anything else. Returns what actually took effect."""
    cpu_s = int(caps["cpu_s"])
    mem_mb = int(caps["memory_mb"])
    fsize_mb = int(caps["file_size_mb"])
    nproc = int(caps["max_procs"])
    nofile = int(caps["max_fds"])
    applied = {}

    def try_set(which, soft, hard):
        try:
            resource.setrlimit(which, (soft, hard))
            applied[_RLIMIT_NAMES[which]] = {"soft": soft, "hard": hard}
            return True
        except (ValueError, OSError):
            return False

    # SIGXCPU at the soft limit, SIGKILL at the hard limit two seconds later.
    try:
        signal.signal(signal.SIGXCPU, signal.SIG_DFL)
    except (ValueError, OSError):
        pass
    try_set(resource.RLIMIT_CPU, cpu_s, cpu_s + 2)
    try_set(resource.RLIMIT_AS, mem_mb * 1024 * 1024, mem_mb * 1024 * 1024)
    try_set(resource.RLIMIT_DATA, mem_mb * 1024 * 1024, mem_mb * 1024 * 1024)
    try_set(resource.RLIMIT_FSIZE, fsize_mb * 1024 * 1024, fsize_mb * 1024 * 1024)
    try_set(resource.RLIMIT_NPROC, nproc, nproc)
    try_set(resource.RLIMIT_NOFILE, nofile, nofile)
    return applied


_RLIMIT_NAMES = {
    resource.RLIMIT_CPU: "RLIMIT_CPU",
    resource.RLIMIT_AS: "RLIMIT_AS",
    resource.RLIMIT_DATA: "RLIMIT_DATA",
    resource.RLIMIT_FSIZE: "RLIMIT_FSIZE",
    resource.RLIMIT_NPROC: "RLIMIT_NPROC",
    resource.RLIMIT_NOFILE: "RLIMIT_NOFILE",
}


def peak_rss_bytes() -> int:
    """ru_maxrss is bytes on macOS, kilobytes on Linux."""
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(raw) if sys.platform == "darwin" else int(raw) * 1024


def write_meta(payload: dict) -> None:
    sys.__stderr__.write(f"{META_MARKER}{json.dumps(payload, default=str)}\n")
    sys.__stderr__.flush()


def _traceback_text(limit: int = 2400) -> str:
    """The stack that reached the refused operation — this is what explains a block."""
    import traceback
    try:
        return "".join(traceback.format_exception(*sys.exc_info()))[-limit:]
    except Exception:
        return ""


def main() -> int:
    global _hook_active, ALLOW_NETWORK, WRITE_ROOTS, SENSITIVE_READ_PREFIXES
    global DENIED_IMPORTS, MEM_MB, TOOL_PATH

    with open(sys.argv[1], encoding="utf-8") as fh:
        job = json.load(fh)
    caps = job["caps"]
    ALLOW_NETWORK = bool(job.get("allow_network", False))
    WRITE_ROOTS = [os.path.realpath(p) for p in job.get("write_roots", [])]
    SENSITIVE_READ_PREFIXES = list(job.get("sensitive_reads", []))
    DENIED_IMPORTS = set(job.get("denied_imports", BANNED_IMPORTS))
    MEM_MB = int(caps["memory_mb"])

    started = time.monotonic()
    limits = apply_limits(caps)

    os.chdir(os.path.realpath(job["jail"]))
    sys.path[:] = [p for p in job.get("python_path", []) if os.path.isdir(p)]
    # No .pyc files: importing must not write anywhere outside the jail.
    sys.dont_write_bytecode = True
    os.environ.clear()
    os.environ.update(job.get("env", {}))

    code_path = os.path.realpath(job["code_path"])
    TOOL_PATH = code_path
    with open(code_path, encoding="utf-8") as fh:
        source = fh.read()

    sys.addaudithook(audit_hook)
    _hook_active = True

    exit_code = 0
    status = "success"
    error: str | None = None
    tb_text = ""
    namespace = {"__name__": "__main__", "__file__": code_path, "__builtins__": __builtins__}
    # What survives between agent actions is limited to JSON-serialisable values, because
    # each action is a fresh process. `final_answer` is injected the same way smolagents'
    # own executor exposes tools; the action source is still executed byte-for-byte.
    for key, value in (job.get("variables") or {}).items():
        if key != "_print_outputs":
            namespace[key] = value
    final_capture: dict[str, Any] = {}
    if job.get("inject_final_answer"):
        def final_answer(value=None, *args, **kwargs):
            final_capture["value"] = value
            sys.__stderr__.write(f"{FINAL_MARKER}{json.dumps({'value': repr(value)})}\n")
            sys.__stderr__.flush()
            raise FinalAnswerSignal(value)
        namespace["final_answer"] = final_answer

    try:
        compiled = compile(source, code_path, "exec")
        exec(compiled, namespace)
    except FinalAnswerSignal:
        status, exit_code = "final-answer", 0
    except SandboxBlocked as blocked:
        status, exit_code, error = "blocked", 97, str(blocked)
        tb_text = _traceback_text()
    except MemoryError as exc:
        status, exit_code = "killed", 96
        error = f"MemoryError: {exc}"
        tb_text = _traceback_text()
        emit_blocked("memory allocation",
                     f"memory limit {MEM_MB} MB exceeded", "rlimit")
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
        exit_code, status = code, ("success" if code == 0 else "failed")
        error = None if code == 0 else f"tool exited with code {code}"
    except BaseException as exc:
        status, exit_code = "failed", 95
        error = f"{type(exc).__name__}: {exc}"
        tb_text = _traceback_text()
    finally:
        _hook_active = False
        usage = resource.getrusage(resource.RUSAGE_SELF)
        write_meta({
            "status": status,
            "error": error,
            "traceback": tb_text,
            "finalAnswer": final_capture.get("value"),
            "exitCode": exit_code,
            "peakRssBytes": peak_rss_bytes(),
            "cpuUserS": round(usage.ru_utime, 4),
            "cpuSysS": round(usage.ru_stime, 4),
            "wallS": round(time.monotonic() - started, 3),
            "limitsApplied": limits,
        })
    return exit_code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException as fatal:
        write_meta({"status": "harness-error",
                    "error": f"{type(fatal).__name__}: {fatal}", "exitCode": 94})
        sys.exit(94)
