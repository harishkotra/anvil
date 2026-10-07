"""Execute a generated tool inside a locked-down subprocess and capture the whole trace.

Pipeline for every tool: AST pre-check -> jail layout -> kernel policy profile ->
rlimited + audit-hooked + kernel-confined execution -> resource accounting -> artifact
collection. Every refusal becomes a trace row carrying its exact reason string.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent.sandbox import isolation, policy
from agent.sandbox.tracer import (ARTIFACT, DONE, EXEC_START, FINAL_MARKER, INFO, KILLED,
                                  POLICY, RESOURCE, BLOCKED_MARKER, META_MARKER, Tracer)

WORKSPACE = Path(__file__).resolve().parents[2]
JAIL_ROOT = WORKSPACE / ".anvil" / "runs"
MPL_CACHE = WORKSPACE / ".anvil" / "mpl-cache"
SCRATCH_DIRS = (".tmp",)
CHILD = str(Path(__file__).resolve().parent / "child.py")
JAIL_KEEP_NAMES = {"artifacts", "tool.py", "job.json", ".mpl", *SCRATCH_DIRS}


def warm_font_cache() -> tuple[bool, str]:
    """Build matplotlib's font cache outside the sandbox.

    matplotlib shells out to `fc-list` when it has to discover system fonts, and process
    creation is denied inside the sandbox globally. Pre-warming removes the only legitimate
    reason a library would try to fork, instead of weakening the rule for it.
    """
    if MPL_CACHE.is_dir() and any(MPL_CACHE.glob("fontlist-*")):
        return True, f"reused {MPL_CACHE.name}"
    MPL_CACHE.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, MPLCONFIGDIR=str(MPL_CACHE))
    probe = ("from matplotlib import font_manager as fm; fm.fontManager; "
             "import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt; "
             "plt.figure()")
    try:
        proc = subprocess.run([sys.executable, "-c", probe], env=env, capture_output=True,
                              text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return False, "font cache build timed out"
    except OSError as exc:
        return False, f"font cache build failed to start: {exc}"
    if proc.returncode != 0:
        return False, (proc.stderr or "").strip()[:200]
    return True, f"built in {MPL_CACHE.name}"

# Never forwarded into the sandbox: a data tool has no business holding credentials.
ENV_SCRUB_PREFIXES = ("OPENAI", "API_KEY", "TOKEN", "SECRET", "AWS", "GH_", "GITHUB",
                      "HF_", "ANTHROPIC", "GOOGLE", "GEMINI", "AZURE", "DATABASE", "PG")


@dataclass
class SandboxConfig:
    timeout_s: int = 10
    memory_mb: int = 512
    cpu_s: int = 5
    file_size_mb: int = 64
    max_procs: int = 64
    max_fds: int = 256
    allow_network: bool = False
    allowed_read_paths: list[str] = field(default_factory=lambda: ["./data"])
    allowed_write_paths: list[str] = field(default_factory=lambda: ["./artifacts"])
    max_output_bytes: int = 200000
    granted_capabilities: list[str] = field(default_factory=list)
    requested_capabilities: list[str] = field(default_factory=list)

    @classmethod
    def from_settings(cls, settings: dict[str, Any] | None = None) -> "SandboxConfig":
        settings = settings or {}

        def num(key: str, default: int) -> int:
            try:
                return int(settings.get(key, default))
            except (TypeError, ValueError):
                return default

        grants = [str(c) for c in settings.get("approvedCapabilities", [])]
        return cls(
            timeout_s=num("timeoutS", 10),
            memory_mb=num("memoryMb", 512),
            cpu_s=num("cpuS", 5),
            file_size_mb=num("fileSizeMb", 64),
            max_procs=num("maxProcs", 64),
            max_fds=num("maxFds", 256),
            allow_network=bool(settings.get("allowNetwork", False)) or "network" in grants,
            allowed_read_paths=list(settings.get("allowedReadPaths") or ["./data"]),
            allowed_write_paths=list(settings.get("allowedWritePaths") or ["./artifacts"]),
            max_output_bytes=num("maxOutputBytes", 200000),
            granted_capabilities=grants,
            requested_capabilities=[str(c) for c in settings.get("requestedCapabilities", [])],
        )


@dataclass
class RunResult:
    run_id: str
    status: str
    exit_code: int | None
    stdout: str
    stderr: str
    resources: dict[str, Any]
    artifacts: list[dict[str, Any]]
    trace: list[dict[str, Any]]
    blocked: list[dict[str, Any]]
    precheck: dict[str, Any]
    isolation_level: str
    jail: str
    duration_ms: int
    killed_by: str | None = None
    action_final: Any = None
    unauthorised_writes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


def _real(raw: str | Path) -> Path:
    return Path(os.path.realpath(os.path.expanduser(str(raw))))


def abs_paths(raw: list[str], base: Path) -> list[Path]:
    """Configured paths, resolved once so every layer compares like with like."""
    out = []
    for item in raw:
        candidate = Path(os.path.expanduser(str(item)))
        if not candidate.is_absolute():
            candidate = base / candidate
        out.append(_real(candidate))
    return out


def jail_write_dirs(jail: Path, configured: list[str]) -> list[Path]:
    """Materialise each ALLOWED_WRITE_PATHS entry inside the jail.

    The setting has to actually move the boundary, so a tool writing to a configured path
    lands in a directory the kernel profile permits, and anything else does not.
    """
    dirs: list[Path] = []
    for raw in configured:
        text = str(raw).strip()
        if not text:
            continue
        candidate = Path(os.path.expanduser(text))
        parts = [part for part in candidate.parts if part != "."]
        if ".." in parts:
            continue  # traversal in a configured root is refused rather than resolved
        target = candidate if candidate.is_absolute() else jail.joinpath(*parts)
        target.mkdir(parents=True, exist_ok=True)
        dirs.append(_real(target))
    return dirs or [jail / "artifacts"]


def build_jail(run_id: str, source: str, read_roots: list[Path]) -> Path:
    """Ephemeral per-run cwd: `./data` and `./artifacts` resolve inside it."""
    jail = JAIL_ROOT / run_id
    if jail.exists():
        shutil.rmtree(jail, ignore_errors=True)
    jail.mkdir(parents=True)
    (jail / "artifacts").mkdir()
    for scratch in SCRATCH_DIRS:
        (jail / scratch).mkdir()
    for root in read_roots:
        link = jail / root.name
        if not link.exists() and root.exists():
            link.symlink_to(root, target_is_directory=True)
    (jail / "tool.py").write_text(source, encoding="utf-8")
    return jail


def _minimal_env(jail: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(jail),
        "MPLCONFIGDIR": str(MPL_CACHE),
        "TMPDIR": str(jail / ".tmp"),
        "PYTHONIOENCODING": "utf-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONWARNINGS": "ignore",
        "LC_ALL": "C",
        "LANG": "C.UTF-8",
    }


def child_python_path() -> list[str]:
    """The interpreter needs its stdlib plus the venv packages, and nothing else.

    The workspace itself is excluded so the tool cannot import our own policy module
    out from under us.
    """
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    site = Path(sys.executable).parent.parent / "lib" / version / "site-packages"
    stdlib = _real(Path(os.__file__).parent)
    keep: list[str] = []
    seen: set[str] = set()
    workspace_real = _real(WORKSPACE)
    for entry in sys.path:
        if not entry:
            continue
        real = _real(Path(entry))
        if str(real) in seen or not real.is_dir():
            continue
        if str(real) == str(workspace_real) or str(real).startswith(str(workspace_real) + os.sep):
            continue
        if str(real) == str(site) or str(real) == str(stdlib) or \
                str(real).startswith(str(stdlib) + os.sep):
            keep.append(str(real))
            seen.add(str(real))
    if site.is_dir() and str(_real(site)) not in seen:
        keep.insert(0, str(_real(site)))
    return keep


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except Exception:
            pass


def _pid_rss_mb(pid: int) -> float | None:
    try:
        out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True,
                             text=True, timeout=2).stdout.strip()
        return float(out) / 1024 if out else None
    except Exception:
        return None


def _watch(proc: subprocess.Popen, deadline: float, memory_mb: int, state: dict) -> None:
    """Wall-clock and resident-memory watchdog.

    macOS does not reliably enforce RLIMIT_AS, so the parent measures real RSS and kills
    the process group. Whatever the kernel refuses, the limit still bites.
    """
    while proc.poll() is None:
        if state.get("stopped"):
            return
        if time.monotonic() > deadline:
            state["killed_by"] = "timeout"
            _kill_group(proc)
            return
        observed = _pid_rss_mb(proc.pid)
        if observed is not None:
            state["peak_rss_mb_observed"] = max(state.get("peak_rss_mb_observed", 0.0), observed)
            if observed > memory_mb:
                state["killed_by"] = "memory"
                _kill_group(proc)
                return
        time.sleep(0.02)


def _collect_artifacts(write_dirs: list[Path], dest: Path) -> list[dict[str, Any]]:
    """Everything the run wrote under a configured write path, copied to artifacts/<runId>/."""
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    dest.mkdir(parents=True, exist_ok=True)
    for root in write_dirs:
        if not root.is_dir():
            continue
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            resolved = str(_real(path))
            if resolved in seen:
                continue
            seen.add(resolved)
            rel = path.relative_to(root)
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            items.append({"name": str(rel), "bytes": target.stat().st_size,
                          "type": _kind(target), "path": str(target.relative_to(WORKSPACE))})
    return items


def _kind(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp"}:
        return "image"
    if suffix in {".csv", ".tsv", ".parquet"}:
        return "table"
    if suffix in {".txt", ".log", ".md", ".json", ".py"}:
        return "text"
    return "binary"


def _split_markers(stderr: str) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
    """Lift the harness's own marker lines out of the child's stderr."""
    blocked, meta, kept = [], {}, []
    for line in stderr.splitlines():
        if line.startswith(BLOCKED_MARKER):
            try:
                blocked.append(json.loads(line[len(BLOCKED_MARKER):]))
            except json.JSONDecodeError:
                kept.append(line)
        elif line.startswith(META_MARKER):
            try:
                meta = json.loads(line[len(META_MARKER):])
            except json.JSONDecodeError:
                kept.append(line)
        elif line.startswith(FINAL_MARKER):
            try:
                meta["finalAnswer"] = json.loads(line[len(FINAL_MARKER):]).get("value")
            except json.JSONDecodeError:
                pass
        else:
            kept.append(line)
    return blocked, meta, "\n".join(kept).strip()


def _detect_unauthorised_writes(jail: Path, read_roots: list[Path], write_dirs: list[Path],
                                started_ns: int) -> list[str]:
    """Prove the boundary held: the read roots and the workspace stay untouched."""
    offenders: list[str] = []
    for root in read_roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.stat().st_mtime_ns > started_ns:
                offenders.append(f"{path} (modified inside a read-only root)")
    permitted = {str(directory) for directory in write_dirs}
    jail_real = _real(jail)
    if jail_real.is_dir():
        for stray in sorted(jail_real.iterdir()):
            if stray.name in JAIL_KEEP_NAMES or str(_real(stray)) in permitted:
                continue
            if any(stray.exists() and stray.samefile(root) for root in read_roots if root.exists()):
                continue
            offenders.append(f"{stray.name} (created outside ALLOWED_WRITE_PATHS)")
    for sensitive in ("/tmp/anvil-escape-write.txt", "/private/tmp/anvil-escape-write.txt"):
        if os.path.exists(sensitive):
            offenders.append(f"{sensitive} (escaped the jail)")
    return offenders


def run_tool(source: str, run_id: str, config: SandboxConfig, *, skip_precheck: bool = False,
             tracer: Tracer | None = None, label: str = "generated tool",
             inject_final_answer: bool = False,
             variables: dict[str, Any] | None = None) -> RunResult:
    """Run one tool through the full pipeline and return everything the UI needs."""
    trace = tracer or Tracer()
    report = isolation.detect()
    started_ns = time.time_ns()

    read_roots = abs_paths(config.allowed_read_paths, WORKSPACE)
    jail = build_jail(run_id, source, read_roots)
    warm_font_cache()
    write_dirs = jail_write_dirs(jail, config.allowed_write_paths)
    writable = [*write_dirs, *[jail / s for s in SCRATCH_DIRS], MPL_CACHE]

    effective = policy.Policy(
        allowed_read_roots=[_real(jail / root.name) for root in read_roots],
        allowed_write_roots=write_dirs,
        allow_network=config.allow_network,
        granted_capabilities=set(config.granted_capabilities),
        requested_capabilities=list(config.requested_capabilities),
        run_root=jail,
    )

    precheck = policy.PrecheckResult(accepted=True, findings=[], lines_checked=len(source.splitlines()))
    if skip_precheck:
        trace.add(POLICY, "static pre-check bypassed on purpose: this run exists to test the "
                          "runtime layers", accepted=None)
    else:
        trace.add(POLICY, f"static pre-check: {len(source.splitlines())} lines, "
                          f"{len(effective.granted_capabilities)} cap(s) granted")
        precheck = policy.precheck(source, effective)
        for finding in precheck.findings:
            trace.add_blocked(finding.rule, finding.reason, "pre-check", finding.line)
        trace.add(POLICY if precheck.accepted else KILLED,
                  "pre-check: accepted" if precheck.accepted
                  else f"pre-check: rejected, {len(precheck.findings)} finding(s)",
                  accepted=precheck.accepted,
                  findings=[f.to_dict() for f in precheck.findings])
        if not precheck.accepted:
            shutil.rmtree(jail, ignore_errors=True)
            return RunResult(
                run_id=run_id, status="blocked", exit_code=None, stdout="", stderr="",
                resources={}, artifacts=[], trace=trace.to_dicts(),
                blocked=[b.to_dict() for b in trace.blocked], precheck=precheck.to_dict(),
                isolation_level=report.level, jail=str(jail), duration_ms=trace.elapsed_ms(),
            )

    job = {
        "code_path": str(jail / "tool.py"),
        "jail": str(jail),
        "caps": {"cpu_s": config.cpu_s, "memory_mb": config.memory_mb,
                 "file_size_mb": config.file_size_mb, "max_procs": config.max_procs,
                 "max_fds": config.max_fds},
        "allow_network": config.allow_network,
        "write_roots": [str(p) for p in writable],
        "sensitive_reads": isolation.SENSITIVE_READ_PATHS,
        "denied_imports": sorted(policy.NETWORK_MODULES | policy.PROCESS_MODULES
                                 | policy.INTROSPECTION_MODULES),
        "python_path": child_python_path(),
        "env": _minimal_env(jail),
        "inject_final_answer": inject_final_answer,
        "variables": _json_safe_variables(variables),
    }
    job_path = jail / "job.json"
    job_path.write_text(json.dumps(job), encoding="utf-8")

    profile = isolation.render_seatbelt_profile(
        writable_roots=[str(p) for p in writable], read_only_roots=[str(p) for p in read_roots],
        allow_network=config.allow_network, deny_reads=isolation.SENSITIVE_READ_PATHS,
    ) if report.level == isolation.LEVEL_SEATBELT else None
    wrapped = isolation.build_exec_argv(
        report.level, python=sys.executable, child_args=[CHILD, str(job_path)],
        writable_roots=[str(p) for p in writable], allow_network=config.allow_network,
        profile=profile)

    withheld = sum(1 for k in os.environ
                   if any(k.upper().startswith(p) for p in ENV_SCRUB_PREFIXES))
    trace.add(EXEC_START,
              f"exec start: isolation={report.level}, cwd={jail.name}, "
              f"{len(job['env'])} env vars ({withheld} credential-shaped vars withheld)",
              isolation=report.level, cpuLimitS=config.cpu_s, memLimitMb=config.memory_mb,
              timeoutS=config.timeout_s, envVars=len(job["env"]), envWithheld=withheld)

    started = time.monotonic()
    proc = subprocess.Popen(wrapped, cwd=str(jail), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            start_new_session=True, close_fds=True)
    state: dict[str, Any] = {"killed_by": None, "peak_rss_mb_observed": 0.0}
    deadline = started + config.timeout_s
    watchdog = threading.Thread(target=_watch, args=(proc, deadline, config.memory_mb, state),
                                daemon=True)
    watchdog.start()
    try:
        stdout, stderr = proc.communicate(timeout=config.timeout_s + 5)
    except subprocess.TimeoutExpired:
        state["killed_by"] = state.get("killed_by") or "timeout"
        _kill_group(proc)
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except Exception:
            stdout, stderr = "", ""
    finally:
        state["stopped"] = True
        watchdog.join(timeout=1)
    wall = time.monotonic() - started

    blocked_records, meta, clean_stderr = _split_markers(stderr or "")
    # The child's own traceback explains a block better than an empty stderr ever could.
    if meta.get("traceback") and not clean_stderr:
        clean_stderr = meta["traceback"]
    for record in blocked_records:
        trace.add_blocked(record.get("call", "?"), record.get("reason", ""),
                          record.get("layer", "audit-hook"))

    exit_code = proc.returncode
    if state.get("killed_by") == "timeout":
        trace.add(KILLED, "killed: timeout", timeoutS=config.timeout_s, wallS=round(wall, 3))
    elif state.get("killed_by") == "memory":
        observed = state.get("peak_rss_mb_observed", 0.0)
        trace.add(KILLED, f"killed: memory limit (observed peak {observed:.1f} MB "
                          f"> {config.memory_mb} MB cap)", capMb=config.memory_mb,
                  observedMb=round(observed, 1))
    elif exit_code in (-signal.SIGXCPU, 128 + signal.SIGXCPU):
        trace.add(KILLED, "killed: cpu limit (RLIMIT_CPU sent SIGXCPU)", exitCode=exit_code)
    elif exit_code == -signal.SIGKILL:
        trace.add(KILLED, "killed: SIGKILL (hard resource limit)", exitCode=exit_code)
    elif exit_code == 96:
        trace.add(KILLED, "killed: memory limit raised MemoryError inside the sandbox",
                  exitCode=exit_code)

    peak_mb = max(meta.get("peakRssBytes", 0) / (1024 * 1024),
                  state.get("peak_rss_mb_observed", 0.0))
    trace.add(RESOURCE,
              f"resources: peak RSS {peak_mb:.1f} MB (cap {config.memory_mb} MB), "
              f"CPU {meta.get('cpuUserS', 0.0):.2f}s user + {meta.get('cpuSysS', 0.0):.2f}s sys "
              f"(cap {config.cpu_s}s), wall {wall:.2f}s (cap {config.timeout_s}s)",
              peakRssMb=round(peak_mb, 2), cpuUserS=meta.get("cpuUserS"),
              cpuSysS=meta.get("cpuSysS"), wallS=round(wall, 3), capRssMb=config.memory_mb,
              capCpuS=config.cpu_s, limitsApplied=meta.get("limitsApplied"))
    trace.add(INFO, f"exit code {exit_code}", exitCode=exit_code)

    dest = WORKSPACE / "artifacts" / run_id
    artifacts = _collect_artifacts(write_dirs, dest)
    for item in artifacts:
        trace.add(ARTIFACT, f"artifact: {item['name']} ({item['bytes']} bytes)", **item)
    if not artifacts:
        trace.add(ARTIFACT, "artifacts: none written", count=0)

    status = _status(exit_code, state, meta, trace)
    trace.add(DONE, f"run {status}: {len(trace.blocked)} blocked call(s), "
                    f"{len(artifacts)} artifact(s)", status=status,
              blockedCount=len(trace.blocked), artifactCount=len(artifacts))

    unauthorised = _detect_unauthorised_writes(jail, read_roots, write_dirs, started_ns)
    shutil.rmtree(jail, ignore_errors=True)

    return RunResult(
        run_id=run_id, status=status, exit_code=exit_code,
        stdout=_truncate(stdout or "", config.max_output_bytes),
        stderr=_truncate(clean_stderr, config.max_output_bytes),
        resources={"peakRssMb": round(peak_mb, 2), "cpuUserS": meta.get("cpuUserS"),
                   "cpuSysS": meta.get("cpuSysS"), "wallS": round(wall, 3),
                   "capRssMb": config.memory_mb, "capCpuS": config.cpu_s,
                   "capTimeoutS": config.timeout_s, "childStatus": meta.get("status"),
                   "limitsApplied": meta.get("limitsApplied"), "killedBy": state.get("killed_by")},
        artifacts=artifacts, trace=trace.to_dicts(), blocked=[b.to_dict() for b in trace.blocked],
        precheck=precheck.to_dict(), isolation_level=report.level, jail=str(jail),
        duration_ms=int(wall * 1000), killed_by=state.get("killed_by"),
        action_final=meta.get("finalAnswer"),
        unauthorised_writes=unauthorised,
    )


def _status(exit_code: int | None, state: dict, meta: dict, trace: Tracer) -> str:
    if state.get("killed_by") == "timeout":
        return "timeout"
    if state.get("killed_by") == "memory":
        return "killed"
    if meta.get("status") == "blocked":
        return "blocked"
    if any(b.layer in {"kernel", "audit-hook", "rlimit"} for b in trace.blocked):
        return "blocked"
    if exit_code == 0:
        return "success"
    if exit_code in (-signal.SIGXCPU, 128 + signal.SIGXCPU, -signal.SIGKILL, 137):
        return "killed"
    return {"95": "failed", "96": "killed", "97": "blocked"}.get(str(exit_code), "failed")


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated at MAX_OUTPUT_BYTES={limit}]"


def _json_safe_variables(variables: dict[str, Any] | None) -> dict[str, Any]:
    """Only values that can cross a process boundary by JSON make it into the action."""
    out: dict[str, Any] = {}
    for key, value in (variables or {}).items():
        try:
            json.dumps(value)
        except (TypeError, ValueError):
            continue
        out[key] = value
    return out


def run_sandboxed_action(code: str, run_id: str, config: SandboxConfig,
                         state: dict[str, Any] | None = None,
                         tracer: Tracer | None = None) -> RunResult:
    """Run one of the agent's own code actions through the identical sandbox path."""
    return run_tool(code, run_id, config, tracer=tracer, label="agent code action",
                    inject_final_answer=True, variables=state)
