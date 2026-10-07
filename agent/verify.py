"""Anvil's verification suite: `python -m agent.verify`.

Every claim the README makes is asserted here against the real pipeline — the real model,
the real sandbox, the real files on disk. Reason strings are printed as captured, and the
process exits non-zero if any check fails.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent import agent as agent_module
from agent import escapes, inference
from agent.sandbox import isolation, policy, runner
from agent.sandbox.runner import SandboxConfig

WORKSPACE = Path(__file__).resolve().parents[1]
DATA = WORKSPACE / "data"
ARTIFACTS = WORKSPACE / "artifacts"
CANARIES = ["/tmp/anvil-escape-write.txt", "/private/tmp/anvil-escape-write.txt",
            str(Path.home() / ".ssh" / "anvil-escape")]

TASKS = [
    "Sum net_amount by region in ./data/sales_2025.csv, write the result to "
    "./artifacts/region_totals.csv and print the grand total",
    "Find the machines whose return_temp_c drifts upward in ./data/sensor_log.csv, write "
    "./artifacts/anomalies.csv and print the mean temperature of the first and last 100 samples",
]


@dataclass
class Check:
    name: str
    passed: bool
    details: list[str] = field(default_factory=list)

    def line(self) -> str:
        head = f"{'PASS' if self.passed else 'FAIL'}  {self.name}"
        return head + "\n" + "\n".join(f"        {d}" for d in self.details)


def _settings(overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    from agent.main import DEFAULT_SETTINGS

    settings = dict(DEFAULT_SETTINGS)
    settings.update(overrides or {})
    return settings


def _config(**overrides: Any) -> SandboxConfig:
    config = SandboxConfig.from_settings(_settings(overrides.get("settings")))
    for key, value in overrides.items():
        if key != "settings" and hasattr(config, key):
            setattr(config, key, value)
    return config


def _fresh_artifact_runs() -> set[str]:
    return {p.name for p in ARTIFACTS.iterdir() if p.is_dir()} if ARTIFACTS.is_dir() else set()


# --- checks ----------------------------------------------------------------

def check_two_real_runs(settings: dict[str, Any], mode: str) -> Check:
    """1. Two different tasks produce two different tools, each with a real artifact."""
    details: list[str] = []
    ok = True
    produced: dict[str, dict[str, Any]] = {}

    for index, task in enumerate(TASKS):
        started = time.monotonic()
        generation, caps = agent_module.generate_tool(task, settings, _config(),
                                                      mode=mode, max_steps=6)
        if generation.spec is None:
            details.append(f"task {index + 1}: no tool produced ({generation.error})")
            ok = False
            continue
        spec = generation.spec
        config = _config()
        config.granted_capabilities = caps.get("granted", [])
        config.requested_capabilities = spec.capabilities_requested
        run_id = f"verify-{index + 1}-{int(time.time())}"
        result = runner.run_tool(spec.code, run_id, config, label=spec.tool_name)
        nonzero = [a for a in result.artifacts if a["bytes"] > 0]
        artifact_on_disk = [
            path for path in (ARTIFACTS / run_id).glob("*")
            if path.is_file() and path.stat().st_size > 0
        ] if (ARTIFACTS / run_id).is_dir() else []
        stdout_ok = bool(result.stdout.strip())
        task_ok = (result.status == "success" and nonzero and artifact_on_disk and stdout_ok
                   and result.precheck["accepted"])
        ok = ok and bool(task_ok)
        produced[spec.tool_name] = {"result": result, "spec": spec}
        details.append(
            f"task {index + 1}: {spec.tool_name} via {generation.mode}"
            f" [{generation.provenance}] in {time.monotonic() - started:.0f}s")
        details.append(
            f"          status={result.status} exit={result.exit_code} "
            f"artifacts={[(a['name'], a['bytes']) for a in result.artifacts]} "
            f"on_disk={[(p.name, p.stat().st_size) for p in artifact_on_disk]}")
        details.append(f"          stdout: {result.stdout.strip().splitlines()[:3]}")
        details.append(f"          caps requested={caps.get('requested')} granted={caps.get('granted')}")
        if not stdout_ok:
            details.append("          FAIL: no stdout summary")
        if not artifact_on_disk:
            details.append("          FAIL: no non-zero artifact written to artifacts/<runId>/")

    names = list(produced)
    codes = {p["spec"].code.strip() for p in produced.values()}
    if len(names) < 2:
        details.append(f"FAIL: only {len(names)} tool(s) produced")
        ok = False
    elif len(codes) < 2:
        details.append("FAIL: both tasks produced identical code")
        ok = False
    else:
        details.append(f"two distinct tools generated: {names}")
    return Check("1. two tasks -> two distinct tools, real artifacts + stdout", ok, details)


def check_escapes_blocked(settings: dict[str, Any]) -> Check:
    """2. Every escape attempt blocked, with the exact reason string captured."""
    details: list[str] = []
    ok = True
    before = _data_state()
    runs_before = _fresh_artifact_runs()

    for attempt in escapes.ATTEMPTS:
        config = _config()
        config.requested_capabilities = ["none"]
        static = policy.precheck(attempt.code, policy.Policy(
            allowed_read_roots=runner.abs_paths(config.allowed_read_paths, WORKSPACE),
            allowed_write_roots=runner.abs_paths(config.allowed_write_paths, WORKSPACE),
            allow_network=config.allow_network,
            granted_capabilities=set(config.granted_capabilities),
            requested_capabilities=["none"], run_root=WORKSPACE))
        # Second pass with the AST layer deliberately bypassed: the runtime layers answer.
        runtime = runner.run_tool(attempt.code, f"verify-break-{attempt.id}", config,
                                  skip_precheck=True, label=attempt.label)
        runtime_reasons = [b["display"] for b in runtime.blocked]
        kernel_reason = _kernel_reason(runtime)
        blocked_static = not static.accepted
        blocked_runtime = runtime.status in {"blocked", "killed", "timeout"} or bool(runtime.blocked)
        passed = blocked_static and blocked_runtime and not runtime.artifacts
        ok = ok and passed
        details.append(f"{attempt.label}: pre-check={'blocked' if blocked_static else 'MISSED'}"
                       f" / runtime={runtime.status}")
        for reason in (static.reasons or ["(none)"])[:2]:
            details.append(f"    static : {reason}")
        for reason in (runtime_reasons or ["(none)"])[:2]:
            details.append(f"    runtime: {reason}")
        if kernel_reason:
            details.append(f"    kernel : {kernel_reason}")
        if runtime.unauthorised_writes:
            details.append(f"    FAIL unauthorised writes: {runtime.unauthorised_writes}")
        if runtime.artifacts:
            details.append(f"    FAIL escape attempt wrote artifacts: {runtime.artifacts}")

    after = _data_state()
    if before != after:
        details.append(f"FAIL: ./data changed during escape attempts: {set(before) ^ set(after)}")
        ok = False
    else:
        details.append("./data unchanged across all four attempts (size+mtime)")
    for canary in CANARIES:
        if os.path.exists(canary):
            details.append(f"FAIL: escape canary exists at {canary}")
            ok = False
    new_runs = _fresh_artifact_runs() - runs_before
    stray = []
    for run_dir in new_runs:
        path = ARTIFACTS / run_dir
        stray += [str(p) for p in path.rglob("*") if p.is_file()]
    if stray:
        details.append(f"FAIL: escape runs wrote artifacts: {stray}")
        ok = False
    else:
        details.append("artifact directory holds no unauthorised writes from escape runs")
    return Check("2. four escape attempts blocked at pre-check and runtime", ok, details)


def _kernel_reason(runtime: Any) -> str:
    """A refusal the kernel produced rather than the audit hook."""
    for token in ("Operation not permitted", "PermissionError"):
        if token in (runtime.stderr or ""):
            return f"{token} surfaced from the sandbox profile (see stderr)"
    return ""


def check_timeout_killed() -> Check:
    """3. An infinite loop is killed at SANDBOX_TIMEOUT_S and shown as killed."""
    timeout_s = 3
    code = "import time\nprint('spinning', flush=True)\nwhile True:\n    time.sleep(0.05)\n"
    config = _config(timeout_s=timeout_s)
    started = time.monotonic()
    result = runner.run_tool(code, "verify-timeout", config, label="infinite loop")
    wall = time.monotonic() - started
    messages = [event["message"] for event in result.trace]
    shown = any(message == "killed: timeout" for message in messages)
    ok = result.status == "timeout" and shown and wall < timeout_s + 6
    details = [
        f"status={result.status} exit={result.exit_code} wall={wall:.2f}s cap={timeout_s}s",
        f"trace: {[m for m in messages if m.startswith('killed')] or '(no kill row)'}",
        f"killed_by={result.killed_by} resources={ {k: result.resources[k] for k in ('wallS', 'capTimeoutS', 'killedBy')} }",
    ]
    if not shown:
        details.append("FAIL: trace does not contain the row 'killed: timeout'")
    return Check("3. infinite loop killed at SANDBOX_TIMEOUT_S with 'killed: timeout'", ok, details)


def check_cpu_limit() -> Check:
    """3b. The CPU rlimit bites independently of the wall clock."""
    code = "x = 0\nwhile True:\n    x += 1\n"
    config = _config(cpu_s=2, timeout_s=25)
    started = time.monotonic()
    result = runner.run_tool(code, "verify-cpu", config, label="busy loop")
    wall = time.monotonic() - started
    messages = [event["message"] for event in result.trace]
    ok = result.status == "killed" and wall < 12
    cpu = result.resources.get("cpuUserS")
    cpu_note = ("not reported: the child died on SIGXCPU before writing its own usage"
                if cpu is None else f"user={cpu}s sys={result.resources.get('cpuSysS')}s")
    details = [f"status={result.status} exit={result.exit_code} wall={wall:.2f}s cpu_cap=2s",
               f"cpu accounting: {cpu_note}",
               f"trace: {[m for m in messages if m.startswith('killed')] or '(no kill row)'}"]
    return Check("3b. busy loop killed by RLIMIT_CPU before the wall clock", ok, details)


def check_memory_limit() -> Check:
    """4. A memory hog is killed by the memory limit, with the observed peak shown."""
    cap_mb = 200
    code = ("keep = []\n"
            "while True:\n"
            "    keep.append(bytearray(16 * 1024 * 1024))\n"
            "    print('allocated', len(keep), flush=True)\n")
    config = _config(memory_mb=cap_mb, timeout_s=40)
    result = runner.run_tool(code, "verify-memory", config, label="memory hog")
    peak = result.resources.get("peakRssMb") or 0
    kill_rows = [e["message"] for e in result.trace if e["message"].startswith("killed")]
    resource_rows = [e["message"] for e in result.trace if e["message"].startswith("resources")]
    ok = result.status == "killed" and result.killed_by == "memory" and peak > 0
    details = [f"status={result.status} killed_by={result.killed_by} observed peak RSS={peak} MB "
               f"(cap {cap_mb} MB)",
               f"trace: {kill_rows}",
               f"resource row: {resource_rows[:1]}"]
    if not ok:
        details.append(f"FAIL: expected a memory kill; got status={result.status} "
                       f"killed_by={result.killed_by}")
    return Check("4. memory hog killed by the memory limit (peak RSS reported)", ok, details)


def check_capability_denial() -> Check:
    """5. Network is requestable, never self-grantable, and denial fails visibly."""
    details: list[str] = []
    requested = ["network", "read:./data", "write:./artifacts"]

    # The model asks for network; the user has approved nothing.
    decision = agent_module.resolve_capabilities(requested, approved=[], allow_network=False)
    self_granted = "network" in decision["granted"]
    pending_ok = "network" in decision["pendingApproval"]
    details.append(f"model requested {requested} with an empty approval list -> "
                   f"granted={decision['granted']} denied={decision['denied']}")
    details.append(f"appears in the approval list as pending: {pending_ok}")

    # Even a request that claims everything cannot widen the grant.
    forged = agent_module.resolve_capabilities(requested + ["process"],
                                               approved=[], allow_network=False)
    forged_ok = not forged["granted"] or all(g.startswith(("read:", "write:"))
                                             for g in forged["granted"])
    details.append(f"widening the request to include 'process' still grants only: "
                   f"{forged['granted']}")

    # A tool that uses the network must fail visibly, not quietly succeed.
    code = ("import socket\n"
            "try:\n"
            "    s = socket.socket()\n"
            "    s.settimeout(2)\n"
            "    s.connect(('93.184.216.34', 80))\n"
            "    print('ESCAPED: reached the network')\n"
            "except Exception as exc:\n"
            "    print('network attempt failed:', type(exc).__name__, exc)\n"
            "    raise\n")
    config = _config()
    config.requested_capabilities = requested
    config.granted_capabilities = decision["granted"]
    static = policy.precheck(code, policy.Policy(
        allowed_read_roots=runner.abs_paths(config.allowed_read_paths, WORKSPACE),
        allowed_write_roots=runner.abs_paths(config.allowed_write_paths, WORKSPACE),
        allow_network=False, granted_capabilities=set(config.granted_capabilities),
        requested_capabilities=requested, run_root=WORKSPACE))
    runtime = runner.run_tool(code, "verify-network-denied", config, skip_precheck=True,
                              label="network tool")
    visible = runtime.status in {"blocked", "failed"} and "ESCAPED" not in runtime.stdout
    reasons = [b["display"] for b in runtime.blocked]
    details.append(f"static pre-check accepted={static.accepted} reasons={static.reasons[:1]}")
    details.append(f"runtime status={runtime.status} stdout={runtime.stdout.strip()[:90]!r}")
    details.append(f"runtime reasons: {reasons[:2]}")

    # And with the user approving it, the same tool is allowed to try (policy permits).
    granted_decision = agent_module.resolve_capabilities(requested, approved=["network"],
                                                        allow_network=True)
    approval_works = "network" in granted_decision["granted"]
    details.append(f"after the user approves 'network': granted={granted_decision['granted']}")

    ok = (not self_granted) and pending_ok and forged_ok and visible and approval_works
    if self_granted:
        details.append("FAIL: the model granted itself network access")
    if not visible:
        details.append("FAIL: a denied capability let a network tool succeed silently")
    return Check("5. capabilities are requestable, never self-grantable, denial is visible",
                 ok, details)


def check_isolation_truthful() -> Check:
    """6. The reported isolation level matches what this machine actually provides."""
    report = isolation.detect()
    details = [f"reported level: {report.level}", f"probes: {json.dumps(report.probes)}",
               f"available: {json.dumps(report.available)}"]
    binaries = {"bwrap": shutil.which("bwrap"), "firejail": shutil.which("firejail"),
                "sandbox-exec": shutil.which("sandbox-exec")}
    ok = True
    if report.level == isolation.LEVEL_RLIMIT:
        claimed_kernel = any("kernel" in value for value in report.enforced.values())
        if claimed_kernel:
            details.append("FAIL: rlimit-only but a kernel enforcement is claimed")
            ok = False
        else:
            details.append("rlimit-only, and no kernel enforcement is claimed")
    else:
        holder = {"bwrap": binaries["bwrap"], "firejail": binaries["firejail"],
                  "seatbelt": binaries["sandbox-exec"]}[report.level]
        if not holder:
            details.append(f"FAIL: reports {report.level} but its binary is not on PATH")
            ok = False
        else:
            details.append(f"{report.level} binary present at {holder} and its probe passed")
        if report.level == isolation.LEVEL_SEATBELT:
            verified = _seatbelt_actually_denies()
            if not verified:
                details.append("FAIL: seatbelt reported but an out-of-jail write succeeded")
                ok = False
            else:
                details.append("re-checked live: kernel refused a write outside the allowed root")
    return Check("6. effective isolation level is truthful for this environment", ok, details)


def _seatbelt_actually_denies() -> bool:
    """Independent confirmation, not the cached probe."""
    if sys.platform != "darwin" or not shutil.which("sandbox-exec"):
        return True
    root = Path("/tmp") / f"anvil-verify-{os.getpid()}"
    root.mkdir(parents=True, exist_ok=True)
    escaped = Path("/tmp") / f"anvil-verify-escape-{os.getpid()}.txt"
    escaped.unlink(missing_ok=True)
    profile = isolation.render_seatbelt_profile([str(root)], [], True, ["/etc"])
    probe = f"open({str(escaped)!r},'w').write('x')"
    import subprocess

    proc = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True,
                          timeout=30, env=dict(os.environ))
    direct_ok = proc.returncode == 0
    # Clear the canary the unsandboxed probe just wrote, so the next result is the
    # sandbox's, not the control's.
    escaped.unlink(missing_ok=True)
    wrapped = subprocess.run(["sandbox-exec", "-p", profile, sys.executable, "-c", probe],
                             capture_output=True, text=True, timeout=30)
    shutil.rmtree(root, ignore_errors=True)
    denied = wrapped.returncode != 0 and not escaped.exists()
    escaped.unlink(missing_ok=True)
    return denied and direct_ok


def check_blast_radius_card(settings: dict[str, Any]) -> Check:
    """Print the card from a real run so the README can quote it."""
    task = TASKS[0]
    generation, caps = agent_module.generate_tool(task, settings, _config(),
                                                  mode=settings.get("generationMode", "codeagent"),
                                                  max_steps=6)
    if generation.spec is None:
        return Check("7. blast-radius card from a real run", False,
                     [f"no tool produced: {generation.error}"])
    spec = generation.spec
    config = _config()
    config.granted_capabilities = caps.get("granted", [])
    config.requested_capabilities = spec.capabilities_requested
    result = runner.run_tool(spec.code, f"verify-card-{int(time.time())}", config,
                             label=spec.tool_name)
    card = {
        "tool": spec.tool_name,
        "status": result.status,
        "isolation": result.isolation_level,
        "capabilities": caps,
        "blocked": [b["display"] for b in result.blocked],
        "artifacts": [(a["name"], a["bytes"]) for a in result.artifacts],
        "resources": {k: result.resources[k] for k in
                      ("peakRssMb", "cpuUserS", "cpuSysS", "wallS", "capRssMb", "capCpuS",
                       "capTimeoutS")},
        "unauthorisedWrites": result.unauthorised_writes,
    }
    details = [json.dumps(card, indent=2)[:1400]]
    ok = result.status == "success" and not result.unauthorised_writes
    return Check("7. blast-radius card produced from a real run", ok, details)


def _data_state() -> dict[str, str]:
    state = {}
    for path in DATA.rglob("*"):
        if path.is_file():
            stat = path.stat()
            state[str(path)] = f"{stat.st_size}:{stat.st_mtime_ns}"
    return state


# --- runner ---------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify the Anvil sandbox and agent")
    parser.add_argument("--mode", default=os.getenv("ANVIL_VERIFY_MODE", "codeagent"),
                        choices=["codeagent", "direct"],
                        help="generation path used for the model-driven checks")
    parser.add_argument("--quick", action="store_true",
                        help="skip the two model-driven checks (offline smoke of the sandbox)")
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--model", default=None)
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--max-tokens", type=int, default=3000,
                        help="completion budget; small local models often have a context "
                             "window that cannot absorb the default")
    args = parser.parse_args(argv)

    settings = _settings({k: v for k, v in {
        "baseUrl": args.base_url, "model": args.model, "apiKey": args.api_key,
        "maxTokens": args.max_tokens}.items() if v is not None})
    settings["generationMode"] = args.mode

    print("Anvil verification")
    print("=" * 78)
    print(f"workspace : {WORKSPACE}")
    print(f"inference : {settings['baseUrl']}  model={settings['model']}")
    print(f"isolation : {isolation.detect().level}")
    print("datasets  : " + ", ".join(
        f"{path.name}({sum(1 for _ in path.open()) - 1} rows)"
        for path in sorted(DATA.glob("*.csv"))))
    print("=" * 78)

    probe = inference.test_connection(settings["baseUrl"], settings["apiKey"], settings["model"])
    if not probe["ok"]:
        print(f"\nNOTE  model endpoint probe: HTTP {probe.get('status')} "
              f"{str(probe.get('error'))[:120]}")

    checks: list[Check] = []
    if not args.quick:
        checks.append(check_two_real_runs(settings, args.mode))
    checks.append(check_escapes_blocked(settings))
    checks.append(check_timeout_killed())
    checks.append(check_cpu_limit())
    checks.append(check_memory_limit())
    checks.append(check_capability_denial())
    checks.append(check_isolation_truthful())
    if not args.quick:
        checks.append(check_blast_radius_card(settings))

    print()
    for check in checks:
        print(check.line())
        print()
    failed = [c.name for c in checks if not c.passed]
    print("=" * 78)
    print(f"{len(checks) - len(failed)}/{len(checks)} checks passed")
    if failed:
        print("FAILED:")
        for name in failed:
            print(f"  - {name}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
