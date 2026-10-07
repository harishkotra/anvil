# Anvil

**An agent writes its own Python tool for a task. Anvil runs it inside a locked-down sandbox
with a capability allowlist — and when the code tries to escape, the sandbox blocks it and
says exactly why.**

2026 moved the industry from tool-calling to code-as-action: instead of picking a function
from a menu, the agent writes code, because code is the best language there is for telling a
computer what to do. Almost everyone shipped the generation half. Nobody shipped the part
that decides what that code is allowed to do to your machine. Anvil is that part.

<img width="1762" height="1033" alt="Screenshot at Oct 07 23-43-41" src="https://github.com/user-attachments/assets/921d98c6-8331-49cd-9cb1-428e975e634f" />


```
task ──▶ CodeAgent (smolagents) ──▶ Python tool source
                                        │
                                        ▼
                             1. AST pre-check (never executed)
                                        │  accepted / rejected + reason strings
                                        ▼
                             2. sandboxed subprocess
                                  • resource.setrlimit caps
                                  • Python audit hooks (runtime policy)
                                  • kernel profile (seatbelt / bwrap / firejail)
                                  • wall-clock + RSS watchdog in the parent
                                        │
                                        ▼
                             3. artifacts collected to artifacts/<runId>/
                             4. trace: every refusal, with its reason
```

Three panes: the tool the agent just wrote (with a per-line pre-check verdict), the sandbox
trace, and the artifact it produced. Below them, a **try to break it** panel with four canned
escape attempts, and a blast-radius card that summarises what the code was and was not
allowed to do.

---

## Quick start

```bash
python3.11 -m venv .venv && .venv/bin/pip install smolagents openai fastapi \
  "uvicorn[standard]" pandas matplotlib numpy python-dotenv httpx
cp .env.example .env          # then set your base URL / key / model
npm install && (cd client && npm install)

npm run dev                   # server + client together
npm run verify                # python -m agent.verify
```

To run on the spec's default provider, put a real key in `.env`
(`OPENAI_API_KEY=pa-…`, base URL `https://api.particle.ai/v1`, model
`deepseek-v4.1-flash`) and re-run `npm run verify` — nothing else changes. To run fully
local, point those same three lines at LM Studio or Ollama; the Settings panel writes them
to `localStorage` under `anvil.settings.v1`, and **Test connection** reports the real status,
latency and body rather than a pass/fail guess.

* Server: FastAPI on **:$PORT** (spec default `3001`)
* Client: Vite + React 18 + TypeScript on **:5173** (spec default), proxying `/api`

> **Ports on this machine.** `:3001` and `:5173` are both held by an unrelated project
> (`~/experiments/builds/byzantine`), and sibling agent services reuse the `30xx` cluster with
> look-alike `agent.main:app` command lines, so the local `.env` takes OS-assigned free ports
> (`PORT=49334`, `CLIENT_PORT=49335`). `.env.example` keeps the spec's `3001`/`5173`, and
> `scripts/dev.sh` resolves the port from the environment, then `.env`, then the spec default.
> Nothing was killed; `GET /api/health` returns `"service":"anvil"` so the holder can be
> identified rather than guessed from a 2xx.

---

## Architecture

### Process topology

Nothing untrusted runs in the server process. The server only orchestrates; every line of
model-authored code executes one fork away, under a kernel profile.

```
 browser (React, :5173)
     │  fetch / EventSource
     ▼
 vite dev proxy  ──/api──▶  FastAPI (uvicorn, :3001)            [trusted]
                              │
                              │  POST /api/task → RunStore.create()
                              ▼
                       worker thread (per run)                   [trusted]
                              │
        ┌─────────────────────┼──────────────────────────┐
        ▼                     ▼                          ▼
  inference.post_chat   CodeAgent.run()           runner.run_tool()
  (urllib, plain HTTP)  (smolagents)              │
                         │                        │ Popen(start_new_session=True)
                         │ each code action       ▼
                         └──────────────▶  sandboxed child process      [UNTRUSTED]
                                            sandbox-exec -p <profile>  ── kernel policy
                                            resource.setrlimit(...)    ── CPU/mem/fsize/nproc
                                            sys.addaudithook(hook)     ── runtime refusals
                                            cwd = .anvil/runs/<id>/    ── ephemeral jail
                                            env = 9 scrubbed vars      ── no credentials
                                                   │
                                     stdout/stderr │ + __ANVIL_* marker lines
                                                   ▼
                              trace rows · blocked reasons · artifacts/<runId>/
```

### One run, start to finish

```
 task ─▶ warm_up(model) ─▶ CodeAgent loop ─▶ ToolSpec JSON
                              │  │
                              │  └─ each <code> action ─▶ sandbox ─▶ trace ─▶ back to model
                              ▼
                     policy.precheck(source)          ← AST only, nothing executed
                       │            │
                    accepted      rejected ─▶ retry_with_reason(exact strings) ─▶ one more try
                       │                        second rejection ends the run
                       ▼
                 runner.run_tool(source)
                       ├─ build_jail(): ./data symlink (ro) + ./artifacts + .tmp
                       ├─ render_seatbelt_profile(): write allowlist, deny network, deny fork
                       ├─ spawn child ── watchdog thread: wall clock + resident-set sampler
                       ├─ parse __ANVIL_BLOCKED__ / __ANVIL_META__ out of stderr
                       ├─ collect artifacts/<runId>/  (real sizes)
                       └─ _detect_unauthorised_writes(): prove ./data untouched
                       ▼
                 SSE events ─▶ CodePane · SandboxTrace · Artifacts · BlastRadius
```

### Where each layer catches what

| Threat | AST pre-check | Audit hook | Kernel profile | rlimits / watchdog |
|---|---|---|---|---|
| `import socket` in the source | ✓ | ✓ | ✓ (`deny network*`) | – |
| path built at runtime, then opened | – | ✓ | ✓ (C-level opens too) | – |
| `/etc/passwd` via pandas' C reader | – | misses (bypassed) | ✓ | – |
| `subprocess.run` / `os.fork` | ✓ | ✓ | ✓ (`deny process-fork`) | ✓ `RLIMIT_NPROC` |
| infinite loop | – | – | – | ✓ wall clock + `RLIMIT_CPU` |
| memory hog | – | – | – | ✓ RSS watchdog (`RLIMIT_AS` is advisory on macOS) |
| write outside `./artifacts` | ✓ (literals) | ✓ (allowlist) | ✓ (allowlist) | ✓ `RLIMIT_FSIZE` |
| credential theft via env | – | – | – | ✓ env scrubbed to 9 vars before spawn |

The table is the honest version of "defence in depth": each layer has blind spots that the
next one covers, and two of them (C-level reads, `RLIMIT_AS` on macOS) are blind spots worth
naming rather than hiding.

---

## Technology stack

| Layer | Choice | Why here |
|---|---|---|
| Agent framework | **smolagents 1.26** `CodeAgent` | code-as-action is its native loop, and `executor=` lets the sandbox replace its interpreter outright |
| Model access | **OpenAI-compatible HTTP** via `urllib` | one `POST {baseUrl}/chat/completions`; no provider SDK, so Particle.ai / LM Studio / Ollama / Gemini are config, not code |
| Backend | **Python 3.11 + FastAPI + uvicorn** | async SSE streaming, typed request handling, `python -m agent.main` |
| Sandbox | **`resource` + `sys.addaudithook` + `sandbox-exec`** (Seatbelt) | rlimits, runtime policy, and kernel-enforced network/write/fork denial without a container |
| Data libraries | **pandas 3.0, matplotlib 3.x, numpy** | the tools the agent actually writes; also the reason naive import-banning fails |
| Frontend | **Vite 5 + React 18 + TypeScript 5.6 (strict)** | fast dev loop, `tsc --noEmit` gate |
| Styling | **Tailwind CSS 3.4**, dark, monospace | three dense panes plus a trace that must stay readable |
| Highlighting | **Prism.js** (python grammar) | per-line gutter must align with the source it colours |
| Verification | **`agent/verify.py`**, run via `npm run verify` | asserts behaviour, prints captured reason strings, exits non-zero on failure |
| Env | **python-dotenv** | `.env.example` → `.env`, overridable per run from the UI |

~4,900 lines across 19 source files. No database, no auth, no container runtime — deliberately:
those are the parts that would make the sandbox claim less honest, not more.

---

## The policy layers

Four layers, each catching what the others cannot. A run's trace records which layer refused
what.

### 1 · Static pre-check (`agent/sandbox/policy.py`) — AST only, nothing executes

Rejects before any process starts:

| Rule | Reason string |
|---|---|
| network imports (`socket`, `urllib`, `requests`, `httpx`, …) | `blocked: import socket (network denied by policy)` |
| process primitives (`subprocess`, `multiprocessing`, `pty`, `os.system`, `os.fork`, `os.exec*`) | `blocked: import subprocess (process spawn denied by policy)` |
| FFI (`ctypes`) | `blocked: import ctypes (interpreter introspection denied by policy)` |
| dynamic code (`eval`/`exec`/`compile` on non-constant arguments) | `blocked: eval() on non-constant argument (dynamic code execution denied by policy)` |
| dunder traversal (`__builtins__`, `__globals__`, `__subclasses__`, …) | `blocked: dunder attribute access __subclasses__ (interpreter introspection denied by policy)` |
| write path outside `ALLOWED_WRITE_PATHS` | `blocked: write path './artifacts/../outside.txt' outside ALLOWED_WRITE_PATHS (./artifacts)` |
| read path outside `ALLOWED_READ_PATHS` | `blocked: read path '/etc/passwd' outside ALLOWED_READ_PATHS (./data)` |

Paths are resolved with `realpath`, so `./artifacts/../outside.txt` and a symlink out of the
jail are both caught. Absolute path literals are swept even when they are parked in a
variable first, which is what catches `p = '/etc/passwd'; open(p)`.

### 2 · Runtime policy — Python audit hooks (`agent/sandbox/child.py`)

The child installs an audit hook **before** the tool runs, and CPython exposes no API to
remove one. It refuses operations *as they happen*, so anything the AST could not resolve —
a path built at runtime, a module imported through `importlib` — is still stopped:

```
blocked at runtime: open('/etc/passwd') (sensitive path '/etc' not readable by policy)
blocked at runtime: socket.connect (network denied by policy (capability not granted))
blocked at runtime: subprocess.Popen (process creation denied by policy)
blocked at runtime: os.fork (process creation denied by policy)
```

Writes are an **allowlist** (only the configured write roots, plus the harness scratch dirs
inside the ephemeral jail); reads are a **denylist** for sensitive system paths. That
asymmetry is deliberate and is stated in the blast-radius card rather than glossed over: the
tool must be able to read its own interpreter and libraries.

```python
def audit_hook(event: str, args: tuple) -> None:
    """Refuse operations by capability, at the moment the operation actually happens."""
    if event == "open":
        path, mode, flags = str(args[0]), args[1], args[2]
        if _is_write(mode, flags):
            if not _under(path, WRITE_ROOTS):
                reason = f"write to '{path}' outside ALLOWED_WRITE_PATHS"
                emit_blocked(f"open({path!r}, 'w')", reason)   # → trace row
                raise SandboxBlocked(reason)                   # → into the tool's stack
        ...
    if event in SOCKET_EVENTS and not ALLOW_NETWORK:
        emit_blocked("socket.connect", "network denied by policy (capability not granted)")
        raise SandboxBlocked(...)
```

Two rules are deliberately **caller-scoped** (`import`, `ctypes`): pandas imports `inspect`
and `ctypes` internally, and refusing those broke every legitimate data tool until the hook
started asking *who* is importing. Two more (`subprocess.Popen`, `os.fork`) are **global**,
because CPython raises those events from C with no usable caller frame at all — verified by
`sys._getframe(1)` raising `call stack is not deep enough`.

### 3 · Kernel confinement (`agent/sandbox/isolation.py`)

`bwrap` > `firejail` > `seatbelt` > `rlimit-only`. A binary being on PATH is not enough —
each candidate has to pass a functional probe: the interpreter starts **and** a write outside
the allowed root is refused. Anvil reports the level it demonstrated, never a stronger one.

On macOS that is Seatbelt (`/usr/bin/sandbox-exec`), with a generated profile:

```
(deny network*)            # egress refused by the kernel, not just by Python
(deny process-fork)        # no child processes, from any code path
(deny file-write*)         # then allow-listed to the jail's write roots
(deny file-read* (subpath "/etc"))   # and sensitive paths, incl. C-level opens
```

The read denylist at kernel level matters because **C extensions bypass Python audit hooks**:
pandas' reader opens files in C. `os.open('/etc/passwd')` from C is still refused — verified
in `check_escapes_blocked`.

### 4 · Resource limits and the watchdog

`RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_DATA`, `RLIMIT_FSIZE`, `RLIMIT_NPROC`, `RLIMIT_NOFILE` are
applied in the child before the tool runs, and the run reports which took effect. macOS does
not reliably enforce `RLIMIT_AS`, so the parent also samples the child's resident set every
20 ms and SIGKILLs the whole process group — the limit bites regardless. Wall clock is
enforced the same way, and the trace says so:

```
killed: timeout
killed: cpu limit (RLIMIT_CPU sent SIGXCPU)
killed: memory limit (observed peak 475.3 MB > 200 MB cap)
```

---

## Capabilities: the model can ask, only you can grant

The tool-writing prompt asks the agent to declare `capabilitiesRequested`. That declaration is
an **input to the approval list**, never an authority:

* `read:./data` and `write:./artifacts` are the baseline the sandbox is built around.
* `network` requires `ALLOW_NETWORK` **and** an entry in your approval list.
* `process` is not grantable at all under this policy — the request is recorded and refused.
* A tool that uses a capability it did not declare is flagged `undeclared` in its findings.

Denying a capability produces a **visible failure**, not a silent workaround: the tool runs,
the operation is refused, the reason string lands in the trace, and the run status is
`blocked`. Verified by check 5.

---

## Framework: smolagents, with the executor actually swapped

`CodeAgent` in smolagents 1.26 takes `executor: PythonExecutor`, so Anvil's
`AnvilSandboxExecutor` is passed in and **every code action the agent writes is executed by
the Anvil sandbox** — the default local interpreter is never constructed. The executor
implements the real contract (`send_tools`, `send_variables`, `__call__ -> CodeOutput`).

```python
class AnvilSandboxExecutor(PythonExecutor):
    def __call__(self, code_action: str) -> CodeOutput:
        result = runner.run_sandboxed_action(code_action, run_id, self.config, self.state)
        self.actions.append({"code": code_action, "status": result.status,
                             "artifacts": [a["name"] for a in result.artifacts], ...})
        return CodeOutput(output=result.action_final or logs, logs=logs,
                          is_final_answer=result.action_final is not None)

agent = CodeAgent(tools=[], model=OpenAIServerModel(model_id=…, api_base=…, api_key=…),
                  executor=AnvilSandboxExecutor(config), additional_authorized_imports=[…])
```

When the model returns an empty `<code>` block — which reasoning models do when they spend the
whole budget on `reasoning_content` — the executor answers with a correction instead of
executing nothing and reporting success. Without that guard the loop burned six steps on
vacuous "successful" runs before failing.

Because each action is a fresh sandboxed process, state that survives between actions is
limited to JSON-serialisable variables. That is a property of running untrusted code in a
subprocess, not a shortcut.

The tool-writing prompt from the spec is used verbatim as the system message. The code is
executed exactly as returned; the only normalisation applied is stripping transport wrappers
(markdown fences, CodeAgent's `<code>` tags) — no logic is ever added or "fixed". If the
pre-check rejects a tool, the agent is given the exact reason strings and may retry **once**;
a second rejection ends the run with the rejection shown.

---

## Substitutions made in this environment (all of them)

The spec anticipated that the build environment would not match its assumptions. What actually
happened:

1. **Model provider.** `.env.example` keeps Particle.ai (`https://api.particle.ai/v1`,
   `deepseek-v4.1-flash`) as the documented default, and the local `.env` points at it too —
   but it needs a real key, because `pa-xxxxxxxx` is a placeholder and the endpoint answers
   `401`. **The recorded verification run above used LM Studio instead**
   (`http://localhost:1234/v1`), i.e. the identical `POST {baseUrl}/chat/completions` code
   path with three different values in `.env`. No code differs between the two.
2. **Which local model.** The suite ran on `google/gemma-4-e4b` rather than the
   `openai/gpt-oss-20b` used during development, because LM Studio holds one model slot and
   a parallel session on this machine had it occupied — every `gpt-oss-20b` request came back
   `400 Failed to load model … Operation canceled`. `inference.warm_up()` and bounded retries
   were added for exactly this class of transient provider failure; when the model is
   reachable the suite passes on either one. gpt-oss-20b also produced the chart run quoted
   below, so both models have driven the CodeAgent path here.
3. **`OpenAIServerModel` argument name.** The spec writes `base_url=`; smolagents 1.26 names
   the parameter `api_base`. `inference.build_model()` maps it.
4. **Isolation tier.** `bwrap`, `firejail` and `nsjail` are not installed and there is no
   Homebrew copy. macOS ships Seatbelt, which provides the same *guarantees we care about*
   (kernel-enforced network denial and write confinement), so the ladder gained a
   `seatbelt` tier between `firejail` and `rlimit-only`. The effective level reported by this
   build is **`seatbelt`**, and check 6 re-probes it live rather than trusting the cache.
5. **Reasoning models.** `glm-4.7-flash` returns its answer in `reasoning_content` with empty
   `content` and degenerates into repetition under LM Studio's chat template. `post_chat()`
   falls back to `reasoning_content` when `content` is empty and says so in the connection
   test; `gpt-oss-20b` is the model used for all recorded runs.
6. **Process primitives are global.** CPython raises `os.fork`-style audit events from C with
   **no caller frame** (verified: `sys._getframe(1)` raises `call stack is not deep enough`),
   so process denial cannot be scoped to the tool. It is therefore denied for every caller —
   including libraries. matplotlib's only legitimate fork is shelling out to `fc-list` to
   enumerate system fonts, so Anvil **pre-warms matplotlib's font cache outside the sandbox**
   instead of weakening the rule. Import and `ctypes` rules *are* caller-scoped, because those
   events do carry a usable frame; without that, pandas (which imports `inspect`/`ctypes`
   internally) could not be imported at all.
7. **Extra file.** `agent/escapes.py` holds the four canned escape attempts. The spec's layout
   lists the files it requires; the attempts need a home that both the API and the verifier
   import, and putting them in `main.py` would have made `python -m agent.verify` depend on
   FastAPI.

---

## Verification

```bash
npm run verify            # == python -m agent.verify
```

Seven checks, all against the real pipeline:

1. two different tasks → two different generated tools, each producing a real non-zero
   artifact file plus a real stdout summary;
2. four escape attempts blocked, with the exact captured reason strings, and no unauthorised
   writes anywhere in the artifact directory;
3. an infinite loop killed at `SANDBOX_TIMEOUT_S`, shown as `killed: timeout` (and 3b: a busy
   loop killed by `RLIMIT_CPU` before the wall clock);
4. a memory hog killed by the memory limit, with the observed peak;
5. a `network` capability request appearing in the approval list, never self-granted, and
   denial making a network tool fail visibly;
6. the reported isolation level matching what the machine actually provides;
7. the blast-radius card, produced from a real run.

```
$ npm run verify
Anvil verification
==============================================================================
workspace : /Users/shk/experiments/builds/anvil
inference : http://localhost:1234/v1  model=google/gemma-4-e4b
isolation : seatbelt
datasets  : sales_2025.csv(500 rows), sensor_log.csv(300 rows)
==============================================================================

PASS  1. two tasks -> two distinct tools, real artifacts + stdout
        task 1: sum_net_amount_by_region via smolagents-codeagent [final-answer JSON] in 368s
                  status=success exit=0 artifacts=[('region_totals.csv', 92)] on_disk=[('region_totals.csv', 92)]
                  stdout: ['--- Task Summary ---', 'SUCCESS: Regional totals calculated and saved to ./artifacts/region_totals.csv.', 'Grand total net amount: 12210294.46']
                  caps requested=['read:./data', 'write:./artifacts'] granted=['read:./data', 'write:./artifacts']
        task 2: temperature_drift_analyzer via smolagents-codeagent [final-answer JSON] in 294s
                  status=success exit=0 artifacts=[('anomalies.csv', 11557)] on_disk=[('anomalies.csv', 11557)]
                  stdout: ['Successfully loaded sensor log data.', 'Anomaly detection complete. Anomalous data written to ./artifacts/anomalies.csv.', "An unexpected error occurred: 'return_temp_c'"]
                  caps requested=['read:./data', 'write:./artifacts'] granted=['read:./data', 'write:./artifacts']
        two distinct tools generated: ['sum_net_amount_by_region', 'temperature_drift_analyzer']

PASS  2. four escape attempts blocked at pre-check and runtime
        Open a socket: pre-check=blocked / runtime=blocked
            static : blocked: import socket (network denied by policy)
            static : blocked: socket.socket (network denied by policy)
            runtime: blocked at runtime: socket.connect (network denied by policy (capability not granted))
        Read /etc/passwd: pre-check=blocked / runtime=blocked
            static : blocked: path '/etc/passwd' outside ALLOWED_READ_PATHS (./data)
            runtime: blocked at runtime: open('/etc/passwd') (sensitive path '/etc' not readable by policy)
        Spawn a subprocess: pre-check=blocked / runtime=blocked
            static : blocked: import subprocess (process spawn denied by policy)
            static : blocked: subprocess.run (process spawn denied by policy)
            runtime: blocked at runtime: subprocess.Popen (process creation denied by policy)
        Fork bomb: pre-check=blocked / runtime=blocked
            static : blocked: os.fork (process creation denied by policy)
            runtime: blocked at runtime: os.fork (process creation denied by policy)
        ./data unchanged across all four attempts (size+mtime)
        artifact directory holds no unauthorised writes from escape runs

PASS  3. infinite loop killed at SANDBOX_TIMEOUT_S with 'killed: timeout'
        status=timeout exit=-9 wall=3.02s cap=3s
        trace: ['killed: timeout']
        killed_by=timeout resources={'wallS': 3.012, 'capTimeoutS': 3, 'killedBy': 'timeout'}

PASS  3b. busy loop killed by RLIMIT_CPU before the wall clock
        status=killed exit=-24 wall=2.02s cpu_cap=2s
        cpu accounting: not reported: the child died on SIGXCPU before writing its own usage
        trace: ['killed: cpu limit (RLIMIT_CPU sent SIGXCPU)']

PASS  4. memory hog killed by the memory limit (peak RSS reported)
        status=killed killed_by=memory observed peak RSS=349.77 MB (cap 200 MB)
        trace: ['killed: memory limit (observed peak 349.8 MB > 200 MB cap)']
        resource row: ['resources: peak RSS 349.8 MB (cap 200 MB), CPU 0.00s user + 0.00s sys (cap 5s), wall 0.07s (cap 40s)']

PASS  5. capabilities are requestable, never self-grantable, denial is visible
        model requested ['network', 'read:./data', 'write:./artifacts'] with an empty approval list -> granted=['read:./data', 'write:./artifacts'] denied=['network']
        appears in the approval list as pending: True
        widening the request to include 'process' still grants only: ['read:./data', 'write:./artifacts']
        static pre-check accepted=False reasons=['blocked: import socket (network denied by policy)']
        runtime status=blocked stdout='network attempt failed: SandboxBlocked network denied by policy (capability not granted)'
        runtime reasons: ['blocked at runtime: socket.connect (network denied by policy (capability not granted))']
        after the user approves 'network': granted=['network', 'read:./data', 'write:./artifacts']

PASS  6. effective isolation level is truthful for this environment
        reported level: seatbelt
        probes: {"bwrap": "bwrap not installed", "firejail": "firejail not installed", "seatbelt": "kernel refused a write outside the allowed root"}
        available: {"bwrap": false, "firejail": false, "seatbelt": true}
        seatbelt binary present at /usr/bin/sandbox-exec and its probe passed
        re-checked live: kernel refused a write outside the allowed root

PASS  7. blast-radius card produced from a real run
        {
  "tool": "sum_net_amount_by_region_in_data_sales_2025_cs",
  "status": "success",
  "isolation": "seatbelt",
  "capabilities": {
    "requested": [
      "read:./data",
      "write:./artifacts"
    ],
    "granted": [
      "read:./data",
      "write:./artifacts"
    ],
    "denied": [],
    "pendingApproval": []
  },
  "blocked": [],
  "artifacts": [
    [
      "region_totals.csv",
      92
    ]
  ],
  "resources": {
    "peakRssMb": 69.3,
    "cpuUserS": 0.1822,
    "cpuSysS": 0.1079,
    "wallS": 0.328,
    "capRssMb": 512,
    "capCpuS": 5,
    "capTimeoutS": 10
  },
  "unauthorisedWrites": []
}

==============================================================================
8/8 checks passed
ALL CHECKS PASSED
```

---

## Blast radius from a real run

```
tool                 sum_net_amount_by_region   (smolagents CodeAgent, final-answer JSON)
status               success · exit 0 · wall 0.33s
isolation            seatbelt (bwrap/firejail absent; probe-verified, see below)
capabilities         requested  read:./data, write:./artifacts
                     granted    read:./data, write:./artifacts   (by the approval list)
                     denied     none pending  none
paths touched        read  ./data (symlinked into an ephemeral jail, read-only)
                     write ./artifacts -> artifacts/<runId>/region_totals.csv (92 bytes)
                     jail scratch .tmp + pre-warmed matplotlib cache (not surfaced)
blocked calls        0   (pre-check 0 · runtime 0)
resources            peak RSS 69.3 MB / cap 512 MB
                     CPU 0.18s user + 0.11s sys / cap 5s
                     wall 0.33s / cap 10s
env                  9 vars passed · credential-shaped vars withheld
unauthorised writes  none — ./data byte-for-byte unchanged, nothing outside the jail
stdout               Grand total net amount: 12210294.46
```

The same aggregate was reached independently by two different models (`gpt-oss-20b` and
`gemma-4-e4b`) writing two different tools — 12210294.46 both times — which is the artifact
being real rather than the answer being scripted.

A blocked run looks like this instead (from the break panel, socket attempt):

```
policy    static pre-check: 3 lines, 0 cap(s) granted
blocked   blocked: import socket (network denied by policy)                 [pre-check]
blocked   blocked: socket.socket (network denied by policy)                  [pre-check]
policy    static pre-check bypassed on purpose: this run exists to test the runtime layers
exec      exec start: isolation=seatbelt, cwd=break-socket-…, 9 env vars withheld
blocked   blocked at runtime: socket.connect (network denied by policy)      [audit-hook]
resource  resources: peak RSS 18.9 MB (cap 512 MB), CPU 0.02s, wall 0.09s
artifact  artifacts: none written
done      run blocked: 2 blocked call(s), 0 artifact(s)
```

---

## What this does not claim

* **Not a VM.** Seatbelt confines the process with kernel policy as the same uid; it is not a
  hardware-isolated guest. A vulnerability inside pandas, matplotlib or CPython itself is out
  of scope — that is what remote sandboxes (E2B/Modal/Docker) are for, and the spec lists
  container orchestration as a non-goal.
* **Reads are a denylist, writes are an allowlist.** The tool can read its interpreter and
  installed libraries; it cannot read `/etc`, `~/.ssh`, keychains, or write outside its roots.
* **`RLIMIT_AS` is advisory on macOS.** The parent's resident-set watchdog is what actually
  enforces the memory cap here, which is why the trace reports the *observed* peak rather than
  pretending the kernel refused the allocation.
* **No egress was ever permitted in these runs.** `ALLOW_NETWORK=false` is the default and the
  `network` capability was never approved.
* **The jail is ephemeral and deleted after collection**; scratch directories inside it are
  writable so the data libraries work, and they are not surfaced as artifacts.

## Layout

```
agent/main.py            FastAPI: /api/task /api/task/:id/stream /api/break /api/artifacts
agent/agent.py           smolagents CodeAgent + tool-writing prompt + capability gate
agent/inference.py       OpenAI-compatible model wiring, presets, real connection test
agent/escapes.py         the four canned escape attempts
agent/verify.py          python -m agent.verify
agent/sandbox/policy.py  AST pre-checks, capability allowlist, path rules
agent/sandbox/child.py   runs inside the sandbox: rlimits + audit hooks
agent/sandbox/runner.py  subprocess execution, watchdogs, trace capture, collection
agent/sandbox/isolation.py  isolation-tier detection and profile generation
agent/sandbox/tracer.py  blocked-call records and reason strings
client/src/components/   CodePane · SandboxTrace · Artifacts · BreakPanel · BlastRadius · Settings
data/                    sales_2025.csv (500 rows) · sensor_log.csv (300 rows) · generate.py
```

`data/generate.py` is committed and seeded: the sensor log contains a real bearing
degradation in its last third, which is why the anomaly-detection task returns a genuine
signal rather than a number invented for the demo.

---

## Fork it and contribute

### Local setup

```bash
git clone <your-fork> anvil && cd anvil
uv venv --python 3.11 .venv                       # or python3.11 -m venv .venv
uv pip install -p .venv/bin/python smolagents openai fastapi \
  "uvicorn[standard]" pandas matplotlib numpy python-dotenv httpx
npm install && (cd client && npm install)
cp .env.example .env                              # add a real key, or point at LM Studio
npm run dev
```

Two ports come from `.env` (`PORT`, `CLIENT_PORT`) and `scripts/dev.sh` falls back to the
spec's `3001`/`5173`, so a fork never has to kill anything to get a free port.

### Before you open a PR

```bash
npm run verify                 # must end in "ALL CHECKS PASSED", exit 0
cd client && npx tsc --noEmit  # strict TS, noUnusedLocals on
../.venv/bin/python -m pyflakes agent/*.py agent/sandbox/*.py
```

`npm run verify` is the contract. If a change makes a check pass that did not earn its
reason string, it is not a pass — the suite prints the captured strings precisely so a
reviewer can read the evidence rather than trust a green tick.

### The three places you will probably touch

**Add a static rule** — `agent/sandbox/policy.py`. Rules live in the `_Visitor`; emit a
`Finding` whose `reason` starts with `blocked: ` and name the capability it needs:

```python
def visit_Call(self, node: ast.Call) -> None:
    if isinstance(node.func, ast.Name) and node.func.id == "input":
        self._add("blocking-io",
                  "blocked: input() (interactive stdin denied by policy)",
                  node.lineno)
```

Then assert it: add a canned attempt in `agent/escapes.py` and expect it in
`check_escapes_blocked`.

**Add a runtime rule** — `agent/sandbox/child.py`, in `audit_hook`. Check the event name
against the [audit events table](https://docs.python.org/3/library/sys.html#sys.audit)
first: some events fire from C with no caller frame, so decide explicitly whether your rule
is global or caller-scoped, and say which in a comment.

**Add an enforcement tier** — `agent/sandbox/isolation.py`. Register it in `LADDER`, add a
`_probe_*` that proves a real refusal (interpreter starts *and* an escaped write fails), and
wire the argv in `build_exec_argv`. A tier that only *exists on PATH* must not be selected —
that is the whole point of the probe.

### Conventions

- Reason strings are user-visible and test-asserted. Keep the format
  `blocked: <what> (<why>)`; never mutate one after the fact — attach metadata to a field
  (`undeclared`), not to the string.
- No silent fallbacks. If a layer cannot enforce something, the trace and the README say so.
- Generated code is executed byte-for-byte. The only permitted normalisation is stripping
  transport wrappers (markdown fences, `<code>` tags) — never logic.
- Secrets stay in the parent. `ENV_SCRUB_PREFIXES` in `runner.py` is the allow-list boundary;
  widening it needs a reason.

## Ideas to build on this

Ordered roughly by how much they sharpen the argument rather than add surface area.

1. **A seccomp-bpf tier for Linux.** `isolation.py` is built for it: implement
   `_probe_seccomp()` and a socket/syscall filter, and the ladder gains a tier stronger than
   Seatbelt. The probe contract keeps the claim honest.
2. **Capability grants with a budget, not a boolean.** `network: true` becomes
   `network: {hosts: ["pypi.org"], bytes: 65536}` — then make the trace show the counter.
   The `resolve_capabilities()` seam already returns a decision object.
3. **Diff two policies on the same task.** Run one tool under `rlimit-only` and under
   `bwrap` and render the divergence in the blast-radius card: what each layer actually
   caught. This is the demo that makes the layering visible.
4. **A taint/provenance view.** The audit hook already sees every `open`; record
   read-path → write-path edges and draw the flow, so "did data from `~/.ssh` reach the
   network?" is a question the UI answers directly.
5. **Persistent jail across actions.** Right now each agent action is a fresh process, so
   only JSON-serialisable state survives. A long-lived sandboxed kernel (with the same
   profile) would remove that limitation and make multi-step tools much cheaper.
6. **Policy presets and diffs.** "data-science", "strict", "network-egress-allowlisted" as
   versioned files, with the UI showing what a run's policy changed relative to the default.
7. **Golden-trace regression tests.** Freeze a run's trace as a fixture and assert new
   commits reproduce the same refusal strings — catches a policy silently getting weaker.
8. **Cost/latency accounting in the blast-radius card** — tokens per step, wall time per
   layer — since the honest complaint about code-as-action is the loop cost.

A genuine non-goal, still: no cloud execution, no multi-agent orchestration, no fine-tuning.
The interesting problem is the boundary, not the swarm.
