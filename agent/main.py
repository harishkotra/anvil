"""FastAPI server: task orchestration, sandbox execution, escape attempts, artifacts.

The run pipeline is generate -> static pre-check -> (one retry carrying the rejection
strings) -> sandboxed execution -> artifact collection. Every step streams to the client.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from agent import agent as agent_module
from agent import escapes
from agent import inference
from agent.sandbox import isolation, policy, runner
from agent.sandbox.runner import SandboxConfig

WORKSPACE = Path(__file__).resolve().parents[1]
load_dotenv(WORKSPACE / ".env")

ARTIFACT_ROOT = WORKSPACE / "artifacts"
HISTORY_ROOT = WORKSPACE / ".anvil" / "history"


def env_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, default))
    except (TypeError, ValueError):
        return default


def env_bool(key: str, default: bool) -> bool:
    raw = os.getenv(key)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_list(key: str, default: list[str]) -> list[str]:
    raw = os.getenv(key)
    if not raw:
        return default
    return [item.strip() for item in raw.split(",") if item.strip()]


DEFAULT_SETTINGS: dict[str, Any] = {
    "baseUrl": os.getenv("OPENAI_BASE_URL", "https://api.particle.ai/v1"),
    "apiKey": os.getenv("OPENAI_API_KEY", ""),
    "model": os.getenv("MODEL", "deepseek-v4.1-flash"),
    "timeoutS": env_int("SANDBOX_TIMEOUT_S", 10),
    "memoryMb": env_int("SANDBOX_MEMORY_MB", 512),
    "cpuS": env_int("SANDBOX_CPU_S", 5),
    "allowNetwork": env_bool("ALLOW_NETWORK", False),
    "allowedReadPaths": env_list("ALLOWED_READ_PATHS", ["./data"]),
    "allowedWritePaths": env_list("ALLOWED_WRITE_PATHS", ["./artifacts"]),
    "maxOutputBytes": env_int("MAX_OUTPUT_BYTES", 200000),
    "approvedCapabilities": [],
    "generationMode": "codeagent",
    "maxTokens": 3000,
}


@dataclass
class Run:
    id: str
    task: str
    status: str = "queued"
    events: list[dict[str, Any]] = field(default_factory=list)
    spec: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    capabilities: dict[str, Any] | None = None
    generation: dict[str, Any] | None = None
    error: str | None = None
    created_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    _done: threading.Event = field(default_factory=threading.Event)

    def emit(self, kind: str, **payload: Any) -> None:
        self.events.append({"atMs": int((time.time() - self.created_at) * 1000),
                            "kind": kind, **payload})

    def finish(self, status: str, error: str | None = None) -> None:
        self.status = status
        self.error = error
        self.finished_at = time.time()
        self.emit("done", status=status, error=error)
        self._done.set()
        # Persist so a run survives a server restart and stays linkable via ?run=.
        try:
            HISTORY_ROOT.mkdir(parents=True, exist_ok=True)
            (HISTORY_ROOT / f"{self.id}.json").write_text(
                json.dumps(self.public(), default=str), encoding="utf-8")
        except OSError:
            pass

    def public(self) -> dict[str, Any]:
        return {"id": self.id, "task": self.task, "status": self.status, "spec": self.spec,
                "result": self.result, "capabilities": self.capabilities,
                "generation": self.generation, "error": self.error,
                "events": self.events, "createdAt": self.created_at,
                "finishedAt": self.finished_at}


class RunStore:
    def __init__(self) -> None:
        self._runs: dict[str, Run] = {}
        self._lock = threading.Lock()

    def create(self, task: str) -> Run:
        run = Run(id=time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6], task=task)
        with self._lock:
            self._runs[run.id] = run
        return run

    def get(self, run_id: str) -> Run | None:
        with self._lock:
            run = self._runs.get(run_id)
        if run:
            return run
        path = HISTORY_ROOT / f"{run_id}.json"
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        restored = Run(id=data["id"], task=data.get("task", ""))
        for attribute, key in [("status", "status"), ("spec", "spec"), ("result", "result"),
                               ("capabilities", "capabilities"), ("generation", "generation"),
                               ("error", "error"), ("events", "events"),
                               ("finished_at", "finishedAt"), ("created_at", "createdAt")]:
            if data.get(key) is not None:
                setattr(restored, attribute, data[key])
        with self._lock:
            self._runs[restored.id] = restored
        return restored

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            known = dict(self._runs)
        for path in HISTORY_ROOT.glob("*.json") if HISTORY_ROOT.is_dir() else []:
            if path.stem not in known:
                run = self.get(path.stem)
                if run:
                    known[run.id] = run
        return [{"id": r.id, "task": r.task, "status": r.status,
                 "artifacts": (r.result or {}).get("artifacts", []),
                 "createdAt": r.created_at} for r in
                sorted(known.values(), key=lambda r: r.created_at, reverse=True)]


STORE = RunStore()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Report the isolation this machine can actually demonstrate, before serving traffic."""
    report = isolation.detect()
    warmed, why = runner.warm_font_cache()
    print(f"[anvil] isolation: {report.level} | probes: {report.probes}")
    print(f"[anvil] matplotlib font cache {'ready' if warmed else 'NOT ready'}: {why}")
    yield


app = FastAPI(title="Anvil", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


def merged_settings(payload: dict[str, Any] | None) -> dict[str, Any]:
    """Client settings win, but the approval list is always the user's, never the model's."""
    settings = dict(DEFAULT_SETTINGS)
    if payload:
        settings.update({k: v for k, v in payload.items() if v is not None})
    settings["approvedCapabilities"] = [str(c) for c in
                                         settings.get("approvedCapabilities", []) or []]
    return settings


def sandbox_config_for(settings: dict[str, Any], granted: list[str]) -> SandboxConfig:
    merged = dict(settings)
    merged["approvedCapabilities"] = list(dict.fromkeys(list(settings.get(
        "approvedCapabilities", [])) + [c for c in granted if c.startswith("read:")
                                        or c.startswith("write:")]))
    config = SandboxConfig.from_settings(merged)
    config.granted_capabilities = list(dict.fromkeys(config.granted_capabilities + granted))
    return config


def execute_run(run: Run, settings: dict[str, Any]) -> None:
    """The whole pipeline for one task, emitting events as it goes."""
    try:
        run.status = "writing-code"
        run.emit("status", status="writing-code", message="agent is writing the tool",
                 isolation=isolation.detect().level)
        config = sandbox_config_for(settings, [])
        run.emit("generating", mode=settings.get("generationMode", "codeagent"),
                 model=settings.get("model", ""), baseUrl=settings.get("baseUrl", ""))
        generation, caps = agent_module.generate_tool(
            run.task, settings, config,
            on_event=lambda kind, detail: run.emit("agent-action", **detail),
            mode=settings.get("generationMode", "codeagent"),
            max_steps=int(settings.get("maxSteps", 6)))
        run.generation = {"mode": generation.mode, "provenance": generation.provenance,
                          "error": generation.error, "attempts": generation.attempts,
                          "actions": generation.actions,
                          "modelLatencyMs": generation.model_latency_ms}
        if generation.spec is None:
            run.finish("failed", generation.error or "the model returned no tool")
            return
        spec = generation.spec
        run.spec = spec.to_dict()
        run.capabilities = caps
        run.emit("spec", tool=spec.to_dict(), capabilities=caps)
        if caps.get("pendingApproval"):
            run.emit("capability-request", pending=caps["pendingApproval"],
                     requested=caps["requested"], granted=caps["granted"],
                     message="the model asked for capabilities it cannot grant itself")

        config = sandbox_config_for(settings, caps.get("granted", []))
        config.requested_capabilities = spec.capabilities_requested
        run.status = "running"
        run.emit("status", status="running", message=f"executing {spec.tool_name}")

        result = runner.run_tool(spec.code, run.id, config, label=spec.tool_name)

        if not result.precheck["accepted"]:
            run.emit("precheck-failed", reasons=result.precheck["reasons"],
                     findings=result.precheck["findings"],
                     message="pre-check rejected the tool; the agent gets one retry")
            retry, retry_caps = agent_module.retry_with_reason(
                run.task, settings, config, result.precheck["reasons"], generation,
                on_event=lambda kind, detail: run.emit("agent-action", **detail))
            run.capabilities = retry_caps or caps
            if retry.spec is None:
                run.result = result.to_dict()
                run.finish("pre-check-failed",
                           "retry produced no tool: " + (retry.error or "unparseable reply"))
                return
            spec = retry.spec
            run.spec = spec.to_dict()
            run.generation = {**(run.generation or {}), "mode": retry.mode,
                              "provenance": retry.provenance or "retry with rejection feedback",
                              "attempts": (run.generation or {}).get("attempts", []) +
                              [{"source": "retry", "reasons": result.precheck["reasons"]}]}
            run.emit("spec", tool=spec.to_dict(), capabilities=run.capabilities, retry=True)
            retry_config = sandbox_config_for(settings, (retry_caps or {}).get("granted", []))
            retry_config.requested_capabilities = spec.capabilities_requested
            result = runner.run_tool(spec.code, f"{run.id}-retry", retry_config,
                                     label=spec.tool_name)
            if not result.precheck["accepted"]:
                run.result = result.to_dict()
                run.finish("pre-check-failed",
                           "second rejection ends the run: " + "; ".join(result.precheck["reasons"]))
                return

        run.result = result.to_dict()
        status = {"success": "success", "blocked": "blocked", "timeout": "timeout-killed",
                  "killed": "killed"}.get(result.status, result.status)
        run.finish(status)
    except Exception as exc:  # surfaced to the UI rather than swallowed
        run.emit("error", message=f"{type(exc).__name__}: {exc}")
        run.finish("failed", f"{type(exc).__name__}: {exc}")


def run_in_background(run: Run, settings: dict[str, Any]) -> None:
    thread = threading.Thread(target=execute_run, args=(run, settings), daemon=True)
    thread.start()


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "service": "anvil", "workspace": str(WORKSPACE),
            "time": time.time()}


@app.get("/api/isolation")
def get_isolation() -> dict[str, Any]:
    return isolation.detect().to_dict()


@app.get("/api/settings/defaults")
def get_defaults() -> dict[str, Any]:
    return {"settings": DEFAULT_SETTINGS, "presets": inference.PRESETS}


@app.post("/api/models/test")
async def test_model(request: Request) -> JSONResponse:
    payload = await request.json()
    settings = merged_settings(payload)
    result = inference.test_connection(settings["baseUrl"], settings["apiKey"],
                                       settings["model"])
    return JSONResponse(result)


@app.post("/api/task")
async def create_task(request: Request) -> JSONResponse:
    payload = await request.json()
    task = str(payload.get("task", "")).strip()
    if not task:
        raise HTTPException(status_code=400, detail="task is required")
    settings = merged_settings(payload.get("settings"))
    run = STORE.create(task)
    run.emit("queued", task=task)
    run_in_background(run, settings)
    return JSONResponse({"runId": run.id, "status": run.status})


@app.get("/api/task/{run_id}")
def get_task(run_id: str) -> dict[str, Any]:
    run = STORE.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="unknown run")
    return run.public()


@app.get("/api/task/{run_id}/stream")
async def stream_task(run_id: str) -> StreamingResponse:
    run = STORE.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="unknown run")

    async def events():
        cursor = 0
        while True:
            batch = run.events[cursor:]
            cursor += len(batch)
            for event in batch:
                yield f"data: {json.dumps(event, default=str)}\n\n"
            if run.finished_at is not None and cursor >= len(run.events):
                yield f"event: end\ndata: {json.dumps({'status': run.status})}\n\n"
                return
            await asyncio.sleep(0.2)

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@app.get("/api/tasks")
def list_tasks() -> list[dict[str, Any]]:
    return STORE.list()


@app.post("/api/break")
async def break_it(request: Request) -> JSONResponse:
    """Run one canned escape attempt through both layers and report what refused it."""
    payload = await request.json()
    attempt = escapes.by_id(str(payload.get("attempt", "")))
    if attempt is None:
        raise HTTPException(status_code=404, detail="unknown attempt")
    settings = merged_settings(payload.get("settings"))
    config = sandbox_config_for(settings, [])
    config.requested_capabilities = ["none"]

    static = policy.precheck(attempt.code, policy.Policy(
        allowed_read_roots=runner.abs_paths(settings["allowedReadPaths"], WORKSPACE),
        allowed_write_roots=runner.abs_paths(settings["allowedWritePaths"], WORKSPACE),
        allow_network=config.allow_network,
        granted_capabilities=set(config.granted_capabilities),
        requested_capabilities=["none"], run_root=WORKSPACE))
    # The runtime layers get their own run with the pre-check deliberately bypassed, so a
    # reason string here comes from the audit hook or the kernel, not from the AST.
    runtime = runner.run_tool(attempt.code, f"break-{attempt.id}-{uuid.uuid4().hex[:4]}",
                              config, skip_precheck=True, label=attempt.label)
    return JSONResponse({
        "attempt": {"id": attempt.id, "label": attempt.label, "intent": attempt.intent,
                    "code": attempt.code},
        "precheck": {"accepted": static.accepted, "reasons": [f.reason for f in static.findings],
                     "findings": [f.to_dict() for f in static.findings]},
        "runtime": {"status": runtime.status, "blocked": [b["display"] for b in runtime.blocked],
                    "exitCode": runtime.exit_code, "stderr": runtime.stderr[:1200],
                    "artifacts": runtime.artifacts, "isolation": runtime.isolation_level,
                    "resources": runtime.resources, "trace": runtime.trace,
                    "unauthorisedWrites": runtime.unauthorised_writes},
        "blocked": (not static.accepted) or runtime.status in {"blocked", "killed", "timeout"}
        or bool(runtime.blocked),
    })


@app.get("/api/escapes")
def list_escapes() -> list[dict[str, Any]]:
    return [{"id": a.id, "label": a.label, "intent": a.intent, "code": a.code}
            for a in escapes.ATTEMPTS]


@app.get("/api/artifacts")
def list_artifacts(run_id: str | None = None) -> list[dict[str, Any]]:
    if not ARTIFACT_ROOT.is_dir():
        return []
    out = []
    for run_dir in sorted(p for p in ARTIFACT_ROOT.iterdir() if p.is_dir()):
        if run_id and run_dir.name != run_id:
            continue
        for path in sorted(run_dir.rglob("*")):
            if path.is_file():
                out.append({"runId": run_dir.name, "name": str(path.relative_to(run_dir)),
                            "bytes": path.stat().st_size,
                            "path": str(path.relative_to(WORKSPACE))})
    return out


@app.get("/api/artifacts/{run_id}/{name:path}")
def artifact_file(run_id: str, name: str) -> FileResponse:
    base = (ARTIFACT_ROOT / run_id).resolve()
    target = (base / name).resolve()
    # Contain path traversal before serving anything from disk.
    if base != WORKSPACE / "artifacts" / run_id or not str(target).startswith(str(base) + os.sep):
        raise HTTPException(status_code=400, detail="invalid artifact path")
    if not target.is_file():
        raise HTTPException(status_code=404, detail="no such artifact")
    return FileResponse(target, filename=target.name)


@app.get("/api/capabilities/pending")
def pending_capabilities() -> list[dict[str, Any]]:
    """Every capability the model asked for and the user has not yet ruled on."""
    out = []
    for run in STORE.list():
        record = STORE.get(run["id"])
        if record and record.capabilities and record.capabilities.get("pendingApproval"):
            out.append({"runId": record.id, "task": record.task,
                        "pending": record.capabilities["pendingApproval"],
                        "requested": record.capabilities["requested"],
                        "granted": record.capabilities["granted"]})
    return out


def main() -> None:
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=env_int("PORT", 3001), log_level="info")


if __name__ == "__main__":
    main()
