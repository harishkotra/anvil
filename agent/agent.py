"""The agent: smolagents CodeAgent whose executor *is* the Anvil sandbox.

smolagents 1.26 exposes `CodeAgent(executor=...)`, so the default local interpreter is
replaced outright rather than bolted on afterwards: every code action the agent writes is
run through the same rlimit + audit-hook + kernel-confined path that runs the final tool.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from smolagents.local_python_executor import CodeOutput, PythonExecutor

from agent.sandbox import policy, runner
from agent.sandbox.runner import RunResult, SandboxConfig
from agent.sandbox.tracer import Tracer

# Verbatim from the build spec, section 6.
TOOL_PROMPT = """You write a single self-contained Python tool for the task. Reply ONLY with JSON:
{"toolName":"snake_case_name",
 "code":"<full python source, no markdown fences>",
 "expectedOutput":"<what the artifact will be>",
 "capabilitiesRequested":["network"|"read:./data"|"write:./artifacts"|"none"],
 "rationale":"<=200 chars"}
Rules: the code must read only from ./data and write only to ./artifacts; no network;
no subprocesses; print a short summary to stdout. Use only the standard library plus
pandas/matplotlib if the task needs them."""

AUTHORIZED_IMPORTS = ["pandas", "matplotlib", "numpy", "csv", "json", "statistics",
                      "datetime", "math", "re", "pathlib", "collections", "itertools"]

EVENT = Callable[[str, dict[str, Any]], None]


@dataclass
class ToolSpec:
    tool_name: str
    code: str
    expected_output: str
    capabilities_requested: list[str]
    rationale: str
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"toolName": self.tool_name, "code": self.code,
                "expectedOutput": self.expected_output,
                "capabilitiesRequested": self.capabilities_requested,
                "rationale": self.rationale}


@dataclass
class Generation:
    spec: ToolSpec | None
    mode: str
    text: str
    error: str | None = None
    attempts: list[dict[str, Any]] = field(default_factory=list)
    model_latency_ms: int = 0
    provenance: str = ""
    actions: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"spec": self.spec.to_dict() if self.spec else None, "mode": self.mode,
                "error": self.error, "attempts": self.attempts, "provenance": self.provenance,
                "actions": self.actions, "modelLatencyMs": self.model_latency_ms,
                "text": self.text}




# --- capability gate -------------------------------------------------------

def resolve_capabilities(requested: list[str], approved: list[str], *,
                         allow_network: bool) -> dict[str, Any]:
    """The model asks; only the user's approval list grants. Never the other way round.

    `read:./data` and `write:./artifacts` are baseline capabilities the sandbox is built
    around, so they are granted when the paths are configured. `network` and `process`
    require an explicit entry in the approval list, and `process` is never grantable at
    all under the kernel policy — a request for it is recorded and refused visibly.
    """
    granted: list[str] = []
    denied: list[str] = []
    for cap in requested:
        if cap == "none":
            continue
        if cap.startswith("read:") or cap.startswith("write:"):
            granted.append(cap)
        elif cap == policy.CAP_NETWORK:
            (granted if allow_network and cap in approved else denied).append(cap)
        elif cap == policy.CAP_PROCESS:
            denied.append(cap)
        elif cap in approved:
            granted.append(cap)
        else:
            denied.append(cap)
    return {"requested": list(requested), "granted": granted, "denied": denied,
            "pendingApproval": [c for c in denied if c not in granted]}


# --- the executor swap -----------------------------------------------------

class AnvilSandboxExecutor(PythonExecutor):
    """A smolagents `PythonExecutor` that runs each code action inside the Anvil sandbox.

    Each action is a fresh sandboxed process, so state that survives between actions is
    limited to JSON-serialisable variables — which is a property of running code in a
    subprocess, not a shortcut.
    """

    def __init__(self, config: SandboxConfig, on_event: EVENT | None = None,
                 run_id_prefix: str = "action"):
        self.config = config
        self.on_event = on_event
        self.run_id_prefix = run_id_prefix
        self.state: dict[str, Any] = {}
        self.static_tools: dict[str, Any] = {}
        self.custom_tools: dict[str, Any] = {}
        self.last_run: RunResult | None = None
        self.actions: list[dict[str, Any]] = []
        self.trace = Tracer()
        self._step = 0
        # Mirrors smolagents' own contract: the executor exposes `_print_outputs`.
        self.state["_print_outputs"] = ""

    def send_tools(self, tools: dict[str, Any]) -> None:
        self.static_tools = dict(tools)
        self.custom_tools = dict(tools)

    def send_variables(self, variables: dict[str, Any]) -> None:
        self.state.update(variables)

    def __call__(self, code_action: str) -> CodeOutput:
        self._step += 1
        if not code_action.strip():
            # A model can emit an empty <code> block (gpt-oss spends the budget on
            # reasoning_content). Executing nothing "succeeds" vacuously and wastes a step,
            # so send the loop a correction instead of pretending a run happened.
            hint = ("No code was received. Either put the tool's Python source inside a "
                    "<code></code> block, or call final_answer(json_string) with the JSON "
                    "tool spec. Do not emit an empty code block.")
            self.actions.append({"runId": f"{self.run_id_prefix}-{self._step}-empty",
                                 "code": "", "status": "empty-action", "stdout": "",
                                 "stderr": "", "artifacts": [], "blocked": []})
            if self.on_event:
                self.on_event("action", {"runId": f"{self.run_id_prefix}-{self._step}-empty",
                                         "code": "", "status": "empty-action",
                                         "artifacts": [], "blocked": []})
            return CodeOutput(output=hint, logs=hint, is_final_answer=False)
        run_id = f"{self.run_id_prefix}-{self._step}-{uuid.uuid4().hex[:6]}"
        config = SandboxConfig(**dict(self.config.__dict__))
        result = runner.run_sandboxed_action(code_action, run_id, config,
                                             self.state, tracer=self.trace)
        self.last_run = result
        self.actions.append({
            "runId": run_id,
            "code": code_action,
            "status": result.status,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "artifacts": [a["name"] for a in result.artifacts],
            "blocked": [b["display"] for b in result.blocked],
        })
        if self.on_event:
            self.on_event("action", {"runId": run_id, "code": code_action,
                                     "status": result.status,
                                     "artifacts": [a["name"] for a in result.artifacts],
                                     "blocked": [b["display"] for b in result.blocked]})
        logs = (result.stdout or "") + (("\n" + result.stderr) if result.stderr else "")
        return CodeOutput(output=result.action_final if result.action_final is not None else logs,
                          logs=logs[:8000],
                          is_final_answer=result.action_final is not None)

    def best_action(self) -> dict[str, Any] | None:
        """The code action that ran successfully *and produced the artifact*.

        Only artifact-producing actions qualify. Falling back to any successful action would
        let an exploratory `print(df.columns)` be presented as the deliverable when the loop
        runs out of steps — which is a real failure mode, not a cosmetic one.
        """
        for action in reversed(self.actions):
            if action["status"] == "success" and action["artifacts"]:
                return action
        return None

    def cleanup(self) -> None:  # pragma: no cover - symmetry with smolagents
        pass


# --- generation ------------------------------------------------------------

def _extract_json(text: str) -> dict[str, Any] | None:
    """Pull the tool spec out of whatever the model actually returned."""
    if not text:
        return None
    cleaned = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.S)
    if fenced:
        cleaned = fenced.group(1)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    start = cleaned.find("{")
    if start == -1:
        return None
    decoder = json.JSONDecoder()
    try:
        obj, _ = decoder.raw_decode(cleaned[start:])
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


def _clean_code(raw: str) -> str:
    """Strip transport wrappers only — fences and CodeAgent's `<code>` tags.

    This normalises how the source was carried, never what it does: no logic is added,
    removed, or "fixed". The code is otherwise executed exactly as the agent returned it.
    """
    text = (raw or "").strip()
    fenced = re.search(r"```(?:python|py)?\s*(.*?)```", text, re.S)
    if fenced:
        text = fenced.group(1).strip()
    for tag in ("<code>", "</code>", "<arguments>", "</arguments>"):
        text = text.replace(tag, "")
    text = text.strip()
    # A double-encoded source string: one line, literal \n sequences.
    if "\n" not in text and text.count("\\n") > 3:
        text = text.replace("\\n", "\n").replace("\\t", "\t").strip("'\"")
    return text.strip() + "\n"


def _to_spec(payload: dict[str, Any] | None, raw: str) -> ToolSpec | None:
    if not payload or "code" not in payload:
        return None
    return ToolSpec(
        tool_name=str(payload.get("toolName") or "unnamed_tool").strip() or "unnamed_tool",
        code=str(payload["code"]),
        expected_output=str(payload.get("expectedOutput") or ""),
        capabilities_requested=policy.normalize_capability_requests(
            payload.get("capabilitiesRequested") or ["none"]),
        rationale=str(payload.get("rationale") or "")[:200],
        raw=raw,
    )


def _spec_from_action(action: dict[str, Any], task: str) -> ToolSpec:
    """Build the tool spec from code the agent actually ran inside the sandbox."""
    code = _clean_code(action["code"])
    needed = sorted(policy.capabilities_needed(code))
    slug = re.sub(r"[^a-z0-9]+", "_", task.strip().lower()[:48]).strip("_") or "generated_tool"
    return ToolSpec(
        tool_name=slug,
        code=code,
        expected_output=", ".join(action["artifacts"]) or "stdout summary",
        capabilities_requested=needed or ["none"],
        rationale="Derived from the code action the agent executed in the sandbox.",
        raw=action["code"],
    )


def build_agent(settings: dict[str, Any], config: SandboxConfig, on_event: EVENT | None = None):
    """CodeAgent wired to the OpenAI-compatible provider and the Anvil sandbox executor."""
    from smolagents import CodeAgent

    from agent.inference import build_model

    model = build_model(settings["baseUrl"], settings.get("apiKey", ""), settings["model"])
    executor = AnvilSandboxExecutor(config, on_event=on_event)
    agent = CodeAgent(tools=[], model=model, executor=executor,
                      additional_authorized_imports=AUTHORIZED_IMPORTS,
                      max_print_outputs_length=8000, stream_outputs=False)
    return agent, executor


def generate_tool(task: str, settings: dict[str, Any], config: SandboxConfig, *,
                  on_event: EVENT | None = None, mode: str = "codeagent",
                  max_steps: int = 6) -> tuple[Generation, dict[str, Any]]:
    """Ask the agent for a tool. Returns the generation plus the capability decision.

    CodeAgent path first; `direct` sends the same verbatim prompt as a single chat turn and
    is what the Settings panel selects when a small local model cannot drive the loop.
    """
    from agent import inference

    messages = [{"role": "system", "content": TOOL_PROMPT},
                {"role": "user", "content": f"Task: {task}"}]
    attempts: list[dict[str, Any]] = []
    latency = 0
    text = ""

    if mode == "codeagent":
        from agent import inference as _inference

        ready, note = _inference.warm_up(settings["baseUrl"], settings.get("apiKey", ""),
                                         settings["model"])
        if on_event:
            on_event("warmup", {"ok": ready, "note": note})
        generation_error: str | None = None
        spec: ToolSpec | None = None
        text = ""
        executor: AnvilSandboxExecutor | None = None
        for attempt in range(2):
            try:
                agent, executor = build_agent(settings, config, on_event)
                prompt = (f"{TOOL_PROMPT}\n\nTask: {task}\n\n"
                          "You are in a ReAct loop: put Python inside a <code></code> block to run "
                          "it in the sandbox, where ./data can be read and ./artifacts written. "
                          "First write that tool and run it. Then call final_answer() with the JSON "
                          "object above, its \"code\" field holding the exact source you just ran.")
                answer = agent.run(prompt, max_steps=max_steps)
                text = answer if isinstance(answer, str) else json.dumps(answer)
                generation_error = None
                break
            except Exception as exc:  # a failed loop is reported, not hidden
                generation_error = f"CodeAgent run failed: {type(exc).__name__}: {exc}"
                transient = any(marker in str(exc).lower() for marker in
                                ("failed to load model", "operation canceled", "rate limit",
                                 "timeout", "connection"))
                if attempt == 0 and transient:
                    if on_event:
                        on_event("retry", {"attempt": attempt + 1, "reason": generation_error[:200]})
                    time.sleep(5)
                    continue
                break
        if generation_error:
            return Generation(spec=None, mode="smolagents-codeagent", text="",
                              error=generation_error, attempts=attempts,
                              actions=executor.actions if executor else []), {}
        payload = _extract_json(text)
        spec = _to_spec(payload, text)
        provenance = "final-answer JSON"
        if spec:
            spec.code = _clean_code(spec.code)
        if spec is None or len(spec.code.strip()) < 20:
            # The ReAct loop's most trustworthy output is the code it actually ran: that
            # code has already been executed in the sandbox and produced the artifact.
            action = executor.best_action()
            if action:
                spec = _spec_from_action(action, task)
                provenance = "last successful sandboxed code action"
                attempts.append({"source": "codeagent-action", "runId": action["runId"],
                                 "artifacts": action["artifacts"]})
        if spec is None:
            return Generation(spec=None, mode="smolagents-codeagent", text=text,
                              error="CodeAgent ended without a parseable tool spec and without "
                                    f"an artifact-producing code action ({len(executor.actions)} "
                                    "action(s) ran)",
                              attempts=attempts, actions=executor.actions,
                              model_latency_ms=latency), {}
        caps = resolve_capabilities(spec.capabilities_requested,
                                    [str(c) for c in settings.get("approvedCapabilities", [])],
                                    allow_network=config.allow_network)
        return Generation(spec=spec, mode="smolagents-codeagent", text=text, attempts=attempts,
                          actions=executor.actions, provenance=provenance,
                          model_latency_ms=latency), caps

    try:
        result = inference.post_chat(settings["baseUrl"], settings.get("apiKey", ""),
                                     settings["model"], messages,
                                     max_tokens=int(settings.get("maxTokens", 3000)),
                                     temperature=float(settings.get("temperature", 0.1)))
    except inference.InferenceError as exc:
        return Generation(spec=None, mode="direct-chat", text="",
                          error=str(exc), attempts=attempts), {}
    latency = result.latency_ms
    text = result.content
    payload = _extract_json(text)
    spec = _to_spec(payload, text)
    if spec:
        spec.code = _clean_code(spec.code)
    caps = resolve_capabilities(spec.capabilities_requested,
                                [str(c) for c in settings.get("approvedCapabilities", [])],
                                allow_network=config.allow_network) if spec else {}
    return Generation(spec=spec, mode="direct-chat", text=text,
                      error=None if spec else "model reply was not a parseable tool spec",
                      attempts=attempts, model_latency_ms=latency), caps


def retry_with_reason(task: str, settings: dict[str, Any], config: SandboxConfig,
                      reasons: list[str], first: Generation,
                      on_event: EVENT | None = None) -> tuple[Generation, dict[str, Any]]:
    """One retry, carrying the exact rejection strings back to the model. Section 6 guardrail.

    A second rejection ends the run with the rejection shown; the code is never silently
    rewritten or patched by the model after execution.
    """
    feedback = "The sandbox pre-check rejected your tool. Fix it and reply ONLY with the JSON.\n" \
        + "\n".join(f"- {reason}" for reason in reasons)
    messages = [{"role": "system", "content": TOOL_PROMPT},
                {"role": "user", "content": f"Task: {task}"},
                {"role": "assistant", "content": first.text[:4000]},
                {"role": "user", "content": feedback}]
    from agent import inference
    try:
        result = inference.post_chat(settings["baseUrl"], settings.get("apiKey", ""),
                                     settings["model"], messages,
                                     max_tokens=int(settings.get("maxTokens", 3000)),
                                     temperature=0.0)
    except inference.InferenceError as exc:
        return Generation(spec=None, mode="direct-chat-retry", text="", error=str(exc),
                          model_latency_ms=0), {}
    payload = _extract_json(result.content)
    spec = _to_spec(payload, result.content)
    caps = resolve_capabilities(spec.capabilities_requested,
                                [str(c) for c in settings.get("approvedCapabilities", [])],
                                allow_network=config.allow_network) if spec else {}
    return Generation(spec=spec, mode="direct-chat-retry", text=result.content,
                      error=None if spec else "retry reply was not parseable JSON",
                      model_latency_ms=result.latency_ms), caps
