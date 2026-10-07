"""OpenAI-compatible inference wiring.

One plain HTTP POST to `{baseUrl}/chat/completions` — no provider SDK — plus the presets the
Settings panel offers. `test_connection` returns the real status code and body; it never
reports success it did not observe.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

PARTICLE = "Particle.ai"
LMSTUDIO = "LM Studio"
OLLAMA = "Ollama"
GEMINI = "Gemini"
CUSTOM = "Custom"

PRESETS: list[dict[str, str]] = [
    {"id": PARTICLE, "baseUrl": "https://api.particle.ai/v1", "model": "deepseek-v4.1-flash",
     "needsKey": "true", "note": "default"},
    {"id": LMSTUDIO, "baseUrl": "http://localhost:1234/v1", "model": "openai/gpt-oss-20b",
     "needsKey": "false", "note": "local"},
    {"id": OLLAMA, "baseUrl": "http://localhost:11434/v1", "model": "llama3.2",
     "needsKey": "false", "note": "local"},
    {"id": GEMINI, "baseUrl": "https://generativelanguage.googleapis.com/v1beta/openai/",
     "model": "gemini-2.5-flash", "needsKey": "true", "note": "hosted"},
    {"id": CUSTOM, "baseUrl": "", "model": "", "needsKey": "true", "note": "any OpenAI-compatible"},
]


@dataclass
class ChatResult:
    text: str
    reasoning: str
    finish_reason: str
    usage: dict[str, Any]
    latency_ms: int
    raw: dict[str, Any]

    @property
    def content(self) -> str:
        """The answer text, with reasoning recovered for reasoning-only replies.

        Local reasoning models (gpt-oss, glm-flash) put their chain of thought in
        `reasoning_content` and can leave `content` empty when the budget runs out, so the
        JSON the agent emits is sometimes only reachable there.
        """
        return self.text or self.reasoning


class InferenceError(RuntimeError):
    def __init__(self, message: str, status: int | None = None, body: str = ""):
        super().__init__(message)
        self.status = status
        self.body = body


def _endpoint(base_url: str) -> str:
    base = (base_url or "").rstrip("/")
    if not base:
        raise InferenceError("no base URL configured")
    if base.endswith("/chat/completions"):
        return base
    return f"{base}/chat/completions"


TRANSIENT_MARKERS = ("failed to load model", "operation canceled", "is loading",
                     "not loaded", "timeout", "timed out", "connection reset")


def _transient(status: int | None, body: str) -> bool:
    """A local server refusing because it is still swapping a model in is retryable."""
    if status not in (400, 408, 425, 429, 500, 502, 503, 504):
        return False
    lowered = (body or "").lower()
    return any(marker in lowered for marker in TRANSIENT_MARKERS)


def post_chat(base_url: str, api_key: str, model: str, messages: list[dict[str, str]],
              *, max_tokens: int = 2000, temperature: float = 0.1,
              timeout: int = 300, extra: dict[str, Any] | None = None,
              retries: int = 3) -> ChatResult:
    """One chat turn, with bounded backoff for a flaky local provider.

    LM Studio answers 400 "Failed to load model … Operation canceled" when two requests
    race to swap a model in; retrying is the correct client behaviour, and a genuine
    401/404 is never retried.
    """
    last: InferenceError | None = None
    for attempt in range(retries):
        try:
            return _post_chat_once(base_url, api_key, model, messages, max_tokens=max_tokens,
                                   temperature=temperature, timeout=timeout, extra=extra)
        except InferenceError as exc:
            last = exc
            if attempt + 1 >= retries or not _transient(exc.status, exc.body):
                raise
            delay = 3 * (attempt + 1)
            time.sleep(delay)
    raise last or InferenceError("chat request failed")


def _post_chat_once(base_url: str, api_key: str, model: str, messages: list[dict[str, str]],
                    *, max_tokens: int, temperature: float, timeout: int,
                    extra: dict[str, Any] | None) -> ChatResult:
    payload: dict[str, Any] = {"model": model, "messages": messages,
                               "max_tokens": max_tokens, "temperature": temperature}
    payload.update(extra or {})
    body = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(_endpoint(base_url), data=body, headers=headers, method="POST")
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:2000]
        raise InferenceError(f"HTTP {exc.code} from {exc.url}", exc.code, detail) from exc
    except urllib.error.URLError as exc:
        raise InferenceError(f"could not reach {base_url}: {exc.reason}", None, "") from exc
    latency = int((time.monotonic() - started) * 1000)
    choices = raw.get("choices") or []
    if not choices:
        raise InferenceError(f"no choices in response from {base_url}", 200,
                             json.dumps(raw)[:2000])
    message = choices[0].get("message") or {}
    return ChatResult(
        text=(message.get("content") or "").strip(),
        reasoning=(message.get("reasoning_content") or message.get("reasoning") or "").strip(),
        finish_reason=choices[0].get("finish_reason") or "",
        usage=raw.get("usage") or {},
        latency_ms=latency,
        raw=raw,
    )


def warm_up(base_url: str, api_key: str, model: str, timeout: int = 240) -> tuple[bool, str]:
    """Force the provider to load the model before a multi-step agent loop starts.

    Without this, the first step of a CodeAgent run is the one that pays for a model swap
    and races any other client doing the same thing.
    """
    try:
        result = post_chat(base_url, api_key, model,
                           [{"role": "user", "content": "Reply with exactly: READY"}],
                           max_tokens=64, temperature=0, timeout=timeout)
    except InferenceError as exc:
        return False, f"{exc} {exc.body[:120]}".strip()
    return True, f"{result.latency_ms}ms"


def list_models(base_url: str, api_key: str, timeout: int = 15) -> list[str]:
    base = (base_url or "").rstrip("/")
    if base.endswith("/chat/completions"):
        base = base[: -len("/chat/completions")]
    request = urllib.request.Request(f"{base}/models",
                                     headers={"Authorization": f"Bearer {api_key}"} if api_key else {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
        return []
    entries = data.get("data") if isinstance(data, dict) else data
    ids = []
    for entry in entries or []:
        if isinstance(entry, str):
            ids.append(entry)
        elif isinstance(entry, dict) and entry.get("id"):
            ids.append(str(entry["id"]))
    return ids


def test_connection(base_url: str, api_key: str, model: str) -> dict[str, Any]:
    """A real round trip, reported honestly: status, latency, body excerpt, or the error."""
    started = time.monotonic()
    try:
        result = post_chat(base_url, api_key, model,
                           [{"role": "user", "content": "Reply with exactly: ANVIL_OK"}],
                           max_tokens=600, temperature=0, timeout=180)
    except InferenceError as exc:
        return {"ok": False, "status": exc.status, "error": str(exc),
                "body": exc.body[:1200], "models": list_models(base_url, api_key)[:20],
                "latencyMs": int((time.monotonic() - started) * 1000)}
    ok = bool(result.content)
    return {
        "ok": ok,
        "status": 200,
        "latencyMs": result.latency_ms,
        "finishReason": result.finish_reason,
        "usage": result.usage,
        "reply": result.content[:200],
        "warning": None if ok else "the provider returned no message text",
        "note": (None if result.text else
                 "reply came back in reasoning_content (a reasoning model); using it as content"),
        "models": list_models(base_url, api_key)[:20],
        "body": json.dumps(result.raw)[:1500],
    }


def build_model(base_url: str, api_key: str, model: str, **kwargs: Any):
    """The OpenAI-compatible model object smolagents drives.

    smolagents 1.26 names this argument `api_base`, not `base_url`; the spec's `base_url=`
    is a keyword for the same endpoint and is mapped here.
    """
    from smolagents import OpenAIServerModel

    return OpenAIServerModel(model_id=model, api_base=base_url, api_key=api_key or "not-needed",
                             **kwargs)
