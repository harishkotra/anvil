"""Trace model shared by the runner, the sandboxed child, and the API layer.

Every interesting thing that happens to a generated tool becomes a chronological event.
Blocked calls carry the exact reason string the UI shows and `agent.verify` asserts.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

# Event kinds, in the order the UI expects to see them.
POLICY = "policy"
EXEC_START = "exec-start"
BLOCKED = "blocked"
RESOURCE = "resource"
KILLED = "killed"
ARTIFACT = "artifact"
INFO = "info"
DONE = "done"

BLOCKED_MARKER = "__ANVIL_BLOCKED__"
META_MARKER = "__ANVIL_META__"
FINAL_MARKER = "__ANVIL_FINAL__"


@dataclass
class BlockedCall:
    """A single operation the sandbox refused."""

    call: str
    reason: str
    layer: str  # "pre-check" | "audit-hook" | "kernel" | "rlimit"
    line: int | None = None

    @property
    def display(self) -> str:
        if self.layer == "pre-check":
            return self.reason
        return f"blocked at runtime: {self.call} ({self.reason})"

    def to_dict(self) -> dict[str, Any]:
        return {"call": self.call, "reason": self.reason, "layer": self.layer,
                "line": self.line, "display": self.display}


@dataclass
class TraceEvent:
    at_ms: int
    kind: str
    message: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"atMs": self.at_ms, "kind": self.kind, "message": self.message,
                "detail": self.detail}


class Tracer:
    """Collects the run's chronology relative to its own start."""

    def __init__(self) -> None:
        self._t0 = time.monotonic()
        self.events: list[TraceEvent] = []
        self.blocked: list[BlockedCall] = []

    def add(self, kind: str, message: str, **detail: Any) -> TraceEvent:
        event = TraceEvent(at_ms=self.elapsed_ms(), kind=kind, message=message,
                           detail={k: v for k, v in detail.items() if v is not None})
        self.events.append(event)
        return event

    def add_blocked(self, call: str, reason: str, layer: str, line: int | None = None) -> BlockedCall:
        record = BlockedCall(call=call, reason=reason, layer=layer, line=line)
        self.blocked.append(record)
        self.add(BLOCKED, record.display, call=call, reason=reason, layer=layer, line=line)
        return record

    def elapsed_ms(self) -> int:
        return int((time.monotonic() - self._t0) * 1000)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [e.to_dict() for e in self.events]
