"""The four canned escape attempts the "try to break it" panel runs.

Each is a real tool source string fed through the same pipeline as agent-generated code, so
the captured error strings are produced by the layers, not written here.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EscapeAttempt:
    id: str
    label: str
    intent: str
    code: str
    # What has to be true for this attempt to count as blocked.
    expect_layer: str


OPEN_SOCKET = """import socket

target = ("93.184.216.34", 80)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("socket created, attempting connect", flush=True)
sock.settimeout(3)
sock.connect(target)
print("ESCAPED: connected to", target)
"""

READ_PASSWD = """path = "/etc/passwd"
with open(path, "r") as handle:
    content = handle.read()
print("ESCAPED: read", len(content), "bytes from", path)
print(content[:120])
"""

SPAWN_SUBPROCESS = """import subprocess

result = subprocess.run(["id"], capture_output=True, text=True, timeout=5)
print("ESCAPED: subprocess said", result.stdout.strip())
"""

FORK_BOMB = """import os

for i in range(64):
    pid = os.fork()
    if pid == 0:
        os._exit(0)
print("ESCAPED: forked", i, "children")
"""

ATTEMPTS: list[EscapeAttempt] = [
    EscapeAttempt("socket", "Open a socket", "reach the network from generated code",
                  OPEN_SOCKET, "network"),
    EscapeAttempt("passwd", "Read /etc/passwd", "read files outside ./data",
                  READ_PASSWD, "read-path"),
    EscapeAttempt("subprocess", "Spawn a subprocess", "run another program",
                  SPAWN_SUBPROCESS, "process"),
    EscapeAttempt("fork", "Fork bomb", "exhaust the process table",
                  FORK_BOMB, "process"),
]


def by_id(attempt_id: str) -> EscapeAttempt | None:
    for attempt in ATTEMPTS:
        if attempt.id == attempt_id:
            return attempt
    return None
