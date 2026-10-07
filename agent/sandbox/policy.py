"""Static pre-checks, capability allowlist, and path rules.

Nothing here executes candidate code. The module parses it to an AST and answers one
question: is this tool allowed to run, and if not, exactly why. Every rejection carries
a reason string that is shown verbatim in the UI and asserted by `agent.verify`.
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# --- module -> (rule, human reason) ----------------------------------------

NETWORK_MODULES = {
    "socket", "ssl", "urllib", "urllib2", "http", "httpx", "requests", "aiohttp",
    "ftplib", "smtplib", "poplib", "imaplib", "telnetlib", "urllib3", "websockets",
    "grpc", "xmlrpc",
}
PROCESS_MODULES = {"subprocess", "multiprocessing", "pty", "sched"}
# Foreign-function access is the one import that can reach past every Python-level guard.
# `inspect`, `gc`, `builtins` and `importlib` are deliberately NOT banned: pandas and
# matplotlib import them internally, and dynamic import is already neutralised by the
# runtime hook refusing the module the tool finally reaches for.
INTROSPECTION_MODULES = {"ctypes"}

# Banned `os.<attr>` calls: these are process/escape primitives.
BANNED_OS_ATTRS = {
    "system": "os.system shell execution denied by policy",
    "popen": "os.popen shell execution denied by policy",
    "fork": "process creation denied by policy",
    "forkpty": "process creation denied by policy",
    "execv": "process replacement denied by policy",
    "execve": "process replacement denied by policy",
    "execl": "process replacement denied by policy",
    "execlp": "process replacement denied by policy",
    "execvp": "process replacement denied by policy",
    "spawnl": "process creation denied by policy",
    "spawnle": "process creation denied by policy",
    "spawnlp": "process creation denied by policy",
    "spawnlpe": "process creation denied by policy",
    "spawnv": "process creation denied by policy",
    "spawnve": "process creation denied by policy",
    "kill": "signalling other processes denied by policy",
    "killpg": "signalling other processes denied by policy",
    "setrlimit": "changing resource limits from inside the sandbox denied by policy",
    "remove": "filesystem mutation outside artifacts denied by policy",
    "unlink": "filesystem mutation outside artifacts denied by policy",
    "rmdir": "filesystem mutation outside artifacts denied by policy",
}

# Dunders that let code walk out of the interpreter's own object graph.
BANNED_DUNDERS = {
    "__builtins__", "__globals__", "__class__", "__subclasses__", "__bases__",
    "__mro__", "__code__", "__reduce__", "__reduce_ex__", "__getattribute__",
    "__setattr__", "__delattr__", "__dict__", "__loader__", "__spec__",
    "__import__", "__call__", "__bypass__", "__requires_gradient__",
}
# Dunders a legitimate data tool will reasonably touch.
SAFE_DUNDERS = {"__name__", "__doc__", "__module__", "__version__", "__file__",
                "__qualname__", "__init__", "__repr__", "__str__", "__enter__",
                "__exit__", "__iter__", "__next__", "__len__", "__contains__"}

DYNAMIC_EXEC_BUILTINS = {"eval", "exec", "compile", "__import__"}

# Calls whose first string argument is a path being written.
WRITE_METHOD_NAMES = {
    "to_csv", "to_excel", "to_json", "to_parquet", "to_pickle", "to_feather",
    "to_hdf", "savefig", "write_text", "write_bytes", "imwrite", "makedir",
    "makedirs", "mkdir", "rename", "replace", "touch", "open",
}
WRITE_FUNCTION_NAMES = {"open", "savefig", "makedirs", "mkdir", "rename", "replace"}
READ_METHOD_NAMES = {"read_csv", "read_excel", "read_json", "read_parquet", "read_pickle",
                     "loadtxt", "genfromtxt", "read_text", "read_table", "read_fwf"}

# Only these calls are treated as path operations, so that `ValueError('some message')`
# is not mistaken for a file access.
PATH_TAKING_NAMES = WRITE_METHOD_NAMES | READ_METHOD_NAMES

CAP_NETWORK = "network"
CAP_PROCESS = "process"
CAP_FS_WRITE = "write:./artifacts"
CAP_FS_READ = "read:./data"


@dataclass
class Finding:
    rule: str
    reason: str
    line: int
    capability: str | None = None
    undeclared: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"rule": self.rule, "reason": self.reason, "line": self.line,
                "capability": self.capability, "undeclared": self.undeclared}


@dataclass
class Policy:
    """Effective policy for one run: settings + what the model asked for."""

    allowed_read_roots: list[Path] = field(default_factory=list)
    allowed_write_roots: list[Path] = field(default_factory=list)
    allow_network: bool = False
    granted_capabilities: set[str] = field(default_factory=set)
    requested_capabilities: list[str] = field(default_factory=list)
    run_root: Path | None = None

    def read_ok(self, path: Path) -> bool:
        return _within(path, self.allowed_read_roots)

    def write_ok(self, path: Path) -> bool:
        return _within(path, self.allowed_write_roots)


def _within(path: Path, roots: list[Path]) -> bool:
    for root in roots:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            continue
    return False


@dataclass
class PrecheckResult:
    accepted: bool
    findings: list[Finding]
    lines_checked: int
    rule_hits: dict[str, int] = field(default_factory=dict)

    @property
    def reasons(self) -> list[str]:
        return [f.reason for f in self.findings]

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "findings": [f.to_dict() for f in self.findings],
            "linesChecked": self.lines_checked,
            "reasons": self.reasons,
        }


def resolve_path(raw: str, run_root: Path) -> Path:
    """Resolve a literal path in the source the way the sandbox child would see it."""
    candidate = Path(os.path.expanduser(raw))
    if not candidate.is_absolute():
        candidate = run_root / candidate
    # realpath resolves symlinks, so `./data` pointing at the repo cannot be used to
    # write outside the jail.
    try:
        return Path(os.path.realpath(str(candidate)))
    except OSError:
        return candidate.resolve()


def _module_root(name: str) -> str:
    return (name or "").split(".")[0]


class _Visitor(ast.NodeVisitor):
    def __init__(self, policy: Policy, source: str):
        self.policy = policy
        self.findings: list[Finding] = []
        self.seen: set[tuple[str, int]] = set()
        # Literals already reported by the path-aware call check, so the generic sweep
        # does not report `open('/etc/passwd')` twice.
        self.call_paths: set[tuple[int, str]] = set()

    # `import x`, `import x.y`, `from x import y`
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._check_module(alias.name, node.lineno)
            sub = _root_module_of(alias.name)
            if sub:
                self._check_module(sub, node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self._check_module(node.module, node.lineno)
        self.generic_visit(node)

    def _check_module(self, name: str, line: int) -> None:
        root = _module_root(name)
        if root in NETWORK_MODULES:
            if CAP_NETWORK not in self.policy.granted_capabilities:
                self._add(
                    "network",
                    f"blocked: import {root} (network denied by policy)",
                    line,
                    CAP_NETWORK,
                )
        elif root in PROCESS_MODULES:
            self._add(
                "process",
                f"blocked: import {root} (process spawn denied by policy)",
                line,
                CAP_PROCESS,
            )
        elif root in INTROSPECTION_MODULES and root != "importlib":
            self._add(
                "introspection",
                f"blocked: import {root} (interpreter introspection denied by policy)",
                line,
            )

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        # bare eval/exec/compile/__import__
        if isinstance(func, ast.Name) and func.id in DYNAMIC_EXEC_BUILTINS:
            dynamic = not (node.args and isinstance(node.args[0], ast.Constant))
            qualifier = " on non-constant argument" if dynamic and func.id in {"eval", "exec"} else ""
            self._add(
                "dynamic-code",
                f"blocked: {func.id}(){qualifier} (dynamic code execution denied by policy)",
                node.lineno,
            )

        # os.<banned>
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) \
                and func.value.id == "os" and func.attr in BANNED_OS_ATTRS:
            self._add(
                "process" if func.attr not in {"remove", "unlink", "rmdir"} else "filesystem",
                f"blocked: os.{func.attr} ({BANNED_OS_ATTRS[func.attr]})",
                node.lineno,
            )

        # socket.socket / any.banned-module.member
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            base = func.value.id
            if base in NETWORK_MODULES and CAP_NETWORK not in self.policy.granted_capabilities:
                self._add("network", f"blocked: {base}.{func.attr} (network denied by policy)",
                          node.lineno, CAP_NETWORK)
            elif base in PROCESS_MODULES:
                self._add("process", f"blocked: {base}.{func.attr} (process spawn denied by policy)",
                          node.lineno, CAP_PROCESS)
            elif base == "socket":
                self._add("network", f"blocked: socket.{func.attr} (network denied by policy)",
                          node.lineno, CAP_NETWORK)

        self._check_path_call(node)
        self.generic_visit(node)

    def _check_path_call(self, node: ast.Call) -> None:
        """Literal path arguments of path-taking calls must land inside the allowed roots."""
        name = _call_name(node)
        if name not in PATH_TAKING_NAMES:
            return
        literal = _first_string_arg(node)
        if literal is None:
            return
        self.call_paths.add((node.lineno, literal))
        resolved = resolve_path(literal, self.policy.run_root)
        is_write = self._is_write(node, name)
        if is_write:
            if not self.policy.write_ok(resolved):
                self._add(
                    "write-path",
                    f"blocked: write path '{literal}' outside ALLOWED_WRITE_PATHS "
                    f"({self._roots_label(self.policy.allowed_write_roots)})",
                    node.lineno,
                    CAP_FS_WRITE,
                )
        else:
            if not self.policy.read_ok(resolved) and not self.policy.write_ok(resolved):
                self._add(
                    "read-path",
                    f"blocked: read path '{literal}' outside ALLOWED_READ_PATHS "
                    f"({self._roots_label(self.policy.allowed_read_roots)})",
                    node.lineno,
                    CAP_FS_READ,
                )

    def _is_write(self, node: ast.Call, name: str) -> bool:
        if name in WRITE_METHOD_NAMES and name not in READ_METHOD_NAMES:
            if name == "open":
                # `open(p)` with no mode is a read; only an explicit w/a/x/+ is a write.
                mode = ""
                if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                    mode = str(node.args[1].value)
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        mode = str(kw.value.value)
                return any(ch in mode for ch in ("w", "a", "x", "+"))
            return True
        return False

    def _roots_label(self, roots: list[Path]) -> str:
        run_root = self.policy.run_root
        labels = []
        for root in roots:
            try:
                labels.append("./" + str(root.relative_to(run_root)))
            except ValueError:
                labels.append(str(root))
        return ", ".join(labels) or "(none)"

    def visit_Attribute(self, node: ast.Attribute) -> None:
        attr = node.attr
        if attr.startswith("__") and attr.endswith("__") and attr not in SAFE_DUNDERS:
            if attr in BANNED_DUNDERS or attr not in SAFE_DUNDERS:
                self._add(
                    "dunder",
                    f"blocked: dunder attribute access {attr} "
                    f"(interpreter introspection denied by policy)",
                    node.lineno,
                )
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        # Catch paths parked in variables, then used later: `p='/etc/passwd'; open(p)`.
        value = node.value
        if isinstance(value, str) and _looks_like_escape_path(value) \
                and (node.lineno, value) not in self.call_paths:
            resolved = resolve_path(value, self.policy.run_root)
            if not self.policy.read_ok(resolved) and not self.policy.write_ok(resolved):
                self._add(
                    "path-literal",
                    f"blocked: path '{value}' outside ALLOWED_READ_PATHS "
                    f"({self._roots_label(self.policy.allowed_read_roots)})",
                    node.lineno,
                    CAP_FS_READ,
                )
        self.generic_visit(node)

    def _add(self, rule: str, reason: str, line: int, capability: str | None = None) -> None:
        key = (reason, line)
        if key in self.seen:
            return
        self.seen.add(key)
        self.findings.append(Finding(rule=rule, reason=reason, line=line, capability=capability))


def _root_module_of(dotted: str) -> str | None:
    """`urllib.request` -> `urllib`; also flags a banned submodule like `os.system`."""
    parts = dotted.split(".")
    if len(parts) > 1 and parts[0] in {*NETWORK_MODULES, *PROCESS_MODULES}:
        return parts[0]
    return None


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _first_string_arg(node: ast.Call) -> str | None:
    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        return node.args[0].value
    for kw in node.keywords:
        if kw.arg in {"filepath_or_buffer", "path", "filename", "buf"} and \
                isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return kw.value.value
    return None


def _looks_like_escape_path(value: str) -> bool:
    if not value or len(value) > 200 or "\n" in value:
        return False
    parts = Path(value).parts
    if not parts:
        return False
    absolute = value.startswith("/") or value.startswith("~") or bool(Path(value).anchor)
    return bool(absolute or ".." in parts)


def precheck(source: str, policy: Policy) -> PrecheckResult:
    """Run every static rule. Returns findings; empty findings means "allowed to run"."""
    findings_header: list[Finding] = []
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        reason = f"blocked: syntax error at line {exc.lineno} ({exc.msg})"
        return PrecheckResult(accepted=False,
                              findings=[Finding(rule="parse", reason=reason, line=exc.lineno or 1)],
                              lines_checked=len(source.splitlines()))

    visitor = _Visitor(policy, source)
    visitor.visit(tree)
    findings = findings_header + visitor.findings

    # Undeclared capability: code reaching for something the model did not ask for. The
    # reason string stays canonical; the flag is what the approval UI reads.
    for finding in findings:
        if finding.capability and finding.capability not in policy.requested_capabilities \
                and finding.capability not in policy.granted_capabilities:
            finding.undeclared = True

    return PrecheckResult(accepted=not findings, findings=findings,
                          lines_checked=len(source.splitlines()))


def capabilities_needed(source: str) -> set[str]:
    """What the code actually touches, independent of what the model claimed."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    needs: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            for name in names:
                root = _module_root(name)
                if root in NETWORK_MODULES:
                    needs.add(CAP_NETWORK)
                if root in PROCESS_MODULES:
                    needs.add(CAP_PROCESS)
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name == "open":
                needs.add(CAP_FS_READ)
                if _is_write_call(node):
                    needs.add(CAP_FS_WRITE)
            elif name in WRITE_METHOD_NAMES:
                needs.add(CAP_FS_WRITE)
            elif name in READ_METHOD_NAMES:
                needs.add(CAP_FS_READ)
    return needs


def _is_write_call(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Attribute) and node.func.attr in WRITE_METHOD_NAMES:
        return node.func.attr != "open" or _open_mode_is_write(node)
    return False


def _open_mode_is_write(node: ast.Call) -> bool:
    mode = ""
    if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
        mode = str(node.args[1].value)
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            mode = str(kw.value.value)
    return any(ch in mode for ch in ("w", "a", "x", "+"))


def normalize_capability_requests(requested: list[str]) -> list[str]:
    """Map the model's free-form capability list onto the canonical set."""
    out: list[str] = []
    for item in requested or []:
        token = str(item).strip().lower()
        if not token or token == "none":
            continue
        if token.startswith("read:"):
            token = CAP_FS_READ if "data" in token else f"read:{token.split(':', 1)[1]}"
        elif token.startswith("write:"):
            token = CAP_FS_WRITE if "artifacts" in token else f"write:{token.split(':', 1)[1]}"
        elif token in {"net", "internet"}:
            token = CAP_NETWORK
        if token not in out:
            out.append(token)
    return out or ["none"]
