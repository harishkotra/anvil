import type { IsolationReport, RunState } from "../types";

const KIND_STYLE: Record<string, string> = {
  policy: "border-l-anvil-purple/70 text-slate-300",
  "exec-start": "border-l-anvil-cyan/70 text-slate-300",
  blocked: "border-l-anvil-red bg-anvil-red/10 text-anvil-red",
  killed: "border-l-anvil-amber bg-anvil-amber/10 text-anvil-amber",
  resource: "border-l-slate-500 text-slate-300",
  artifact: "border-l-anvil-green/70 text-slate-300",
  info: "border-l-slate-600 text-slate-400",
  done: "border-l-slate-400 text-slate-200",
};

const EVENT_LABEL: Record<string, string> = {
  queued: "queued",
  status: "state",
  generating: "model call",
  "agent-action": "code action (sandboxed)",
  spec: "tool spec received",
  "capability-request": "capability request — needs your approval",
  "precheck-failed": "pre-check rejected — retrying once",
  error: "error",
  done: "run finished",
};

export default function SandboxTrace({
  run,
  isolation,
}: {
  run: RunState | null;
  isolation: IsolationReport | null;
}) {
  const trace = run?.result?.trace ?? [];
  const events = run?.events ?? [];
  const blockedCount = run?.result?.blocked?.length ?? 0;

  return (
    <section className="pane">
      <div className="pane-head">
        <span className="pane-title">sandbox trace</span>
        <div className="flex items-center gap-2 text-[10px]">
          <span className="chip border-slate-600 text-slate-400">
            {isolation?.level ?? "detecting…"}
          </span>
          <span
            className={`chip ${blockedCount ? "border-anvil-red/60 text-anvil-red" : "border-slate-600 text-slate-500"}`}
          >
            {blockedCount} blocked
          </span>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        {events.length === 0 && trace.length === 0 ? (
          <p className="p-4 text-xs text-slate-600">
            the trace records the static verdict, the execution, every refused call with its
            reason, and the resource accounting.
          </p>
        ) : (
          <ol className="text-[11px]">
            {events.map((event, index) => (
              <li
                key={`e${index}`}
                className="border-l-2 border-l-ink-600 bg-ink-900/40 px-3 py-1.5 text-slate-400"
              >
                <span className="text-slate-600">+{event.atMs}ms</span>{" "}
                <span className="text-slate-500">{EVENT_LABEL[event.kind] || event.kind}</span>{" "}
                {describe(event)}
              </li>
            ))}
            {trace.map((event, index) => (
              <li
                key={`t${index}`}
                className={`border-l-2 px-3 py-1.5 ${KIND_STYLE[event.kind] || "border-l-slate-700 text-slate-400"}`}
              >
                <span className="text-slate-600">+{event.atMs}ms</span>{" "}
                <span className="break-words">{event.message}</span>
                {event.kind === "blocked" && layerOf(event.detail) && (
                  <span className="ml-1 text-[10px] text-slate-500">[{layerOf(event.detail)}]</span>
                )}
              </li>
            ))}
          </ol>
        )}
      </div>

      {run?.result && (
        <div className="grid grid-cols-3 gap-px border-t border-ink-700 bg-ink-700 text-center text-[10px]">
          <Cell
            label="peak RSS"
            value={`${run.result.resources.peakRssMb ?? 0} MB`}
            cap={`cap ${run.result.resources.capRssMb} MB`}
          />
          <Cell
            label="cpu"
            value={`${(((run.result.resources.cpuUserS ?? 0) +
              (run.result.resources.cpuSysS ?? 0)) as number).toFixed(2)}s`}
            cap={`cap ${run.result.resources.capCpuS}s`}
          />
          <Cell
            label="wall"
            value={`${(run.result.resources.wallS ?? 0).toFixed(2)}s`}
            cap={`cap ${run.result.resources.capTimeoutS}s`}
          />
        </div>
      )}

      {run?.result && (run.result.stdout || run.result.stderr) && (
        <div className="max-h-40 overflow-auto border-t border-ink-700 bg-ink-950 px-3 py-2">
          {run.result.stdout && (
            <pre className="whitespace-pre-wrap text-[11px] text-slate-300">
              {run.result.stdout}
            </pre>
          )}
          {run.result.stderr && (
            <pre className="mt-1 whitespace-pre-wrap text-[11px] text-anvil-red/80">
              {run.result.stderr.slice(0, 1500)}
            </pre>
          )}
        </div>
      )}
    </section>
  );
}

const layerOf = (detail: Record<string, unknown>) =>
  typeof detail?.layer === "string" ? detail.layer : "";

function Cell({ label, value, cap }: { label: string; value: string; cap: string }) {
  return (
    <div className="bg-ink-900 px-2 py-1.5">
      <div className="text-slate-500">{label}</div>
      <div className="text-slate-200">{value}</div>
      <div className="text-[9px] text-slate-600">{cap}</div>
    </div>
  );
}

function describe(event: { kind: string } & Record<string, unknown>): string {
  if (event.kind === "capability-request") {
    const pending = (event.pending as string[]) || [];
    return `requested ${pending.join(", ")} — not granted`;
  }
  if (event.kind === "agent-action") {
    const blocked = (event.blocked as string[]) || [];
    return `${String(event.status)}${blocked.length ? ` · ${blocked[0]}` : ""}`;
  }
  if (event.kind === "precheck-failed") {
    const reasons = (event.reasons as string[]) || [];
    return reasons.slice(0, 2).join(" · ");
  }
  if (event.kind === "status" || event.kind === "done") {
    return String(event.status ?? event.message ?? "");
  }
  if (event.kind === "generating") {
    return `${String(event.mode)} · ${String(event.model)}`;
  }
  if (event.kind === "spec") {
    const tool = event.tool as { toolName?: string } | undefined;
    return String(tool?.toolName ?? "");
  }
  return String(event.message ?? "");
}
