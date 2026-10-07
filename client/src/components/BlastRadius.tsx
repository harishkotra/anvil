import type { ReactNode } from "react";
import type { IsolationReport, RunState, Settings } from "../types";

export default function BlastRadius({
  run,
  isolation,
  settings,
}: {
  run: RunState | null;
  isolation: IsolationReport | null;
  settings: Settings;
}) {
  const result = run?.result;
  const caps = run?.capabilities;
  const blocked = result?.blocked ?? [];
  const precheckBlocked = blocked.filter((b) => b.layer === "pre-check").length;
  const runtimeBlocked = blocked.filter((b) => b.layer !== "pre-check").length;

  return (
    <section className="pane max-h-[46%]">
      <div className="pane-head">
        <span className="pane-title">blast radius</span>
        <span
          className={`chip ${
            isolation?.level === "rlimit-only"
              ? "border-anvil-amber/60 text-anvil-amber"
              : "border-anvil-purple/50 text-anvil-purple"
          }`}
        >
          {isolation?.level ?? "detecting…"}
        </span>
      </div>

      <div className="min-h-0 flex-1 overflow-auto p-3 text-[11px]">
        <Row label="allowed to do">
          <span className="text-anvil-green">
            read {settings.allowedReadPaths.join(", ") || "(nothing)"} · write{" "}
            {settings.allowedWritePaths.join(", ") || "(nothing)"} · print to stdout · use{" "}
            {result?.isolation_level === "rlimit-only" ? "the interpreter only" : "installed data libraries"}
          </span>
        </Row>
        <Row label="refused">
          <span className="text-anvil-red">
            network egress · spawning processes · reading outside the allowed roots · dynamic
            code · interpreter introspection
          </span>
        </Row>

        <div className="mt-3 grid grid-cols-3 gap-px overflow-hidden rounded-sm border border-ink-700 bg-ink-700">
          <Stat label="blocked calls" value={String(blocked.length)} tone="red" />
          <Stat label="by pre-check" value={String(precheckBlocked)} tone="purple" />
          <Stat label="by runtime" value={String(runtimeBlocked)} tone="amber" />
        </div>

        <Group title="capabilities">
          {caps ? (
            <>
              <List
                label="requested by the model"
                items={caps.requested}
                empty="none"
                tone="slate"
              />
              <List label="granted by you" items={caps.granted} empty="none" tone="green" />
              <List label="denied" items={caps.denied} empty="none" tone="red" />
              {caps.pendingApproval?.length > 0 && (
                <p className="mt-1 text-[10px] text-anvil-amber">
                  awaiting approval: {caps.pendingApproval.join(", ")} — the model cannot grant
                  these to itself
                </p>
              )}
            </>
          ) : (
            <p className="text-slate-600">no run yet</p>
          )}
        </Group>

        <Group title="paths touched">
          <p className="text-slate-400">
            jail: <span className="text-slate-300">ephemeral per-run cwd</span>
            <br />
            read roots: {settings.allowedReadPaths.join(", ")}
            <br />
            write roots: {settings.allowedWritePaths.join(", ")}
            <br />
            artifacts collected: {result?.artifacts.length ?? 0}
            <br />
            unauthorised writes:{" "}
            <span
              className={
                result?.unauthorised_writes?.length ? "text-anvil-red" : "text-anvil-green"
              }
            >
              {result ? result.unauthorised_writes.length : "—"}
            </span>
          </p>
        </Group>

        <Group title="what enforces what">
          {isolation ? (
            <ul className="space-y-0.5">
              {Object.entries(isolation.enforced).map(([key, value]) => (
                <li key={key} className="text-[10px]">
                  <span className="text-slate-500">{humanize(key)}: </span>
                  <span className="text-slate-300">{value}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-slate-600">probing…</p>
          )}
        </Group>

        {result && (
          <Group title="resource accounting">
            <p className="text-slate-400">
              peak RSS {result.resources.peakRssMb ?? 0} MB / cap {result.resources.capRssMb} MB
              <br />
              CPU{" "}
              {(((result.resources.cpuUserS ?? 0) + (result.resources.cpuSysS ?? 0)) as number).toFixed(
                2,
              )}
              s / cap {result.resources.capCpuS}s · wall {result.resources.wallS}s / cap{" "}
              {result.resources.capTimeoutS}s
              <br />
              exit code {String(result.exit_code)} · status {result.status}
              {result.killed_by && (
                <span className="text-anvil-amber"> · killed by {result.killed_by}</span>
              )}
            </p>
          </Group>
        )}
      </div>
    </section>
  );
}

const humanize = (key: string) => key.replace(/_/g, " ");

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <p className="mb-1.5 leading-relaxed">
      <span className="text-[9px] uppercase tracking-wider text-slate-600">{label}</span>
      <br />
      {children}
    </p>
  );
}

function Group({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="mt-3 border-t border-ink-700 pt-2">
      <p className="mb-1 text-[9px] uppercase tracking-wider text-slate-600">{title}</p>
      {children}
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: string; tone: string }) {
  const color =
    tone === "red"
      ? "text-anvil-red"
      : tone === "amber"
        ? "text-anvil-amber"
        : tone === "purple"
          ? "text-anvil-purple"
          : "text-slate-300";
  return (
    <div className="bg-ink-900 px-2 py-2 text-center">
      <div className={`text-base ${color}`}>{value}</div>
      <div className="text-[9px] uppercase tracking-wider text-slate-600">{label}</div>
    </div>
  );
}

function List({
  label,
  items,
  empty,
  tone,
}: {
  label: string;
  items: string[];
  empty: string;
  tone: "green" | "red" | "slate";
}) {
  const color =
    tone === "green" ? "text-anvil-green" : tone === "red" ? "text-anvil-red" : "text-slate-400";
  return (
    <p className="text-[10px]">
      <span className="text-slate-600">{label}: </span>
      <span className={color}>{items?.length ? items.join(", ") : empty}</span>
    </p>
  );
}
