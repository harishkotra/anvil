import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, loadSettings, saveSettings } from "./api";
import Artifacts from "./components/Artifacts";
import BlastRadius from "./components/BlastRadius";
import BreakPanel from "./components/BreakPanel";
import CodePane from "./components/CodePane";
import SandboxTrace from "./components/SandboxTrace";
import Settings from "./components/Settings";
import type { IsolationReport, RunState, Settings as SettingsType } from "./types";

const STATUS_COLORS: Record<string, string> = {
  queued: "border-slate-600 text-slate-400",
  "writing-code": "border-anvil-cyan/60 text-anvil-cyan",
  generating: "border-anvil-cyan/60 text-anvil-cyan",
  running: "border-anvil-amber/60 text-anvil-amber",
  success: "border-anvil-green/60 text-anvil-green",
  blocked: "border-anvil-red/60 text-anvil-red",
  "pre-check-failed": "border-anvil-red/60 text-anvil-red",
  "timeout-killed": "border-anvil-amber/60 text-anvil-amber",
  killed: "border-anvil-amber/60 text-anvil-amber",
  failed: "border-anvil-red/60 text-anvil-red",
};

const EXAMPLE_TASKS = [
  "Sum net_amount by region in ./data/sales_2025.csv, write ./artifacts/region_totals.csv and print the total",
  "Plot monthly gross profit from ./data/sales_2025.csv as ./artifacts/profit_by_month.png and print the peak month",
  "Find machines whose return_temp_c rises in ./data/sensor_log.csv; write ./artifacts/anomalies.csv and summarise",
];

export default function App() {
  const [settings, setSettings] = useState<SettingsType>(() => loadSettings());
  const [isolation, setIsolation] = useState<IsolationReport | null>(null);
  const [task, setTask] = useState(EXAMPLE_TASKS[0]);
  const [run, setRun] = useState<RunState | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const streamRef = useRef<EventSource | null>(null);

  const status = run?.status ?? "idle";

  const refreshRun = useCallback(async (id: string) => {
    const state = (await api.run(id)) as RunState;
    setRun(state);
    return state;
  }, []);

  useEffect(() => {
    api.isolation().then((report) => setIsolation(report as IsolationReport)).catch(() => {});
    api
      .defaults()
      .then((payload: any) => setSettings(loadSettings(payload?.settings)))
      .catch(() => {});
    // A finished run is addressable, so results can be linked and re-opened.
    const preset = new URLSearchParams(window.location.search).get("run");
    if (preset) refreshRun(preset).catch(() => {});
    return () => streamRef.current?.close();
  }, [refreshRun]);

  const startRun = useCallback(async () => {
    if (!task.trim() || busy) return;
    setBusy(true);
    setError(null);
    streamRef.current?.close();
    try {
      const created = await api.createTask(task.trim(), settings);
      const source = new EventSource(`/api/task/${created.runId}/stream`);
      streamRef.current = source;
      source.addEventListener("end", () => {
        source.close();
        refreshRun(created.runId).finally(() => setBusy(false));
      });
      source.onmessage = (message) => {
        try {
          JSON.parse(message.data);
        } catch {
          /* malformed progress frames are ignored; the final state is fetched anyway */
        }
        refreshRun(created.runId);
      };
      source.onerror = () => {
        source.close();
        refreshRun(created.runId).finally(() => setBusy(false));
      };
      await refreshRun(created.runId);
    } catch (exc) {
      setError(String(exc instanceof Error ? exc.message : exc));
      setBusy(false);
    }
  }, [busy, refreshRun, settings, task]);

  const updateSettings = useCallback((next: SettingsType) => {
    setSettings(next);
    saveSettings(next);
  }, []);

  const statusClass = useMemo(
    () => STATUS_COLORS[status] || "border-slate-600 text-slate-400",
    [status],
  );

  return (
    <div className="flex h-full flex-col">
      <header className="border-b border-ink-700 bg-ink-900 px-4 py-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-baseline gap-3">
            <h1 className="text-sm font-semibold tracking-[0.2em] text-slate-100">ANVIL</h1>
            <span className="text-[11px] text-slate-500">
              the agent writes the tool · the sandbox decides what it may do
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className={`chip ${isolation?.level === "rlimit-only" ? "border-anvil-amber/60 text-anvil-amber" : "border-anvil-purple/50 text-anvil-purple"}`}>
              isolation: {isolation?.level ?? "detecting…"}
            </span>
            <span className="chip border-slate-600 text-slate-400">
              {settings.model || "no model"}
            </span>
            <span className={`chip ${statusClass}`}>{status}</span>
            <button
              onClick={() => setShowSettings(true)}
              className="rounded-sm border border-ink-600 px-2 py-1 text-[11px] text-slate-300 hover:border-anvil-purple hover:text-white"
            >
              settings
            </button>
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-start gap-2">
          <textarea
            value={task}
            onChange={(event) => setTask(event.target.value)}
            rows={2}
            spellCheck={false}
            placeholder="Give the agent a task over ./data"
            className="min-w-[320px] flex-1 resize-y rounded-sm border border-ink-600 bg-ink-850 px-3 py-2 text-xs text-slate-200 outline-none focus:border-anvil-purple"
          />
          <button
            onClick={startRun}
            disabled={busy || !task.trim()}
            className="h-full rounded-sm bg-anvil-purple px-4 py-2 text-xs font-semibold text-white disabled:cursor-not-allowed disabled:opacity-40"
          >
            {busy ? "working…" : "forge tool"}
          </button>
        </div>
        <div className="mt-2 flex flex-wrap gap-2">
          {EXAMPLE_TASKS.map((example, index) => (
            <button
              key={example}
              onClick={() => setTask(example)}
              className="rounded-sm border border-ink-700 px-2 py-1 text-[10px] text-slate-500 hover:border-ink-500 hover:text-slate-300"
            >
              task {index + 1}
            </button>
          ))}
        </div>
        {error && <p className="mt-2 text-[11px] text-anvil-red">{error}</p>}
        {run?.error && (
          <p className="mt-2 text-[11px] text-anvil-red">run error: {run.error}</p>
        )}
      </header>

      <main className="grid min-h-0 flex-1 grid-cols-1 gap-2 p-2 lg:grid-cols-[1fr_1.1fr_1fr]">
        <CodePane run={run} />
        <SandboxTrace run={run} isolation={isolation} />
        <div className="flex min-h-0 flex-col gap-2">
          <Artifacts run={run} />
          <BlastRadius run={run} isolation={isolation} settings={settings} />
        </div>
      </main>

      <BreakPanel settings={settings} isolation={isolation} />

      <footer className="flex items-center justify-between border-t border-ink-700 bg-ink-950 px-4 py-2 text-[10px] text-slate-600">
        <span>
          smolagents CodeAgent · {isolation?.level ?? "…"} sandbox · {settings.model || "no model"}
        </span>
        <span>
          Built by{" "}
          <a
            href="https://harishkotra.me"
            target="_blank"
            rel="noreferrer"
            className="text-anvil-purple hover:underline"
          >
            Harish Kotra
          </a>
          {" · "}
          <a
            href="https://dailybuild.xyz"
            target="_blank"
            rel="noreferrer"
            className="text-anvil-cyan hover:underline"
          >
            Checkout my other builds
          </a>
        </span>
      </footer>

      {showSettings && (
        <Settings
          settings={settings}
          onClose={() => setShowSettings(false)}
          onSave={(next) => {
            updateSettings(next);
            setShowSettings(false);
          }}
        />
      )}
    </div>
  );
}
