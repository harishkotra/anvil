import { useEffect, useState } from "react";
import { api } from "../api";
import type { BreakResponse, EscapeAttempt, IsolationReport, Settings } from "../types";

export default function BreakPanel({
  settings,
  isolation,
}: {
  settings: Settings;
  isolation: IsolationReport | null;
}) {
  const [attempts, setAttempts] = useState<EscapeAttempt[]>([]);
  const [results, setResults] = useState<Record<string, BreakResponse | { error: string }>>({});
  const [running, setRunning] = useState<string | null>(null);

  useEffect(() => {
    api.escapes().then((list) => setAttempts(list as EscapeAttempt[])).catch(() => {});
  }, []);

  const fire = async (attempt: string) => {
    setRunning(attempt);
    try {
      const result = (await api.breakIt(attempt, settings)) as BreakResponse;
      setResults((current) => ({ ...current, [attempt]: result }));
    } catch (exc) {
      setResults((current) => ({
        ...current,
        [attempt]: { error: String(exc instanceof Error ? exc.message : exc) },
      }));
    } finally {
      setRunning(null);
    }
  };

  return (
    <section className="border-t border-ink-700 bg-ink-900">
      <div className="flex items-center justify-between px-4 py-2">
        <div className="flex items-center gap-2">
          <span className="pane-title">try to break it</span>
          <span className="text-[10px] text-slate-500">
            each attempt runs the real pipeline: static pre-check, then execution with the
            pre-check bypassed so the runtime layers have to answer
          </span>
        </div>
        <button
          onClick={() => attempts.forEach((attempt) => fire(attempt.id))}
          disabled={!!running || !attempts.length}
          className="rounded-sm border border-anvil-red/60 px-3 py-1 text-[11px] text-anvil-red hover:bg-anvil-red/10 disabled:opacity-40"
        >
          run all four
        </button>
      </div>

      <div className="grid grid-cols-1 gap-2 px-4 pb-4 md:grid-cols-2 xl:grid-cols-4">
        {attempts.map((attempt) => {
          const raw = results[attempt.id];
          const result = raw && "attempt" in raw ? (raw as BreakResponse) : null;
          const failure = raw && !("attempt" in raw) ? (raw as { error: string }).error : null;
          const passed = !!result && result.blocked;
          return (
            <div key={attempt.id} className="rounded-md border border-ink-700 bg-ink-850 p-2">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <p className="text-[11px] text-slate-200">{attempt.label}</p>
                  <p className="text-[10px] text-slate-500">{attempt.intent}</p>
                </div>
                <button
                  onClick={() => fire(attempt.id)}
                  disabled={running === attempt.id}
                  className="rounded-sm border border-ink-600 px-2 py-0.5 text-[10px] text-slate-300 hover:border-anvil-red hover:text-anvil-red disabled:opacity-40"
                >
                  {running === attempt.id ? "…" : "break"}
                </button>
              </div>

              <div className="mt-2 space-y-1">
                {failure && <p className="text-[10px] text-anvil-amber">{failure}</p>}
                {result && (
                  <>
                    <Line
                      label="pre-check"
                      ok={passed}
                      text={
                        result.precheck.accepted
                          ? "not caught statically (runtime had to decide)"
                          : result.precheck.reasons[0]
                      }
                    />
                    <Line
                      label="runtime"
                      ok={passed}
                      text={
                        result.runtime.blocked[0] ||
                        `no hook record — status ${result.runtime.status}, exit ${result.runtime.exitCode}`
                      }
                    />
                    <div className="flex items-center justify-between pt-1">
                      <span className="text-[9px] text-slate-600">
                        kernel: {result.runtime.isolation} · artifacts written:{" "}
                        {result.runtime.artifacts.length}
                      </span>
                      <span
                        className={`chip ${passed ? "border-anvil-green/60 text-anvil-green" : "border-anvil-red/60 text-anvil-red"}`}
                      >
                        {passed ? "blocked" : "ESCAPED"}
                      </span>
                    </div>
                  </>
                )}
                {!result && !failure && (
                  <p className="text-[10px] text-slate-600">
                    not run yet — isolation available: {isolation?.level ?? "…"}
                  </p>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function Line({ label, ok, text }: { label: string; ok: boolean; text: string }) {
  return (
    <div className="rounded-sm border border-ink-700 bg-ink-900 px-2 py-1">
      <div className="flex items-center gap-1 text-[9px] uppercase tracking-wider text-slate-600">
        <span
          className={ok ? "text-anvil-green" : "text-anvil-amber"}
          title={ok ? "refused here" : "did not refuse here"}
        >
          {ok ? "✓" : "·"}
        </span>
        {label}
      </div>
      <p className="break-words text-[10px] text-slate-300">{text}</p>
    </div>
  );
}
