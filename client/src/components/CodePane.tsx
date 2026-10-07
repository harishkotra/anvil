import { useMemo, useState } from "react";
import Prism from "prismjs";
import "prismjs/components/prism-python";
import type { RunState } from "../types";

const LINE_HEIGHT = 20;

export default function CodePane({ run }: { run: RunState | null }) {
  const [copied, setCopied] = useState(false);
  const code = run?.spec?.code ?? "";

  const highlighted = useMemo(() => {
    if (!code) return "";
    try {
      return Prism.highlight(code, Prism.languages.python, "python");
    } catch {
      return code.replace(/&/g, "&amp;").replace(/</g, "&lt;");
    }
  }, [code]);

  const findingsByLine = useMemo(() => {
    const map = new Map<number, { reason: string; undeclared?: boolean }[]>();
    for (const finding of run?.result?.precheck?.findings ?? []) {
      const list = map.get(finding.line) || [];
      list.push({ reason: finding.reason, undeclared: finding.undeclared });
      map.set(finding.line, list);
    }
    return map;
  }, [run]);

  const lines = code ? code.replace(/\n$/, "").split("\n") : [];
  const rejected = run?.result?.precheck && !run.result.precheck.accepted;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      const area = document.createElement("textarea");
      area.value = code;
      document.body.appendChild(area);
      area.select();
      document.execCommand("copy");
      document.body.removeChild(area);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    }
  };

  return (
    <section className="pane">
      <div className="pane-head">
        <div className="flex items-center gap-2">
          <span className="pane-title">generated tool</span>
          {run?.spec && (
            <span className="text-[11px] text-anvil-cyan">{run.spec.toolName}</span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-slate-500">{lines.length} lines</span>
          {run?.generation?.provenance && (
            <span
              title={`spec came from: ${run.generation.provenance}`}
              className="chip border-slate-600 text-slate-400"
            >
              {run.generation.mode?.replace("smolagents-", "")}
            </span>
          )}
          <span
            className={`chip ${rejected ? "border-anvil-red/60 text-anvil-red" : "border-anvil-green/60 text-anvil-green"}`}
          >
            {rejected ? "pre-check rejected" : code ? "pre-check ok" : "idle"}
          </span>
          <button
            onClick={copy}
            disabled={!code}
            className="rounded-sm border border-ink-600 px-2 py-0.5 text-[10px] text-slate-400 hover:border-anvil-purple hover:text-white disabled:opacity-30"
          >
            {copied ? "copied" : "copy"}
          </button>
        </div>
      </div>

      <div className="relative min-h-0 flex-1 overflow-auto bg-ink-950">
        {!code ? (
          <p className="p-4 text-xs text-slate-600">
            nothing yet — forge a tool and the source the agent writes appears here, with the
            pre-check verdict on every line.
          </p>
        ) : (
          <div className="flex min-w-max">
            <div className="select-none border-r border-ink-800 bg-ink-900">
              {lines.map((_, index) => {
                const hits = findingsByLine.get(index + 1);
                const color = hits
                  ? "bg-anvil-red/20 text-anvil-red"
                  : "text-slate-600";
                return (
                  <div
                    key={index}
                    style={{ height: LINE_HEIGHT, lineHeight: `${LINE_HEIGHT}px` }}
                    className={`px-2 text-right text-[10px] ${color}`}
                    title={hits ? hits.map((h) => h.reason).join("\n") : "no finding"}
                  >
                    {index + 1}
                  </div>
                );
              })}
            </div>
            <pre
              className="language-python m-0 px-3"
              style={{ lineHeight: `${LINE_HEIGHT}px` }}
            >
              <code
                className="language-python"
                dangerouslySetInnerHTML={{ __html: highlighted }}
              />
            </pre>
          </div>
        )}
      </div>

      {run?.spec && (
        <div className="border-t border-ink-700 bg-ink-850 px-3 py-2 text-[10px] text-slate-500">
          <span className="text-slate-400">expected output:</span> {run.spec.expectedOutput}
          <span className="mx-2">·</span>
          <span className="text-slate-400">requested:</span>{" "}
          {run.spec.capabilitiesRequested.join(", ") || "none"}
          {run.spec.rationale && (
            <>
              <br />
              <span className="text-slate-400">rationale:</span> {run.spec.rationale}
            </>
          )}
        </div>
      )}

      {findingsByLine.size > 0 && (
        <ul className="max-h-32 overflow-auto border-t border-ink-700 bg-ink-900 px-3 py-2">
          {[...findingsByLine.entries()].map(([line, hits]) =>
            hits.map((hit) => (
              <li key={`${line}-${hit.reason}`} className="py-0.5 text-[10px] text-anvil-red">
                <span className="text-slate-500">L{line}</span> {hit.reason}
                {hit.undeclared && (
                  <span className="ml-1 text-anvil-amber">[capability not declared]</span>
                )}
              </li>
            )),
          )}
        </ul>
      )}
    </section>
  );
}
