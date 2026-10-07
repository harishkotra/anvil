import { useEffect, useState } from "react";
import { api } from "../api";
import type { Artifact, RunState } from "../types";

export default function Artifacts({ run }: { run: RunState | null }) {
  const artifacts = run?.result?.artifacts ?? [];
  const [selected, setSelected] = useState<Artifact | null>(null);
  const [preview, setPreview] = useState<string>("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!artifacts.length) {
      setSelected(null);
      return;
    }
    setSelected(artifacts[0]);
  }, [artifacts]);

  useEffect(() => {
    let cancelled = false;
    setPreview("");
    setError(null);
    if (!selected || !run || selected.type === "image") return;
    api
      .artifactText(run.id, selected.name)
      .then((text) => !cancelled && setPreview(text))
      .catch((exc) => !cancelled && setError(String(exc.message || exc)));
    return () => {
      cancelled = true;
    };
  }, [selected, run?.id]);

  return (
    <section className="pane min-h-[220px] flex-1">
      <div className="pane-head">
        <span className="pane-title">artifacts</span>
        <span className="text-[10px] text-slate-500">{artifacts.length} file(s)</span>
      </div>

      {!artifacts.length ? (
        <p className="p-4 text-xs text-slate-600">
          files the sandboxed run actually wrote under ALLOWED_WRITE_PATHS, collected to
          artifacts/&lt;runId&gt;/ with real sizes.
        </p>
      ) : (
        <div className="flex min-h-0 flex-1 flex-col">
          <ul className="flex flex-wrap gap-1 border-b border-ink-700 bg-ink-900 p-2">
            {artifacts.map((artifact) => (
              <li key={artifact.name}>
                <button
                  onClick={() => setSelected(artifact)}
                  className={`rounded-sm border px-2 py-1 text-[10px] ${
                    selected?.name === artifact.name
                      ? "border-anvil-purple text-white"
                      : "border-ink-600 text-slate-400 hover:border-ink-500"
                  }`}
                >
                  {artifact.name}
                  <span className="ml-1 text-slate-600">{formatBytes(artifact.bytes)}</span>
                </button>
              </li>
            ))}
          </ul>

          <div className="min-h-0 flex-1 overflow-auto bg-ink-950 p-3">
            {selected?.type === "image" && run ? (
              <img
                src={api.artifactUrl(run.id, selected.name)}
                alt={selected.name}
                className="max-h-[420px] rounded-sm border border-ink-700 bg-white object-contain"
              />
            ) : error ? (
              <p className="text-[11px] text-anvil-red">{error}</p>
            ) : selected?.type === "table" ? (
              <CsvTable text={preview} />
            ) : (
              <pre className="whitespace-pre-wrap text-[11px] text-slate-300">{preview}</pre>
            )}
          </div>
        </div>
      )}
    </section>
  );
}

function CsvTable({ text }: { text: string }) {
  const rows = text
    .trim()
    .split("\n")
    .slice(0, 60)
    .map((line) => line.split(","));
  if (rows.length < 2) {
    return <pre className="text-[11px] text-slate-300">{text}</pre>;
  }
  const [header, ...body] = rows;
  return (
    <table className="w-full border-collapse text-[11px]">
      <thead>
        <tr>
          {header.map((cell, index) => (
            <th
              key={index}
              className="border-b border-ink-600 px-2 py-1 text-left text-anvil-cyan"
            >
              {cell}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {body.map((row, rowIndex) => (
          <tr key={rowIndex} className="odd:bg-ink-900/50">
            {row.map((cell, cellIndex) => (
              <td key={cellIndex} className="px-2 py-1 text-slate-300">
                {cell}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
