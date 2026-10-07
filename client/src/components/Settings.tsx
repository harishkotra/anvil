import { useEffect, useState, type ReactNode } from "react";
import { api } from "../api";
import type { ConnectionTest, Preset, Settings } from "../types";

const CAPABILITIES = ["network", "process", "read:./data", "write:./artifacts"];

export default function SettingsModal({
  settings,
  onSave,
  onClose,
}: {
  settings: Settings;
  onSave: (next: Settings) => void;
  onClose: () => void;
}) {
  const [draft, setDraft] = useState<Settings>({ ...settings });
  const [presets, setPresets] = useState<Preset[]>([]);
  const [test, setTest] = useState<ConnectionTest | null>(null);
  const [testing, setTesting] = useState(false);
  const [pathLists, setPathLists] = useState({
    read: settings.allowedReadPaths.join(", "),
    write: settings.allowedWritePaths.join(", "),
  });

  useEffect(() => {
    api
      .defaults()
      .then((payload: any) => setPresets((payload?.presets || []) as Preset[]))
      .catch(() => {});
  }, []);

  const patch = (changes: Partial<Settings>) => setDraft((current) => ({ ...current, ...changes }));

  const applyPreset = (preset: Preset) =>
    patch({ baseUrl: preset.baseUrl || draft.baseUrl, model: preset.model || draft.model });

  const runTest = async () => {
    setTesting(true);
    setTest(null);
    try {
      setTest((await api.testConnection(draft)) as ConnectionTest);
    } catch (exc) {
      setTest({ ok: false, error: String(exc instanceof Error ? exc.message : exc) });
    } finally {
      setTesting(false);
    }
  };

  const save = () =>
    onSave({
      ...draft,
      allowedReadPaths: splitList(pathLists.read),
      allowedWritePaths: splitList(pathLists.write),
    });

  const toggleCapability = (capability: string) => {
    const current = new Set(draft.approvedCapabilities);
    if (current.has(capability)) current.delete(capability);
    else current.add(capability);
    patch({ approvedCapabilities: [...current] });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/70 p-4">
      <div className="max-h-full w-full max-w-2xl overflow-auto rounded-md border border-ink-600 bg-ink-900">
        <div className="pane-head sticky top-0 z-10">
          <span className="pane-title">settings</span>
          <span className="text-[10px] text-slate-600">saved to localStorage anvil.settings.v1</span>
        </div>

        <div className="space-y-4 p-4 text-[11px]">
          <section>
            <SectionTitle>inference</SectionTitle>
            <div className="grid grid-cols-2 gap-2">
              <Field label="base URL">
                <input
                  value={draft.baseUrl}
                  onChange={(e) => patch({ baseUrl: e.target.value })}
                  className="w-full rounded-sm border border-ink-600 bg-ink-850 px-2 py-1 text-slate-200"
                />
              </Field>
              <Field label="model">
                <input
                  value={draft.model}
                  onChange={(e) => patch({ model: e.target.value })}
                  className="w-full rounded-sm border border-ink-600 bg-ink-850 px-2 py-1 text-slate-200"
                />
              </Field>
              <Field label="api key">
                <input
                  value={draft.apiKey}
                  type="password"
                  onChange={(e) => patch({ apiKey: e.target.value })}
                  className="w-full rounded-sm border border-ink-600 bg-ink-850 px-2 py-1 text-slate-200"
                />
              </Field>
              <Field label="generation">
                <select
                  value={draft.generationMode}
                  onChange={(e) => patch({ generationMode: e.target.value as Settings["generationMode"] })}
                  className="w-full rounded-sm border border-ink-600 bg-ink-850 px-2 py-1 text-slate-200"
                >
                  <option value="codeagent">smolagents CodeAgent (sandbox executor)</option>
                  <option value="direct">single-turn tool prompt</option>
                </select>
              </Field>
            </div>

            <div className="mt-2 flex flex-wrap items-center gap-1">
              {presets.map((preset) => (
                <button
                  key={preset.id}
                  onClick={() => applyPreset(preset)}
                  className={`rounded-sm border px-2 py-1 text-[10px] ${
                    draft.baseUrl === preset.baseUrl
                      ? "border-anvil-purple text-white"
                      : "border-ink-600 text-slate-400 hover:border-ink-500"
                  }`}
                >
                  {preset.id}
                  <span className="ml-1 text-slate-600">{preset.note}</span>
                </button>
              ))}
              <button
                onClick={runTest}
                disabled={testing}
                className="ml-auto rounded-sm border border-anvil-cyan/60 px-2 py-1 text-[10px] text-anvil-cyan disabled:opacity-50"
              >
                {testing ? "testing…" : "test connection"}
              </button>
            </div>

            {test && (
              <div className="mt-2 rounded-sm border border-ink-600 bg-ink-850 p-2">
                <p className={test.ok ? "text-anvil-green" : "text-anvil-red"}>
                  {test.ok ? "reachable" : "failed"} · HTTP {String(test.status ?? "—")} ·{" "}
                  {test.latencyMs ?? 0}ms
                </p>
                {test.reply && <p className="text-slate-400">reply: {test.reply}</p>}
                {test.error && <p className="text-slate-400">error: {test.error}</p>}
                {test.warning && <p className="text-anvil-amber">warning: {test.warning}</p>}
                {test.note && <p className="text-slate-500">note: {test.note}</p>}
                {test.models?.length ? (
                  <p className="mt-1 text-slate-500">
                    models: {test.models.slice(0, 8).join(", ")}
                    {test.models.length > 8 ? ` (+${test.models.length - 8})` : ""}
                  </p>
                ) : null}
                {test.body && (
                  <pre className="mt-1 max-h-24 overflow-auto text-[10px] text-slate-600">
                    {test.body.slice(0, 600)}
                  </pre>
                )}
              </div>
            )}
          </section>

          <section>
            <SectionTitle>sandbox limits</SectionTitle>
            <div className="grid grid-cols-4 gap-2">
              <Num label="timeout s" value={draft.timeoutS} onChange={(v) => patch({ timeoutS: v })} />
              <Num label="memory MB" value={draft.memoryMb} onChange={(v) => patch({ memoryMb: v })} />
              <Num label="CPU s" value={draft.cpuS} onChange={(v) => patch({ cpuS: v })} />
              <Num
                label="max output B"
                value={draft.maxOutputBytes}
                onChange={(v) => patch({ maxOutputBytes: v })}
              />
            </div>
            <label className="mt-2 flex items-center gap-2 text-slate-300">
              <input
                type="checkbox"
                checked={draft.allowNetwork}
                onChange={(e) => patch({ allowNetwork: e.target.checked })}
              />
              allow network (off = egress refused by policy)
            </label>
          </section>

          <section>
            <SectionTitle>allowed paths</SectionTitle>
            <Field label="read paths (comma separated)">
              <input
                value={pathLists.read}
                onChange={(e) => setPathLists((p) => ({ ...p, read: e.target.value }))}
                className="w-full rounded-sm border border-ink-600 bg-ink-850 px-2 py-1 text-slate-200"
              />
            </Field>
            <Field label="write paths (comma separated)">
              <input
                value={pathLists.write}
                onChange={(e) => setPathLists((p) => ({ ...p, write: e.target.value }))}
                className="mt-1 w-full rounded-sm border border-ink-600 bg-ink-850 px-2 py-1 text-slate-200"
              />
            </Field>
          </section>

          <section>
            <SectionTitle>capability approvals</SectionTitle>
            <p className="mb-2 text-[10px] text-slate-500">
              the model can request these; only this list grants them. a denied capability
              produces a visible failure, never a silent workaround.
            </p>
            <div className="flex flex-wrap gap-1">
              {CAPABILITIES.map((capability) => {
                const approved = draft.approvedCapabilities.includes(capability);
                return (
                  <button
                    key={capability}
                    onClick={() => toggleCapability(capability)}
                    className={`rounded-sm border px-2 py-1 text-[10px] ${
                      approved
                        ? "border-anvil-green/60 text-anvil-green"
                        : "border-ink-600 text-slate-500 hover:border-ink-500"
                    }`}
                  >
                    {approved ? "approved" : "not approved"}: {capability}
                  </button>
                );
              })}
            </div>
          </section>
        </div>

        <div className="sticky bottom-0 flex justify-end gap-2 border-t border-ink-700 bg-ink-850 px-4 py-3">
          <button onClick={onClose} className="rounded-sm border border-ink-600 px-3 py-1 text-slate-400">
            cancel
          </button>
          <button onClick={save} className="rounded-sm bg-anvil-purple px-3 py-1 font-semibold text-white">
            save
          </button>
        </div>
      </div>
    </div>
  );
}

const SectionTitle = ({ children }: { children: ReactNode }) => (
  <h3 className="mb-1 text-[9px] uppercase tracking-[0.18em] text-slate-500">{children}</h3>
);

const Field = ({ label, children }: { label: string; children: ReactNode }) => (
  <label className="block">
    <span className="text-[9px] uppercase tracking-wider text-slate-600">{label}</span>
    {children}
  </label>
);

function Num({
  label,
  value,
  onChange,
}: {
  label: string;
  value: number;
  onChange: (next: number) => void;
}) {
  return (
    <label className="block">
      <span className="text-[9px] uppercase tracking-wider text-slate-600">{label}</span>
      <input
        type="number"
        value={value}
        onChange={(e) => onChange(Number(e.target.value) || 0)}
        className="w-full rounded-sm border border-ink-600 bg-ink-850 px-2 py-1 text-slate-200"
      />
    </label>
  );
}

function splitList(raw: string): string[] {
  return raw
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}
