import { DEFAULT_SETTINGS, type Settings } from "./types";

const json = async (response: Response) => {
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`HTTP ${response.status}: ${text.slice(0, 400)}`);
  }
  return response.json();
};

export const api = {
  isolation: () => fetch("/api/isolation").then(json),
  defaults: () => fetch("/api/settings/defaults").then(json),
  escapes: () => fetch("/api/escapes").then(json),
  tasks: () => fetch("/api/tasks").then(json),
  run: (id: string) => fetch(`/api/task/${id}`).then(json),
  createTask: (task: string, settings: Settings) =>
    fetch("/api/task", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ task, settings }),
    }).then(json),
  breakIt: (attempt: string, settings: Settings) =>
    fetch("/api/break", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ attempt, settings }),
    }).then(json),
  testConnection: (settings: Settings) =>
    fetch("/api/models/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(settings),
    }).then(json),
  artifactText: async (runId: string, name: string) => {
    const response = await fetch(`/api/artifacts/${encodeURIComponent(runId)}/${name}`);
    if (!response.ok) throw new Error(`could not read artifact (${response.status})`);
    return response.text();
  },
  artifactUrl: (runId: string, name: string) =>
    `/api/artifacts/${encodeURIComponent(runId)}/${encodeURIComponent(name)}`,
};

/** Precedence: shipped defaults < what the server's .env says < what the user saved. */
export function loadSettings(serverDefaults?: Partial<Settings>): Settings {
  const stored = readStored();
  return {
    ...DEFAULT_SETTINGS,
    ...(serverDefaults || {}),
    ...stored,
  };
}

function readStored(): Partial<Settings> {
  try {
    const raw = localStorage.getItem("anvil.settings.v1");
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

export function saveSettings(settings: Settings) {
  try {
    localStorage.setItem("anvil.settings.v1", JSON.stringify(settings));
  } catch {
    /* storage full or blocked; the run still uses the in-memory settings */
  }
}
