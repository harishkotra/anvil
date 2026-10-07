export type CapabilityDecision = {
  requested: string[];
  granted: string[];
  denied: string[];
  pendingApproval: string[];
};

export type Finding = {
  rule: string;
  reason: string;
  line: number;
  capability?: string | null;
  undeclared?: boolean;
};

export type Precheck = {
  accepted: boolean;
  findings: Finding[];
  linesChecked: number;
  reasons: string[];
};

export type BlockedCall = {
  call: string;
  reason: string;
  layer: string;
  line?: number | null;
  display: string;
};

export type TraceEvent = {
  atMs: number;
  kind: string;
  message: string;
  detail: Record<string, unknown>;
};

export type Artifact = {
  name: string;
  bytes: number;
  type: string;
  path: string;
};

export type Resources = {
  peakRssMb?: number;
  cpuUserS?: number;
  cpuSysS?: number;
  wallS?: number;
  capRssMb?: number;
  capCpuS?: number;
  capTimeoutS?: number;
  killedBy?: string | null;
  limitsApplied?: Record<string, unknown>;
};

export type RunResult = {
  run_id: string;
  status: string;
  exit_code: number | null;
  stdout: string;
  stderr: string;
  resources: Resources;
  artifacts: Artifact[];
  trace: TraceEvent[];
  blocked: BlockedCall[];
  precheck: Precheck;
  isolation_level: string;
  duration_ms: number;
  killed_by: string | null;
  unauthorised_writes: string[];
};

export type ToolSpec = {
  toolName: string;
  code: string;
  expectedOutput: string;
  capabilitiesRequested: string[];
  rationale: string;
};

export type AgentAction = {
  runId: string;
  code: string;
  status: string;
  stdout: string;
  artifacts: string[];
  blocked: string[];
};

export type RunState = {
  id: string;
  task: string;
  status: string;
  spec: ToolSpec | null;
  result: RunResult | null;
  capabilities: CapabilityDecision | null;
  generation: {
    mode: string;
    provenance: string;
    error: string | null;
    attempts: unknown[];
    actions: AgentAction[];
    modelLatencyMs: number;
  } | null;
  error: string | null;
  events: StreamEvent[];
};

export type StreamEvent = {
  atMs: number;
  kind: string;
  [key: string]: unknown;
};

export type IsolationReport = {
  level: string;
  available: Record<string, boolean>;
  probes: Record<string, string>;
  enforced: Record<string, string>;
  ladder: string[];
  details: string;
};

export type EscapeAttempt = {
  id: string;
  label: string;
  intent: string;
  code: string;
};

export type BreakResponse = {
  attempt: EscapeAttempt;
  precheck: { accepted: boolean; reasons: string[]; findings: Finding[] };
  runtime: {
    status: string;
    blocked: string[];
    exitCode: number | null;
    stderr: string;
    isolation: string;
    resources: Resources;
    artifacts: Artifact[];
    unauthorisedWrites: string[];
  };
  blocked: boolean;
};

export type Preset = {
  id: string;
  baseUrl: string;
  model: string;
  needsKey: string;
  note: string;
};

export type ConnectionTest = {
  ok: boolean;
  status?: number | null;
  latencyMs?: number;
  reply?: string;
  error?: string;
  body?: string;
  warning?: string | null;
  note?: string | null;
  models?: string[];
  finishReason?: string;
};

export type Settings = {
  baseUrl: string;
  apiKey: string;
  model: string;
  timeoutS: number;
  memoryMb: number;
  cpuS: number;
  allowNetwork: boolean;
  allowedReadPaths: string[];
  allowedWritePaths: string[];
  maxOutputBytes: number;
  approvedCapabilities: string[];
  generationMode: "codeagent" | "direct";
};

export const SETTINGS_KEY = "anvil.settings.v1";

export const DEFAULT_SETTINGS: Settings = {
  baseUrl: "https://api.particle.ai/v1",
  apiKey: "",
  model: "deepseek-v4.1-flash",
  timeoutS: 10,
  memoryMb: 512,
  cpuS: 5,
  allowNetwork: false,
  allowedReadPaths: ["./data"],
  allowedWritePaths: ["./artifacts"],
  maxOutputBytes: 200000,
  approvedCapabilities: [],
  generationMode: "codeagent",
};
