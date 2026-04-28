import type { AgentGateClient } from "./client.js";
import { decideOrDeny } from "./client.js";
import type {
  AdapterRegistration,
  GuardDecision,
  Obligation,
  PolicyRequest,
  Surface,
} from "./types.js";

export interface AgentGateOpenClawConfig {
  base_url?: string;
  baseUrl?: string;
  adapter_id?: string;
  adapterId?: string;
  integration_id?: string;
  integrationId?: string;
  host_version?: string;
  hostVersion?: string;
  input_hook_name?: string;
  inputHookName?: string;
  runtime_hook_name?: string;
  runtimeHookName?: string;
  adapter_token?: string;
  adapterToken?: string;
}

export interface NormalizedAgentGateOpenClawConfig {
  baseUrl: string;
  adapterId: string;
  integrationId?: string;
  hostVersion?: string;
  inputHookName: string;
  runtimeHookName: string;
  adapterToken?: string;
}

export interface OpenClawInputEvent {
  session_id?: string;
  sessionId?: string;
  sessionKey?: string;
  task_id?: string;
  taskId?: string;
  user_id?: string;
  userId?: string;
  from?: string;
  host_id?: string;
  hostId?: string;
  agent_id?: string;
  agentId?: string;
  text?: string;
  body?: string;
  bodyForAgent?: string;
  content?: string;
  prompt?: string;
  source?: string;
  channelId?: string;
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface OpenClawToolAttemptEvent {
  session_id?: string;
  sessionId?: string;
  sessionKey?: string;
  task_id?: string;
  taskId?: string;
  attempt_id?: string;
  attemptId?: string;
  toolCallId?: string;
  runId?: string;
  user_id?: string;
  userId?: string;
  host_id?: string;
  hostId?: string;
  agent_id?: string;
  agentId?: string;
  tool?: string;
  toolName?: string;
  params?: Record<string, unknown>;
  args?: Record<string, unknown>;
  taints?: string[];
  data_classes?: string[];
  dataClasses?: string[];
  [key: string]: unknown;
}

export interface OpenClawHookResult {
  block?: boolean;
  requireApproval?: boolean;
  reason?: string;
  bodyForAgent?: string;
  content?: string;
  prompt?: string;
  params?: Record<string, unknown>;
  args?: Record<string, unknown>;
}

export function normalizeConfig(config: AgentGateOpenClawConfig = {}): NormalizedAgentGateOpenClawConfig {
  return {
    baseUrl:
      config.baseUrl ??
      config.base_url ??
      readEnv("AGENTGATE_BASE_URL") ??
      "http://127.0.0.1:8080",
    adapterId: config.adapterId ?? config.adapter_id ?? "openclaw-agentgate",
    integrationId: config.integrationId ?? config.integration_id ?? readEnv("AGENTGATE_INTEGRATION_ID"),
    hostVersion: config.hostVersion ?? config.host_version ?? readEnv("OPENCLAW_VERSION"),
    inputHookName: config.inputHookName ?? config.input_hook_name ?? "before_prompt_build",
    runtimeHookName: config.runtimeHookName ?? config.runtime_hook_name ?? "before_tool_call",
    adapterToken: config.adapterToken ?? config.adapter_token ?? readEnv("AGENTGATE_ADAPTER_TOKEN"),
  };
}

export function createRegistration(config: NormalizedAgentGateOpenClawConfig): AdapterRegistration {
  return {
    adapter_id: config.adapterId,
    integration_id: config.integrationId,
    adapter_kind: "host_plugin",
    host: {
      kind: "openclaw",
      version: config.hostVersion,
    },
    surfaces: ["input", "runtime"],
    capabilities: {
      can_block: true,
      can_rewrite_input: true,
      can_rewrite_tool_args: true,
      can_pause_for_approval: true,
    },
  };
}

export function createAgentGateInputHook(
  client: AgentGateClient,
  config: NormalizedAgentGateOpenClawConfig,
) {
  return async function agentGateInputHook(event: OpenClawInputEvent): Promise<OpenClawHookResult> {
    const request = mapInputEventToPolicyRequest(event);
    const decision = await decideOrDeny(client, request);
    await reportDecision(client, config.adapterId, "input", decision, "input_hook_decided");
    return applyInputDecision(event, decision);
  };
}

export function createAgentGateToolHook(
  client: AgentGateClient,
  config: NormalizedAgentGateOpenClawConfig,
) {
  return async function agentGateToolHook(event: OpenClawToolAttemptEvent): Promise<OpenClawHookResult> {
    const request = mapToolAttemptToPolicyRequest(event);
    const decision = await decideOrDeny(client, request);
    await reportDecision(client, config.adapterId, "runtime", decision, "runtime_hook_decided");
    return applyRuntimeDecision(decision);
  };
}

export function mapInputEventToPolicyRequest(event: OpenClawInputEvent): PolicyRequest {
  const sessionId = stringValue(event.session_id ?? event.sessionId ?? event.sessionKey, "unknown-session");
  const taskId = stringValue(event.task_id ?? event.taskId, sessionId);
  const text = stringValue(event.bodyForAgent ?? event.prompt ?? event.content ?? event.text ?? event.body, "");

  return {
    request_id: `req_input_${Date.now()}`,
    request_kind: "input",
    actor: {
      user_id: stringValue(event.user_id ?? event.userId ?? event.from, undefined),
      host_id: stringValue(event.host_id ?? event.hostId, "openclaw"),
      agent_id: stringValue(event.agent_id ?? event.agentId, undefined),
    },
    session: {
      session_id: sessionId,
      task_id: taskId,
    },
    action: {
      operation: "model_input",
    },
    target: {
      kind: "model_context",
    },
    content: {
      summary: text.slice(0, 300),
    },
    context: {
      surface: "input",
      raw: {
        text,
        source: stringValue(event.source, "feishu_message"),
        channel_id: stringValue(event.channelId, undefined),
        metadata: event.metadata ?? {},
      },
    },
    policy: {},
  };
}

export function mapToolAttemptToPolicyRequest(event: OpenClawToolAttemptEvent): PolicyRequest {
  const sessionId = stringValue(event.session_id ?? event.sessionId ?? event.sessionKey, "unknown-session");
  const taskId = stringValue(event.task_id ?? event.taskId, sessionId);
  const attemptId = stringValue(
    event.attempt_id ?? event.attemptId ?? event.toolCallId ?? event.runId,
    `attempt_${Date.now()}`,
  );
  const tool = stringValue(event.tool ?? event.toolName, "unknown_tool");
  const args = objectValue(event.args ?? event.params);

  return {
    request_id: `req_tool_${attemptId}`,
    request_kind: "tool_attempt",
    actor: {
      user_id: stringValue(event.user_id ?? event.userId, undefined),
      host_id: stringValue(event.host_id ?? event.hostId, "openclaw"),
      agent_id: stringValue(event.agent_id ?? event.agentId, undefined),
    },
    session: {
      session_id: sessionId,
      task_id: taskId,
      attempt_id: attemptId,
    },
    action: {
      tool,
      operation: tool === "bash" ? "execute" : tool,
      side_effects: inferSideEffects(tool),
      open_world: tool === "bash",
    },
    target: {
      kind: tool === "bash" ? "process" : "tool",
    },
    content: {
      summary: JSON.stringify(args).slice(0, 500),
      data_classes: arrayValue(event.data_classes ?? event.dataClasses) as never,
    },
    context: {
      surface: "runtime",
      taints: arrayValue(event.taints) as never,
      raw: { args },
    },
    policy: {},
  };
}

export function applyInputDecision(
  event: OpenClawInputEvent,
  decision: GuardDecision,
): OpenClawHookResult {
  if (decision.effect === "deny" || decision.effect === "exclusion") {
    return { block: true, reason: decision.reason_code };
  }
  if (decision.effect === "approval_required") {
    return { requireApproval: true, reason: decision.reason_code };
  }

  const rewrite = findRewriteInput(decision.obligations);
  if (rewrite !== undefined) {
    return {
      bodyForAgent: rewrite,
      content: rewrite,
      prompt: rewrite,
      reason: decision.reason_code,
    };
  }

  if (typeof event.bodyForAgent === "string") {
    return { bodyForAgent: event.bodyForAgent };
  }
  return {};
}

export function applyRuntimeDecision(decision: GuardDecision): OpenClawHookResult {
  if (decision.effect === "deny" || decision.effect === "exclusion") {
    return { block: true, reason: decision.reason_code };
  }
  if (decision.effect === "approval_required") {
    return { requireApproval: true, reason: decision.reason_code };
  }

  const rewriteArgs = findRewriteToolArgs(decision.obligations);
  if (rewriteArgs !== undefined) {
    return { params: rewriteArgs, args: rewriteArgs };
  }

  return {};
}

async function reportDecision(
  client: AgentGateClient,
  adapterId: string,
  surface: Surface,
  decision: GuardDecision,
  outcome: string,
): Promise<void> {
  try {
    await client.report({
      request_id: decision.request_id,
      decision_id: decision.decision_id,
      adapter_id: adapterId,
      surface,
      outcome,
      obligations: decision.obligations,
    });
  } catch {
    // Reporting must not turn an already-returned allow/deny into a local policy decision.
  }
}

function findRewriteInput(obligations: Obligation[]): string | undefined {
  for (const obligation of obligations) {
    if (obligation.type !== "rewrite_input") {
      continue;
    }
    const text = obligation.params?.text ?? obligation.params?.bodyForAgent;
    if (typeof text === "string") {
      return text;
    }
  }
  return undefined;
}

function findRewriteToolArgs(obligations: Obligation[]): Record<string, unknown> | undefined {
  for (const obligation of obligations) {
    if (obligation.type !== "rewrite_tool_args") {
      continue;
    }
    const args = obligation.params?.args ?? obligation.params?.params;
    if (isRecord(args)) {
      return args;
    }
  }
  return undefined;
}

function inferSideEffects(tool: string): string[] {
  if (tool === "bash") {
    return ["filesystem_read", "filesystem_write", "network_egress", "process_spawn"];
  }
  if (tool === "write" || tool === "edit") {
    return ["filesystem_write"];
  }
  if (tool === "read" || tool === "grep" || tool === "rg") {
    return ["filesystem_read"];
  }
  return [];
}

function stringValue(value: unknown, fallback: string): string;
function stringValue(value: unknown, fallback: undefined): string | undefined;
function stringValue(value: unknown, fallback: string | undefined): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

function objectValue(value: unknown): Record<string, unknown> {
  return isRecord(value) ? value : {};
}

function arrayValue(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readEnv(name: string): string | undefined {
  const env = globalThis as typeof globalThis & {
    process?: { env?: Record<string, string | undefined> };
  };
  return env.process?.env?.[name];
}
