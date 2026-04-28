import { AgentGateClient } from "./client.js";
import {
  createAgentGateInputHook,
  createAgentGateToolHook,
  createRegistration,
  normalizeConfig,
  type AgentGateOpenClawConfig,
  type NormalizedAgentGateOpenClawConfig,
} from "./openclaw.js";

interface OpenClawPluginApi {
  on?: (hookName: string, handler: unknown, options?: Record<string, unknown>) => void;
  registerHook?: (hookName: string, handler: unknown, options?: Record<string, unknown>) => void;
  config?: unknown;
  runtime?: {
    config?: unknown;
    logger?: LoggerLike;
  };
  logger?: LoggerLike;
}

interface LoggerLike {
  info?: (...args: unknown[]) => void;
  warn?: (...args: unknown[]) => void;
  error?: (...args: unknown[]) => void;
}

const plugin = {
  id: "agentgate-openclaw-adapter",
  name: "AgentGate OpenClaw Adapter",
  description: "Connects OpenClaw input and runtime hooks to AgentGate Core.",

  register(api: OpenClawPluginApi) {
    const config = normalizeConfig(readPluginConfig(api));
    const client = new AgentGateClient({
      baseUrl: config.baseUrl,
      token: config.adapterToken,
    });
    const logger = api.logger ?? api.runtime?.logger;

    void registerWithAgentGate(client, config, logger);

    registerHook(api, config.inputHookName, createAgentGateInputHook(client, config), {
      priority: 1000,
    });
    registerHook(api, config.runtimeHookName, createAgentGateToolHook(client, config), {
      priority: 1000,
    });

    logger?.info?.("AgentGate OpenClaw adapter registered", {
      adapter_id: config.adapterId,
      base_url: config.baseUrl,
      input_hook: config.inputHookName,
      runtime_hook: config.runtimeHookName,
    });
  },
};

export default plugin;

async function registerWithAgentGate(
  client: AgentGateClient,
  config: NormalizedAgentGateOpenClawConfig,
  logger?: LoggerLike,
): Promise<void> {
  try {
    await client.register(createRegistration(config));
  } catch (error) {
    logger?.error?.("AgentGate adapter registration failed", error);
  }
}

function registerHook(
  api: OpenClawPluginApi,
  hookName: string,
  handler: unknown,
  options: Record<string, unknown>,
): void {
  if (typeof api.on === "function") {
    api.on(hookName, handler, options);
    return;
  }
  if (typeof api.registerHook === "function") {
    api.registerHook(hookName, handler, options);
    return;
  }
  throw new Error("OpenClaw plugin API does not expose on() or registerHook()");
}

function readPluginConfig(api: OpenClawPluginApi): AgentGateOpenClawConfig {
  return (
    pickAgentGateConfig(api.config) ??
    pickAgentGateConfig(api.runtime?.config) ??
    {}
  );
}

function pickAgentGateConfig(value: unknown): AgentGateOpenClawConfig | undefined {
  if (!isRecord(value)) {
    return undefined;
  }
  const candidate = value.agentGate ?? value.agentgate ?? value.agent_gate ?? value;
  return isRecord(candidate) ? (candidate as AgentGateOpenClawConfig) : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
