#!/usr/bin/env node
import { FeishuApprovalAdapter } from "./adapter.js";
import type { FeishuApprovalAdapterConfig } from "./types.js";

const config = readConfig();
const adapter = new FeishuApprovalAdapter(config);

process.on("SIGINT", () => void shutdown());
process.on("SIGTERM", () => void shutdown());

await adapter.start();
console.log(
  `AgentGate Feishu adapter started on :${config.cardCallbackPort ?? 8787}${config.cardCallbackPath ?? "/feishu/card"}`,
);

async function shutdown(): Promise<void> {
  await adapter.stop();
  process.exit(0);
}

function readConfig(): FeishuApprovalAdapterConfig {
  return {
    agentGateBaseUrl: requiredEnv("AGENTGATE_BASE_URL"),
    adapterId: env("AGENTGATE_FEISHU_ADAPTER_ID") ?? "feishu-agentgate-approval",
    integrationId: env("AGENTGATE_FEISHU_INTEGRATION_ID"),
    adapterToken: requiredEnv("AGENTGATE_ADAPTER_TOKEN"),
    operatorToken: requiredEnv("AGENTGATE_OPERATOR_TOKEN"),
    appId: requiredEnv("FEISHU_APP_ID"),
    appSecret: requiredEnv("FEISHU_APP_SECRET"),
    receiveId: requiredEnv("FEISHU_RECEIVE_ID"),
    receiveIdType: (env("FEISHU_RECEIVE_ID_TYPE") ?? "chat_id") as FeishuApprovalAdapterConfig["receiveIdType"],
    domain: (env("FEISHU_DOMAIN") ?? "feishu") as FeishuApprovalAdapterConfig["domain"],
    encryptKey: env("FEISHU_ENCRYPT_KEY"),
    verificationToken: env("FEISHU_VERIFICATION_TOKEN"),
    cardCallbackPath: env("FEISHU_CARD_CALLBACK_PATH") ?? "/feishu/card",
    cardCallbackPort: numberEnv("FEISHU_CARD_CALLBACK_PORT") ?? 8787,
    pollIntervalMs: numberEnv("AGENTGATE_FEISHU_POLL_MS") ?? 2000,
  };
}

function requiredEnv(name: string): string {
  const value = env(name);
  if (value === undefined) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function env(name: string): string | undefined {
  const value = process.env[name];
  return value === undefined || value.length === 0 ? undefined : value;
}

function numberEnv(name: string): number | undefined {
  const value = env(name);
  if (value === undefined) {
    return undefined;
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    throw new Error(`${name} must be a number`);
  }
  return parsed;
}
