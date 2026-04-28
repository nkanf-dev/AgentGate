import http from "node:http";
import * as lark from "@larksuiteoapi/node-sdk";
import type { InteractiveCardActionEvent } from "@larksuiteoapi/node-sdk";

import { AgentGateHTTPError, AgentGateTransportClient } from "./agentgate.js";
import { buildApprovalCard, buildResolvedCard } from "./card.js";
import type { ApprovalCardPayload, ApprovalRecord, EventEnvelope, FeishuApprovalAdapterConfig } from "./types.js";

export class FeishuApprovalAdapter {
  private readonly config: Required<
    Pick<
      FeishuApprovalAdapterConfig,
      "adapterId" | "domain" | "cardCallbackPath" | "cardCallbackPort" | "pollIntervalMs"
    >
  > &
    FeishuApprovalAdapterConfig;
  private readonly agentGate: AgentGateTransportClient;
  private readonly client: lark.Client;
  private readonly sentApprovals = new Set<string>();
  private pollTimer: ReturnType<typeof setTimeout> | undefined;
  private server: http.Server | undefined;

  constructor(config: FeishuApprovalAdapterConfig) {
    this.config = {
      domain: "feishu",
      cardCallbackPath: "/feishu/card",
      cardCallbackPort: 8787,
      pollIntervalMs: 2000,
      ...config,
    };
    this.agentGate = new AgentGateTransportClient({
      baseUrl: this.config.agentGateBaseUrl,
      adapterToken: this.config.adapterToken,
      operatorToken: this.config.operatorToken,
    });
    this.client = new lark.Client({
      appId: this.config.appId,
      appSecret: this.config.appSecret,
      appType: lark.AppType.SelfBuild,
      domain: this.config.domain === "lark" ? lark.Domain.Lark : lark.Domain.Feishu,
    });
  }

  async start(): Promise<void> {
    await this.agentGate.registerFeishuTransport(this.config.adapterId, this.config.integrationId);
    this.startCardCallbackServer();
    await this.pollOnce();
    this.schedulePoll();
  }

  async stop(): Promise<void> {
    if (this.pollTimer !== undefined) {
      clearTimeout(this.pollTimer);
      this.pollTimer = undefined;
    }
    if (this.server !== undefined) {
      await new Promise<void>((resolve, reject) => {
        this.server?.close((error?: Error) => (error ? reject(error) : resolve()));
      });
      this.server = undefined;
    }
  }

  async pollOnce(): Promise<void> {
    const approvals = await this.agentGate.approvals();
    for (const approval of approvals) {
      const payload = approvalPayloadFromApproval(approval);
      if (payload === undefined || this.sentApprovals.has(payload.approvalId)) {
        continue;
      }
      await this.sendApprovalCard(payload);
      this.sentApprovals.add(payload.approvalId);
    }
  }

  async sendApprovalCard(payload: ApprovalCardPayload): Promise<string | undefined> {
    const response = await this.client.im.message.create({
      params: {
        receive_id_type: this.config.receiveIdType,
      },
      data: {
        receive_id: this.config.receiveId,
        msg_type: "interactive",
        content: JSON.stringify(buildApprovalCard(payload)),
      },
    });

    const data = response.data as { message_id?: string } | undefined;
    return data?.message_id;
  }

  private startCardCallbackServer(): void {
    const handler = new lark.CardActionHandler(
      {
        encryptKey: this.config.encryptKey,
        verificationToken: this.config.verificationToken,
      },
      async (event: InteractiveCardActionEvent) => this.handleCardAction(event),
    );
    this.server = http.createServer();
    this.server.on("request", lark.adaptDefault(this.config.cardCallbackPath, handler));
    this.server.listen(this.config.cardCallbackPort);
  }

  private async handleCardAction(event: InteractiveCardActionEvent): Promise<Record<string, unknown>> {
    const value = actionValue(event);
    const approvalId = stringValue(value.approval_id);
    const decision = value.decision === "allow_once" ? "allow_once" : value.decision === "deny" ? "deny" : undefined;
    const operatorId = cardOperatorId(event);
    if (approvalId === undefined || decision === undefined) {
      return buildResolvedCard("denied", operatorId);
    }

    try {
      const result = await this.agentGate.resolveApproval(approvalId, decision, operatorId);
      return buildResolvedCard(result.status === "approved" ? "approved" : result.status === "expired" ? "expired" : "denied", operatorId);
    } catch (error) {
      if (error instanceof AgentGateHTTPError && error.code === "approval_expired") {
        return buildResolvedCard("expired", operatorId);
      }
      throw error;
    }
  }

  private schedulePoll(): void {
    this.pollTimer = setTimeout(async () => {
      try {
        await this.pollOnce();
      } finally {
        this.schedulePoll();
      }
    }, this.config.pollIntervalMs);
  }
}

export function approvalPayloadFromApproval(approval: ApprovalRecord): ApprovalCardPayload | undefined {
  if (approval.status !== "pending") {
    return undefined;
  }
  return {
    approvalId: approval.approval_id,
    requestId: approval.request_id,
    sessionId: approval.session_id,
    taskId: approval.task_id,
    attemptId: approval.attempt_id,
    reason: approval.reason,
    surface: "runtime",
    scope: "attempt",
    expiresAt: approval.expires_at,
    occurredAt: approval.created_at,
  };
}

export function approvalPayloadFromEvent(event: EventEnvelope): ApprovalCardPayload | undefined {
  if (event.event_type !== "policy_decision" || event.effect !== "approval_required") {
    return undefined;
  }
  const approvalId = stringValue(event.metadata?.approval_id);
  if (approvalId === undefined) {
    return undefined;
  }
  return {
    approvalId,
    requestId: event.request_id,
    sessionId: event.session_id,
    taskId: stringValue(event.metadata?.task_id),
    attemptId: stringValue(event.metadata?.attempt_id),
    reason: event.summary,
    surface: event.surface,
    scope: stringValue(event.metadata?.approval_scope),
    expiresAt: stringValue(event.metadata?.approval_expires_at),
    occurredAt: event.occurred_at,
  };
}

function actionValue(event: InteractiveCardActionEvent): Record<string, unknown> {
  const candidate = (event as { action?: { value?: unknown } }).action?.value;
  return typeof candidate === "object" && candidate !== null && !Array.isArray(candidate)
    ? (candidate as Record<string, unknown>)
    : {};
}

function cardOperatorId(event: InteractiveCardActionEvent): string {
  const operator = (event as { operator?: Record<string, unknown>; user?: Record<string, unknown> }).operator ?? {};
  const user = (event as { user?: Record<string, unknown> }).user ?? {};
  return (
    stringValue(operator.open_id) ??
    stringValue(operator.user_id) ??
    stringValue(user.open_id) ??
    stringValue(user.user_id) ??
    "feishu-user"
  );
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}
