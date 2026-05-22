import * as lark from "@larksuiteoapi/node-sdk";
import type { CardActionEvent, NormalizedMessage } from "@larksuiteoapi/node-sdk";

import { AgentGateHTTPError, AgentGateTransportClient } from "./agentgate.js";
import { buildApprovalCard, buildResolvedCard } from "./card.js";
import type { ApprovalCardPayload, ApprovalRecord, EventEnvelope, FeishuApprovalAdapterConfig } from "./types.js";

const APPROVAL_COMMAND = /^\/?(approve|allow|deny)\s+([A-Za-z0-9._:-]+)\s*$/i;

export class FeishuApprovalAdapter {
  private readonly config: Required<Pick<FeishuApprovalAdapterConfig, "adapterId" | "domain" | "pollIntervalMs">> &
    FeishuApprovalAdapterConfig;
  private readonly agentGate: AgentGateTransportClient;
  private readonly client: lark.Client;
  private readonly channel: lark.LarkChannel;
  private readonly sentApprovals = new Set<string>();
  private readonly approvalMessages = new Map<string, string>();
  private readonly resolvedApprovals = new Set<string>();
  private pollTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(config: FeishuApprovalAdapterConfig) {
    this.config = {
      domain: "feishu",
      pollIntervalMs: 2000,
      ...config,
    };
    const domain = this.config.domain === "lark" ? lark.Domain.Lark : lark.Domain.Feishu;
    this.agentGate = new AgentGateTransportClient({
      baseUrl: this.config.agentGateBaseUrl,
      adapterToken: this.config.adapterToken,
      operatorToken: this.config.operatorToken,
    });
    this.client = new lark.Client({
      appId: this.config.appId,
      appSecret: this.config.appSecret,
      appType: lark.AppType.SelfBuild,
      domain,
    });
    this.channel = lark.createLarkChannel({
      appId: this.config.appId,
      appSecret: this.config.appSecret,
      domain,
      transport: "websocket",
      includeRawInMessage: true,
      policy: {
        groupAllowlist: [this.config.receiveId],
        dmMode: "disabled",
        requireMention: false,
      },
    });
    this.channel.on("cardAction", (event) => void this.handleCardActionEvent(event));
    this.channel.on("message", (message) => void this.handleMessage(message));
    this.channel.on("error", (error) => {
      console.error("[agentgate-feishu] channel error:", error);
    });
    this.channel.on("reconnecting", () => {
      console.warn("[agentgate-feishu] reconnecting to Feishu long connection");
    });
    this.channel.on("reconnected", () => {
      console.log("[agentgate-feishu] Feishu long connection reconnected");
    });
  }

  async start(): Promise<void> {
    await this.agentGate.registerFeishuTransport(this.config.adapterId, this.config.integrationId);
    await this.channel.connect();
    await this.pollOnce();
    this.schedulePoll();
  }

  async stop(): Promise<void> {
    if (this.pollTimer !== undefined) {
      clearTimeout(this.pollTimer);
      this.pollTimer = undefined;
    }
    await this.channel.disconnect();
  }

  async pollOnce(): Promise<void> {
    const approvals = await this.agentGate.approvals();
    const approvalEvents = await this.agentGate.events(200);
    for (const approval of approvals) {
      if (approval.channel && approval.channel !== this.config.adapterId) {
        continue;
      }
      const approvalEvent = findApprovalEvent(approval, approvalEvents);
      const payload = approvalPayloadFromApproval(approval, approvalEvent);
      if (payload === undefined || this.sentApprovals.has(payload.approvalId)) {
        continue;
      }
      const messageId = await this.sendApprovalCard(payload);
      this.sentApprovals.add(payload.approvalId);
      if (messageId) {
        this.approvalMessages.set(payload.approvalId, messageId);
      }
    }
  }

  async sendApprovalCard(payload: ApprovalCardPayload): Promise<string | undefined> {
    console.log("[agentgate-feishu] sending approval card", {
      approvalId: payload.approvalId,
      sessionId: payload.sessionId,
      taskId: payload.taskId,
    });
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

  private async handleCardActionEvent(event: CardActionEvent): Promise<void> {
    console.log("[agentgate-feishu] received card action", {
      messageId: event.messageId,
      chatId: event.chatId,
      operatorOpenId: event.operator.openId,
      action: event.action,
    });
    const value = objectValue(event.action.value);
    const approvalId = stringValue(value.approval_id);
    const decision = normalizeDecision(value.decision);
    const operatorId = event.operator.openId || event.operator.userId || "feishu-user";
    if (approvalId === undefined || decision === undefined) {
      return;
    }
    await this.resolveAndUpdate(approvalId, decision, operatorId);
  }

  private async handleMessage(message: NormalizedMessage): Promise<void> {
    console.log("[agentgate-feishu] received message", {
      messageId: message.messageId,
      chatId: message.chatId,
      chatType: message.chatType,
      senderId: message.senderId,
      content: message.content,
      mentionedBot: message.mentionedBot,
    });
    if (message.chatId !== this.config.receiveId) {
      return;
    }
    const match = message.content.trim().match(APPROVAL_COMMAND);
    if (!match) {
      return;
    }
    const decision = match[1].toLowerCase() === "deny" ? "deny" : "allow_once";
    const approvalId = match[2];
    const operatorId = message.senderId || "feishu-user";
    try {
      const status = await this.resolveAndUpdate(approvalId, decision, operatorId);
      await this.channel.send(this.config.receiveId, {
        text:
          status === "approved"
            ? `Approval ${approvalId} approved by ${operatorId}.`
            : status === "expired"
              ? `Approval ${approvalId} has already expired.`
              : `Approval ${approvalId} denied by ${operatorId}.`,
      });
    } catch (error) {
      const messageText = error instanceof Error ? error.message : String(error);
      console.error("[agentgate-feishu] message approval command failed", {
        approvalId,
        decision,
        operatorId,
        error: messageText,
      });
      await this.channel.send(this.config.receiveId, {
        text: `Approval ${approvalId} could not be resolved: ${messageText}`,
      });
    }
  }

  private async resolveAndUpdate(
    approvalId: string,
    decision: "allow_once" | "deny",
    operatorId: string,
  ): Promise<"approved" | "denied" | "expired"> {
    console.log("[agentgate-feishu] resolving approval", {
      approvalId,
      decision,
      operatorId,
    });
    try {
      const result = await this.agentGate.resolveApproval(approvalId, decision);
      const status = result.status === "approved" ? "approved" : result.status === "expired" ? "expired" : "denied";
      console.log("[agentgate-feishu] approval resolved", {
        approvalId,
        decision,
        operatorId,
        status,
      });
      await this.updateApprovalCard(approvalId, status, operatorId);
      return status;
    } catch (error) {
      if (error instanceof AgentGateHTTPError && error.code === "approval_expired") {
        console.warn("[agentgate-feishu] approval already expired", {
          approvalId,
          operatorId,
        });
        await this.updateApprovalCard(approvalId, "expired", operatorId);
        return "expired";
      }
      if (error instanceof AgentGateHTTPError && error.code === "approval_already_resolved") {
        console.warn("[agentgate-feishu] approval already resolved", {
          approvalId,
          operatorId,
        });
        return "denied";
      }
      throw error;
    }
  }

  private async updateApprovalCard(
    approvalId: string,
    status: "approved" | "denied" | "expired",
    operatorId: string,
  ): Promise<void> {
    if (this.resolvedApprovals.has(approvalId)) {
      return;
    }
    const messageId = this.approvalMessages.get(approvalId);
    this.resolvedApprovals.add(approvalId);
    if (messageId) {
      try {
        await this.channel.recallMessage(messageId);
      } catch (error) {
        console.warn(`[agentgate-feishu] failed to recall approval card ${approvalId}:`, error);
      }
    }

    try {
      const response = await this.client.im.message.create({
        params: {
          receive_id_type: this.config.receiveIdType,
        },
        data: {
          receive_id: this.config.receiveId,
          msg_type: "interactive",
          content: JSON.stringify(buildResolvedCard(status, operatorId)),
        },
      });
      const resolvedMessageId = (response.data as { message_id?: string } | undefined)?.message_id;
      if (resolvedMessageId) {
        this.approvalMessages.set(approvalId, resolvedMessageId);
      }
    } catch (error) {
      console.warn(`[agentgate-feishu] failed to send resolved approval card ${approvalId}:`, error);
    }
  }

  private schedulePoll(): void {
    this.pollTimer = setTimeout(async () => {
      try {
        await this.pollOnce();
      } catch (error) {
        console.error("[agentgate-feishu] poll failed:", error);
      } finally {
        this.schedulePoll();
      }
    }, this.config.pollIntervalMs);
  }
}

export function approvalPayloadFromApproval(
  approval: ApprovalRecord,
  event?: EventEnvelope,
): ApprovalCardPayload | undefined {
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
    surface: event?.surface ?? "runtime",
    scope: stringValue(event?.metadata?.approval_scope) ?? "attempt",
    expiresAt: approval.expires_at,
    occurredAt: approval.created_at,
    tool: stringValue(event?.metadata?.tool),
    operation: stringValue(event?.metadata?.operation),
    targetKind: stringValue(event?.metadata?.target_kind),
    targetIdentifier: stringValue(event?.metadata?.target_identifier),
    contentSummary: stringValue(event?.metadata?.content_summary),
    sideEffects: stringArrayValue(event?.metadata?.side_effects),
    selectedRule: stringValue(event?.metadata?.selected_rule),
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

function normalizeDecision(value: unknown): "allow_once" | "deny" | undefined {
  return value === "allow_once" ? "allow_once" : value === "deny" ? "deny" : undefined;
}

function objectValue(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function stringArrayValue(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }
  const result = value.filter((entry): entry is string => typeof entry === "string" && entry.length > 0);
  return result.length > 0 ? result : undefined;
}

function findApprovalEvent(approval: ApprovalRecord, events: EventEnvelope[]): EventEnvelope | undefined {
  return events.find(
    (event) =>
      event.event_type === "policy_decision" &&
      event.effect === "approval_required" &&
      event.request_id === approval.request_id &&
      event.session_id === approval.session_id &&
      stringValue(event.metadata?.approval_id) === approval.approval_id,
  );
}
