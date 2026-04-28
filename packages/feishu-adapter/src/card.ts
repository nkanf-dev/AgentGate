import type { ApprovalCardPayload } from "./types.js";

export function buildApprovalCard(payload: ApprovalCardPayload): Record<string, unknown> {
  const fields = [
    field("Session", payload.sessionId),
    field("Task", payload.taskId),
    field("Attempt", payload.attemptId),
    field("Surface", payload.surface),
    field("Scope", payload.scope === "attempt" ? "this attempt only" : payload.scope),
    field("Expires", formatTime(payload.expiresAt)),
  ].filter(Boolean);

  return {
    config: {
      wide_screen_mode: true,
    },
    header: {
      template: "orange",
      title: {
        tag: "plain_text",
        content: "AgentGate approval required",
      },
    },
    elements: [
      {
        tag: "markdown",
        content: `**Reason**\n${escapeMarkdown(payload.reason)}\n\nAllow once grants only this concrete attempt. Deny keeps the attempt blocked.`,
      },
      ...(fields.length > 0
        ? [
            {
              tag: "div",
              fields,
            },
          ]
        : []),
      {
        tag: "hr",
      },
      {
        tag: "action",
        actions: [
          button("Allow once", "primary", {
            approval_id: payload.approvalId,
            decision: "allow_once",
          }),
          button("Deny", "danger", {
            approval_id: payload.approvalId,
            decision: "deny",
          }),
        ],
      },
    ],
  };
}

export function buildResolvedCard(status: "approved" | "denied" | "expired", operatorId: string): Record<string, unknown> {
  const title =
    status === "approved"
      ? "AgentGate approval granted"
      : status === "expired"
        ? "AgentGate approval expired"
        : "AgentGate approval denied";
  return {
    config: {
      wide_screen_mode: true,
    },
    header: {
      template: status === "approved" ? "green" : status === "expired" ? "grey" : "red",
      title: {
        tag: "plain_text",
        content: title,
      },
    },
    elements: [
      {
        tag: "markdown",
        content: `Resolved by ${escapeMarkdown(operatorId)}.`,
      },
    ],
  };
}

function field(label: string, value: string | undefined): Record<string, unknown> | undefined {
  if (!value) {
    return undefined;
  }
  return {
    is_short: true,
    text: {
      tag: "lark_md",
      content: `**${label}:**\n${escapeMarkdown(value)}`,
    },
  };
}

function button(text: string, type: "primary" | "danger", value: Record<string, string>): Record<string, unknown> {
  return {
    tag: "button",
    text: {
      tag: "plain_text",
      content: text,
    },
    type,
    value,
  };
}

function escapeMarkdown(value: string): string {
  return value.replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function formatTime(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toISOString();
}
