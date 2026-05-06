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
  const riskSummary = summarizeRisk(payload);
  const operationSummary = summarizeOperation(payload);
  const choiceSummary = [
    "Allow once: only this concrete attempt will continue.",
    "Deny: this attempt stays blocked and no command is executed.",
  ].join("\n");
  const technicalDetails = summarizeTechnicalDetails(payload);

  return {
    config: {
      wide_screen_mode: true,
    },
    header: {
      template: "orange",
      title: {
        tag: "plain_text",
        content: "AgentGate blocked a high-risk action",
      },
    },
    elements: [
      {
        tag: "markdown",
        content: "**Execution is paused. Please confirm whether this single action should continue.**",
      },
      {
        tag: "div",
        text: {
          tag: "lark_md",
          content: `**Why it was blocked**\n${escapeMarkdown(riskSummary)}`,
        },
      },
      {
        tag: "div",
        text: {
          tag: "lark_md",
          content: `**What the agent is trying to do**\n${escapeMarkdown(operationSummary)}`,
        },
      },
      {
        tag: "div",
        text: {
          tag: "lark_md",
          content: `**What your choice means**\n${escapeMarkdown(choiceSummary)}`,
        },
      },
      {
        tag: "note",
        elements: [
          {
            tag: "plain_text",
            content: technicalDetails,
          },
        ],
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
          button("Allow Once", "primary", {
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
      ? "AgentGate allowed this attempt"
      : status === "expired"
        ? "AgentGate approval expired"
        : "AgentGate denied this attempt";
  const body =
    status === "approved"
      ? "This one attempt was approved and may continue."
      : status === "expired"
        ? "The approval window expired. The blocked action was not executed."
        : "The blocked action remains denied and will not execute.";
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
        content: `${escapeMarkdown(body)}\n\nResolved by ${escapeMarkdown(operatorId)}.`,
      },
    ],
  };
}

function summarizeRisk(payload: ApprovalCardPayload): string {
  const sideEffects = payload.sideEffects ?? [];
  const highRiskBits: string[] = [];
  if (sideEffects.includes("filesystem_read")) {
    highRiskBits.push("read local data");
  }
  if (sideEffects.includes("filesystem_write")) {
    highRiskBits.push("modify local files");
  }
  if (sideEffects.includes("network_egress")) {
    highRiskBits.push("send data to an external address");
  }
  if (sideEffects.includes("process_spawn")) {
    highRiskBits.push("execute a local command");
  }

  if (highRiskBits.length > 0) {
    return `AgentGate detected a tool attempt that may ${joinPhrases(highRiskBits)}. This kind of action can affect your machine or move data outside the current chat.`;
  }
  return "AgentGate detected a high-risk tool attempt and paused it before execution.";
}

function summarizeOperation(payload: ApprovalCardPayload): string {
  const toolText = payload.tool ? `Tool: ${payload.tool}.` : "A privileged tool call is about to run.";
  const targetParts = [payload.targetKind, payload.targetIdentifier].filter(Boolean).join(": ");
  const targetText = targetParts ? ` Target: ${targetParts}.` : "";
  const summaryText = payload.contentSummary ? ` Summary: ${payload.contentSummary}.` : "";
  return `${toolText}${targetText}${summaryText}`.trim();
}

function summarizeTechnicalDetails(payload: ApprovalCardPayload): string {
  const details = [
    payload.selectedRule ? `Rule: ${payload.selectedRule}` : undefined,
    payload.operation ? `Operation: ${payload.operation}` : undefined,
    payload.sideEffects?.length ? `Side effects: ${payload.sideEffects.join(", ")}` : undefined,
    payload.scope ? `Scope: ${payload.scope}` : undefined,
  ].filter(Boolean);
  return details.length > 0 ? details.join(" | ") : "Technical details unavailable";
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

function joinPhrases(values: string[]): string {
  if (values.length === 1) {
    return values[0]!;
  }
  if (values.length === 2) {
    return `${values[0]} and ${values[1]}`;
  }
  return `${values.slice(0, -1).join(", ")}, and ${values[values.length - 1]}`;
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
