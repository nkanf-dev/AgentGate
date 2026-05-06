import type { ApprovalRecord, ApprovalResolveResponse, ApprovalsResponse, EventEnvelope } from "./types.js";

export interface AgentGateTransportClientOptions {
  baseUrl: string;
  adapterToken: string;
  operatorToken: string;
  fetch?: typeof fetch;
}

export class AgentGateTransportClient {
  private readonly baseUrl: string;
  private readonly adapterToken: string;
  private readonly operatorToken: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: AgentGateTransportClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.adapterToken = options.adapterToken;
    this.operatorToken = options.operatorToken;
    this.fetchImpl = options.fetch ?? fetch;
  }

  async registerFeishuTransport(adapterId: string, integrationId?: string): Promise<void> {
    await this.post(
      "/v1/register",
      {
        adapter_id: adapterId,
        integration_id: integrationId,
        adapter_kind: "approval_transport",
        host: {
          kind: "feishu",
        },
        surfaces: [],
        supporting_channels: ["approval_transport", "notification"],
        capabilities: {
          can_block: false,
          can_rewrite_input: false,
          can_rewrite_tool_args: false,
          can_pause_for_approval: false,
        },
      },
      this.adapterToken,
    );
  }

  async events(limit = 200): Promise<EventEnvelope[]> {
    const response = await this.get<{ events: EventEnvelope[] }>(
      `/v1/events?limit=${encodeURIComponent(limit)}`,
      this.operatorToken,
    );
    return response.events;
  }

  async approvals(limit = 200): Promise<ApprovalRecord[]> {
    const response = await this.get<ApprovalsResponse>(
      `/v1/approvals?limit=${encodeURIComponent(limit)}`,
      this.operatorToken,
    );
    return response.approvals;
  }

  async resolveApproval(
    approvalId: string,
    decision: "allow_once" | "deny",
    operatorId: string,
  ): Promise<ApprovalResolveResponse> {
    return this.post<ApprovalResolveResponse>(
      `/v1/approvals/${encodeURIComponent(approvalId)}/resolve`,
      {
        decision,
        operator_id: operatorId,
        channel: "feishu",
      },
      this.operatorToken,
    );
  }

  private async get<T>(path: string, token: string): Promise<T> {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      headers: {
        authorization: `Bearer ${token}`,
      },
    });
    return parseResponse<T>(response);
  }

  private async post<T>(path: string, body: unknown, token: string): Promise<T> {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
    });
    return parseResponse<T>(response);
  }
}

export class AgentGateHTTPError extends Error {
  readonly status: number;
  readonly code?: string;

  constructor(status: number, message: string, code?: string) {
    super(`AgentGate request failed: ${status} ${code ?? "error"}: ${message}`);
    this.name = "AgentGateHTTPError";
    this.status = status;
    this.code = code;
  }
}

async function parseResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const text = await response.text();
    try {
      const body = JSON.parse(text) as { error?: { code?: string; message?: string } };
      throw new AgentGateHTTPError(
        response.status,
        body.error?.message ?? response.statusText,
        body.error?.code,
      );
    } catch (error) {
      if (error instanceof AgentGateHTTPError) {
        throw error;
      }
      throw new AgentGateHTTPError(response.status, text || response.statusText);
    }
  }
  return response.json() as Promise<T>;
}
