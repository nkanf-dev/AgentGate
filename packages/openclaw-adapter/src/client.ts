import type {
  AdapterRegistration,
  CoverageResponse,
  EventsResponse,
  GuardDecision,
  PolicyRequest,
  RegistrationResult,
  ReportRequest,
  ReportResponse,
} from "./types.js";

export interface AgentGateClientOptions {
  baseUrl: string;
  token?: string;
  fetch?: typeof fetch;
}

export class AgentGateClient {
  private readonly baseUrl: string;
  private readonly token?: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: AgentGateClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.token = options.token;
    this.fetchImpl = options.fetch ?? fetch;
  }

  register(request: AdapterRegistration): Promise<RegistrationResult> {
    return this.post<RegistrationResult>("/v1/register", request);
  }

  decide(request: PolicyRequest): Promise<GuardDecision> {
    return this.post<GuardDecision>("/v1/decide", request);
  }

  report(request: ReportRequest): Promise<ReportResponse> {
    return this.post<ReportResponse>("/v1/report", request);
  }

  coverage(): Promise<CoverageResponse> {
    return this.get<CoverageResponse>("/v1/coverage");
  }

  events(limit?: number): Promise<EventsResponse> {
    const suffix = limit === undefined ? "" : `?limit=${encodeURIComponent(limit)}`;
    return this.get<EventsResponse>(`/v1/events${suffix}`);
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: this.headers({ "content-type": "application/json" }),
      body: JSON.stringify(body),
    });

    return parseResponse<T>(response);
  }

  private async get<T>(path: string): Promise<T> {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method: "GET",
      headers: this.headers(),
    });

    return parseResponse<T>(response);
  }

  private headers(extra?: Record<string, string>): Record<string, string> {
    return {
      ...(this.token ? { authorization: `Bearer ${this.token}` } : {}),
      ...(extra ?? {}),
    };
  }
}

export async function decideOrDeny(
  client: AgentGateClient,
  request: PolicyRequest,
): Promise<GuardDecision> {
  try {
    return await client.decide(request);
  } catch (error) {
    return {
      decision_id: `dec_fail_closed_${Date.now()}`,
      request_id: request.request_id,
      effect: "deny",
      reason_code: "agentgate_unavailable_fail_closed",
      obligations: [
        {
          type: "audit_event",
          params: {
            severity: "critical",
            message: error instanceof Error ? error.message : "unknown error",
          },
        },
        {
          type: "task_control",
          params: {
            action: "abort_task",
          },
        },
      ],
      applied_rules: ["local-pep-fail-closed"],
      explanation: {
        summary: "AgentGate Core is unavailable; PEP failed closed.",
      },
      decided_at: new Date().toISOString(),
    };
  }
}

async function parseResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const message = await response.text();
    throw new Error(`AgentGate request failed: ${response.status} ${message}`);
  }

  return response.json() as Promise<T>;
}
