import type {
  AdapterRegistration,
  PolicyDecision,
  PolicyRequest,
  ReportRequest,
} from "./types.js";

export interface AgentGateResourceClientOptions {
  baseUrl: string;
  token?: string;
  fetch?: typeof fetch;
}

export class AgentGateResourceClient {
  private readonly baseUrl: string;
  private readonly token?: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: AgentGateResourceClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.token = options.token;
    this.fetchImpl = options.fetch ?? fetch;
  }

  register(request: AdapterRegistration): Promise<unknown> {
    return this.post("/v1/register", request);
  }

  decide(request: PolicyRequest): Promise<PolicyDecision> {
    return this.post<PolicyDecision>("/v1/decide", request);
  }

  report(request: ReportRequest): Promise<unknown> {
    return this.post("/v1/report", request);
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: {
        ...(this.token ? { authorization: `Bearer ${this.token}` } : {}),
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      throw new Error(`AgentGate request failed: ${response.status} ${await response.text()}`);
    }
    return response.json() as Promise<T>;
  }
}
