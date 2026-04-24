export * from "./types.js";

import type {
  GuardDecision,
  InputAssessRequest,
  InputAssessment,
  ToolInvocationRequest
} from "./types.js";

export interface AgentGateClientOptions {
  baseUrl: string;
  fetch?: typeof fetch;
}

export class AgentGateClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: AgentGateClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.fetchImpl = options.fetch ?? fetch;
  }

  assessInput(request: InputAssessRequest): Promise<InputAssessment> {
    return this.post<InputAssessment>("/internal/input/assess", request);
  }

  evaluateToolCall(request: ToolInvocationRequest): Promise<GuardDecision> {
    return this.post<GuardDecision>("/internal/runtime/evaluate", request);
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      const message = await response.text();
      throw new Error(`AgentGate request failed: ${response.status} ${message}`);
    }

    return response.json() as Promise<T>;
  }
}
