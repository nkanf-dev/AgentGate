import { AgentGateResourceClient } from "./client.js";
import type {
  AdapterRegistration,
  Obligation,
  ResolveSecretHandleRequest,
  ResolvedSecretHandle,
} from "./types.js";

export interface AgentGateResourceAdapterOptions {
  baseUrl: string;
  adapterId?: string;
  integrationId?: string;
  adapterToken?: string;
  hostKind?: string;
  hostVersion?: string;
  fetch?: typeof fetch;
}

export class AgentGateResourceAdapter {
  readonly adapterId: string;
  private readonly client: AgentGateResourceClient;
  private readonly integrationId?: string;
  private readonly hostKind: string;
  private readonly hostVersion?: string;

  constructor(options: AgentGateResourceAdapterOptions) {
    this.adapterId = options.adapterId ?? "agentgate-resource-adapter";
    this.integrationId = options.integrationId;
    this.hostKind = options.hostKind ?? "generic-resource-provider";
    this.hostVersion = options.hostVersion;
    this.client = new AgentGateResourceClient({
      baseUrl: options.baseUrl,
      token: options.adapterToken,
      fetch: options.fetch,
    });
  }

  register(): Promise<unknown> {
    return this.client.register(createResourceRegistration(this.adapterId, this.hostKind, this.hostVersion, this.integrationId));
  }

  async resolveSecretHandle(request: ResolveSecretHandleRequest): Promise<ResolvedSecretHandle> {
    const policyRequest = {
      request_id: `req_resource_${Date.now()}`,
      request_kind: "resource_access" as const,
      actor: {
        user_id: request.actor?.userId,
        host_id: request.actor?.hostId ?? this.hostKind,
        agent_id: request.actor?.agentId,
      },
      session: {
        session_id: request.sessionId,
        task_id: request.taskId,
        attempt_id: request.attemptId,
      },
      action: {
        operation: "resolve_secret_handle",
        side_effects: ["secret_resolve"],
      },
      target: {
        kind: "secret_handle",
        identifier: request.handleId,
      },
      context: {
        surface: "resource" as const,
        raw: {
          purpose: request.purpose,
        },
      },
      policy: {},
    };
    const decision = await this.client.decide(policyRequest);
    const resolved = secretFromObligations(decision.obligations);

    if ((decision.effect === "deny" || decision.effect === "exclusion") || resolved === undefined) {
      await this.client.report({
        request_id: decision.request_id,
        decision_id: decision.decision_id,
        adapter_id: this.adapterId,
        surface: "resource",
        outcome: decision.reason_code,
        obligations: reportableObligations(decision.obligations),
      });
      throw new Error(`AgentGate denied secret handle resolve: ${decision.reason_code}`);
    }

    await this.client.report({
      request_id: decision.request_id,
      decision_id: decision.decision_id,
      adapter_id: this.adapterId,
      surface: "resource",
      outcome: "secret_handle_resolved",
      obligations: reportableObligations(decision.obligations),
      metadata: {
        handle_id: resolved.handleId,
        kind: resolved.kind,
      },
    });

    return {
      handleId: resolved.handleId,
      placeholder: resolved.placeholder,
      kind: resolved.kind,
      secretValue: resolved.secretValue,
      decisionId: decision.decision_id,
      requestId: decision.request_id,
    };
  }
}

export function createResourceRegistration(
  adapterId: string,
  hostKind = "generic-resource-provider",
  hostVersion?: string,
  integrationId?: string,
): AdapterRegistration {
  return {
    adapter_id: adapterId,
    integration_id: integrationId,
    adapter_kind: "resource_provider",
    host: {
      kind: hostKind,
      version: hostVersion,
    },
    surfaces: ["resource"],
    capabilities: {
      can_block: true,
      can_rewrite_input: false,
      can_rewrite_tool_args: false,
      can_pause_for_approval: false,
    },
  };
}

function reportableObligations(obligations: Obligation[]): Obligation[] {
  return obligations.map((obligation) => ({ type: obligation.type }));
}

function secretFromObligations(obligations: Obligation[]):
  | { handleId: string; placeholder?: string; kind?: string; secretValue: string }
  | undefined {
  for (const obligation of obligations) {
    if (obligation.type !== "resolve_secret_handle") {
      continue;
    }
    const handleId = stringValue(obligation.params?.handle_id);
    const secretValue = stringValue(obligation.params?.secret_value);
    if (handleId !== undefined && secretValue !== undefined) {
      return {
        handleId,
        placeholder: stringValue(obligation.params?.placeholder),
        kind: stringValue(obligation.params?.kind),
        secretValue,
      };
    }
  }
  return undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}
