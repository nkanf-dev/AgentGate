export type Surface = "input" | "runtime" | "resource";

export type Effect =
  | "allow"
  | "allow_with_audit"
  | "approval_required"
  | "deny"
  | "exclusion";

export interface AdapterRegistration {
  adapter_id: string;
  integration_id?: string;
  adapter_kind: string;
  host: {
    kind: string;
    version?: string;
  };
  surfaces: Surface[];
  supporting_channels?: string[];
  capabilities: {
    can_block: boolean;
    can_rewrite_input: boolean;
    can_rewrite_tool_args: boolean;
    can_pause_for_approval: boolean;
  };
  metadata?: Record<string, unknown>;
}

export interface PolicyRequest {
  request_id: string;
  request_kind: "resource_access";
  actor: {
    user_id?: string;
    host_id?: string;
    agent_id?: string;
  };
  session: {
    session_id: string;
    task_id: string;
    attempt_id?: string;
  };
  action: {
    operation?: string;
    tool?: string;
    side_effects?: string[];
    open_world?: boolean;
  };
  target: {
    kind: string;
    identifier: string;
  };
  context: {
    surface: "resource";
    taints?: string[];
    raw?: Record<string, unknown>;
  };
  policy?: Record<string, unknown>;
}

export interface Obligation {
  type: string;
  params?: Record<string, unknown>;
}

export interface PolicyDecision {
  decision_id: string;
  request_id: string;
  effect: Effect;
  reason_code: string;
  obligations: Obligation[];
  applied_rules?: string[];
  decided_at: string;
}

export interface ReportRequest {
  request_id: string;
  decision_id?: string;
  adapter_id?: string;
  surface?: Surface;
  outcome: string;
  obligations?: Obligation[];
  error_message?: string;
  metadata?: Record<string, unknown>;
}

export interface ResolveSecretHandleRequest {
  handleId: string;
  sessionId: string;
  taskId: string;
  attemptId?: string;
  actor?: {
    userId?: string;
    hostId?: string;
    agentId?: string;
  };
  purpose?: string;
}

export interface ResolvedSecretHandle {
  handleId: string;
  placeholder?: string;
  kind?: string;
  secretValue: string;
  decisionId: string;
  requestId: string;
}
