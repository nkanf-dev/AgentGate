export type FeishuDomain = "feishu" | "lark";

export interface FeishuApprovalAdapterConfig {
  agentGateBaseUrl: string;
  adapterId: string;
  integrationId?: string;
  adapterToken: string;
  operatorToken: string;
  appId: string;
  appSecret: string;
  receiveId: string;
  receiveIdType: "chat_id" | "open_id" | "user_id" | "union_id" | "email";
  domain?: FeishuDomain;
  pollIntervalMs?: number;
}

export interface EventEnvelope {
  event_id: string;
  event_type: string;
  request_id?: string;
  decision_id?: string;
  session_id?: string;
  adapter_id?: string;
  surface?: "input" | "runtime" | "resource";
  effect?: "allow" | "allow_with_audit" | "approval_required" | "deny" | "exclusion";
  summary: string;
  metadata?: Record<string, unknown>;
  occurred_at: string;
}

export interface ApprovalCardPayload {
  approvalId: string;
  requestId?: string;
  sessionId?: string;
  taskId?: string;
  attemptId?: string;
  reason: string;
  surface?: string;
  scope?: string;
  expiresAt?: string;
  occurredAt?: string;
  tool?: string;
  operation?: string;
  targetKind?: string;
  targetIdentifier?: string;
  contentSummary?: string;
  sideEffects?: string[];
  selectedRule?: string;
}

export interface ApprovalResolveResponse {
  approval_id: string;
  status: "pending" | "approved" | "denied" | "expired";
  resolved_at: string;
}

export interface ApprovalRecord {
  approval_id: string;
  request_id?: string;
  session_id: string;
  task_id?: string;
  attempt_id?: string;
  status: "pending" | "approved" | "denied" | "expired";
  reason: string;
  operator_id?: string;
  channel?: string;
  created_at: string;
  expires_at: string;
  resolved_at?: string;
}

export interface ApprovalsResponse {
  approvals: ApprovalRecord[];
}
