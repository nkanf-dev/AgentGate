export type Taint =
  | "untrusted_external"
  | "possible_prompt_injection"
  | "embedded_instruction"
  | "secret_bearing";

export type SegmentKind =
  | "trusted_instruction"
  | "user_intent"
  | "external_observation";

export interface ContentSegment {
  kind: SegmentKind;
  text: string;
  offset: number;
  length: number;
}

export interface SecretFinding {
  kind: string;
  placeholder: string;
  hash: string;
  length: number;
}

export interface InputAssessment {
  assessment_id?: string;
  session_id: string;
  source: string;
  normalized_text?: string;
  content_segments: ContentSegment[];
  taints: Taint[];
  secret_findings: SecretFinding[];
  instruction_authority: boolean;
  blocked: boolean;
  assessed_at: string;
}

export interface InputAssessRequest {
  session_id: string;
  source: string;
  user_id?: string;
  content: string;
  attachments?: unknown[];
}

export type DataClass =
  | "pii"
  | "secret"
  | "business"
  | "financial"
  | "credential";

export interface InvocationContext {
  user_id?: string;
  source?: string;
  taints: Taint[];
  data_classes: DataClass[];
}

export interface ToolInvocationRequest {
  session_id: string;
  agent_id: string;
  tool: string;
  args: Record<string, unknown>;
  context: InvocationContext;
}

export type DecisionKind = "allow" | "deny" | "approval_required";

export type DecisionReason =
  | "policy_allow"
  | "policy_deny_not_in_allowlist"
  | "policy_deny_exclusion_list"
  | "tainted_instruction_with_secret_tool"
  | "tainted_sensitive_egress"
  | "first_use_requires_approval"
  | "user_allow_once_valid"
  | "user_deny";

export interface GuardDecision {
  decision: DecisionKind;
  reason: DecisionReason;
  approval_id?: string;
  preview?: ApprovalPreview;
  audit_event_id: string;
}

export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface ApprovalPreview {
  tool: string;
  target?: string;
  risk_level: RiskLevel;
  data_classes: DataClass[];
  reason: string;
  args_summary: string;
}

export type ApprovalStatus = "pending" | "approved" | "denied" | "expired";

export interface ApprovalRecord {
  approval_id: string;
  session_id: string;
  request: ToolInvocationRequest;
  preview: ApprovalPreview;
  status: ApprovalStatus;
  operator_id?: string;
  channel?: string;
  decided_at?: string;
  expires_at: string;
}

export interface ApprovalResolveRequest {
  decision: string;
  operator_id: string;
  channel: string;
}

export interface ApprovalResolveResponse {
  approval_id: string;
  status: ApprovalStatus;
  resolved_at: string;
}

export type SecurityEventType =
  | "secret_blocked_pre_model"
  | "prompt_injection_detected"
  | "tool_call_allowed"
  | "tool_call_denied"
  | "tool_call_approval_required"
  | "approval_granted"
  | "approval_denied"
  | "approval_expired"
  | "egress_blocked"
  | "egress_allowed"
  | "path_traversal_blocked"
  | "clipboard_read_redacted"
  | "pii_redacted_in_output";

export interface SecurityEvent {
  event_id: string;
  session_id: string;
  agent_id: string;
  event_type: SecurityEventType;
  decision: string;
  reason: string;
  data_classes: DataClass[];
  taints: Taint[];
  summary: string;
  evidence_id?: string;
  evidence_hash?: string;
  occurred_at: string;
  layer: "input_guard" | "runtime_guard" | "resource_guard";
}

export interface PolicyBundle {
  version: number;
  issued_at: string;
  tool_policy: ToolPolicy[];
  egress_policy: EgressPolicy;
  path_policy: PathPolicy;
}

export interface ToolPolicy {
  tool_pattern: string;
  risk_level: RiskLevel;
  require_approval: boolean;
  require_first_use_approval: boolean;
  exclusion: boolean;
  data_classes_triggers: DataClass[];
}

export interface EgressPolicy {
  host_allowlist: string[];
  block_sensitive_query_params: string[];
  require_purpose_declaration: boolean;
}

export interface PathPolicy {
  workspace_root: string;
  allow_worktree_siblings: boolean;
  blocked_prefixes: string[];
}

export interface EvidenceRecord {
  evidence_id: string;
  event_id: string;
  access_class: string;
  retention_days: number;
  created_at: string;
}

export interface EgressEvaluateRequest {
  session_id: string;
  url: string;
  method: string;
  body: string;
}

export interface EgressEvaluateResponse {
  decision: string;
  redacted_body?: string;
  findings?: SecretFinding[];
  audit_event_id: string;
}

export interface CheckPathRequest {
  session_id: string;
  path: string;
  operation: string;
}

export interface CheckPathResponse {
  allowed: boolean;
  reason: string;
}
