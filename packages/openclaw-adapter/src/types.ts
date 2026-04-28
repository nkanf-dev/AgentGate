export type RequestKind =
  | "input"
  | "tool_attempt"
  | "resource_egress"
  | "resource_access"
  | "initial_envelope"
  | "envelope_amendment";

export type Surface = "input" | "runtime" | "resource";

export type Effect =
  | "allow"
  | "allow_with_audit"
  | "approval_required"
  | "deny"
  | "exclusion";

export type Taint =
  | "untrusted_external"
  | "possible_prompt_injection"
  | "embedded_instruction"
  | "secret_bearing";

export type DataClass =
  | "pii"
  | "secret"
  | "business"
  | "financial"
  | "credential";

export interface HostDescriptor {
  kind: string;
  version?: string;
}

export interface AdapterCapabilities {
  can_block: boolean;
  can_rewrite_input: boolean;
  can_rewrite_tool_args: boolean;
  can_pause_for_approval: boolean;
}

export interface AdapterRegistration {
  adapter_id: string;
  integration_id?: string;
  adapter_kind: string;
  host: HostDescriptor;
  surfaces: Surface[];
  supporting_channels?: string[];
  capabilities: AdapterCapabilities;
  metadata?: Record<string, unknown>;
}

export interface RegistrationResult {
  adapter_id: string;
  registered_at: string;
  accepted: boolean;
}

export interface ActorContext {
  user_id?: string;
  host_id?: string;
  agent_id?: string;
}

export interface SessionContext {
  session_id: string;
  task_id?: string;
  attempt_id?: string;
}

export interface ActionContext {
  operation?: string;
  tool?: string;
  side_effects?: string[];
  open_world?: boolean;
}

export interface TargetContext {
  kind?: string;
  identifier?: string;
}

export interface ContentContext {
  summary?: string;
  data_classes?: DataClass[];
}

export interface DecisionContext {
  surface: Surface;
  taints?: Taint[];
  raw?: Record<string, unknown>;
}

export interface PolicyRequest {
  request_id: string;
  request_kind: RequestKind;
  actor: ActorContext;
  session: SessionContext;
  action: ActionContext;
  target: TargetContext;
  content?: ContentContext;
  context: DecisionContext;
  policy?: Record<string, unknown>;
}

export interface Obligation {
  type: string;
  params?: Record<string, unknown>;
}

export interface SecretHandle {
  handle_id: string;
  session_id: string;
  task_id?: string;
  kind: string;
  placeholder: string;
  secret_hash: string;
  created_at: string;
}

export interface SecretFindingSummary {
  kind: string;
  placeholder: string;
  handle_id: string;
  hash: string;
  offset: number;
  length: number;
}

export interface PolicyRuleTrace {
  rule_id: string;
  priority: number;
  effect: Effect;
  reason_code: string;
}

export interface PolicyTrace {
  policy_version?: number;
  policy_status?: string;
  selected_rule?: string;
  top_priority?: number;
  defaulted?: boolean;
  matched_rules?: PolicyRuleTrace[];
}

export interface DecisionExplanation {
  summary?: string;
  warnings?: string[];
  policy_trace?: PolicyTrace;
}

export interface GuardDecision {
  decision_id: string;
  request_id: string;
  effect: Effect;
  reason_code: string;
  obligations: Obligation[];
  applied_rules?: string[];
  explanation?: DecisionExplanation;
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

export interface ReportResponse {
  accepted: boolean;
  recorded_at: string;
}

export interface AdapterCoverage {
  adapter_id: string;
  integration_id?: string;
  adapter_kind: string;
  host: HostDescriptor;
  surfaces: Surface[];
  supporting_channels?: string[];
  registered_at: string;
  last_seen_at: string;
}

export interface CoverageResponse {
  generated_at: string;
  adapters: AdapterCoverage[];
  surfaces: Record<Surface, number>;
  warnings?: string[];
}

export interface EventEnvelope {
  event_id: string;
  event_type: string;
  request_id?: string;
  decision_id?: string;
  session_id?: string;
  adapter_id?: string;
  surface?: Surface;
  effect?: Effect;
  summary: string;
  metadata?: Record<string, unknown>;
  occurred_at: string;
}

export interface EventsResponse {
  events: EventEnvelope[];
}
