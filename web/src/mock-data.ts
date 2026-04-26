// MOCK DATA ONLY.
// This file is the only data source for the current static frontend mock.
// Replace these fixtures with `/v1/events`, `/v1/coverage`, and approval API
// calls when the console is wired to a running AgentGate Core.

export type Surface = "input" | "runtime" | "resource"
export type Effect = "allow_with_audit" | "deny" | "approval_required" | "rewrite"

export type SecurityEvent = {
  id: string
  created_at: string
  decision_id: string
  effect: Effect
  request_kind:
    | "input"
    | "tool_attempt"
    | "resource_access"
    | "resource_egress"
    | "envelope_amendment"
  surface: Surface
  adapter_id: string
  session_id: string
  task_id: string
  attempt_id?: string
  approval_id?: string
  reason_code: string
  latency_ms: number
  policy_version: string
  redacted_summary: string
  applied_rules: string[]
  obligations: string[]
  findings: string[]
  taints: string[]
  data_classes: string[]
}

export type CoverageAdapter = {
  adapter_id: string
  host: string
  version: string
  surfaces: Surface[]
  supporting_channels: string[]
  capabilities: string[]
  last_seen: string
  warnings: string[]
}

export type Approval = {
  approval_id: string
  created_at: string
  session_id: string
  task_id: string
  attempt_id: string
  operator_id: string
  reason: string
  status: "pending" | "resolved"
  expires_in: string
}

export const events: SecurityEvent[] = [
  {
    id: "evt_0007",
    created_at: "2026-04-26T14:18:48.391Z",
    decision_id: "dec_resource_42",
    effect: "deny",
    request_kind: "resource_egress",
    surface: "resource",
    adapter_id: "resource-provider-http",
    session_id: "sess_feishu_42",
    task_id: "task_secret_rotation",
    attempt_id: "att_009",
    reason_code: "resource.egress.unapproved_host",
    latency_ms: 18,
    policy_version: "policy_2026_04_26_a",
    redacted_summary:
      "Blocked outbound POST to unknown host carrying handle [SECRET_HANDLE:api_token_1].",
    applied_rules: ["resource.no_unknown_egress", "secret_handle.resolve_scope"],
    obligations: ["block", "audit_event:critical"],
    findings: ["secret handle present", "unknown egress host"],
    taints: ["secret"],
    data_classes: ["api_token"],
  },
  {
    id: "evt_0006",
    created_at: "2026-04-26T14:18:41.012Z",
    decision_id: "dec_report_41",
    effect: "allow_with_audit",
    request_kind: "envelope_amendment",
    surface: "runtime",
    adapter_id: "openclaw-agentgate",
    session_id: "sess_feishu_42",
    task_id: "task_secret_rotation",
    attempt_id: "att_008",
    reason_code: "approval.envelope_grant_applied",
    latency_ms: 11,
    policy_version: "policy_2026_04_26_a",
    redacted_summary:
      "Applied task envelope grant for exact bash attempt after operator approval.",
    applied_rules: ["runtime.approval_budget", "runtime.exact_attempt_grant"],
    obligations: ["audit_event:info"],
    findings: ["grant matched exact attempt"],
    taints: ["secret"],
    data_classes: ["api_token"],
  },
  {
    id: "evt_0005",
    created_at: "2026-04-26T14:18:08.774Z",
    decision_id: "dec_runtime_40",
    effect: "approval_required",
    request_kind: "tool_attempt",
    surface: "runtime",
    adapter_id: "openclaw-agentgate",
    session_id: "sess_feishu_42",
    task_id: "task_secret_rotation",
    attempt_id: "att_008",
    approval_id: "appr_77",
    reason_code: "runtime.open_world_secret_context",
    latency_ms: 24,
    policy_version: "policy_2026_04_26_a",
    redacted_summary:
      "bash command requested network-capable execution while task context contained [SECRET_HANDLE:api_token_1].",
    applied_rules: ["runtime.open_world_requires_approval"],
    obligations: ["pause_for_approval", "audit_event:warning"],
    findings: ["open world tool", "secret taint in context"],
    taints: ["secret", "network_egress"],
    data_classes: ["api_token"],
  },
  {
    id: "evt_0004",
    created_at: "2026-04-26T14:18:02.331Z",
    decision_id: "dec_input_39",
    effect: "rewrite",
    request_kind: "input",
    surface: "input",
    adapter_id: "openclaw-agentgate",
    session_id: "sess_feishu_42",
    task_id: "task_secret_rotation",
    reason_code: "input.secret_detected_handle_created",
    latency_ms: 32,
    policy_version: "policy_2026_04_26_a",
    redacted_summary:
      "Detected API token in Feishu message; replaced model-visible text with [SECRET_HANDLE:api_token_1].",
    applied_rules: ["input.secret_to_handle", "input.redact_model_context"],
    obligations: ["rewrite_input", "create_secret_handle", "audit_event:warning"],
    findings: ["api token pattern"],
    taints: ["secret"],
    data_classes: ["api_token"],
  },
  {
    id: "evt_0003",
    created_at: "2026-04-26T14:15:19.080Z",
    decision_id: "dec_runtime_31",
    effect: "deny",
    request_kind: "tool_attempt",
    surface: "runtime",
    adapter_id: "openclaw-agentgate",
    session_id: "sess_demo_19",
    task_id: "task_shell_audit",
    attempt_id: "att_004",
    reason_code: "runtime.filesystem_write_outside_envelope",
    latency_ms: 15,
    policy_version: "policy_2026_04_26_a",
    redacted_summary:
      "Denied filesystem write outside approved task envelope for demo workspace.",
    applied_rules: ["runtime.workspace_write_scope"],
    obligations: ["block", "audit_event:critical"],
    findings: ["filesystem write", "path outside envelope"],
    taints: ["filesystem"],
    data_classes: ["workspace_file"],
  },
  {
    id: "evt_0002",
    created_at: "2026-04-26T14:13:02.902Z",
    decision_id: "dec_input_18",
    effect: "allow_with_audit",
    request_kind: "input",
    surface: "input",
    adapter_id: "openclaw-agentgate",
    session_id: "sess_docs_11",
    task_id: "task_readme_update",
    reason_code: "input.low_risk_task",
    latency_ms: 9,
    policy_version: "policy_2026_04_26_a",
    redacted_summary:
      "Allowed low-risk documentation request with audit-only obligation.",
    applied_rules: ["input.low_risk_allow"],
    obligations: ["audit_event:info"],
    findings: ["documentation intent"],
    taints: [],
    data_classes: [],
  },
  {
    id: "evt_0001",
    created_at: "2026-04-26T14:12:44.015Z",
    decision_id: "dec_resource_12",
    effect: "allow_with_audit",
    request_kind: "resource_access",
    surface: "resource",
    adapter_id: "resource-provider-http",
    session_id: "sess_docs_11",
    task_id: "task_readme_update",
    attempt_id: "att_002",
    reason_code: "resource.public_docs_allowed",
    latency_ms: 13,
    policy_version: "policy_2026_04_26_a",
    redacted_summary: "Allowed public docs fetch; no sensitive evidence attached.",
    applied_rules: ["resource.public_get_allow"],
    obligations: ["audit_event:info"],
    findings: ["public host"],
    taints: [],
    data_classes: [],
  },
]

export const coverage: CoverageAdapter[] = [
  {
    adapter_id: "openclaw-agentgate",
    host: "openclaw",
    version: "verified-plugin-hook",
    surfaces: ["input", "runtime"],
    supporting_channels: ["approval_transport", "notification"],
    capabilities: [
      "can_block",
      "can_rewrite_input",
      "can_rewrite_tool_args",
      "can_pause_for_approval",
    ],
    last_seen: "2026-04-26T14:18:49.110Z",
    warnings: ["resource surface provided by separate provider"],
  },
  {
    adapter_id: "resource-provider-http",
    host: "generic-resource-provider",
    version: "mock-contract-shape",
    surfaces: ["resource"],
    supporting_channels: [],
    capabilities: ["can_block", "can_resolve_secret_handle"],
    last_seen: "2026-04-26T14:18:48.992Z",
    warnings: [],
  },
]

export const approvals: Approval[] = [
  {
    approval_id: "appr_77",
    created_at: "2026-04-26T14:18:08.774Z",
    session_id: "sess_feishu_42",
    task_id: "task_secret_rotation",
    attempt_id: "att_008",
    operator_id: "operator_demo",
    reason: "Open-world runtime attempt while secret handle is in task context.",
    status: "pending",
    expires_in: "08:42",
  },
]

export const histogram = [
  { minute: "14:12", input: 1, runtime: 0, resource: 1 },
  { minute: "14:13", input: 1, runtime: 0, resource: 0 },
  { minute: "14:14", input: 0, runtime: 0, resource: 0 },
  { minute: "14:15", input: 0, runtime: 1, resource: 0 },
  { minute: "14:16", input: 0, runtime: 0, resource: 0 },
  { minute: "14:17", input: 0, runtime: 0, resource: 0 },
  { minute: "14:18", input: 1, runtime: 2, resource: 1 },
]
