export const policyRequestKinds = [
  "input",
  "tool_attempt",
  "resource_egress",
  "resource_access",
  "initial_envelope",
  "envelope_amendment",
] as const

export const policyTaints = [
  "untrusted_external",
  "possible_prompt_injection",
  "embedded_instruction",
  "secret_bearing",
] as const

export const policyDataClasses = [
  "secret",
  "credential",
  "pii",
  "business",
  "financial",
] as const

export const ruleFactSuggestions = {
  tools: ["bash", "read", "grep", "write", "edit", "fetch"],
  operations: ["model_input", "execute", "read", "write", "fetch", "resolve_secret_handle"],
  sideEffects: ["filesystem_read", "filesystem_write", "network_egress", "process_spawn", "secret_resolve"],
  targetKinds: ["model_context", "process", "file", "url", "secret_handle", "api"],
} as const

export type ObligationCatalogItem = {
  type: string
  defaultParams: Record<string, unknown>
  executor: "Core" | "Adapter" | "Resource Provider"
  status: "supported" | "planned"
  description: string
}

export const obligationCatalog = [
  {
    type: "approval.request",
    defaultParams: { scope: "attempt", choices: ["deny", "allow_once"] },
    executor: "Core",
    status: "planned",
    description: "Core-layer approval.",
  },
  {
    type: "audit.redact",
    defaultParams: { fields: ["content.raw"] },
    executor: "Core",
    status: "planned",
    description: "Redact fields from audit records.",
  },
  {
    type: "audit_event",
    defaultParams: { severity: "info" },
    executor: "Core",
    status: "supported",
    description: "Emit an audit event.",
  },
  {
    type: "adapter.report_required",
    defaultParams: { timeout_ms: 30000 },
    executor: "Adapter",
    status: "planned",
    description: "Require adapter report.",
  },
  {
    type: "input.redact",
    defaultParams: { fields: ["content.raw"] },
    executor: "Core",
    status: "planned",
    description: "Redact input content.",
  },
  {
    type: "secret.create_handle",
    defaultParams: { scope: "session_task" },
    executor: "Core",
    status: "planned",
    description: "Create a SecretHandle.",
  },
  {
    type: "resource.resolve",
    defaultParams: { provider: "default" },
    executor: "Resource Provider",
    status: "planned",
    description: "Resolve resource reference.",
  },
  {
    type: "task_control",
    defaultParams: { action: "pause_for_approval" },
    executor: "Core",
    status: "supported",
    description: "Pause or abort execution.",
  },
] as const satisfies readonly ObligationCatalogItem[]

export const celSnippets = [
  {
    label: "Bash Side Effect",
    expression:
      'action.tool == "bash" && action.side_effects.exists(x, x in ["network_egress", "filesystem_write"])',
  },
  {
    label: "Secret Context",
    expression: 'content.data_classes.exists(x, x in ["secret", "credential"])',
  },
  {
    label: "Injection Taint",
    expression: 'context.taints.exists(x, x == "possible_prompt_injection")',
  },
] as const

export type CelCompletionItem = {
  label: string
  type: "variable" | "property" | "function" | "keyword" | "text"
  detail?: string
  info?: string
  apply?: string
}

export const celFactCompletions = [
  { label: "request_kind", type: "variable", detail: "string", info: "Policy request kind, such as tool_attempt or resource_access." },
  { label: "surface", type: "variable", detail: "input | runtime | resource", info: "Current enforcement surface." },
  { label: "actor", type: "variable", detail: "Actor Facts", info: "Actor identity reported by the adapter." },
  { label: "actor.user_id", type: "property", detail: "string", info: "End-user identity when available." },
  { label: "actor.host_id", type: "property", detail: "string", info: "Host and runtime identity reported by the adapter." },
  { label: "actor.agent_id", type: "property", detail: "string", info: "Agent identity when available." },
  { label: "session", type: "variable", detail: "Session Facts", info: "Session, task, and attempt correlation identifiers." },
  { label: "session.session_id", type: "property", detail: "string", info: "AgentGate session ID." },
  { label: "session.task_id", type: "property", detail: "string", info: "Current task ID." },
  { label: "session.attempt_id", type: "property", detail: "string", info: "Current attempt ID." },
  { label: "action", type: "variable", detail: "Action Facts", info: "Tool, operation, and side-effect facts." },
  { label: "action.operation", type: "property", detail: "string", info: "Normalized operation name." },
  { label: "action.tool", type: "property", detail: "string", info: "Tool name reported by the adapter." },
  { label: "action.side_effects", type: "property", detail: "list<string>", info: "Normalized side effects such as filesystem_write or network_egress." },
  { label: "action.open_world", type: "property", detail: "bool", info: "Whether the action can reach an open-world boundary." },
  { label: "target", type: "variable", detail: "Target Facts", info: "Resource or execution target." },
  { label: "target.kind", type: "property", detail: "string", info: "Target kind such as file, url, process, or secret_handle." },
  { label: "target.identifier", type: "property", detail: "string", info: "Target identifier or handle ID." },
  { label: "content", type: "variable", detail: "Content Facts", info: "Content classification facts from scanner or input processing." },
  { label: "content.summary", type: "property", detail: "string", info: "Redacted content summary." },
  { label: "content.data_classes", type: "property", detail: "list<string>", info: "Detected data classes such as secret, credential, or pii." },
  { label: "context", type: "variable", detail: "Decision Context", info: "Decision context and taint facts." },
  { label: "context.surface", type: "property", detail: "string", info: "Equivalent to surface; also accessible via context." },
  { label: "context.taints", type: "property", detail: "list<string>", info: "Taints such as untrusted_external or possible_prompt_injection." },
  { label: "context.raw", type: "property", detail: "map", info: "Raw context map provided by the adapter." },
  { label: "policy", type: "variable", detail: "Policy Input Map", info: "Additional context injected by policy evaluation." },
] as const satisfies readonly CelCompletionItem[]

export const celMacroCompletions = [
  {
    label: "exists",
    type: "function",
    detail: "list.exists(x, predicate)",
    apply: "exists(x, x == \"\")",
  },
  {
    label: "all",
    type: "function",
    detail: "list.all(x, predicate)",
    apply: "all(x, x != \"\")",
  },
  {
    label: "exists_one",
    type: "function",
    detail: "list.exists_one(x, predicate)",
    apply: "exists_one(x, x == \"\")",
  },
  {
    label: "filter",
    type: "function",
    detail: "list.filter(x, predicate)",
    apply: "filter(x, x != \"\")",
  },
  {
    label: "map",
    type: "function",
    detail: "list.map(x, expr)",
    apply: "map(x, x)",
  },
] as const satisfies readonly CelCompletionItem[]

export const celKeywordCompletions = [
  { label: "true", type: "keyword" },
  { label: "false", type: "keyword" },
  { label: "in", type: "keyword" },
  { label: "&&", type: "keyword", detail: "and" },
  { label: "||", type: "keyword", detail: "or" },
  { label: "!", type: "keyword", detail: "not" },
] as const satisfies readonly CelCompletionItem[]

export function defaultObligationParams(type: string): Record<string, unknown> {
  return (
    obligationCatalog.find((item) => item.type === type)?.defaultParams ?? {}
  )
}

export function obligationTypeOptions() {
  return obligationCatalog.map((item) => item.type) as string[]
}
