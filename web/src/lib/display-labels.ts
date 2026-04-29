import type {
  Effect,
  EventSurface,
  IntegrationHealthStatus,
  Surface,
} from "@/lib/agentgate-api"

export const surfaceLabels: Record<Surface, string> = {
  input: "Input",
  runtime: "Runtime",
  resource: "Resource",
}

export const effectLabels: Record<Effect, string> = {
  allow: "Allow",
  allow_with_audit: "Allow & Audit",
  deny: "Deny",
  approval_required: "Approval Required",
  exclusion: "Excluded",
}

export const requestKindLabels: Record<string, string> = {
  input: "Input",
  tool_attempt: "Tool Attempt",
  resource_egress: "Resource Egress",
  resource_access: "Resource Access",
  initial_envelope: "Initial Envelope",
  envelope_amendment: "Envelope Amendment",
}

export const dataClassLabels: Record<string, string> = {
  secret: "Secret",
  credential: "Credential",
  pii: "PII",
  business: "Business",
  financial: "Financial",
}

export const taintLabels: Record<string, string> = {
  untrusted_external: "Untrusted External",
  possible_prompt_injection: "Possible Prompt Injection",
  embedded_instruction: "Embedded Instruction",
  secret_bearing: "Secret Bearing",
}

export const statusLabels: Record<string, string> = {
  active: "Active",
  inactive: "Inactive",
  archived: "Archived",
  approved: "Approved",
  denied: "Denied",
  pending: "Pending",
  supported: "Supported",
  planned: "Planned",
  attempt: "Attempt",
  task: "Task",
  session: "Session",
  session_task: "Session Task",
  connected: "Connected",
  stale: "Stale",
  missing: "Missing",
  unmanaged: "Unmanaged",
  disabled: "Disabled",
  adapter: "Adapter",
  transport: "Transport",
  resource_provider: "Resource Provider",
}

export const integrationHealthLabels: Record<IntegrationHealthStatus, string> = {
  connected: "Connected",
  stale: "Stale",
  missing: "Missing",
  unmanaged: "Unmanaged",
  disabled: "Disabled",
}

export function surfaceLabel(surface: EventSurface | Surface) {
  return surface === "none" ? "Unknown Surface" : surfaceLabels[surface]
}

export function effectLabel(effect: Effect) {
  return effectLabels[effect] ?? effect
}

export function requestKindLabel(requestKind: string) {
  return requestKindLabels[requestKind] ?? requestKind
}

export function statusLabel(status?: string) {
  return status ? statusLabels[status] ?? status : "Inactive"
}

export function dataClassLabel(dataClass: string) {
  return dataClassLabels[dataClass] ?? titleCaseOption(dataClass)
}

export function taintLabel(taint: string) {
  return taintLabels[taint] ?? titleCaseOption(taint)
}

export function titleCaseOption(value: string) {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ")
}
