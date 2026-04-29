export type Surface = "input" | "runtime" | "resource"
export type EventSurface = Surface | "none"
export type Effect =
  | "allow"
  | "allow_with_audit"
  | "approval_required"
  | "deny"
  | "exclusion"

export type ConsoleConfig = {
  baseUrl: string
  operatorToken: string
  adminToken: string
}

export type EventEnvelope = {
  event_id: string
  event_type: string
  request_id?: string
  decision_id?: string
  session_id?: string
  adapter_id?: string
  surface?: Surface
  effect?: Effect
  summary: string
  metadata?: Record<string, unknown>
  occurred_at: string
}

export type EventsResponse = {
  events: EventEnvelope[]
}

export type CoverageResponse = {
  generated_at: string
  adapters: AdapterCoverage[]
  surfaces: Partial<Record<Surface, number>>
  warnings?: string[]
}

export type AdapterCoverage = {
  adapter_id: string
  integration_id?: string
  adapter_kind: string
  host: {
    kind: string
    version?: string
  }
  surfaces: Surface[]
  supporting_channels?: string[]
  registered_at: string
  last_seen_at: string
}

export type IntegrationHealthStatus =
  | "connected"
  | "stale"
  | "missing"
  | "unmanaged"
  | "disabled"

export type IntegrationHealth = {
  status: IntegrationHealthStatus
  matched_adapter_id?: string
  matched_adapter_count?: number
  last_seen_at?: string
  computed_at: string
}

export type IntegrationMatchedAdapter = {
  adapter_id: string
  integration_id: string
  adapter_kind: string
  host: {
    kind: string
    version?: string
  }
  surfaces: Surface[]
  supporting_channels?: string[]
  status: IntegrationHealthStatus
  registered_at: string
  last_seen_at: string
}

export type IntegrationDefinition = {
  id: string
  name: string
  kind: string
  enabled: boolean
  expected_surfaces?: Surface[]
  health: IntegrationHealth
  matched_adapters?: IntegrationMatchedAdapter[]
}

export type IntegrationDefinitionInput = {
  id: string
  name: string
  kind: string
  enabled: boolean
  expected_surfaces?: Surface[]
}

export type IntegrationsResponse = {
  integrations: IntegrationDefinition[]
}

export type SecurityEvent = {
  id: string
  created_at: string
  decision_id: string
  effect: Effect
  request_kind: string
  surface: EventSurface
  adapter_id: string
  session_id: string
  task_id: string
  attempt_id?: string
  approval_id?: string
  reason_code: string
  latency_ms?: number
  policy_version?: string
  policy_status?: string
  selected_rule?: string
  matched_rules: string[]
  redacted_summary: string
  applied_rules: string[]
  obligations: string[]
  metadata: string[]
  findings: string[]
  taints: string[]
  data_classes: string[]
  event_type: string
}

export type Approval = {
  approval_id: string
  request_id?: string
  created_at: string
  expires_at: string
  resolved_at?: string
  session_id: string
  task_id: string
  attempt_id: string
  operator_id: string
  reason: string
  scope: string
  status: "pending" | "approved" | "denied" | "expired"
  expires_in: string
}

export type ApprovalsResponse = {
  approvals: ApprovalRecord[]
}

export type ApprovalRecord = {
  approval_id: string
  request_id?: string
  session_id: string
  task_id?: string
  attempt_id?: string
  status: "pending" | "approved" | "denied" | "expired"
  reason: string
  operator_id?: string
  channel?: string
  created_at: string
  expires_at: string
  resolved_at?: string
}

export type HistogramBucket = {
  minute: string
  input: number
  runtime: number
  resource: number
}

export type ConsoleData = {
  events: SecurityEvent[]
  coverage: CoverageResponse
  approvals: Approval[]
  histogram: HistogramBucket[]
}

export type PolicyCondition = {
  language?: "cel"
  expression?: string
  always?: boolean
  tools?: string[]
  operations?: string[]
  side_effects_any?: string[]
  side_effects_all?: string[]
  open_world?: boolean
  target_kinds?: string[]
  target_identifiers?: string[]
  taints_any?: string[]
  data_classes_any?: string[]
  actor_user_ids?: string[]
}

export type PolicyRule = {
  id: string
  description?: string
  priority: number
  surface: Surface
  request_kinds?: string[]
  effect: Effect
  reason_code: string
  when?: PolicyCondition
  obligations?: Array<{ type: string; params?: Record<string, unknown> }>
}

export type PolicyBundle = {
  bundle_id?: string
  name?: string
  description?: string
  priority?: number
  version: number
  status?: string
  issued_at: string
  created_at?: string
  updated_at?: string
  rules: PolicyRule[]
  input_policy: { secret_mode: string }
  runtime_policy?: Record<string, unknown>
  resource_policy: { secret_handle_scope: string }
  egress_policy?: Record<string, unknown>
  path_policy?: Record<string, unknown>
}

export type PolicyVersionRecord = {
  version: number
  status: string
  active: boolean
  rule_count: number
  published_at: string
  published_by?: string
  message?: string
  source_version?: number
}

export type PolicyCurrentResponse = {
  bundle: PolicyBundle
  record: PolicyVersionRecord
}

export type PolicyValidationResponse = {
  valid: boolean
  errors?: string[]
  warnings?: string[]
  version?: number
  rule_count?: number
  surface_rules?: Partial<Record<Surface, number>>
}

export type PolicyVersionsResponse = {
  versions: PolicyVersionRecord[]
}

export type PolicyBundlesResponse = {
  bundles: PolicyBundle[]
}

export const defaultConfig: ConsoleConfig = {
  baseUrl: import.meta.env.VITE_AGENTGATE_BASE_URL ?? "http://localhost:8080",
  operatorToken: import.meta.env.VITE_AGENTGATE_OPERATOR_TOKEN ?? "",
  adminToken: import.meta.env.VITE_AGENTGATE_ADMIN_TOKEN ?? "",
}

const configStorageKey = "agentgate.console.config.v1"

export function loadConfig(): ConsoleConfig {
  const stored = window.localStorage.getItem(configStorageKey)
  if (!stored) {
    return defaultConfig
  }

  try {
    return normalizeConsoleConfig({ ...defaultConfig, ...JSON.parse(stored) })
  } catch {
    return defaultConfig
  }
}

export function saveConfig(config: ConsoleConfig) {
  window.localStorage.setItem(
    configStorageKey,
    JSON.stringify(normalizeConsoleConfig(config))
  )
}

function normalizeConsoleConfig(config: ConsoleConfig): ConsoleConfig {
  return {
    baseUrl: config.baseUrl.trim() || defaultConfig.baseUrl,
    operatorToken: config.operatorToken.trim(),
    adminToken: config.adminToken.trim(),
  }
}

export async function fetchConsoleData(
  baseUrl: string,
  signal?: AbortSignal
): Promise<ConsoleData> {
  const [eventsResponse, coverage, approvalsResponse] = await Promise.all([
    fetchAgentGate<EventsResponse>(baseUrl, "/v1/events?limit=200", signal),
    fetchAgentGate<CoverageResponse>(baseUrl, "/v1/coverage", signal),
    fetchAgentGate<ApprovalsResponse>(baseUrl, "/v1/approvals?limit=200", signal),
  ])
  const events = eventsResponse.events
    .map(normalizeEvent)
    .sort((left, right) => right.created_at.localeCompare(left.created_at))

  return {
    events,
    coverage: normalizeCoverage(coverage),
    approvals: normalizeApprovals(approvalsResponse.approvals, events),
    histogram: buildHistogram(events),
  }
}

export async function resolveApproval(
  baseUrl: string,
  approvalId: string,
  decision: "allow_once" | "deny",
  operatorId = "web-console"
) {
  return fetchAgentGate<{ approval_id: string; status: string; resolved_at: string }>(
    baseUrl,
    `/v1/approvals/${encodeURIComponent(approvalId)}/resolve`,
    undefined,
    {
      method: "POST",
      body: JSON.stringify({
        decision,
        operator_id: operatorId,
        channel: "web_console",
      }),
    }
  )
}

export async function currentPolicy(
  baseUrl: string,
  adminToken: string,
  signal?: AbortSignal
) {
  return fetchAgentGate<PolicyCurrentResponse>(
    baseUrl,
    "/internal/policy/current",
    signal,
    undefined,
    adminToken
  )
}

export async function policyVersions(
  baseUrl: string,
  adminToken: string,
  signal?: AbortSignal
) {
  return fetchAgentGate<PolicyVersionsResponse>(
    baseUrl,
    "/internal/policy/versions?limit=50",
    signal,
    undefined,
    adminToken
  )
}

export async function validatePolicy(
  baseUrl: string,
  adminToken: string,
  bundle: PolicyBundle
) {
  return fetchAgentGate<PolicyValidationResponse>(
    baseUrl,
    "/internal/policy/validate",
    undefined,
    {
      method: "POST",
      body: JSON.stringify({ bundle }),
    },
    adminToken
  )
}

export async function policyBundles(
  baseUrl: string,
  adminToken: string,
  signal?: AbortSignal
) {
  return fetchAgentGate<PolicyBundlesResponse>(
    baseUrl,
    "/internal/policy/bundles",
    signal,
    undefined,
    adminToken
  )
}

export async function createPolicyBundle(
  baseUrl: string,
  adminToken: string,
  bundle: PolicyBundle
) {
  return fetchAgentGate<PolicyBundle>(
    baseUrl,
    "/internal/policy/bundles",
    undefined,
    {
      method: "POST",
      body: JSON.stringify(bundle),
    },
    adminToken
  )
}

export async function updatePolicyBundle(
  baseUrl: string,
  adminToken: string,
  bundleId: string,
  bundle: PolicyBundle
) {
  return fetchAgentGate<PolicyBundle>(
    baseUrl,
    `/internal/policy/bundles/${encodeURIComponent(bundleId)}`,
    undefined,
    {
      method: "PATCH",
      body: JSON.stringify(bundle),
    },
    adminToken
  )
}

export async function deletePolicyBundle(
  baseUrl: string,
  adminToken: string,
  bundleId: string
) {
  return fetchAgentGate<void>(
    baseUrl,
    `/internal/policy/bundles/${encodeURIComponent(bundleId)}`,
    undefined,
    { method: "DELETE" },
    adminToken
  )
}

export async function validatePolicyBundle(
  baseUrl: string,
  adminToken: string,
  bundleId: string
) {
  return fetchAgentGate<PolicyValidationResponse>(
    baseUrl,
    `/internal/policy/bundles/${encodeURIComponent(bundleId)}/validate`,
    undefined,
    { method: "POST" },
    adminToken
  )
}

export async function publishPolicyBundle(
  baseUrl: string,
  adminToken: string,
  bundleId: string
) {
  return fetchAgentGate<PolicyBundle>(
    baseUrl,
    `/internal/policy/bundles/${encodeURIComponent(bundleId)}/publish`,
    undefined,
    { method: "POST" },
    adminToken
  )
}

export async function publishPolicy(
  baseUrl: string,
  adminToken: string,
  bundle: PolicyBundle,
  message: string,
  operatorId = "web-console"
) {
  return fetchAgentGate<PolicyCurrentResponse>(
    baseUrl,
    "/internal/policy/publish",
    undefined,
    {
      method: "POST",
      body: JSON.stringify({ bundle, message, operator_id: operatorId }),
    },
    adminToken
  )
}

export async function rollbackPolicy(
  baseUrl: string,
  adminToken: string,
  version: number,
  message: string,
  operatorId = "web-console"
) {
  return fetchAgentGate<PolicyCurrentResponse>(
    baseUrl,
    "/internal/policy/rollback",
    undefined,
    {
      method: "POST",
      body: JSON.stringify({ version, message, operator_id: operatorId }),
    },
    adminToken
  )
}

export async function integrationDefinitions(
  baseUrl: string,
  adminToken: string,
  signal?: AbortSignal
) {
  return fetchAgentGate<IntegrationsResponse>(
    baseUrl,
    "/internal/integrations",
    signal,
    undefined,
    adminToken
  )
}

export async function createIntegrationDefinition(
  baseUrl: string,
  adminToken: string,
  definition: IntegrationDefinitionInput
) {
  return fetchAgentGate<IntegrationDefinition>(
    baseUrl,
    "/internal/integrations",
    undefined,
    {
      method: "POST",
      body: JSON.stringify(definition),
    },
    adminToken
  )
}

export async function updateIntegrationDefinition(
  baseUrl: string,
  adminToken: string,
  integrationId: string,
  definition: IntegrationDefinitionInput
) {
  return fetchAgentGate<IntegrationDefinition>(
    baseUrl,
    `/internal/integrations/${encodeURIComponent(integrationId)}`,
    undefined,
    {
      method: "PATCH",
      body: JSON.stringify(definition),
    },
    adminToken
  )
}

export async function deleteIntegrationDefinition(
  baseUrl: string,
  adminToken: string,
  integrationId: string
) {
  return fetchAgentGate<void>(
    baseUrl,
    `/internal/integrations/${encodeURIComponent(integrationId)}`,
    undefined,
    { method: "DELETE" },
    adminToken
  )
}

async function fetchAgentGate<T>(
  baseUrl: string,
  path: string,
  signal?: AbortSignal,
  init?: RequestInit,
  token?: string
): Promise<T> {
  const config = loadConfig()
  const authToken = token ?? config.operatorToken
  const response = await fetch(`${normalizeBaseUrl(baseUrl)}${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
      ...(init?.headers ?? {}),
    },
    signal,
  })

  if (!response.ok) {
    const message = await readError(response)
    throw new Error(message)
  }

  if (response.status === 204) {
    return undefined as T
  }

  return response.json() as Promise<T>
}

function normalizeBaseUrl(baseUrl: string) {
  return baseUrl.trim().replace(/\/+$/, "")
}

async function readError(response: Response) {
  try {
    const body = (await response.json()) as {
      error?: { code?: string; message?: string }
    }
    if (body.error?.code || body.error?.message) {
      return `${response.status} ${body.error.code ?? "error"}: ${
        body.error.message ?? response.statusText
      }`
    }
  } catch {
    // Fall through to the HTTP status line.
  }
  return `${response.status} ${response.statusText}`
}

function normalizeEvent(event: EventEnvelope): SecurityEvent {
  const metadata = event.metadata ?? {}
  const taskId = stringValue(metadata.task_id) ?? ""
  const attemptId = stringValue(metadata.attempt_id)
  const requestKind = stringValue(metadata.request_kind) ?? event.event_type
  const warnings = stringArray(metadata.warnings)
  const reason = event.summary || event.event_type

  return {
    id: event.event_id,
    created_at: event.occurred_at,
    decision_id: event.decision_id ?? event.request_id ?? event.event_id,
    effect: event.effect ?? "allow_with_audit",
    request_kind: requestKind,
    surface: event.surface ?? inferSurface(requestKind),
    adapter_id: event.adapter_id ?? stringValue(metadata.adapter_id) ?? "core",
    session_id: event.session_id ?? stringValue(metadata.session_id) ?? "none",
    task_id: taskId || "none",
    attempt_id: attemptId,
    approval_id: stringValue(metadata.approval_id),
    reason_code: reason,
    latency_ms: numberValue(metadata.latency_ms),
    policy_version: stringValue(metadata.policy_version) ?? numberString(metadata.policy_version),
    policy_status: stringValue(metadata.policy_status),
    selected_rule: stringValue(metadata.selected_rule),
    matched_rules: stringArray(metadata.matched_rules),
    redacted_summary: event.summary,
    applied_rules: stringArray(metadata.applied_rules),
    obligations: stringArray(metadata.obligations),
    metadata: metadataItems(metadata),
    findings: warnings,
    taints: stringArray(metadata.taints),
    data_classes: stringArray(metadata.data_classes),
    event_type: event.event_type,
  }
}

function normalizeCoverage(coverage: CoverageResponse): CoverageResponse {
  return {
    generated_at: coverage.generated_at || new Date().toISOString(),
    adapters: Array.isArray(coverage.adapters) ? coverage.adapters : [],
    surfaces: coverage.surfaces ?? {},
    warnings: Array.isArray(coverage.warnings) ? coverage.warnings : [],
  }
}

function inferSurface(requestKind: string): EventSurface {
  if (requestKind.startsWith("resource_")) {
    return "resource"
  }
  if (requestKind === "input" || requestKind.includes("prompt")) {
    return "input"
  }
  if (requestKind === "tool_attempt") {
    return "runtime"
  }
  return "none"
}

function stringValue(value: unknown) {
  return typeof value === "string" && value.length > 0 ? value : undefined
}

function numberValue(value: unknown) {
  return typeof value === "number" ? value : undefined
}

function numberString(value: unknown) {
  return typeof value === "number" ? String(value) : undefined
}

function stringArray(value: unknown) {
  if (!Array.isArray(value)) {
    return []
  }
  return value.filter((item): item is string => typeof item === "string")
}

function metadataItems(metadata: Record<string, unknown>) {
  return Object.entries(metadata)
    .filter(
      ([key]) =>
        ![
          "applied_rules",
          "obligations",
          "warnings",
          "matched_rules",
        ].includes(key)
    )
    .map(([key, value]) => `${key}:${shortValue(value)}`)
}

function shortValue(value: unknown) {
  const serialized =
    typeof value === "string" ? value : JSON.stringify(value, (_key, item) => item)
  if (serialized === undefined) {
    return "undefined"
  }
  return serialized.length > 160 ? `${serialized.slice(0, 157)}...` : serialized
}

function normalizeApprovals(records: ApprovalRecord[], events: SecurityEvent[]): Approval[] {
  const eventsByApproval = new Map(
    events
      .filter((event) => event.approval_id)
      .map((event) => [event.approval_id, event])
  )
  return records.map((record) => {
    const event = eventsByApproval.get(record.approval_id)
    return {
      approval_id: record.approval_id,
      request_id: record.request_id,
      created_at: record.created_at,
      expires_at: record.expires_at,
      resolved_at: record.resolved_at,
      session_id: record.session_id || event?.session_id || "none",
      task_id: record.task_id || event?.task_id || "none",
      attempt_id: record.attempt_id || event?.attempt_id || "none",
      operator_id: record.operator_id || "unassigned",
      reason: record.reason || event?.redacted_summary || "approval_required",
      scope: approvalScope(event),
      status: record.status,
      expires_in: formatExpiresIn(record.expires_at, record.status),
    }
  })
}

function approvalScope(event: SecurityEvent | undefined) {
  const item = event?.metadata.find((value) => value.startsWith("approval_scope:"))
  return stringValue(item?.slice("approval_scope:".length)) ?? "attempt"
}

function formatExpiresIn(expiresAt: string, status: Approval["status"]) {
  if (status === "expired") {
    return "expired"
  }
  if (status !== "pending") {
    return "resolved"
  }
  const expiresMs = new Date(expiresAt).getTime()
  const deltaSeconds = Math.max(0, Math.floor((expiresMs - Date.now()) / 1000))
  if (deltaSeconds <= 0) {
    return "expired"
  }
  const minutes = Math.floor(deltaSeconds / 60)
  const seconds = deltaSeconds % 60
  return `${minutes}m ${seconds}s`
}

function buildHistogram(events: SecurityEvent[]): HistogramBucket[] {
  const buckets = new Map<string, HistogramBucket>()

  for (const event of events) {
    const minute = event.created_at.slice(11, 16)
    const bucket =
      buckets.get(minute) ??
      ({
        minute,
        input: 0,
        runtime: 0,
        resource: 0,
      } satisfies HistogramBucket)
    if (event.surface !== "none") {
      bucket[event.surface] += 1
    }
    buckets.set(minute, bucket)
  }

  return Array.from(buckets.values()).sort((left, right) =>
    left.minute.localeCompare(right.minute)
  )
}
