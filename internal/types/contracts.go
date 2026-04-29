package types

import "time"

type RequestKind string

const (
	RequestKindInput             RequestKind = "input"
	RequestKindToolAttempt       RequestKind = "tool_attempt"
	RequestKindResourceEgress    RequestKind = "resource_egress"
	RequestKindResourceAccess    RequestKind = "resource_access"
	RequestKindInitialEnvelope   RequestKind = "initial_envelope"
	RequestKindEnvelopeAmendment RequestKind = "envelope_amendment"
)

type Surface string

const (
	SurfaceInput    Surface = "input"
	SurfaceRuntime  Surface = "runtime"
	SurfaceResource Surface = "resource"
)

type Effect string

const (
	EffectAllow            Effect = "allow"
	EffectAllowWithAudit   Effect = "allow_with_audit"
	EffectApprovalRequired Effect = "approval_required"
	EffectDeny             Effect = "deny"
	EffectExclusion        Effect = "exclusion"
)

type AdapterRegistration struct {
	AdapterID          string                 `json:"adapter_id"`
	IntegrationID      string                 `json:"integration_id,omitempty"`
	AdapterKind        string                 `json:"adapter_kind"`
	Host               HostDescriptor         `json:"host"`
	Surfaces           []Surface              `json:"surfaces"`
	SupportingChannels []string               `json:"supporting_channels,omitempty"`
	Capabilities       AdapterCapabilities    `json:"capabilities"`
	Metadata           map[string]interface{} `json:"metadata,omitempty"`
}

type HostDescriptor struct {
	Kind    string `json:"kind"`
	Version string `json:"version,omitempty"`
}

type AdapterCapabilities struct {
	CanBlock            bool `json:"can_block"`
	CanRewriteInput     bool `json:"can_rewrite_input"`
	CanRewriteToolArgs  bool `json:"can_rewrite_tool_args"`
	CanPauseForApproval bool `json:"can_pause_for_approval"`
}

type RegistrationResult struct {
	AdapterID    string    `json:"adapter_id"`
	RegisteredAt time.Time `json:"registered_at"`
	Accepted     bool      `json:"accepted"`
}

type CoverageResponse struct {
	GeneratedAt time.Time         `json:"generated_at"`
	Adapters    []AdapterCoverage `json:"adapters"`
	Surfaces    map[Surface]int   `json:"surfaces"`
	Warnings    []string          `json:"warnings,omitempty"`
}

type AdapterCoverage struct {
	AdapterID          string         `json:"adapter_id"`
	IntegrationID      string         `json:"integration_id,omitempty"`
	AdapterKind        string         `json:"adapter_kind"`
	Host               HostDescriptor `json:"host"`
	Surfaces           []Surface      `json:"surfaces"`
	SupportingChannels []string       `json:"supporting_channels,omitempty"`
	RegisteredAt       time.Time      `json:"registered_at"`
	LastSeenAt         time.Time      `json:"last_seen_at"`
}

type IntegrationHealthStatus string

const (
	IntegrationHealthConnected IntegrationHealthStatus = "connected"
	IntegrationHealthStale     IntegrationHealthStatus = "stale"
	IntegrationHealthMissing   IntegrationHealthStatus = "missing"
	IntegrationHealthUnmanaged IntegrationHealthStatus = "unmanaged"
	IntegrationHealthDisabled  IntegrationHealthStatus = "disabled"
)

type IntegrationDefinition struct {
	ID               string                      `json:"id"`
	Name             string                      `json:"name"`
	Kind             string                      `json:"kind"`
	Enabled          bool                        `json:"enabled"`
	ExpectedSurfaces []Surface                   `json:"expected_surfaces,omitempty"`
	Health           IntegrationHealth           `json:"health"`
	MatchedAdapters  []IntegrationMatchedAdapter `json:"matched_adapters,omitempty"`
}

type IntegrationHealth struct {
	Status              IntegrationHealthStatus `json:"status"`
	MatchedAdapterID    string                  `json:"matched_adapter_id,omitempty"`
	MatchedAdapterCount int                     `json:"matched_adapter_count,omitempty"`
	LastSeenAt          *time.Time              `json:"last_seen_at,omitempty"`
	ComputedAt          time.Time               `json:"computed_at"`
}

type IntegrationMatchedAdapter struct {
	AdapterID          string                  `json:"adapter_id"`
	IntegrationID      string                  `json:"integration_id"`
	AdapterKind        string                  `json:"adapter_kind"`
	Host               HostDescriptor          `json:"host"`
	Surfaces           []Surface               `json:"surfaces"`
	SupportingChannels []string                `json:"supporting_channels,omitempty"`
	Status             IntegrationHealthStatus `json:"status"`
	RegisteredAt       time.Time               `json:"registered_at"`
	LastSeenAt         time.Time               `json:"last_seen_at"`
}

type IntegrationsResponse struct {
	Integrations []IntegrationDefinition `json:"integrations"`
}

type PolicyRequest struct {
	RequestID   string                 `json:"request_id"`
	RequestKind RequestKind            `json:"request_kind"`
	Actor       ActorContext           `json:"actor"`
	Session     SessionContext         `json:"session"`
	Action      ActionContext          `json:"action"`
	Target      TargetContext          `json:"target"`
	Content     ContentContext         `json:"content,omitempty"`
	Context     DecisionContext        `json:"context"`
	Policy      map[string]interface{} `json:"policy,omitempty"`
}

type ActorContext struct {
	UserID  string `json:"user_id,omitempty"`
	HostID  string `json:"host_id,omitempty"`
	AgentID string `json:"agent_id,omitempty"`
}

type SessionContext struct {
	SessionID string `json:"session_id"`
	TaskID    string `json:"task_id,omitempty"`
	AttemptID string `json:"attempt_id,omitempty"`
}

type ActionContext struct {
	Operation   string   `json:"operation,omitempty"`
	Tool        string   `json:"tool,omitempty"`
	SideEffects []string `json:"side_effects,omitempty"`
	OpenWorld   bool     `json:"open_world,omitempty"`
}

type TargetContext struct {
	Kind       string `json:"kind,omitempty"`
	Identifier string `json:"identifier,omitempty"`
}

type ContentContext struct {
	Summary     string      `json:"summary,omitempty"`
	DataClasses []DataClass `json:"data_classes,omitempty"`
}

type DecisionContext struct {
	Surface Surface                `json:"surface"`
	Taints  []Taint                `json:"taints,omitempty"`
	Raw     map[string]interface{} `json:"raw,omitempty"`
}

type SessionFactsRecord struct {
	SessionID string       `json:"session_id"`
	AdapterID string       `json:"adapter_id,omitempty"`
	UpdatedAt time.Time    `json:"updated_at"`
	Facts     SessionFacts `json:"facts"`
}

type SessionFacts struct {
	RequestCount        int        `json:"request_count"`
	DenyCount           int        `json:"deny_count"`
	ApprovalCount       int        `json:"approval_count"`
	AllowCount          int        `json:"allow_count"`
	DistinctTargets     []string   `json:"distinct_targets"`
	DistinctTools       []string   `json:"distinct_tools"`
	DistinctReasonCodes []string   `json:"distinct_reason_codes"`
	SideEffectSequence  []string   `json:"side_effect_sequence"`
	LastEffect          string     `json:"last_effect,omitempty"`
	LastRequestAt       *time.Time `json:"last_request_at,omitempty"`
	FirstRequestAt      *time.Time `json:"first_request_at,omitempty"`
}

type Obligation struct {
	Type   string                 `json:"type"`
	Params map[string]interface{} `json:"params,omitempty"`
}

type SecretHandle struct {
	HandleID    string    `json:"handle_id"`
	SessionID   string    `json:"session_id"`
	TaskID      string    `json:"task_id,omitempty"`
	Kind        string    `json:"kind"`
	Placeholder string    `json:"placeholder"`
	SecretHash  string    `json:"secret_hash"`
	CreatedAt   time.Time `json:"created_at"`
}

type SecretFindingSummary struct {
	Kind        string `json:"kind"`
	Placeholder string `json:"placeholder"`
	HandleID    string `json:"handle_id"`
	Hash        string `json:"hash"`
	Offset      int    `json:"offset"`
	Length      int    `json:"length"`
}

type PolicyDecision struct {
	DecisionID   string              `json:"decision_id"`
	RequestID    string              `json:"request_id"`
	Effect       Effect              `json:"effect"`
	ReasonCode   string              `json:"reason_code"`
	Obligations  []Obligation        `json:"obligations"`
	AppliedRules []string            `json:"applied_rules,omitempty"`
	Explanation  DecisionExplanation `json:"explanation,omitempty"`
	DecidedAt    time.Time           `json:"decided_at"`
}

type DecisionExplanation struct {
	Summary     string      `json:"summary,omitempty"`
	Warnings    []string    `json:"warnings,omitempty"`
	PolicyTrace PolicyTrace `json:"policy_trace,omitempty"`
}

type PolicyTrace struct {
	PolicyVersion  int               `json:"policy_version,omitempty"`
	PolicyStatus   string            `json:"policy_status,omitempty"`
	SelectedBundle string            `json:"selected_bundle,omitempty"`
	BundlePriority int               `json:"bundle_priority,omitempty"`
	SelectedRule   string            `json:"selected_rule,omitempty"`
	TopPriority    int               `json:"top_priority,omitempty"`
	Defaulted      bool              `json:"defaulted,omitempty"`
	MatchedRules   []PolicyRuleTrace `json:"matched_rules,omitempty"`
}

type PolicyRuleTrace struct {
	BundleID       string `json:"bundle_id,omitempty"`
	BundlePriority int    `json:"bundle_priority,omitempty"`
	RuleID         string `json:"rule_id"`
	Priority       int    `json:"priority"`
	Effect         Effect `json:"effect"`
	ReasonCode     string `json:"reason_code"`
}

type ReportRequest struct {
	RequestID    string                 `json:"request_id"`
	DecisionID   string                 `json:"decision_id,omitempty"`
	AdapterID    string                 `json:"adapter_id,omitempty"`
	Surface      Surface                `json:"surface,omitempty"`
	Outcome      string                 `json:"outcome"`
	Obligations  []Obligation           `json:"obligations,omitempty"`
	ErrorMessage string                 `json:"error_message,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

type ReportResponse struct {
	Accepted   bool      `json:"accepted"`
	RecordedAt time.Time `json:"recorded_at"`
}

type ApprovalRecord struct {
	ApprovalID string         `json:"approval_id"`
	RequestID  string         `json:"request_id,omitempty"`
	SessionID  string         `json:"session_id"`
	TaskID     string         `json:"task_id,omitempty"`
	AttemptID  string         `json:"attempt_id,omitempty"`
	Status     ApprovalStatus `json:"status"`
	Reason     string         `json:"reason"`
	OperatorID string         `json:"operator_id,omitempty"`
	Channel    string         `json:"channel,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	ExpiresAt  time.Time      `json:"expires_at"`
	ResolvedAt *time.Time     `json:"resolved_at,omitempty"`
}

type AttemptGrant struct {
	ApprovalID string    `json:"approval_id"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type ApprovalsResponse struct {
	Approvals []ApprovalRecord `json:"approvals"`
}

type EventEnvelope struct {
	EventID    string                 `json:"event_id"`
	EventType  string                 `json:"event_type"`
	RequestID  string                 `json:"request_id,omitempty"`
	DecisionID string                 `json:"decision_id,omitempty"`
	SessionID  string                 `json:"session_id,omitempty"`
	AdapterID  string                 `json:"adapter_id,omitempty"`
	Surface    Surface                `json:"surface,omitempty"`
	Effect     Effect                 `json:"effect,omitempty"`
	Summary    string                 `json:"summary"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	OccurredAt time.Time              `json:"occurred_at"`
}
