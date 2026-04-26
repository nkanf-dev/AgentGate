package types

import "time"

type Taint string

const (
	TaintUntrustedExternal   Taint = "untrusted_external"
	TaintPossibleInjection   Taint = "possible_prompt_injection"
	TaintEmbeddedInstruction Taint = "embedded_instruction"
	TaintSecretBearing       Taint = "secret_bearing"
)

type SegmentKind string

const (
	SegmentTrustedInstruction  SegmentKind = "trusted_instruction"
	SegmentUserIntent          SegmentKind = "user_intent"
	SegmentExternalObservation SegmentKind = "external_observation"
)

type ContentSegment struct {
	Kind   SegmentKind `json:"kind"`
	Text   string      `json:"text"`
	Offset int         `json:"offset"`
	Length int         `json:"length"`
}

type SecretFinding struct {
	Kind        string `json:"kind"`
	Placeholder string `json:"placeholder"`
	Hash        string `json:"hash"`
	Length      int    `json:"length"`
}

type InputAssessment struct {
	AssessmentID         string           `json:"assessment_id,omitempty"`
	SessionID            string           `json:"session_id"`
	Source               string           `json:"source"`
	NormalizedText       string           `json:"normalized_text,omitempty"`
	ContentSegments      []ContentSegment `json:"content_segments"`
	Taints               []Taint          `json:"taints"`
	SecretFindings       []SecretFinding  `json:"secret_findings"`
	InstructionAuthority bool             `json:"instruction_authority"`
	Blocked              bool             `json:"blocked"`
	AssessedAt           time.Time        `json:"assessed_at"`
}

type InputAssessRequest struct {
	SessionID   string        `json:"session_id"`
	Source      string        `json:"source"`
	UserID      string        `json:"user_id,omitempty"`
	Content     string        `json:"content"`
	Attachments []interface{} `json:"attachments,omitempty"`
}

type DataClass string

const (
	DataClassPII        DataClass = "pii"
	DataClassSecret     DataClass = "secret"
	DataClassBusiness   DataClass = "business"
	DataClassFinancial  DataClass = "financial"
	DataClassCredential DataClass = "credential"
)

type InvocationContext struct {
	UserID      string      `json:"user_id,omitempty"`
	Source      string      `json:"source,omitempty"`
	Taints      []Taint     `json:"taints"`
	DataClasses []DataClass `json:"data_classes"`
}

type ToolInvocationRequest struct {
	SessionID string                 `json:"session_id"`
	AgentID   string                 `json:"agent_id"`
	Tool      string                 `json:"tool"`
	Args      map[string]interface{} `json:"args"`
	Context   InvocationContext      `json:"context"`
}

type DecisionKind string

const (
	DecisionAllow            DecisionKind = "allow"
	DecisionDeny             DecisionKind = "deny"
	DecisionApprovalRequired DecisionKind = "approval_required"
)

type DecisionReason string

const (
	ReasonPolicyAllow              DecisionReason = "policy_allow"
	ReasonPolicyDenyNotInAllowlist DecisionReason = "policy_deny_not_in_allowlist"
	ReasonPolicyDenyExclusion      DecisionReason = "policy_deny_exclusion_list"
	ReasonTaintedInstructionSecret DecisionReason = "tainted_instruction_with_secret_tool"
	ReasonTaintedSensitiveEgress   DecisionReason = "tainted_sensitive_egress"
	ReasonFirstUseRequiresApproval DecisionReason = "first_use_requires_approval"
	ReasonUserAllowOnce            DecisionReason = "user_allow_once_valid"
	ReasonUserDeny                 DecisionReason = "user_deny"
)

type GuardDecision struct {
	Decision     DecisionKind     `json:"decision"`
	Reason       DecisionReason   `json:"reason"`
	ApprovalID   string           `json:"approval_id,omitempty"`
	Preview      *ApprovalPreview `json:"preview,omitempty"`
	AuditEventID string           `json:"audit_event_id"`
}

type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

type ApprovalPreview struct {
	Tool        string      `json:"tool"`
	Target      string      `json:"target,omitempty"`
	RiskLevel   RiskLevel   `json:"risk_level"`
	DataClasses []DataClass `json:"data_classes"`
	Reason      string      `json:"reason"`
	ArgsSummary string      `json:"args_summary"`
}

type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalDenied   ApprovalStatus = "denied"
	ApprovalExpired  ApprovalStatus = "expired"
)

type LegacyApprovalRecord struct {
	ApprovalID string                `json:"approval_id"`
	SessionID  string                `json:"session_id"`
	Request    ToolInvocationRequest `json:"request"`
	Preview    ApprovalPreview       `json:"preview"`
	Status     ApprovalStatus        `json:"status"`
	OperatorID string                `json:"operator_id,omitempty"`
	Channel    string                `json:"channel,omitempty"`
	DecidedAt  *time.Time            `json:"decided_at,omitempty"`
	ExpiresAt  time.Time             `json:"expires_at"`
}

type ApprovalResolveRequest struct {
	Decision   string `json:"decision"`
	OperatorID string `json:"operator_id"`
	Channel    string `json:"channel"`
}

type ApprovalResolveResponse struct {
	ApprovalID string         `json:"approval_id"`
	Status     ApprovalStatus `json:"status"`
	ResolvedAt time.Time      `json:"resolved_at"`
}

type SecurityEventType string

const (
	EventSecretBlockedPreModel    SecurityEventType = "secret_blocked_pre_model"
	EventPromptInjectionDetected  SecurityEventType = "prompt_injection_detected"
	EventToolCallAllowed          SecurityEventType = "tool_call_allowed"
	EventToolCallDenied           SecurityEventType = "tool_call_denied"
	EventToolCallApprovalRequired SecurityEventType = "tool_call_approval_required"
	EventApprovalGranted          SecurityEventType = "approval_granted"
	EventApprovalDenied           SecurityEventType = "approval_denied"
	EventApprovalExpired          SecurityEventType = "approval_expired"
	EventEgressBlocked            SecurityEventType = "egress_blocked"
	EventEgressAllowed            SecurityEventType = "egress_allowed"
	EventPathTraversalBlocked     SecurityEventType = "path_traversal_blocked"
	EventClipboardReadRedacted    SecurityEventType = "clipboard_read_redacted"
	EventPIIRedactedInOutput      SecurityEventType = "pii_redacted_in_output"
)

type SecurityEvent struct {
	EventID      string            `json:"event_id"`
	SessionID    string            `json:"session_id"`
	AgentID      string            `json:"agent_id"`
	EventType    SecurityEventType `json:"event_type"`
	Decision     string            `json:"decision"`
	Reason       string            `json:"reason"`
	DataClasses  []DataClass       `json:"data_classes"`
	Taints       []Taint           `json:"taints"`
	Summary      string            `json:"summary"`
	EvidenceID   string            `json:"evidence_id,omitempty"`
	EvidenceHash string            `json:"evidence_hash,omitempty"`
	OccurredAt   time.Time         `json:"occurred_at"`
	Layer        string            `json:"layer"`
}

type PolicyBundle struct {
	Version    int          `json:"version"`
	IssuedAt   time.Time    `json:"issued_at"`
	ToolPolicy []ToolPolicy `json:"tool_policy"`
	Egress     EgressPolicy `json:"egress_policy"`
	Path       PathPolicy   `json:"path_policy"`
}

type ToolPolicy struct {
	ToolPattern             string      `json:"tool_pattern"`
	RiskLevel               RiskLevel   `json:"risk_level"`
	RequireApproval         bool        `json:"require_approval"`
	RequireFirstUseApproval bool        `json:"require_first_use_approval"`
	Exclusion               bool        `json:"exclusion"`
	DataClassTriggers       []DataClass `json:"data_classes_triggers"`
}

type EgressPolicy struct {
	HostAllowlist             []string `json:"host_allowlist"`
	BlockSensitiveQueryParams []string `json:"block_sensitive_query_params"`
	RequirePurposeDeclaration bool     `json:"require_purpose_declaration"`
}

type PathPolicy struct {
	WorkspaceRoot         string   `json:"workspace_root"`
	AllowWorktreeSiblings bool     `json:"allow_worktree_siblings"`
	BlockedPrefixes       []string `json:"blocked_prefixes"`
}

type EvidenceRecord struct {
	EvidenceID    string    `json:"evidence_id"`
	EventID       string    `json:"event_id"`
	AccessClass   string    `json:"access_class"`
	RetentionDays int       `json:"retention_days"`
	Payload       []byte    `json:"-"`
	CreatedAt     time.Time `json:"created_at"`
}

type EgressEvaluateRequest struct {
	SessionID string `json:"session_id"`
	URL       string `json:"url"`
	Method    string `json:"method"`
	Body      string `json:"body"`
}

type EgressEvaluateResponse struct {
	Decision     string          `json:"decision"`
	RedactedBody string          `json:"redacted_body,omitempty"`
	Findings     []SecretFinding `json:"findings,omitempty"`
	AuditEventID string          `json:"audit_event_id"`
}

type CheckPathRequest struct {
	SessionID string `json:"session_id"`
	Path      string `json:"path"`
	Operation string `json:"operation"`
}

type CheckPathResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}
