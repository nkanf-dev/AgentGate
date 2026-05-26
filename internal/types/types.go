package types

import "time"

type Taint string

const (
	TaintUntrustedExternal   Taint = "untrusted_external"
	TaintPossibleInjection   Taint = "possible_prompt_injection"
	TaintEmbeddedInstruction Taint = "embedded_instruction"
	TaintSecretBearing       Taint = "secret_bearing"
)

type DataClass string

const (
	DataClassPII        DataClass = "pii"
	DataClassSecret     DataClass = "secret"
	DataClassBusiness   DataClass = "business"
	DataClassFinancial  DataClass = "financial"
	DataClassCredential DataClass = "credential"
)

type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalDenied   ApprovalStatus = "denied"
	ApprovalExpired  ApprovalStatus = "expired"
)

type ApprovalResolveRequest struct {
	Decision   string `json:"decision"`
	OperatorID string `json:"operator_id,omitempty"`
	Channel    string `json:"channel"`
}

type ApprovalResolveResponse struct {
	ApprovalID string         `json:"approval_id"`
	Status     ApprovalStatus `json:"status"`
	ResolvedAt time.Time      `json:"resolved_at"`
}

type ApprovalResolveCommand struct {
	ApprovalID string
	Decision   string
	OperatorID string
	Channel    string
	ResolvedAt time.Time
}

type ApprovalResolveResult struct {
	Approval ApprovalRecord
	Grant    *AttemptGrant
}

type AgentType string

const (
	AgentTypeOpenClaw AgentType = "openclaw"
	AgentTypeGateway  AgentType = "gateway"
	AgentTypeCustom   AgentType = "custom"
)
