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
	OperatorID string `json:"operator_id"`
	Channel    string `json:"channel"`
}

type ApprovalResolveResponse struct {
	ApprovalID string         `json:"approval_id"`
	Status     ApprovalStatus `json:"status"`
	ResolvedAt time.Time      `json:"resolved_at"`
}
