package types

// ObligationType represents the type of an obligation that the engine must execute.
type ObligationType string

const (
	ObligationRewriteInput        ObligationType = "rewrite_input"
	ObligationApprovalRequest     ObligationType = "approval_request"
	ObligationResolveSecretHandle ObligationType = "resolve_secret_handle"
	ObligationTaskControl         ObligationType = "task_control"
	ObligationAuditEvent          ObligationType = "audit_event"
)
