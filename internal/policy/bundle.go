package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/agentgate/agentgate/internal/types"
)

type Bundle struct {
	BundleID       string         `json:"bundle_id,omitempty"`
	Name           string         `json:"name,omitempty"`
	Description    string         `json:"description,omitempty"`
	Priority       int            `json:"priority,omitempty"`
	Version        int            `json:"version"`
	Status         string         `json:"status,omitempty"`
	IssuedAt       time.Time      `json:"issued_at"`
	CreatedAt      time.Time      `json:"created_at,omitempty"`
	UpdatedAt      time.Time      `json:"updated_at,omitempty"`
	Rules          []Rule         `json:"rules"`
	InputPolicy    InputPolicy    `json:"input_policy"`
	RuntimePolicy  RuntimePolicy  `json:"runtime_policy"`
	ResourcePolicy ResourcePolicy `json:"resource_policy"`
	EgressPolicy   EgressPolicy   `json:"egress_policy"`
	PathPolicy     PathPolicy     `json:"path_policy"`
}

const (
	BundleStatusActive   = "active"
	BundleStatusInactive = "inactive"
	BundleStatusArchived = "archived"
)

type VersionRecord struct {
	Version       int       `json:"version"`
	Status        string    `json:"status"`
	Active        bool      `json:"active"`
	RuleCount     int       `json:"rule_count"`
	PublishedAt   time.Time `json:"published_at"`
	PublishedBy   string    `json:"published_by,omitempty"`
	Message       string    `json:"message,omitempty"`
	SourceVersion int       `json:"source_version,omitempty"`
}

type Rule struct {
	ID           string              `json:"id"`
	Description  string              `json:"description,omitempty"`
	Priority     int                 `json:"priority"`
	Surface      types.Surface       `json:"surface"`
	RequestKinds []types.RequestKind `json:"request_kinds,omitempty"`
	Effect       types.Effect        `json:"effect"`
	ReasonCode   string              `json:"reason_code"`
	When         Condition           `json:"when,omitempty"`
	Obligations  []Obligation        `json:"obligations,omitempty"`
}

type Condition struct {
	Language          string            `json:"language,omitempty"`
	Expression        string            `json:"expression,omitempty"`
	Always            bool              `json:"always,omitempty"`
	Tools             []string          `json:"tools,omitempty"`
	Operations        []string          `json:"operations,omitempty"`
	SideEffectsAny    []string          `json:"side_effects_any,omitempty"`
	SideEffectsAll    []string          `json:"side_effects_all,omitempty"`
	OpenWorld         *bool             `json:"open_world,omitempty"`
	TargetKinds       []string          `json:"target_kinds,omitempty"`
	TargetIdentifiers []string          `json:"target_identifiers,omitempty"`
	TaintsAny         []types.Taint     `json:"taints_any,omitempty"`
	DataClassesAny    []types.DataClass `json:"data_classes_any,omitempty"`
	ActorUserIDs      []string          `json:"actor_user_ids,omitempty"`
}

type Obligation struct {
	Type   string                 `json:"type"`
	Params map[string]interface{} `json:"params,omitempty"`
}

type Evaluation struct {
	Effect         types.Effect
	ReasonCode     string
	AppliedRules   []string
	Obligations    []types.Obligation
	MatchedRules   []MatchedRule
	SelectedRule   string
	SelectedBundle string
	BundlePriority int
	TopPriority    int
	Defaulted      bool
}

type MatchedRule struct {
	BundleID       string
	BundleName     string
	BundlePriority int
	Rule           Rule
}

type InputPolicy struct {
	SecretMode string `json:"secret_mode"`
}

type RuntimePolicy struct {
	RequireApprovalTools       []string `json:"require_approval_tools,omitempty"`
	RequireApprovalSideEffects []string `json:"require_approval_side_effects,omitempty"`
	RequireApprovalOpenWorld   bool     `json:"require_approval_open_world,omitempty"`
}

type ResourcePolicy struct {
	SecretHandleScope string `json:"secret_handle_scope"`
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

func DefaultBundle() Bundle {
	trueValue := true
	return Bundle{
		Version:  1,
		Status:   "active_minimal",
		IssuedAt: time.Date(2026, 4, 24, 0, 0, 0, 0, time.UTC),
		Rules: []Rule{
			{
				ID:           "input.secret.rewrite_to_handle",
				Description:  "Secret-like input must be converted into SecretHandle placeholders before model execution.",
				Priority:     100,
				Surface:      types.SurfaceInput,
				RequestKinds: []types.RequestKind{types.RequestKindInput},
				Effect:       types.EffectAllowWithAudit,
				ReasonCode:   "input_secret_rewritten_to_handles",
				When:         Condition{DataClassesAny: []types.DataClass{types.DataClassSecret}},
			},
			{
				ID:           "runtime.bash.requires_approval",
				Description:  "Shell execution can mutate files, spawn processes, and reach the network.",
				Priority:     100,
				Surface:      types.SurfaceRuntime,
				RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
				Effect:       types.EffectApprovalRequired,
				ReasonCode:   "runtime_high_risk_requires_approval",
				When:         Condition{Tools: []string{"bash"}},
			},
			{
				ID:           "runtime.open_world.requires_approval",
				Description:  "Open-world tool attempts require explicit operator approval.",
				Priority:     100,
				Surface:      types.SurfaceRuntime,
				RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
				Effect:       types.EffectApprovalRequired,
				ReasonCode:   "runtime_high_risk_requires_approval",
				When:         Condition{OpenWorld: &trueValue},
			},
			{
				ID:           "runtime.side_effect.requires_approval",
				Description:  "High-risk side effects require explicit operator approval.",
				Priority:     100,
				Surface:      types.SurfaceRuntime,
				RequestKinds: []types.RequestKind{types.RequestKindToolAttempt},
				Effect:       types.EffectApprovalRequired,
				ReasonCode:   "runtime_high_risk_requires_approval",
				When: Condition{SideEffectsAny: []string{
					"filesystem_write",
					"network_egress",
					"process_spawn",
					"secret_resolve",
				}},
			},
			{
				ID:           "resource.secret_handle.resolve",
				Description:  "SecretHandle resolution is eligible only through the resource surface and same-session scope checks.",
				Priority:     100,
				Surface:      types.SurfaceResource,
				RequestKinds: []types.RequestKind{types.RequestKindResourceAccess},
				Effect:       types.EffectAllowWithAudit,
				ReasonCode:   "secret_handle_resolve_allowed",
				When: Condition{
					Operations:  []string{"resolve_secret_handle"},
					TargetKinds: []string{"secret_handle"},
				},
			},
		},
		InputPolicy: InputPolicy{
			SecretMode: "secret_handle",
		},
		RuntimePolicy: RuntimePolicy{
			RequireApprovalTools:       []string{"bash"},
			RequireApprovalSideEffects: []string{"filesystem_write", "network_egress", "process_spawn", "secret_resolve"},
			RequireApprovalOpenWorld:   true,
		},
		ResourcePolicy: ResourcePolicy{
			SecretHandleScope: "session_task",
		},
		EgressPolicy: EgressPolicy{
			BlockSensitiveQueryParams: []string{"token", "key", "secret", "password"},
			RequirePurposeDeclaration: true,
		},
		PathPolicy: PathPolicy{
			WorkspaceRoot:   ".",
			BlockedPrefixes: []string{"~/.ssh", "~/.aws", "/etc"},
		},
	}
}

func LoadFile(path string) (Bundle, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return Bundle{}, fmt.Errorf("read policy bundle: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()

	var bundle Bundle
	if err := decoder.Decode(&bundle); err != nil {
		return Bundle{}, fmt.Errorf("parse policy bundle: %w", err)
	}
	if err := bundle.Validate(); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func (b Bundle) Validate() error {
	if b.Version <= 0 {
		return fmt.Errorf("policy bundle version must be positive")
	}
	if b.IssuedAt.IsZero() {
		return fmt.Errorf("policy bundle issued_at is required")
	}
	if b.InputPolicy.SecretMode == "" {
		return fmt.Errorf("input_policy.secret_mode is required")
	}
	if b.InputPolicy.SecretMode != "secret_handle" {
		return fmt.Errorf("unsupported input_policy.secret_mode %q", b.InputPolicy.SecretMode)
	}
	if b.ResourcePolicy.SecretHandleScope == "" {
		return fmt.Errorf("resource_policy.secret_handle_scope is required")
	}
	if b.ResourcePolicy.SecretHandleScope != "session_task" {
		return fmt.Errorf("unsupported resource_policy.secret_handle_scope %q", b.ResourcePolicy.SecretHandleScope)
	}
	if len(b.Rules) == 0 {
		return fmt.Errorf("policy bundle must define at least one rule")
	}

	ids := make(map[string]struct{}, len(b.Rules))
	for index, rule := range b.Rules {
		if rule.ID == "" {
			return fmt.Errorf("rules[%d].id is required", index)
		}
		if strings.TrimSpace(rule.ID) != rule.ID {
			return fmt.Errorf("rule id %q must not contain leading or trailing whitespace", rule.ID)
		}
		if _, exists := ids[rule.ID]; exists {
			return fmt.Errorf("duplicate policy rule id %q", rule.ID)
		}
		ids[rule.ID] = struct{}{}
		if rule.Priority < 0 {
			return fmt.Errorf("rule %q priority must be non-negative", rule.ID)
		}
		if !validSurface(rule.Surface) {
			return fmt.Errorf("rule %q has unsupported surface %q", rule.ID, rule.Surface)
		}
		if !validEffect(rule.Effect) {
			return fmt.Errorf("rule %q has unsupported effect %q", rule.ID, rule.Effect)
		}
		if rule.ReasonCode == "" {
			return fmt.Errorf("rule %q reason_code is required", rule.ID)
		}
		if strings.TrimSpace(rule.ReasonCode) != rule.ReasonCode || strings.ContainsAny(rule.ReasonCode, " \t\n\r") {
			return fmt.Errorf("rule %q reason_code must be a compact token", rule.ID)
		}
		for _, kind := range rule.RequestKinds {
			if !validRequestKind(kind) {
				return fmt.Errorf("rule %q has unsupported request kind %q", rule.ID, kind)
			}
		}
		if err := validateCondition(rule.ID, rule.When); err != nil {
			return err
		}
		for _, obligation := range rule.Obligations {
			if obligation.Type == "" {
				return fmt.Errorf("rule %q has obligation without type", rule.ID)
			}
			if strings.TrimSpace(obligation.Type) != obligation.Type || strings.ContainsAny(obligation.Type, " \t\n\r") {
				return fmt.Errorf("rule %q obligation type must be a compact token", rule.ID)
			}
			if containsSensitiveParam(obligation.Params) {
				return fmt.Errorf("rule %q obligation params contain sensitive key", rule.ID)
			}
			if err := validateObligationCompatibility(rule, obligation); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b Bundle) StatusValue() string {
	if b.Status != "" {
		return b.Status
	}
	return "active"
}

func (b Bundle) Evaluate(request types.PolicyRequest) Evaluation {
	return EvaluateBundles([]Bundle{
		{
			BundleID:       "default",
			Name:           "Default policy",
			Priority:       0,
			Status:         BundleStatusActive,
			Version:        b.Version,
			IssuedAt:       b.IssuedAt,
			Rules:          b.Rules,
			InputPolicy:    b.InputPolicy,
			RuntimePolicy:  b.RuntimePolicy,
			ResourcePolicy: b.ResourcePolicy,
			EgressPolicy:   b.EgressPolicy,
			PathPolicy:     b.PathPolicy,
		},
	}, request)
}

func EvaluateBundles(bundles []Bundle, request types.PolicyRequest) Evaluation {
	if !validRequestKind(request.RequestKind) || !validSurface(request.Context.Surface) {
		return Evaluation{
			Effect:       types.EffectDeny,
			ReasonCode:   "policy_invalid_request",
			AppliedRules: []string{"policy.request.validation"},
			Obligations: []types.Obligation{
				auditObligation("critical", request.Context.Surface),
				{
					Type: "task_control",
					Params: map[string]interface{}{
						"action": "abort_task",
					},
				},
			},
			SelectedRule:   "policy.request.validation",
			SelectedBundle: "core",
			Defaulted:      true,
		}
	}

	matched := make([]MatchedRule, 0)
	activeBundleSeen := false
	for _, bundle := range bundles {
		if bundle.Status != BundleStatusActive {
			continue
		}
		activeBundleSeen = true
		for _, rule := range bundle.Rules {
			matches, err := ruleMatches(rule, request)
			if err != nil {
				return Evaluation{
					Effect:       types.EffectDeny,
					ReasonCode:   "policy_condition_indeterminate",
					AppliedRules: []string{"policy.condition.indeterminate"},
					Obligations: []types.Obligation{
						auditObligation("critical", request.Context.Surface),
						{
							Type: "task_control",
							Params: map[string]interface{}{
								"action": "abort_task",
							},
						},
					},
					SelectedRule:   rule.ID,
					SelectedBundle: bundle.BundleID,
					Defaulted:      true,
				}
			}
			if matches {
				matched = append(matched, MatchedRule{
					BundleID:       bundle.BundleID,
					BundleName:     bundle.Name,
					BundlePriority: bundle.Priority,
					Rule:           rule,
				})
			}
		}
	}
	if !activeBundleSeen {
		return Evaluation{
			Effect:       types.EffectDeny,
			ReasonCode:   "policy_no_active_bundle",
			AppliedRules: []string{"policy.bundle.active_required"},
			Obligations: []types.Obligation{
				auditObligation("critical", request.Context.Surface),
				{
					Type: "task_control",
					Params: map[string]interface{}{
						"action": "abort_task",
					},
				},
			},
			SelectedRule:   "policy.bundle.active_required",
			SelectedBundle: "core",
			Defaulted:      true,
		}
	}
	if len(matched) == 0 {
		return Evaluation{
			Effect:         types.EffectAllowWithAudit,
			ReasonCode:     "policy_allow_with_audit",
			AppliedRules:   []string{"policy.default.allow_with_audit"},
			Obligations:    []types.Obligation{auditObligation("info", request.Context.Surface)},
			SelectedRule:   "policy.default.allow_with_audit",
			SelectedBundle: "policy.default",
			Defaulted:      true,
		}
	}

	sort.SliceStable(matched, func(i, j int) bool {
		if matched[i].BundlePriority == matched[j].BundlePriority {
			if matched[i].Rule.Priority == matched[j].Rule.Priority {
				if effectRank(matched[i].Rule.Effect) == effectRank(matched[j].Rule.Effect) {
					return matched[i].Rule.ID < matched[j].Rule.ID
				}
				return effectRank(matched[i].Rule.Effect) > effectRank(matched[j].Rule.Effect)
			}
			return matched[i].Rule.Priority > matched[j].Rule.Priority
		}
		return matched[i].BundlePriority > matched[j].BundlePriority
	})

	topBundlePriority := matched[0].BundlePriority
	topPriority := matched[0].Rule.Priority
	selected := matched[0]
	applied := make([]string, 0)
	obligations := []types.Obligation{auditObligation("info", request.Context.Surface)}
	for _, rule := range matched {
		if rule.BundlePriority != topBundlePriority || rule.Rule.Priority != topPriority {
			continue
		}
		applied = append(applied, rule.BundleID+"/"+rule.Rule.ID)
		if effectRank(rule.Rule.Effect) > effectRank(selected.Rule.Effect) {
			selected = rule
		}
		if compatibleObligations(selected.Rule.Effect, rule.Rule.Effect) {
			obligations = append(obligations, convertObligations(rule.Rule.Obligations)...)
		}
	}

	obligations = ensureEffectObligations(selected.Rule.Effect, obligations)

	return Evaluation{
		Effect:         selected.Rule.Effect,
		ReasonCode:     selected.Rule.ReasonCode,
		AppliedRules:   applied,
		Obligations:    obligations,
		MatchedRules:   matched,
		SelectedRule:   selected.Rule.ID,
		SelectedBundle: selected.BundleID,
		BundlePriority: topBundlePriority,
		TopPriority:    topPriority,
	}
}

func (b Bundle) RequiresRuntimeApproval(request types.PolicyRequest) bool {
	return b.Evaluate(request).Effect == types.EffectApprovalRequired
}

func ruleMatches(rule Rule, request types.PolicyRequest) (bool, error) {
	if rule.Surface != request.Context.Surface {
		return false, nil
	}
	if len(rule.RequestKinds) > 0 && !containsRequestKind(rule.RequestKinds, request.RequestKind) {
		return false, nil
	}
	condition := rule.When
	if condition.Always {
		return true, nil
	}
	if len(condition.Tools) > 0 && !containsStringPattern(condition.Tools, request.Action.Tool) {
		return false, nil
	}
	if len(condition.Operations) > 0 && !containsStringPattern(condition.Operations, request.Action.Operation) {
		return false, nil
	}
	if len(condition.SideEffectsAny) > 0 && !intersectsString(condition.SideEffectsAny, request.Action.SideEffects) {
		return false, nil
	}
	if len(condition.SideEffectsAll) > 0 && !containsAllString(request.Action.SideEffects, condition.SideEffectsAll) {
		return false, nil
	}
	if condition.OpenWorld != nil && request.Action.OpenWorld != *condition.OpenWorld {
		return false, nil
	}
	if len(condition.TargetKinds) > 0 && !containsStringPattern(condition.TargetKinds, request.Target.Kind) {
		return false, nil
	}
	if len(condition.TargetIdentifiers) > 0 && !containsStringPattern(condition.TargetIdentifiers, request.Target.Identifier) {
		return false, nil
	}
	if len(condition.TaintsAny) > 0 && !intersectsTaint(condition.TaintsAny, request.Context.Taints) {
		return false, nil
	}
	if len(condition.DataClassesAny) > 0 && !intersectsDataClass(condition.DataClassesAny, request.Content.DataClasses) {
		return false, nil
	}
	if len(condition.ActorUserIDs) > 0 && !containsStringPattern(condition.ActorUserIDs, request.Actor.UserID) {
		return false, nil
	}
	if strings.TrimSpace(condition.Expression) != "" {
		matches, err := evaluateCELCondition(condition.Expression, request)
		if err != nil {
			return false, err
		}
		return matches, nil
	}
	return true, nil
}

func compatibleObligations(selected types.Effect, candidate types.Effect) bool {
	return selected == candidate || candidate == types.EffectAllowWithAudit || candidate == types.EffectAllow
}

func convertObligations(obligations []Obligation) []types.Obligation {
	result := make([]types.Obligation, 0, len(obligations))
	for _, obligation := range obligations {
		result = append(result, types.Obligation{
			Type:   obligation.Type,
			Params: obligation.Params,
		})
	}
	return result
}

func ensureEffectObligations(effect types.Effect, obligations []types.Obligation) []types.Obligation {
	switch effect {
	case types.EffectDeny, types.EffectExclusion:
		if !hasObligation(obligations, "task_control") {
			obligations = append(obligations, types.Obligation{
				Type: "task_control",
				Params: map[string]interface{}{
					"action": "abort_task",
				},
			})
		}
	}
	return obligations
}

func hasObligation(obligations []types.Obligation, obligationType string) bool {
	for _, obligation := range obligations {
		if obligation.Type == obligationType {
			return true
		}
	}
	return false
}

func auditObligation(severity string, surface types.Surface) types.Obligation {
	return types.Obligation{
		Type: "audit_event",
		Params: map[string]interface{}{
			"severity": severity,
			"surface":  surface,
		},
	}
}

func effectRank(effect types.Effect) int {
	switch effect {
	case types.EffectDeny, types.EffectExclusion:
		return 40
	case types.EffectApprovalRequired:
		return 30
	case types.EffectAllowWithAudit:
		return 20
	case types.EffectAllow:
		return 10
	default:
		return 0
	}
}

func containsRequestKind(values []types.RequestKind, candidate types.RequestKind) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func containsStringPattern(patterns []string, candidate string) bool {
	if candidate == "" {
		return false
	}
	for _, pattern := range patterns {
		if pattern == "*" || strings.EqualFold(pattern, candidate) {
			return true
		}
	}
	return false
}

func intersectsString(left []string, right []string) bool {
	for _, candidate := range right {
		if containsStringPattern(left, candidate) {
			return true
		}
	}
	return false
}

func containsAllString(values []string, required []string) bool {
	for _, value := range required {
		if !containsStringPattern(values, value) {
			return false
		}
	}
	return true
}

func intersectsTaint(left []types.Taint, right []types.Taint) bool {
	for _, l := range left {
		for _, r := range right {
			if l == r {
				return true
			}
		}
	}
	return false
}

func intersectsDataClass(left []types.DataClass, right []types.DataClass) bool {
	for _, l := range left {
		for _, r := range right {
			if l == r {
				return true
			}
		}
	}
	return false
}

func validSurface(surface types.Surface) bool {
	switch surface {
	case types.SurfaceInput, types.SurfaceRuntime, types.SurfaceResource:
		return true
	default:
		return false
	}
}

func validRequestKind(kind types.RequestKind) bool {
	switch kind {
	case types.RequestKindInput,
		types.RequestKindToolAttempt,
		types.RequestKindResourceEgress,
		types.RequestKindResourceAccess,
		types.RequestKindInitialEnvelope,
		types.RequestKindEnvelopeAmendment:
		return true
	default:
		return false
	}
}

func validEffect(effect types.Effect) bool {
	switch effect {
	case types.EffectAllow,
		types.EffectAllowWithAudit,
		types.EffectApprovalRequired,
		types.EffectDeny,
		types.EffectExclusion:
		return true
	default:
		return false
	}
}

func validateCondition(ruleID string, condition Condition) error {
	if condition.Always && !conditionOnlyAlways(condition) {
		return fmt.Errorf("rule %q condition always cannot be combined with other match fields", ruleID)
	}
	if !condition.Always && conditionEmpty(condition) {
		return fmt.Errorf("rule %q condition must be explicit; use always:true for intentional catch-all", ruleID)
	}
	if condition.Language != "" && condition.Language != "cel" {
		return fmt.Errorf("rule %q condition language %q is unsupported", ruleID, condition.Language)
	}
	if condition.Language == "cel" && strings.TrimSpace(condition.Expression) == "" {
		return fmt.Errorf("rule %q condition language cel requires expression", ruleID)
	}
	if condition.Language == "" && strings.TrimSpace(condition.Expression) != "" {
		return fmt.Errorf("rule %q condition expression requires language", ruleID)
	}
	if condition.Language == "cel" {
		if err := compileCELCondition(condition.Expression); err != nil {
			return fmt.Errorf("rule %q condition cel expression invalid: %w", ruleID, err)
		}
	}
	checks := []struct {
		name   string
		values []string
	}{
		{name: "tools", values: condition.Tools},
		{name: "operations", values: condition.Operations},
		{name: "side_effects_any", values: condition.SideEffectsAny},
		{name: "side_effects_all", values: condition.SideEffectsAll},
		{name: "target_kinds", values: condition.TargetKinds},
		{name: "target_identifiers", values: condition.TargetIdentifiers},
		{name: "actor_user_ids", values: condition.ActorUserIDs},
	}
	for _, check := range checks {
		if err := validateStringList(ruleID, check.name, check.values); err != nil {
			return err
		}
	}
	if err := validateTaintList(ruleID, condition.TaintsAny); err != nil {
		return err
	}
	if err := validateDataClassList(ruleID, condition.DataClassesAny); err != nil {
		return err
	}
	return nil
}

func conditionOnlyAlways(condition Condition) bool {
	empty := condition
	empty.Always = false
	return conditionEmpty(empty)
}

func conditionEmpty(condition Condition) bool {
	return condition.Language == "" &&
		strings.TrimSpace(condition.Expression) == "" &&
		len(condition.Tools) == 0 &&
		len(condition.Operations) == 0 &&
		len(condition.SideEffectsAny) == 0 &&
		len(condition.SideEffectsAll) == 0 &&
		condition.OpenWorld == nil &&
		len(condition.TargetKinds) == 0 &&
		len(condition.TargetIdentifiers) == 0 &&
		len(condition.TaintsAny) == 0 &&
		len(condition.DataClassesAny) == 0 &&
		len(condition.ActorUserIDs) == 0
}

func validateStringList(ruleID string, field string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value {
			return fmt.Errorf("rule %q condition %s contains blank or padded value", ruleID, field)
		}
		normalized := strings.ToLower(value)
		if _, exists := seen[normalized]; exists {
			return fmt.Errorf("rule %q condition %s contains duplicate value %q", ruleID, field, value)
		}
		seen[normalized] = struct{}{}
	}
	return nil
}

func validateObligationCompatibility(rule Rule, obligation Obligation) error {
	switch obligation.Type {
	case "rewrite_input", "resolve_secret_handle", "approval_request":
		return fmt.Errorf("rule %q uses core-owned obligation type %q", rule.ID, obligation.Type)
	case "task_control":
		action, ok := obligation.Params["action"].(string)
		if !ok || action == "" {
			return fmt.Errorf("rule %q task_control obligation requires action", rule.ID)
		}
		switch action {
		case "abort_task":
			if rule.Effect == types.EffectAllow || rule.Effect == types.EffectAllowWithAudit || rule.Effect == types.EffectApprovalRequired {
				return fmt.Errorf("rule %q effect %q cannot use abort_task obligation", rule.ID, rule.Effect)
			}
		case "pause_for_approval":
			if rule.Effect != types.EffectApprovalRequired {
				return fmt.Errorf("rule %q pause_for_approval obligation requires approval_required effect", rule.ID)
			}
		default:
			return fmt.Errorf("rule %q has unsupported task_control action %q", rule.ID, action)
		}
	}
	return nil
}

func validateTaintList(ruleID string, values []types.Taint) error {
	seen := make(map[types.Taint]struct{}, len(values))
	for _, value := range values {
		switch value {
		case types.TaintUntrustedExternal, types.TaintPossibleInjection, types.TaintEmbeddedInstruction, types.TaintSecretBearing:
		default:
			return fmt.Errorf("rule %q condition taints_any has unsupported taint %q", ruleID, value)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("rule %q condition taints_any contains duplicate value %q", ruleID, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateDataClassList(ruleID string, values []types.DataClass) error {
	seen := make(map[types.DataClass]struct{}, len(values))
	for _, value := range values {
		switch value {
		case types.DataClassPII, types.DataClassSecret, types.DataClassBusiness, types.DataClassFinancial, types.DataClassCredential:
		default:
			return fmt.Errorf("rule %q condition data_classes_any has unsupported data class %q", ruleID, value)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("rule %q condition data_classes_any contains duplicate value %q", ruleID, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func containsSensitiveParam(params map[string]interface{}) bool {
	for key, value := range params {
		if isSensitiveKey(key) {
			return true
		}
		switch typed := value.(type) {
		case map[string]interface{}:
			if containsSensitiveParam(typed) {
				return true
			}
		case []interface{}:
			for _, item := range typed {
				nested, ok := item.(map[string]interface{})
				if ok && containsSensitiveParam(nested) {
					return true
				}
			}
		}
	}
	return false
}

func isSensitiveKey(key string) bool {
	switch strings.ToLower(strings.ReplaceAll(key, "-", "_")) {
	case "secret", "secret_value", "value", "token", "api_key", "apikey", "password", "authorization", "access_token", "refresh_token":
		return true
	default:
		return false
	}
}
