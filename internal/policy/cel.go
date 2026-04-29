package policy

import (
	"fmt"
	"time"

	"github.com/agentgate/agentgate/internal/types"
	"github.com/google/cel-go/cel"
)

func compileCELCondition(expression string) error {
	env, err := newCELEnv()
	if err != nil {
		return err
	}
	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return issues.Err()
	}
	if ast.OutputType() != cel.BoolType {
		return fmt.Errorf("expression must return bool, got %s", ast.OutputType().String())
	}
	return nil
}

func evaluateCELCondition(expression string, request types.PolicyRequest, sessionFacts types.SessionFacts) (bool, error) {
	env, err := newCELEnv()
	if err != nil {
		return false, err
	}
	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return false, issues.Err()
	}
	if ast.OutputType() != cel.BoolType {
		return false, fmt.Errorf("expression must return bool, got %s", ast.OutputType().String())
	}
	program, err := env.Program(ast)
	if err != nil {
		return false, err
	}
	value, _, err := program.Eval(celActivation(request, sessionFacts))
	if err != nil {
		return false, err
	}
	result, ok := value.Value().(bool)
	if !ok {
		return false, fmt.Errorf("expression result must be bool, got %T", value.Value())
	}
	return result, nil
}

func newCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("request_kind", cel.StringType),
		cel.Variable("surface", cel.StringType),
		cel.Variable("actor", cel.DynType),
		cel.Variable("session", cel.DynType),
		cel.Variable("action", cel.DynType),
		cel.Variable("target", cel.DynType),
		cel.Variable("content", cel.DynType),
		cel.Variable("context", cel.DynType),
		cel.Variable("policy", cel.DynType),
		cel.Variable("session_facts", cel.DynType),
	)
}

func celActivation(request types.PolicyRequest, sessionFacts types.SessionFacts) map[string]interface{} {
	return map[string]interface{}{
		"request_kind": string(request.RequestKind),
		"surface":      string(request.Context.Surface),
		"actor": map[string]interface{}{
			"user_id":  request.Actor.UserID,
			"host_id":  request.Actor.HostID,
			"agent_id": request.Actor.AgentID,
		},
		"session": map[string]interface{}{
			"session_id": request.Session.SessionID,
			"task_id":    request.Session.TaskID,
			"attempt_id": request.Session.AttemptID,
		},
		"action": map[string]interface{}{
			"operation":    request.Action.Operation,
			"tool":         request.Action.Tool,
			"side_effects": request.Action.SideEffects,
			"open_world":   request.Action.OpenWorld,
		},
		"target": map[string]interface{}{
			"kind":       request.Target.Kind,
			"identifier": request.Target.Identifier,
		},
		"content": map[string]interface{}{
			"summary":      request.Content.Summary,
			"data_classes": dataClassStrings(request.Content.DataClasses),
		},
		"context": map[string]interface{}{
			"surface": string(request.Context.Surface),
			"taints":  taintStrings(request.Context.Taints),
			"raw":     request.Context.Raw,
		},
		"policy": request.Policy,
		"session_facts": map[string]interface{}{
			"request_count":         sessionFacts.RequestCount,
			"deny_count":            sessionFacts.DenyCount,
			"approval_count":        sessionFacts.ApprovalCount,
			"allow_count":           sessionFacts.AllowCount,
			"distinct_targets":      sessionFacts.DistinctTargets,
			"distinct_tools":        sessionFacts.DistinctTools,
			"distinct_reason_codes": sessionFacts.DistinctReasonCodes,
			"side_effect_sequence":  sessionFacts.SideEffectSequence,
			"last_effect":           sessionFacts.LastEffect,
			"last_request_at":       timeString(sessionFacts.LastRequestAt),
			"first_request_at":      timeString(sessionFacts.FirstRequestAt),
		},
	}
}

func timeString(value *time.Time) string {
	if value == nil || value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func dataClassStrings(values []types.DataClass) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, string(value))
	}
	return result
}

func taintStrings(values []types.Taint) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, string(value))
	}
	return result
}
