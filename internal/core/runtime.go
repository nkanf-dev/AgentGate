package core

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/agentgate/agentgate/internal/types"
)

type runtimeState struct {
	mu sync.RWMutex

	IntegrationID string
	Command       []string
	Status        string
	RestartCount  int
	LastStartedAt *time.Time
	LastExitedAt  *time.Time
	LastHealthyAt *time.Time
	LastError     string
	Pid           int
	cancel        context.CancelFunc
}

func (s *runtimeState) snapshot() *types.IntegrationRuntimeView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	view := &types.IntegrationRuntimeView{
		Managed:      true,
		Command:      append([]string(nil), s.Command...),
		Status:       s.Status,
		RestartCount: s.RestartCount,
		LastError:    s.LastError,
		Pid:          s.Pid,
	}
	if s.LastStartedAt != nil {
		started := *s.LastStartedAt
		view.LastStartedAt = &started
	}
	if s.LastExitedAt != nil {
		exited := *s.LastExitedAt
		view.LastExitedAt = &exited
	}
	if s.LastHealthyAt != nil {
		healthy := *s.LastHealthyAt
		view.LastHealthyAt = &healthy
	}
	return view
}

type RuntimeSupervisor struct {
	mu       sync.RWMutex
	runtimes map[string]*runtimeState
}

func newRuntimeSupervisor() *RuntimeSupervisor {
	return &RuntimeSupervisor{runtimes: make(map[string]*runtimeState)}
}

func (s *RuntimeSupervisor) View(integrationID string) *types.IntegrationRuntimeView {
	s.mu.RLock()
	state := s.runtimes[integrationID]
	s.mu.RUnlock()
	if state == nil {
		return nil
	}
	return state.snapshot()
}

func (s *RuntimeSupervisor) Ensure(definition types.IntegrationDefinition) error {
	if definition.Runtime == nil || !definition.Runtime.Managed || !definition.Runtime.Enabled || !definition.Enabled {
		s.Stop(definition.ID)
		return nil
	}
	s.mu.RLock()
	current := s.runtimes[definition.ID]
	s.mu.RUnlock()
	if current != nil {
		snap := current.snapshot()
		if snap.Status == "starting" || snap.Status == "running" {
			return nil
		}
	}
	return s.Start(definition)
}

func (s *RuntimeSupervisor) Start(definition types.IntegrationDefinition) error {
	if definition.Runtime == nil {
		return nil
	}
	command, env, err := managedRuntimeCommand(definition)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Dir = resolveRepoRoot()

	now := time.Now().UTC()
	state := &runtimeState{
		IntegrationID: definition.ID,
		Command:       append([]string(nil), command...),
		Status:        "starting",
		LastStartedAt: &now,
		cancel:        cancel,
	}
	s.mu.Lock()
	s.runtimes[definition.ID] = state
	s.mu.Unlock()

	if err := cmd.Start(); err != nil {
		cancel()
		s.setError(definition.ID, "start_failed", err)
		return err
	}

	state.mu.Lock()
	state.Pid = cmd.Process.Pid
	state.Status = "running"
	started := time.Now().UTC()
	state.LastHealthyAt = &started
	state.mu.Unlock()

	go s.watch(definition, state, cmd)
	return nil
}

func (s *RuntimeSupervisor) watch(definition types.IntegrationDefinition, state *runtimeState, cmd *exec.Cmd) {
	err := cmd.Wait()
	exitedAt := time.Now().UTC()

	state.mu.Lock()
	state.LastExitedAt = &exitedAt
	state.Pid = 0
	if err != nil {
		state.Status = "degraded"
		state.LastError = err.Error()
	} else {
		state.Status = "stopped"
		state.LastError = ""
	}
	restartCount := state.RestartCount
	state.mu.Unlock()

	if definition.Runtime == nil || !definition.Runtime.Restart.Enabled {
		return
	}
	if definition.Runtime.Restart.MaxAttempts > 0 && restartCount >= definition.Runtime.Restart.MaxAttempts {
		return
	}
	backoff := definition.Runtime.Restart.BackoffMs
	if backoff <= 0 {
		backoff = 2000
	}
	time.Sleep(time.Duration(backoff) * time.Millisecond)
	state.mu.Lock()
	state.RestartCount++
	state.mu.Unlock()
	_ = s.Start(definition)
}

func (s *RuntimeSupervisor) Stop(integrationID string) {
	s.mu.Lock()
	state := s.runtimes[integrationID]
	if state != nil {
		delete(s.runtimes, integrationID)
	}
	s.mu.Unlock()
	if state != nil && state.cancel != nil {
		state.cancel()
	}
}

func (s *RuntimeSupervisor) setError(integrationID string, status string, err error) {
	now := time.Now().UTC()
	s.mu.Lock()
	state := s.runtimes[integrationID]
	if state == nil {
		state = &runtimeState{IntegrationID: integrationID}
		s.runtimes[integrationID] = state
	}
	s.mu.Unlock()
	state.mu.Lock()
	defer state.mu.Unlock()
	state.Status = status
	state.LastExitedAt = &now
	if err != nil {
		state.LastError = err.Error()
	}
}

func managedRuntimeCommand(definition types.IntegrationDefinition) ([]string, []string, error) {
	if definition.Runtime == nil {
		return nil, nil, nil
	}
	if len(definition.Runtime.Command) == 0 {
		return nil, nil, fmt.Errorf("runtime.command is required")
	}
	env, err := managedRuntimeEnv(definition)
	if err != nil {
		return nil, nil, err
	}
	return append([]string(nil), definition.Runtime.Command...), env, nil
}

func managedRuntimeEnv(definition types.IntegrationDefinition) ([]string, error) {
	if definition.Runtime == nil {
		return nil, fmt.Errorf("missing runtime spec")
	}
	env := make([]string, 0, len(definition.Runtime.Env)+4)
	env = append(env,
		fmt.Sprintf("AGENTGATE_BASE_URL=%s", strings.TrimSpace(os.Getenv("AGENTGATE_MANAGED_BASE_URL"))),
		fmt.Sprintf("AGENTGATE_ADAPTER_TOKEN=%s", strings.TrimSpace(os.Getenv("AGENTGATE_MANAGED_ADAPTER_TOKEN"))),
		fmt.Sprintf("AGENTGATE_OPERATOR_TOKEN=%s", strings.TrimSpace(os.Getenv("AGENTGATE_MANAGED_OPERATOR_TOKEN"))),
		fmt.Sprintf("AGENTGATE_INTEGRATION_ID=%s", definition.ID),
	)
	for key, rawValue := range definition.Runtime.Env {
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("runtime.env keys must be non-empty")
		}
		value := mapString(rawValue)
		if strings.HasPrefix(value, "${env:") && strings.HasSuffix(value, "}") {
			envKey := strings.TrimSuffix(strings.TrimPrefix(value, "${env:"), "}")
			value = strings.TrimSpace(os.Getenv(envKey))
		}
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	sort.Strings(env)
	return env, nil
}

func resolveRepoRoot() string {
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return cwd
}
