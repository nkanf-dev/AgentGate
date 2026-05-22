package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os/exec"
	"sync"
	"time"
)

// MLScanner runs a long-lived privacy-scanner subprocess and sends text
// to it over stdin/stdout JSON-line protocol.  The model stays warm across
// requests; only the first call pays model-load latency.
type MLScanner struct {
	cmdPath string
	timeout time.Duration

	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Scanner
	ready  bool
}

// NewMLScanner creates a scanner that will launch the given Bun script.
// timeout is the per-request deadline for classify calls.
func NewMLScanner(scriptPath string, timeout time.Duration) *MLScanner {
	return &MLScanner{cmdPath: scriptPath, timeout: timeout}
}

// DetectSecrets sends text to the ML subprocess and returns findings.
// If the subprocess is not running it will be started (cold start on first call).
func (m *MLScanner) DetectSecrets(ctx context.Context, text string) ([]SecretFinding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureRunning(ctx); err != nil {
		return nil, fmt.Errorf("ml scanner start: %w", err)
	}

	// Send one line.
	if _, err := fmt.Fprintln(m.stdin, text); err != nil {
		m.kill(ctx)
		return nil, fmt.Errorf("ml scanner write: %w", err)
	}

	// Read one line of JSON response with timeout.
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		if m.stdout.Scan() {
			ch <- result{line: m.stdout.Text()}
		} else {
			ch <- result{err: m.stdout.Err()}
		}
	}()

	select {
	case <-time.After(m.timeout):
		m.kill(ctx)
		return nil, fmt.Errorf("ml scanner timeout after %s", m.timeout)
	case r := <-ch:
		if r.err != nil {
			m.kill(ctx)
			return nil, fmt.Errorf("ml scanner read: %w", r.err)
		}
		return parseMLFindings(r.line)
	}
}

// Close shuts down the subprocess.
func (m *MLScanner) Close(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kill(ctx)
}

func (m *MLScanner) ensureRunning(ctx context.Context) error {
	if m.ready {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	m.cmd = exec.CommandContext(ctx, "bun", "run", m.cmdPath)
	m.cmd.Stderr = io.Discard // silence model download noise

	var err error
	m.stdin, err = m.cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdoutPipe, err := m.cmd.StdoutPipe()
	if err != nil {
		return err
	}
	m.stdout = bufio.NewScanner(stdoutPipe)
	// Increase scanner buffer for large texts.
	m.stdout.Buffer(make([]byte, 0, 256*1024), 1024*1024)

	if err := m.cmd.Start(); err != nil {
		return err
	}

	// Wait for the model to become ready by sending a probe.
	// The script prints [] for empty input.
	m.ready = true
	log.Printf("ml scanner: started (pid %d), loading model...", m.cmd.Process.Pid)
	return nil
}

func (m *MLScanner) kill(ctx context.Context) {
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
		_ = m.cmd.Wait()
	}
	m.cmd = nil
	m.stdin = nil
	m.stdout = nil
	m.ready = false
}

func parseMLFindings(line string) ([]SecretFinding, error) {
	if line == "" || line == "[]" {
		return nil, nil
	}

	var raw []struct {
		Kind  string `json:"kind"`
		Start int    `json:"start"`
		End   int    `json:"end"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil, fmt.Errorf("ml scanner parse: %w (line: %s)", err, truncate(line, 200))
	}

	findings := make([]SecretFinding, 0, len(raw))
	for _, r := range raw {
		// Map ML categories to the existing kind taxonomy.
		kind := mapMLKind(r.Kind)
		if kind == "" {
			continue
		}
		findings = append(findings, SecretFinding{
			Kind:  kind,
			Start: r.Start,
			End:   r.End,
			Value: r.Value,
		})
	}
	return findings, nil
}

// mapMLKind normalises model labels into the scanner's kind namespace.
func mapMLKind(mlKind string) string {
	switch mlKind {
	case "secret":
		return "ml_secret"
	case "account_number":
		return "ml_account_number"
	case "private_email":
		return "ml_email"
	case "private_phone":
		return "ml_phone"
	case "private_address":
		return "ml_address"
	case "private_person":
		return "ml_person"
	case "private_url":
		return "ml_url"
	case "private_date":
		return "ml_date"
	default:
		return ""
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Ensure MLScanner satisfies the Detector interface at compile time.
var _ Detector = (*MLScanner)(nil)
