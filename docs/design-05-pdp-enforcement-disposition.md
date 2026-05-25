# AgentGate ADR: PDP Internalizes Approval Workflow, PEP Receives Only Allow/Deny

Generated: 2026-05-25  
Status: Accepted  
Scope: Core decision pipeline, adapter contract, approval workflow

---

## Background

AgentGate currently exposes `approval_required` as a first-class `Effect` in the public decision contract.

Today the flow is:

1. Policy evaluation returns `approval_required`
2. Core returns `approval_required + approval_request + task_control` to the adapter
3. The enforcement-side adapter pauses, polls, or waits for approval resolution
4. The adapter folds the result back into an executable allow/deny outcome

This leaks PDP workflow state into the PEP contract.

That boundary is wrong for the long term:

- `approval_required` is not an executable command
- only Core knows how to create approvals, notify approval channels, and mint grants
- a PEP should execute a final disposition, not participate in approval orchestration
- new surfaces such as Linux resource enforcement should not inherit the current adapter-side approval loop

The current model was useful as an intermediate architecture because it allowed approval flow to work end-to-end before Core owned the full workflow. It should now be treated as a transitional contract, not a stable one.

---

## Problem Statement

AgentGate currently mixes two different layers into one return object:

- **policy effect**: internal result of rule evaluation
- **enforcement disposition**: final command delivered to a PEP

These are not the same thing.

Examples:

- `allow_with_audit` is an internal policy result, but the PEP still executes `allow`
- `exclusion` is an internal policy result, but the PEP still executes `deny`
- `approval_required` is not executable at all; it means Core must run a workflow before a final executable answer exists

As long as these layers remain collapsed:

- adapters must understand Core workflow states
- approval logic keeps leaking into every new enforcement surface
- `can_pause_for_approval` gets forced into the adapter capability model even though approval is PDP-owned
- the public contract overstates PEP responsibility and understates PDP authority

---

## Decision

AgentGate will separate **policy evaluation output** from **PEP-facing enforcement disposition**.

### Decision 1: Policy evaluation may remain fine-grained

The rule engine may continue to produce internal effects such as:

- `allow`
- `allow_with_audit`
- `approval_required`
- `deny`
- `exclusion`

These remain valid **internal** policy outcomes.

### Decision 2: PEP-facing disposition collapses to two executable commands

The only final dispositions delivered to a PEP are:

- `allow`
- `deny`

Everything else must be consumed inside the PDP.

### Decision 3: Approval workflow is PDP-owned

If policy evaluation yields `approval_required`, the PDP must:

1. create the approval record
2. append the audit/event record
3. notify or expose the approval to the configured approval channel
4. wait for, poll for, or resume from approval resolution
5. create a grant if resolution is approving
6. translate the workflow result into final `allow` or `deny`

The PEP must not implement approval orchestration.

### Decision 4: Internal effect-to-disposition mapping is explicit

The authoritative mapping is:

| Internal policy effect | Final PEP disposition |
|---|---|
| `allow` | `allow` |
| `allow_with_audit` | `allow` |
| `approval_required` | no direct PEP output; PDP continues workflow, then emits `allow` or `deny` |
| `deny` | `deny` |
| `exclusion` | `deny` |

---

## Architecture Changes

### 1. Split decision model into internal vs external forms

Core should stop treating one object as both policy result and enforcement result.

Target model:

```go
type PolicyEvaluation struct {
    Effect       types.Effect
    ReasonCode   string
    Obligations  []types.Obligation
    AppliedRules []string
    Trace        types.DecisionExplanation
}

type EnforcementDisposition string

const (
    EnforcementAllow EnforcementDisposition = "allow"
    EnforcementDeny  EnforcementDisposition = "deny"
)

type EnforcementDecision struct {
    DecisionID   string
    RequestID    string
    Disposition  EnforcementDisposition
    ReasonCode   string
    DecidedAt    time.Time
}
```

`PolicyEvaluation` is PDP-internal.  
`EnforcementDecision` is the PEP contract.

### 2. Introduce a PDP workflow stage between rule evaluation and PEP response

The decision pipeline becomes:

1. normalize and validate request
2. enrich secret / taint / session facts
3. evaluate policy
4. execute internal workflow obligations
5. if needed, complete approval workflow inside Core
6. emit final `allow` / `deny` disposition to PEP
7. persist decision event and derived state

This makes approval one workflow branch inside the PDP, not a special effect the PEP must understand.

### 3. Remove approval capability from enforcement adapters

`can_pause_for_approval` should be removed from the long-term PEP capability model.

The only capabilities that matter to a PEP are things like:

- block / deny
- input rewrite
- tool arg rewrite
- reporting

Approval transport adapters remain separate. They are not PEPs.

### 4. Keep approval channels as supporting integrations, not enforcement participants

Approval transports such as Feishu continue to:

- list pending approvals
- present approval UI
- resolve approvals

But they do not determine what the PEP API returns. They only feed the PDP-owned workflow.

---

## API Consequences

### Public decision API

The long-term `/v1/decide` response contract should expose only the final executable disposition for the calling surface.

For enforcement surfaces, that means:

```json
{
  "decision_id": "dec_01",
  "request_id": "req_01",
  "disposition": "allow",
  "reason_code": "user_allow_once_valid",
  "decided_at": "2026-05-25T00:00:00Z"
}
```

or:

```json
{
  "decision_id": "dec_01",
  "request_id": "req_01",
  "disposition": "deny",
  "reason_code": "approval_denied",
  "decided_at": "2026-05-25T00:00:00Z"
}
```

The fine-grained internal `Effect` may still appear in audit events, traces, or operator-facing diagnostics, but not as the required executable branch for a PEP.

### Timeout behavior

If an approval cannot be completed within the configured decision window, the PDP returns final `deny`.

Fail-closed remains the rule.

---

## Transitional Strategy

This is a contract refactor, so migration must be staged.

### Stage 1: Internal split

- introduce internal `PolicyEvaluation` / workflow result types
- keep existing wire response temporarily
- move approval folding logic out of adapters and into Core-owned workflow helpers

### Stage 2: Dual contract support

- support current `effect` response for existing adapters
- add new final-disposition response path for updated PEPs
- keep approval transport behavior unchanged

### Stage 3: Contract cleanup

- remove adapter-side approval waiting logic
- remove `can_pause_for_approval`
- stop documenting `approval_required` as a PEP-facing outcome
- update examples and SDKs so PEPs consume only `allow` / `deny`

---

## Consequences

### Positive

- PEP responsibility becomes simple and stable
- approval semantics stop leaking into every new surface
- Linux resource surface can implement synchronous enforcement without inheriting adapter-side pause logic
- Core becomes the sole owner of approval workflow correctness
- audit semantics become clearer: internal workflow state vs final executable disposition

### Costs

- Core must own more workflow orchestration
- `/v1/decide` contract needs a compatibility migration
- existing adapters, especially OpenClaw, need to shed approval wait/retry logic
- tests must be updated to distinguish internal effect from final disposition

---

## Explicit Non-Goals

- this ADR does not redesign approval channel UX
- this ADR does not change approval persistence schema beyond what workflow ownership requires
- this ADR does not define the exact transport mechanism Core will use to wait, resume, or asynchronously complete approvals for every surface
- this ADR does not remove internal `approval_required` from the rule engine

---

## Why This Matters Now

AgentGate is about to grow a Linux resource surface. That surface should be built on the correct authority boundary:

- the PEP enforces
- the PDP decides
- approval is PDP workflow, not PEP protocol

If this boundary is not corrected now, the current transitional contract will be copied into the resource surface and become much harder to unwind later.
