import assert from "node:assert/strict";
import test from "node:test";

import { mapToolAttemptToPolicyRequest } from "../dist/openclaw.js";

test("mapToolAttemptToPolicyRequest uses OpenClaw tool context for exec calls", () => {
  const request = mapToolAttemptToPolicyRequest(
    {
      toolName: "exec",
      params: {
        command: "printf AGENTGATE_RUNTIME_TEST",
        cwd: "/tmp/demo",
      },
    },
    {
      agentId: "agent-main",
      sessionId: "sess-123",
      sessionKey: "agent:main:explicit:sess-123",
      runId: "run-123",
      toolCallId: "call-123",
      toolName: "exec",
    },
    "openclaw-main",
  );

  assert.equal(request.request_kind, "tool_attempt");
  assert.equal(request.actor.agent_id, "agent-main");
  assert.equal(request.session.session_id, "sess-123");
  assert.equal(request.session.task_id, "run-123");
  assert.equal(request.session.attempt_id, "call-123");
  assert.equal(request.action.tool, "exec");
  assert.equal(request.action.operation, "execute");
  assert.equal(request.action.open_world, true);
  assert.deepEqual(request.action.side_effects, [
    "filesystem_read",
    "filesystem_write",
    "network_egress",
    "process_spawn",
  ]);
  assert.equal(request.target.kind, "process");
  assert.deepEqual(request.context.raw, {
    args: {
      command: "printf AGENTGATE_RUNTIME_TEST",
      cwd: "/tmp/demo",
    },
    integration_id: "openclaw-main",
    run_id: "run-123",
    tool_call_id: "call-123",
    session_key: "agent:main:explicit:sess-123",
  });
  assert.deepEqual(request.policy, {
    integration_id: "openclaw-main",
  });
});

test("mapToolAttemptToPolicyRequest classifies path-based tools as read operations", () => {
  const request = mapToolAttemptToPolicyRequest({
    toolName: "view",
    params: {
      path: "/tmp/report.txt",
    },
  });

  assert.equal(request.action.tool, "view");
  assert.equal(request.action.operation, "read");
  assert.deepEqual(request.action.side_effects, ["filesystem_read"]);
  assert.equal(request.target.kind, "tool");
});
