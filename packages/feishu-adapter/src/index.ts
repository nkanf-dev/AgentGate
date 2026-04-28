export { AgentGateTransportClient } from "./agentgate.js";
export { FeishuApprovalAdapter, approvalPayloadFromApproval, approvalPayloadFromEvent } from "./adapter.js";
export { buildApprovalCard, buildResolvedCard } from "./card.js";
export type {
  ApprovalCardPayload,
  ApprovalRecord,
  ApprovalResolveResponse,
  ApprovalsResponse,
  EventEnvelope,
  FeishuApprovalAdapterConfig,
  FeishuDomain,
} from "./types.js";
