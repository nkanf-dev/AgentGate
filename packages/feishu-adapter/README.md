# @agentgate/feishu-adapter

Feishu long-connection approval transport for AgentGate.

## Usage

```bash
export AGENTGATE_BASE_URL=http://127.0.0.1:8080
export AGENTGATE_ADAPTER_TOKEN=adapter-local-token
export AGENTGATE_OPERATOR_TOKEN=operator-local-token
export FEISHU_APP_ID=cli_xxx
export FEISHU_APP_SECRET=xxx
export FEISHU_RECEIVE_ID=oc_xxx
export FEISHU_RECEIVE_ID_TYPE=chat_id

agentgate-feishu-adapter
```

## Local Development

```bash
bun run --filter @agentgate/feishu-adapter build
npm pack ./packages/feishu-adapter
```
