# @agentgate/openclaw-adapter

OpenClaw plugin that registers AgentGate input and runtime guard hooks.

## Install Into OpenClaw

```bash
mkdir -p ~/.openclaw/npm
cd ~/.openclaw/npm
npm install @agentgate/openclaw-adapter
```

Then add the plugin config to `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "allow": ["agentgate-openclaw-adapter"]
  },
  "pluginConfig": {
    "agentgate-openclaw-adapter": {
      "agentGate": {
        "baseUrl": "http://127.0.0.1:8080",
        "adapterToken": "adapter-local-token",
        "integrationId": "openclaw-main"
      }
    }
  }
}
```

## Local Development

```bash
bun run --filter @agentgate/openclaw-adapter build
npm pack ./packages/openclaw-adapter
```
