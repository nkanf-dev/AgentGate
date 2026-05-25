# AgentGate 安装与部署指南

## 1. 目标

这份指南对应本地优先的快速部署场景：

- `go run ./cmd/agentgate` 后即可打开控制台
- 默认本地令牌已内置，不需要先手填 token
- OpenClaw 通过插件接入 AgentGate
- Feishu 审批通过长连接接入，不依赖公网回调

默认本地令牌如下：

- `adapter-local-token`
- `operator-local-token`
- `admin-local-token`

## 2. 环境要求

- Go 1.22+
- Node.js 20+
- Bun 1.3+
- npm
- OpenClaw 已安装

## 3. 一键安装

在仓库根目录执行：

```bash
./scripts/install-agentgate.sh
```

脚本会完成这些事情：

- 安装 Bun workspace 依赖
- 构建 Web 控制台
- 构建 OpenClaw / Feishu / Resource adapters
- 将 `@agentgate/openclaw-adapter` 安装到 `~/.openclaw/npm`

## 4. 启动 AgentGate

最简单的启动方式：

```bash
cd /path/to/AgentGate
go run ./cmd/agentgate
```

启动后直接访问：

- [http://localhost:8080/](http://localhost:8080/)

说明：

- 如果仓库里已有 `web/dist`，Go 服务会直接托管前端
- 默认数据库是当前目录下的 `agentgate.db`
- 默认策略来自 `config/default_policy.json`

常用环境变量：

```bash
export AGENTGATE_ADDR=127.0.0.1:8080
export AGENTGATE_SQLITE_DSN=agentgate.db
export AGENTGATE_ADAPTER_TOKENS=adapter-local-token
export AGENTGATE_OPERATOR_TOKENS=operator-local-token
export AGENTGATE_ADMIN_TOKENS=admin-local-token
```

## 5. 接入 OpenClaw

先确保插件已安装到：

- `~/.openclaw/npm`

然后编辑 `~/.openclaw/openclaw.json`，至少加入：

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

然后启动 OpenClaw。AgentGate 控制台的 `Integrations` 和 `Live Adapters` 中应看到对应注册。

## 6. 启动 Feishu 审批

Feishu 审批运行时是独立 worker，但它注册为 AgentGate 的审批传输通道。

先准备环境变量：

```bash
export AGENTGATE_BASE_URL=http://127.0.0.1:8080
export AGENTGATE_ADAPTER_TOKEN=adapter-local-token
export AGENTGATE_OPERATOR_TOKEN=operator-local-token
export FEISHU_APP_ID=cli_xxx
export FEISHU_APP_SECRET=xxx
export FEISHU_RECEIVE_ID=oc_xxx
export FEISHU_RECEIVE_ID_TYPE=chat_id
```

启动命令：

```bash
node packages/feishu-adapter/dist/cli.js
```

说明：

- 采用飞书长连接模式
- 不需要公网 IP 或回调地址
- `FEISHU_RECEIVE_ID` 建议填群 `chat_id`

## 7. 快速体验

推荐启动顺序：

1. `go run ./cmd/agentgate`
2. 打开 [http://localhost:8080/](http://localhost:8080/)
3. 启动 Feishu 审批 worker
4. 启动 OpenClaw
5. 在群聊或本地入口发起真实高风险请求
6. 在 Feishu 中点击 `Allow Once` 或 `Deny`
7. 回到控制台查看 `Events`、`Approvals`、`Timeline`

## 8. 常见问题

### 控制台打开后是空白页

先执行：

```bash
bun run build:web
```

然后重新启动 `go run ./cmd/agentgate`。

### Integrations 页面黑屏

请使用当前版本代码。这个问题已修复，缺省或空数组的 integration coverage 数据会被前端正常归一化处理。

### OpenClaw 没注册到 AgentGate

检查：

- OpenClaw 是否加载了 `agentgate-openclaw-adapter`
- `baseUrl` 是否指向 `http://127.0.0.1:8080`
- `adapterToken` 是否为 `adapter-local-token`

### Feishu 审批没有消息

检查：

- 飞书机器人是否已经进群
- 长连接模式是否已开启
- `FEISHU_RECEIVE_ID` 是否是实际群 `chat_id`
- AgentGate 是否已经产生 `approval_requested` 事件
