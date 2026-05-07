# AgentGate 发布说明

## 1. 发布目标

本仓库当前建议同时准备三类交付物：

- GitHub 源码 release
- npm 包：`@agentgate/openclaw-adapter`
- npm 包：`@agentgate/feishu-adapter`

其中：

- OpenClaw 插件包用于宿主接入
- Feishu 包用于审批通道运行时分发

## 2. 发布前检查

在仓库根目录执行：

```bash
bun install --frozen-lockfile
go test ./...
bun run typecheck
bun run build
```

## 3. 生成 npm 包

```bash
npm pack ./packages/openclaw-adapter
npm pack ./packages/feishu-adapter
```

产物会出现在仓库根目录，例如：

- `agentgate-openclaw-adapter-0.1.0.tgz`
- `agentgate-feishu-adapter-0.1.0.tgz`

## 4. 发布到 npm

先完成 npm 登录：

```bash
npm login
```

然后发布：

```bash
npm publish ./packages/openclaw-adapter --access public
npm publish ./packages/feishu-adapter --access public
```

如果要先做预览，可以使用：

```bash
npm pack ./packages/openclaw-adapter
npm pack ./packages/feishu-adapter
```

## 5. GitHub Release

建议流程：

```bash
git tag v0.1.0
git push origin v0.1.0
```

如果本机已经配置 GitHub CLI：

```bash
gh release create v0.1.0 \
  ./agentgate-openclaw-adapter-0.1.0.tgz \
  ./agentgate-feishu-adapter-0.1.0.tgz \
  --title "AgentGate v0.1.0" \
  --notes-file docs/install-and-deploy.md
```

## 6. 现场分发建议

对于评委电脑不一定有 Docker 的场景，建议优先提供：

1. 仓库源码
2. `docs/install-and-deploy.md`
3. npm 打包产物 `.tgz`
4. 预构建的 `web/dist`

这样即使不走 Docker，也能快速本地跑通。
