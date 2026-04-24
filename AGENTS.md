# AGENTS.md

## Project Context

AgentGate is a security control framework for agent tool boundaries. It is not an agent runtime, SDK-only helper, or OS sandbox. The core service is authoritative: adapters and hosts send intent to AgentGate, and AgentGate returns policy decisions.

The current implementation follows the AgentGate V2 project plan dated 2026-04-24.

## Repository Layout

- `cmd/agentgate/`: Go service entrypoint.
- `internal/types/`: Shared Go data contracts from the v2 plan.
- `internal/httpapi/`: chi router and HTTP handlers.
- `internal/store/`: SQLite setup and migrations using `modernc.org/sqlite`.
- `config/`: Default policy bundle and future runtime config.
- `packages/openclaw-adapter/`: TypeScript workspace package for the thin OpenClaw adapter.
- `apps/`: Future demo apps.
- `scripts/`: Future red-team and demo scripts.

## Commands

- Go format: `gofmt -w ./cmd ./internal`
- Go tests: `go test ./...`
- Install TypeScript deps: `bun install`
- TypeScript typecheck: `bun run typecheck`
- TypeScript build: `bun run build`
- Run service: `go run ./cmd/agentgate`

By default the service listens on `:8080` and opens SQLite at `agentgate.db`. Override with `AGENTGATE_ADDR` and `AGENTGATE_SQLITE_DSN`.

## Engineering Rules

- Keep Go core decisions host-authoritative. Adapter packages must stay thin and should not duplicate security policy logic.
- Keep API fields aligned with the v2 plan JSON contracts. TypeScript types should mirror Go JSON shapes, including snake_case field names.
- Use `chi` with standard `net/http` handlers. Avoid hidden framework behavior in security-critical paths.
- Use `modernc.org/sqlite` for the default local store so builds remain CGO-free.
- Store raw sensitive evidence separately from redacted audit events.
- Fail closed for policy load/update errors once policy loading is implemented.

## Git And Workspace Safety

- Do not revert user changes unless explicitly asked.
- Keep edits scoped to the task.
- Prefer small, verifiable commits when committing is requested.
- Run Go and TypeScript checks before handing off code changes.
