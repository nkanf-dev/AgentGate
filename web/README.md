# AgentGate Web Console

This app is the operator console for a live AgentGate Core instance.

## Runtime Data

- The console calls the real AgentGate API. It does not use mock event data.
- Configure the Core URL with `VITE_AGENTGATE_BASE_URL`.
- Configure the operator bearer token with `VITE_AGENTGATE_OPERATOR_TOKEN`.
- Runtime overrides are stored in this browser through the Settings page.
- Feishu app secrets must stay in deployment secrets or server-side environment configuration, not in this browser UI.

## Component Constraint

Use mature components instead of hand-rolled UI primitives:

- shadcn/ui generated components in `src/components/ui/*`
- Radix primitives through shadcn/ui
- TanStack React Table for the event table
- shadcn Chart + Recharts for the timeline histogram
- lucide-react icons

Application code should focus on AgentGate data mapping and composition. Do not hand-roll tables, selects, sidebars, badges, pagination, tooltips, icon buttons, collapsibles, or chart primitives.

## Commands

```bash
bun install
bun run build
bun run dev
```
