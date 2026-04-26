# AgentGate Web Mock

This app is the current frontend mock for AgentGate's operator console.

## Mock Status

This is explicitly a static mock:

- Mock data lives in `src/mock-data.ts`.
- The UI displays a `MOCK DATA` badge in the header.
- No real AgentGate Core API calls are made yet.
- The mock data mirrors the intended `/v1/events`, `/v1/coverage`, and approvals shapes.

## Component Constraint

The mock intentionally uses mature components instead of hand-rolled UI primitives:

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
