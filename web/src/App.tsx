import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  type ColumnDef,
  type ColumnFiltersState,
  type SortingState,
  type VisibilityState,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from "@tanstack/react-table"
import {
  ChevronDown,
  Check,
  Columns3,
  KeyRound,
  ListFilter,
  Plug,
  RefreshCw,
  Save,
  Settings,
  ShieldCheck,
  Split,
  X,
} from "lucide-react"
import { Bar, BarChart, CartesianGrid, ReferenceLine, XAxis } from "recharts"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart"
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible"
import { Input } from "@/components/ui/input"
import {
  Pagination,
  PaginationContent,
  PaginationItem,
  PaginationNext,
  PaginationPrevious,
} from "@/components/ui/pagination"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  defaultConfig,
  fetchConsoleData,
  loadConfig,
  resolveApproval,
  saveConfig,
  type Approval,
  type ConsoleConfig,
  type Effect,
  type EventSurface,
  type HistogramBucket,
  type SecurityEvent,
  type Surface,
} from "@/lib/agentgate-api"
import {
  effectLabel,
  requestKindLabel,
  statusLabel,
  surfaceLabel,
  surfaceLabels,
} from "@/lib/display-labels"
import { IntegrationsView } from "@/features/integrations/IntegrationsView"
import { PolicyView } from "@/features/policy/PolicyView"

type View =
  | "events"
  | "timeline"
  | "approvals"
  | "policy"
  | "integrations"
  | "settings"

const navItems: Array<{
  value: View
  label: string
  icon: React.ComponentType<{ className?: string }>
  badge?: number
}> = [
  { value: "events", label: "Events", icon: ListFilter },
  { value: "timeline", label: "Timeline", icon: Split },
  { value: "approvals", label: "Approvals", icon: KeyRound },
  { value: "policy", label: "Policy", icon: ShieldCheck },
  { value: "integrations", label: "Integrations", icon: Plug },
  { value: "settings", label: "Settings", icon: Settings },
]

const effectVariant: Record<Effect, "default" | "secondary" | "destructive" | "outline"> = {
  allow: "secondary",
  allow_with_audit: "secondary",
  deny: "destructive",
  approval_required: "outline",
  exclusion: "outline",
}

const surfaceVariant: Record<Surface, "default" | "secondary" | "outline"> = {
  input: "secondary",
  runtime: "outline",
  resource: "default",
}

function SurfaceBadge({ surface }: { surface: EventSurface }) {
  if (surface === "none") {
    return <Badge variant="outline">{surfaceLabel(surface)}</Badge>
  }
  return <Badge variant={surfaceVariant[surface]}>{surfaceLabel(surface)}</Badge>
}

function ConsoleNavItem({
  item,
  active,
  badge,
  onSelect,
}: {
  item: (typeof navItems)[number]
  active: boolean
  badge?: number
  onSelect: (view: View) => void
}) {
  const { isMobile, setOpenMobile } = useSidebar()

  return (
    <SidebarMenuItem>
      <SidebarMenuButton
        type="button"
        tooltip={item.label}
        isActive={active}
        onClick={() => {
          onSelect(item.value)
          if (isMobile) {
            setOpenMobile(false)
          }
        }}
      >
        <item.icon />
        <span>{item.label}</span>
      </SidebarMenuButton>
      {badge ? <SidebarMenuBadge>{badge}</SidebarMenuBadge> : null}
    </SidebarMenuItem>
  )
}

const chartConfig = {
  input: { label: "Input", color: "var(--chart-1)" },
  runtime: { label: "Runtime", color: "var(--chart-2)" },
  resource: { label: "Resource", color: "var(--chart-3)" },
} satisfies ChartConfig

const columns: ColumnDef<SecurityEvent>[] = [
  {
    accessorKey: "created_at",
    header: "Timestamp",
    cell: ({ row }) => (
      <span className="font-mono">
        {new Date(row.original.created_at).toLocaleTimeString("en-US", {
          hour12: false,
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          fractionalSecondDigits: 3,
        })}
      </span>
    ),
  },
  {
    accessorKey: "effect",
    header: "Effect",
    cell: ({ row }) => (
      <Badge variant={effectVariant[row.original.effect]}>
        {effectLabel(row.original.effect)}
      </Badge>
    ),
  },
  {
    accessorKey: "request_kind",
    header: "Request Kind",
    cell: ({ row }) => requestKindLabel(row.original.request_kind),
  },
  {
    accessorKey: "surface",
    header: "Surface",
    cell: ({ row }) => <SurfaceBadge surface={row.original.surface} />,
  },
  { accessorKey: "adapter_id", header: "Adapter ID" },
  { accessorKey: "session_id", header: "Session ID" },
  { accessorKey: "task_id", header: "Task ID" },
  { accessorKey: "reason_code", header: "Reason Code" },
  {
    accessorKey: "redacted_summary",
    header: "Redacted Summary",
    cell: ({ row }) => (
      <span className="block max-w-[32rem] truncate">
        {row.original.redacted_summary}
      </span>
    ),
  },
]

function formatDate(value: string) {
  return new Date(value).toLocaleString("en-US", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  })
}

function eventMinute(event: SecurityEvent) {
  return event.created_at.slice(11, 16)
}

function App() {
  const queryClient = useQueryClient()
  const [view, setView] = React.useState<View>("events")
  const [config, setConfig] = React.useState<ConsoleConfig>(() => loadConfig())
  const [selectedId, setSelectedId] = React.useState<string>()
  const [selectedTimelineId, setSelectedTimelineId] = React.useState<string>()
  const [effectFilter, setEffectFilter] = React.useState("all")
  const [surfaceFilter, setSurfaceFilter] = React.useState("all")
  const [queryText, setQueryText] = React.useState("")
  const { data, error, isFetching, refetch } = useQuery({
    queryKey: ["agentgate-console", config.baseUrl || defaultConfig.baseUrl, config.operatorToken],
    queryFn: ({ signal }) =>
      fetchConsoleData(config.baseUrl || defaultConfig.baseUrl, signal),
    retry: 1,
  })
  const approvalMutation = useMutation({
    mutationFn: ({
      approvalId,
      decision,
    }: {
      approvalId: string
      decision: "allow_once" | "deny"
    }) =>
      resolveApproval(
        config.baseUrl || defaultConfig.baseUrl,
        approvalId,
        decision
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["agentgate-console"] })
    },
  })
  const events = data?.events ?? []
  const coverage = data?.coverage
  const approvals = data?.approvals ?? []
  const pendingApprovals = approvals.filter((approval) => approval.status === "pending")
  const histogram = data?.histogram ?? []

  React.useEffect(() => {
    if (!selectedId && events[0]) {
      setSelectedId(events[0].id)
    }
    if (!selectedTimelineId && events[0]) {
      setSelectedTimelineId(events[0].id)
    }
  }, [events, selectedId, selectedTimelineId])

  const filteredEvents = React.useMemo(() => {
    return events.filter((event) => {
      const effectMatches = effectFilter === "all" || event.effect === effectFilter
      const surfaceMatches =
        surfaceFilter === "all" || event.surface === surfaceFilter
      const text = queryText.trim().toLowerCase()
      const textMatches =
        text.length === 0 ||
        [
          event.adapter_id,
          event.session_id,
          event.task_id,
          event.reason_code,
          event.redacted_summary,
        ]
          .join(" ")
          .toLowerCase()
          .includes(text)

      return effectMatches && surfaceMatches && textMatches
    })
  }, [events, effectFilter, queryText, surfaceFilter])

  const selectedEvent =
    filteredEvents.find((event) => event.id === selectedId) ?? filteredEvents[0]
  const coveredSurfaces = coverage?.surfaces ?? {}
  const dataError = error instanceof Error ? error.message : undefined
  const configuredBaseUrl = config.baseUrl.trim() || defaultConfig.baseUrl
  const currentTitle =
    view === "events"
      ? "Security Events"
      : view === "timeline"
        ? "Timeline"
        : view === "approvals"
          ? "Approvals"
          : view === "policy"
            ? "Policy"
            : view === "integrations"
              ? "Integrations"
            : "Configuration"

  React.useEffect(() => {
    document.title = `AgentGate Console - ${currentTitle}`
  }, [currentTitle])

  return (
    <TooltipProvider>
      <SidebarProvider>
        <Sidebar collapsible="icon">
          <SidebarHeader>
            <div className="flex min-w-0 items-center gap-2 px-2 py-1.5">
              <ShieldCheck className="size-5 shrink-0" />
              <div className="min-w-0">
                <div className="truncate text-sm font-medium">AgentGate</div>
                <div className="truncate text-xs text-muted-foreground">
                  Live Control Plane
                </div>
              </div>
            </div>
          </SidebarHeader>
          <SidebarContent>
            <SidebarGroup>
              <SidebarGroupLabel>Console</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {navItems.map((item) => {
                    const badge =
                      item.value === "events"
                        ? events.length
                        : item.value === "approvals"
                          ? pendingApprovals.length
                          : item.badge

                    return (
                      <ConsoleNavItem
                        key={item.value}
                        item={item}
                        active={view === item.value}
                        badge={badge}
                        onSelect={setView}
                      />
                    )
                  })}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          </SidebarContent>
          <SidebarFooter className="group-data-[collapsible=icon]:hidden">
            <SidebarGroup>
              <SidebarGroupLabel>Surfaces</SidebarGroupLabel>
              <SidebarGroupContent className="space-y-2 px-2 text-xs">
                {(["input", "runtime", "resource"] as Surface[]).map((surface) => (
                  <div key={surface} className="flex items-center justify-between gap-2">
                    <Badge variant={surfaceVariant[surface]}>
                      {surfaceLabel(surface)}
                    </Badge>
                    <span className="text-muted-foreground">
                      {(coveredSurfaces[surface] ?? 0) > 0
                        ? "Covered"
                        : "Gap"}
                    </span>
                  </div>
                ))}
              </SidebarGroupContent>
            </SidebarGroup>
          </SidebarFooter>
        </Sidebar>
        <SidebarInset className="min-w-0">
          <div className="flex min-h-svh min-w-0 flex-col">
            <header className="sticky top-0 z-10 border-b bg-background/95 backdrop-blur">
              <div className="grid min-w-0 grid-cols-1 gap-3 px-4 py-3 xl:grid-cols-[minmax(18rem,1fr)_auto] xl:items-center">
                <div className="flex min-w-0 items-center gap-2">
                  <SidebarTrigger />
                  <Separator orientation="vertical" className="h-6" />
                  <div className="min-w-0">
                    <div className="flex min-w-0 items-center gap-2">
                      <h1 className="truncate text-base font-medium">
                        {currentTitle}
                      </h1>
                      <Badge variant={dataError ? "destructive" : "outline"}>
                        {dataError ? "API ERROR" : "LIVE API"}
                      </Badge>
                    </div>
                    <p className="truncate text-sm text-muted-foreground">
                      AgentGate Core · {configuredBaseUrl}
                    </p>
                  </div>
                </div>
                {view === "events" || view === "timeline" ? (
                  <Toolbar
                    queryText={queryText}
                    effectFilter={effectFilter}
                    surfaceFilter={surfaceFilter}
                    onQueryText={setQueryText}
                    onEffectFilter={setEffectFilter}
                    onSurfaceFilter={setSurfaceFilter}
                    onRefresh={() => void refetch()}
                    isRefreshing={isFetching}
                  />
                ) : (
                  <RefreshButton
                    onRefresh={() => void refetch()}
                    isRefreshing={isFetching}
                  />
                )}
              </div>
            </header>
            <main className="min-w-0 flex-1 p-4">
              <ApiStatus error={dataError} isFetching={isFetching} />
              {view === "events" ? (
                <EventsView
                  events={filteredEvents}
                  selectedEvent={selectedEvent}
                  selectedId={selectedId}
                  onSelectedId={setSelectedId}
                />
              ) : null}
              {view === "timeline" ? (
                <TimelineView
                  events={events}
                  histogram={histogram}
                  selectedTimelineId={selectedTimelineId}
                  onSelectedTimelineId={setSelectedTimelineId}
                />
              ) : null}
              {view === "approvals" ? (
                <ApprovalsView
                  approvals={approvals}
                  error={
                    approvalMutation.error instanceof Error
                      ? approvalMutation.error.message
                      : undefined
                  }
                  pendingApprovalId={
                    approvalMutation.isPending
                      ? approvalMutation.variables?.approvalId
                      : undefined
                  }
                  onAllowOnce={(approvalId) =>
                    approvalMutation.mutate({ approvalId, decision: "allow_once" })
                  }
                  onDeny={(approvalId) =>
                    approvalMutation.mutate({ approvalId, decision: "deny" })
                  }
                />
              ) : null}
              {view === "policy" ? (
                <PolicyView config={config} />
              ) : null}
              {view === "integrations" ? (
                <IntegrationsView config={config} coverage={coverage} />
              ) : null}
              {view === "settings" ? (
                <SettingsView
                  config={config}
                  onConfig={(nextConfig) => {
                    saveConfig(nextConfig)
                    setConfig(nextConfig)
                  }}
                />
              ) : null}
            </main>
          </div>
        </SidebarInset>
      </SidebarProvider>
    </TooltipProvider>
  )
}

function Toolbar({
  queryText,
  effectFilter,
  surfaceFilter,
  onQueryText,
  onEffectFilter,
  onSurfaceFilter,
  onRefresh,
  isRefreshing,
}: {
  queryText: string
  effectFilter: string
  surfaceFilter: string
  onQueryText: (value: string) => void
  onEffectFilter: (value: string) => void
  onSurfaceFilter: (value: string) => void
  onRefresh: () => void
  isRefreshing: boolean
}) {
  return (
    <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-center sm:justify-end">
      <Input
        className="sm:w-80 xl:w-[28rem]"
        value={queryText}
        onChange={(event) => onQueryText(event.target.value)}
        placeholder="session, adapter, reason, summary"
      />
      <Select value={surfaceFilter} onValueChange={onSurfaceFilter}>
        <SelectTrigger className="sm:w-40">
          <SelectValue placeholder="Surface" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All Surfaces</SelectItem>
          <SelectItem value="input">{surfaceLabels.input}</SelectItem>
          <SelectItem value="runtime">{surfaceLabels.runtime}</SelectItem>
          <SelectItem value="resource">{surfaceLabels.resource}</SelectItem>
        </SelectContent>
      </Select>
      <Select value={effectFilter} onValueChange={onEffectFilter}>
        <SelectTrigger className="sm:w-40">
          <SelectValue placeholder="Effect" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All Effects</SelectItem>
          <SelectItem value="allow">{effectLabel("allow")}</SelectItem>
          <SelectItem value="allow_with_audit">
            {effectLabel("allow_with_audit")}
          </SelectItem>
          <SelectItem value="deny">{effectLabel("deny")}</SelectItem>
          <SelectItem value="approval_required">
            {effectLabel("approval_required")}
          </SelectItem>
          <SelectItem value="exclusion">{effectLabel("exclusion")}</SelectItem>
        </SelectContent>
      </Select>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="outline"
            size="icon"
            aria-label="Refresh"
            onClick={onRefresh}
          >
            <RefreshCw className={isRefreshing ? "animate-spin" : undefined} />
          </Button>
        </TooltipTrigger>
        <TooltipContent>Refresh</TooltipContent>
      </Tooltip>
    </div>
  )
}

function RefreshButton({
  onRefresh,
  isRefreshing,
}: {
  onRefresh: () => void
  isRefreshing: boolean
}) {
  return (
    <div className="flex justify-end">
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="outline"
            size="icon"
            aria-label="Refresh"
            onClick={onRefresh}
          >
            <RefreshCw className={isRefreshing ? "animate-spin" : undefined} />
          </Button>
        </TooltipTrigger>
        <TooltipContent>Refresh</TooltipContent>
      </Tooltip>
    </div>
  )
}

function ApiStatus({
  error,
  isFetching,
}: {
  error?: string
  isFetching: boolean
}) {
  if (!error && !isFetching) {
    return null
  }

  return (
    <Card className="mb-4 min-w-0">
      <CardContent className="flex min-w-0 flex-wrap items-center gap-2 py-3 text-sm">
        <Badge variant={error ? "destructive" : "outline"}>
          {error ? "Connection" : "Loading"}
        </Badge>
        <span className="min-w-0 break-words text-muted-foreground">
          {error ?? "Refreshing…"}
        </span>
      </CardContent>
    </Card>
  )
}

function EventsView({
  events,
  selectedEvent,
  selectedId,
  onSelectedId,
}: {
  events: SecurityEvent[]
  selectedEvent?: SecurityEvent
  selectedId?: string
  onSelectedId: (id: string) => void
}) {
  return (
    <div className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,1fr)_24rem]">
      <EventTable
        events={events}
        selectedId={selectedId}
        onSelectedId={onSelectedId}
      />
      <EventDetail event={selectedEvent} />
    </div>
  )
}

function EventTable({
  events,
  selectedId,
  onSelectedId,
}: {
  events: SecurityEvent[]
  selectedId?: string
  onSelectedId: (id: string) => void
}) {
  const [sorting, setSorting] = React.useState<SortingState>([])
  const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>([])
  const [columnVisibility, setColumnVisibility] = React.useState<VisibilityState>({})
  const table = useReactTable({
    data: events,
    columns,
    state: { sorting, columnFilters, columnVisibility },
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    onColumnVisibilityChange: setColumnVisibility,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getSortedRowModel: getSortedRowModel(),
    initialState: { pagination: { pageSize: 6 } },
  })

  return (
    <Card className="min-w-0">
      <CardHeader className="border-b">
        <CardTitle>Events</CardTitle>
        <CardDescription>{events.length} matching events</CardDescription>
        <CardAction>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm">
                <Columns3 />
                Columns
                <ChevronDown />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>Visible columns</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {table
                .getAllColumns()
                .filter((column) => column.getCanHide())
                .map((column) => (
                  <DropdownMenuCheckboxItem
                    key={column.id}
                    checked={column.getIsVisible()}
                    onCheckedChange={(value) => column.toggleVisibility(!!value)}
                  >
                    {typeof column.columnDef.header === "string"
                      ? column.columnDef.header
                      : column.id}
                  </DropdownMenuCheckboxItem>
                ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </CardAction>
      </CardHeader>
      <CardContent className="min-w-0 p-0">
        <Table>
          <TableHeader className="sticky top-0 z-[1] bg-background">
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id}>
                {headerGroup.headers.map((header) => (
                  <TableHead key={header.id}>
                    {header.isPlaceholder
                      ? null
                      : flexRender(header.column.columnDef.header, header.getContext())}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {table.getRowModel().rows.length ? (
              table.getRowModel().rows.map((row) => (
                <TableRow
                  key={row.id}
                  data-state={selectedId === row.original.id ? "selected" : undefined}
                  onClick={() => onSelectedId(row.original.id)}
                >
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell colSpan={columns.length} className="h-24 text-center">
                  No events match the current filters.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </CardContent>
      <div className="border-t px-4 py-3">
        <Pagination>
          <PaginationContent>
            <PaginationItem>
              <PaginationPrevious
                href="#previous"
                text="Previous"
                onClick={(event) => {
                  event.preventDefault()
                  table.previousPage()
                }}
                aria-disabled={!table.getCanPreviousPage()}
              />
            </PaginationItem>
            <PaginationItem>
              <Badge variant="outline">
                Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount()}
              </Badge>
            </PaginationItem>
            <PaginationItem>
              <PaginationNext
                href="#next"
                text="Next"
                onClick={(event) => {
                  event.preventDefault()
                  table.nextPage()
                }}
                aria-disabled={!table.getCanNextPage()}
              />
            </PaginationItem>
          </PaginationContent>
        </Pagination>
      </div>
    </Card>
  )
}

function EventDetail({ event }: { event?: SecurityEvent }) {
  if (!event) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Event Detail</CardTitle>
          <CardDescription>No selected event</CardDescription>
        </CardHeader>
      </Card>
    )
  }

  return (
    <Card className="min-w-0 xl:sticky xl:top-24 xl:self-start">
      <CardHeader className="border-b">
        <CardTitle>Event Detail</CardTitle>
        <CardDescription>{event.decision_id}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-2">
          <Badge variant={effectVariant[event.effect]}>
            {effectLabel(event.effect)}
          </Badge>
          <SurfaceBadge surface={event.surface} />
          <Badge variant="outline">{requestKindLabel(event.request_kind)}</Badge>
        </div>
        <DetailGrid
          rows={[
            ["Timestamp", formatDate(event.created_at)],
            ["Adapter ID", event.adapter_id],
            ["Session ID", event.session_id],
            ["Task ID", event.task_id],
            ["Attempt ID", event.attempt_id ?? "None"],
            ["Approval ID", event.approval_id ?? "None"],
            ["Reason Code", event.reason_code],
            ["Latency (ms)", event.latency_ms ? `${event.latency_ms}` : "Unknown"],
            ["Policy Version", event.policy_version ?? "Unknown"],
            ["Policy Status", event.policy_status ?? "Unknown"],
            ["Matched Rule", event.selected_rule ?? "None"],
          ]}
        />
        <Separator />
        <EvidenceSection title="Redacted Evidence" items={[event.redacted_summary]} />
        <EvidenceSection title="Matched Rules" items={event.matched_rules} />
        <EvidenceSection title="Applied Rules" items={event.applied_rules} />
        <EvidenceSection title="Obligations" items={event.obligations} />
        <EvidenceSection title="Redacted Metadata" items={event.metadata} />
        <EvidenceSection title="Findings / Taints / Data Classes" items={[...event.findings, ...event.taints, ...event.data_classes]} />
      </CardContent>
    </Card>
  )
}

function DetailGrid({ rows }: { rows: Array<[string, string]> }) {
  return (
    <div className="grid gap-2 text-sm">
      {rows.map(([label, value]) => (
        <div key={label} className="grid min-w-0 grid-cols-[8rem_minmax(0,1fr)] gap-2">
          <div className="text-muted-foreground">{label}</div>
          <div className="min-w-0 break-words font-mono text-xs">{value}</div>
        </div>
      ))}
    </div>
  )
}

function EvidenceSection({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="min-w-0 space-y-2">
      <div className="text-xs font-medium text-muted-foreground">{title}</div>
      <div className="flex min-w-0 flex-wrap gap-2">
        {items.length ? (
          items.map((item) => (
            <Badge key={item} variant="outline" className="h-auto max-w-full justify-start whitespace-normal">
              {item}
            </Badge>
          ))
        ) : (
          <Badge variant="secondary">None</Badge>
        )}
      </div>
    </div>
  )
}

function EmptyCard({
  title,
  description,
}: {
  title: string
  description: string
}) {
  return (
    <Card className="min-w-0">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
    </Card>
  )
}

function TimelineView({
  events,
  histogram,
  selectedTimelineId,
  onSelectedTimelineId,
}: {
  events: SecurityEvent[]
  histogram: HistogramBucket[]
  selectedTimelineId?: string
  onSelectedTimelineId: (id: string) => void
}) {
  const [selectedMinute, setSelectedMinute] = React.useState<string>("all")
  const [expandedIds, setExpandedIds] = React.useState<string[]>([])
  const selectedTimelineEvent =
    events.find((event) => event.id === selectedTimelineId) ?? events[0]
  if (!selectedTimelineEvent) {
    return <EmptyCard title="Time Flow" description="No events recorded by AgentGate yet." />
  }

  const sessionIds = Array.from(new Set(events.map((event) => event.session_id)))
  const sessionEvents = events.filter(
    (event) => event.session_id === selectedTimelineEvent.session_id
  )
  const timelineBuckets = histogram.map((bucket) => {
    const bucketEvents = sessionEvents.filter(
      (event) => eventMinute(event) === bucket.minute
    )

    return {
      minute: bucket.minute,
      input: bucketEvents.filter((event) => event.surface === "input").length,
      runtime: bucketEvents.filter((event) => event.surface === "runtime").length,
      resource: bucketEvents.filter((event) => event.surface === "resource").length,
    }
  })
  const visibleSessionEvents =
    selectedMinute === "all"
      ? sessionEvents
      : sessionEvents.filter((event) => eventMinute(event) === selectedMinute)
  const selectSession = (sessionId: string) => {
    const nextEvent = events.find((event) => event.session_id === sessionId)
    if (nextEvent) {
      onSelectedTimelineId(nextEvent.id)
      setSelectedMinute("all")
    }
  }
  const setExpanded = (eventId: string, open: boolean) => {
    setExpandedIds((current) =>
      open
        ? Array.from(new Set([...current, eventId]))
        : current.filter((id) => id !== eventId)
    )
  }

  return (
    <div className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,1fr)_24rem]">
      <div className="min-w-0 space-y-4">
        <Card className="min-w-0">
          <CardHeader className="border-b">
            <CardTitle>Time Flow</CardTitle>
            <CardDescription>
              {selectedTimelineEvent.session_id} / {selectedTimelineEvent.task_id}
              {selectedMinute === "all" ? "" : ` / ${selectedMinute}`}
            </CardDescription>
            <CardAction>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setSelectedMinute("all")}
                >
                  All Minutes
                </Button>
                <Select
                  value={selectedTimelineEvent.session_id}
                  onValueChange={selectSession}
                >
                  <SelectTrigger className="w-48">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {sessionIds.map((sessionId) => (
                      <SelectItem key={sessionId} value={sessionId}>
                        {sessionId}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </CardAction>
          </CardHeader>
          <CardContent>
            <ChartContainer config={chartConfig} className="h-[220px] w-full">
              <BarChart
                accessibilityLayer
                data={timelineBuckets}
                onClick={(state) => {
                  if (typeof state?.activeLabel === "string") {
                    setSelectedMinute(state.activeLabel)
                  }
                }}
              >
                <CartesianGrid vertical={false} />
                <XAxis
                  dataKey="minute"
                  tickLine={false}
                  tickMargin={10}
                  axisLine={false}
                />
                <ChartTooltip content={<ChartTooltipContent />} />
                {selectedMinute !== "all" ? (
                  <ReferenceLine x={selectedMinute} stroke="var(--ring)" />
                ) : null}
                <Bar dataKey="input" stackId="events" fill="var(--color-input)" radius={[2, 2, 0, 0]} />
                <Bar dataKey="runtime" stackId="events" fill="var(--color-runtime)" radius={[2, 2, 0, 0]} />
                <Bar dataKey="resource" stackId="events" fill="var(--color-resource)" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ChartContainer>
          </CardContent>
        </Card>
        <Card className="min-w-0">
          <CardHeader className="border-b">
            <CardTitle>Event Volume</CardTitle>
            <CardDescription>
              {selectedMinute === "all"
                ? "All minute buckets"
                : `Minute bucket ${selectedMinute}`}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {visibleSessionEvents.length ? (
                visibleSessionEvents.map((event) => {
                  const open = expandedIds.includes(event.id)

                  return (
                    <Collapsible
                      key={event.id}
                      open={open}
                      onOpenChange={(nextOpen) => setExpanded(event.id, nextOpen)}
                    >
                      <div className="flex min-w-0 items-center gap-2 rounded-lg border bg-background p-2">
                        <Button
                          type="button"
                          variant={
                            selectedTimelineEvent.id === event.id
                              ? "secondary"
                              : "ghost"
                          }
                          className="h-auto min-w-0 flex-1 justify-start gap-2 whitespace-normal px-2 py-1.5"
                          onClick={() => onSelectedTimelineId(event.id)}
                        >
                          <SurfaceBadge surface={event.surface} />
                          <span className="font-mono text-xs">{event.decision_id}</span>
                          <span className="min-w-0 truncate text-muted-foreground">
                            {event.reason_code}
                          </span>
                        </Button>
                        <CollapsibleTrigger asChild>
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            aria-label={
                              open
                                ? `Collapse ${event.decision_id}`
                                : `Expand ${event.decision_id}`
                            }
                          >
                            <ChevronDown
                              className={
                                open
                                  ? "transition-transform rotate-180"
                                  : "transition-transform"
                              }
                            />
                          </Button>
                        </CollapsibleTrigger>
                      </div>
                      <CollapsibleContent className="px-3 py-3">
                        <DetailGrid
                          rows={[
                            ["Timestamp", formatDate(event.created_at)],
                            ["Span Kind", `${requestKindLabel(event.request_kind)} + ${surfaceLabel(event.surface)}`],
                            ["Duration", `${event.latency_ms}ms`],
                            ["Summary", event.redacted_summary],
                          ]}
                        />
                      </CollapsibleContent>
                    </Collapsible>
                  )
                })
              ) : (
                <Card size="sm">
                  <CardContent>
                    <div className="text-sm text-muted-foreground">
                      No spans in this minute bucket.
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
      <TimelineSpanDetail event={selectedTimelineEvent} />
    </div>
  )
}

function TimelineSpanDetail({ event }: { event: SecurityEvent }) {
  return (
    <Card className="min-w-0 xl:sticky xl:top-24 xl:self-start">
      <CardHeader className="border-b">
        <CardTitle>Selected Span</CardTitle>
        <CardDescription>
          {event.session_id} / {event.task_id}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-2">
          <SurfaceBadge surface={event.surface} />
          <Badge variant="outline">{requestKindLabel(event.request_kind)}</Badge>
          <Badge variant={effectVariant[event.effect]}>
            {effectLabel(event.effect)}
          </Badge>
        </div>
        <DetailGrid
          rows={[
            ["Trace ID", event.session_id],
            ["Task Trace", event.task_id],
            ["Span ID", event.attempt_id ?? event.approval_id ?? event.decision_id],
            ["Span Kind", `${requestKindLabel(event.request_kind)} + ${surfaceLabel(event.surface)}`],
            ["Decision ID", event.decision_id],
            ["Duration", `${event.latency_ms}ms`],
            ["Reason Code", event.reason_code],
            ["Matched Rule", event.selected_rule ?? "None"],
            ["Timestamp", formatDate(event.created_at)],
          ]}
        />
        <Separator />
        <EvidenceSection title="Redacted Evidence" items={[event.redacted_summary]} />
        <EvidenceSection title="Matched Rules" items={event.matched_rules} />
        <EvidenceSection title="Obligations" items={event.obligations} />
        <EvidenceSection title="Applied Rules" items={event.applied_rules} />
        <EvidenceSection title="Redacted Metadata" items={event.metadata} />
      </CardContent>
    </Card>
  )
}

function ApprovalsView({
  approvals,
  error,
  pendingApprovalId,
  onAllowOnce,
  onDeny,
}: {
  approvals: Approval[]
  error?: string
  pendingApprovalId?: string
  onAllowOnce: (approvalId: string) => void
  onDeny: (approvalId: string) => void
}) {
  return (
    <Card className="min-w-0">
      <CardHeader className="border-b">
        <CardTitle>Approvals</CardTitle>
        <CardDescription>
          Pending rows are paused attempts. Allow Once applies only to the current attempt.
        </CardDescription>
      </CardHeader>
      {error ? (
        <CardContent className="border-b py-3">
          <div className="flex min-w-0 items-center gap-2 text-sm">
            <Badge variant="destructive">Resolution Failed</Badge>
            <span className="min-w-0 break-words text-muted-foreground">{error}</span>
          </div>
        </CardContent>
      ) : null}
      <CardContent className="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Approval ID</TableHead>
              <TableHead>Timestamp</TableHead>
              <TableHead>Session ID</TableHead>
              <TableHead>Task ID</TableHead>
              <TableHead>Attempt ID</TableHead>
              <TableHead>Scope</TableHead>
              <TableHead>Operator ID</TableHead>
              <TableHead>Reason</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Expires In</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {approvals.length ? (
              approvals.map((approval) => {
                const pending = approval.status === "pending"
                const busy = pendingApprovalId === approval.approval_id

                return (
                  <TableRow key={approval.approval_id}>
                    <TableCell className="font-mono">{approval.approval_id}</TableCell>
                    <TableCell>{formatDate(approval.created_at)}</TableCell>
                    <TableCell className="font-mono">{approval.session_id}</TableCell>
                    <TableCell className="font-mono">{approval.task_id}</TableCell>
                    <TableCell className="font-mono">{approval.attempt_id}</TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        {approval.scope === "attempt" ? "This Attempt" : statusLabel(approval.scope)}
                      </Badge>
                    </TableCell>
                    <TableCell>{approval.operator_id}</TableCell>
                    <TableCell>
                      <span className="block max-w-[32rem] truncate">
                        {approval.reason}
                      </span>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          approval.status === "denied"
                            ? "destructive"
                            : approval.status === "approved"
                              ? "secondary"
                              : "outline"
                        }
                      >
                        {statusLabel(approval.status)}
                      </Badge>
                    </TableCell>
                    <TableCell>{approval.expires_in}</TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-2">
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              type="button"
                              size="icon"
                              variant="outline"
                              disabled={!pending || busy}
                              aria-label={`Allow Once · ${approval.approval_id}`}
                              onClick={() => onAllowOnce(approval.approval_id)}
                            >
                              <Check />
                              <span className="sr-only">
                                Allow Once for {approval.approval_id}
                              </span>
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>Allow this attempt only</TooltipContent>
                        </Tooltip>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              type="button"
                              size="icon"
                              variant="outline"
                              disabled={!pending || busy}
                              aria-label={`Deny · ${approval.approval_id}`}
                              onClick={() => onDeny(approval.approval_id)}
                            >
                              <X />
                              <span className="sr-only">
                                Deny {approval.approval_id}
                              </span>
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>Deny and keep attempt blocked</TooltipContent>
                        </Tooltip>
                      </div>
                    </TableCell>
                  </TableRow>
                )
              })
            ) : (
              <TableRow>
                <TableCell colSpan={10} className="h-24 text-center">
                  No pending approvals.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

function SettingsView({
  config,
  onConfig,
}: {
  config: ConsoleConfig
  onConfig: (config: ConsoleConfig) => void
}) {
  const [draft, setDraft] = React.useState(config)

  React.useEffect(() => {
    setDraft(config)
  }, [config])

  const updateDraft = (key: keyof ConsoleConfig, value: string) => {
    setDraft((current) => ({ ...current, [key]: value }))
  }

  return (
    <div className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,1fr)_24rem]">
      <Card className="min-w-0">
        <CardHeader className="border-b">
          <CardTitle>AgentGate Connection</CardTitle>
          <CardDescription>Stored in this browser only.</CardDescription>
          <CardAction>
            <Button
              type="button"
              size="sm"
              onClick={() => onConfig({ ...draft, baseUrl: draft.baseUrl.trim() })}
            >
              <Save />
              Save
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent className="grid gap-4">
          <Field
            label="AgentGate Base URL"
            value={draft.baseUrl}
            placeholder={defaultConfig.baseUrl}
            onChange={(value) => updateDraft("baseUrl", value)}
          />
          <Field
            label="Operator Token"
            value={draft.operatorToken}
            placeholder="operator-local-token"
            onChange={(value) => updateDraft("operatorToken", value)}
            type="password"
          />
          <Field
            label="Admin Token"
            value={draft.adminToken}
            placeholder="admin-local-token"
            onChange={(value) => updateDraft("adminToken", value)}
            type="password"
          />
        </CardContent>
      </Card>
      <Card className="min-w-0 xl:sticky xl:top-24 xl:self-start">
        <CardHeader className="border-b">
          <CardTitle>Connection Status</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <DetailGrid
            rows={[
              ["Base URL", draft.baseUrl || defaultConfig.baseUrl],
              ["Operator Token", draft.operatorToken ? "Configured" : "Not Set"],
              ["Admin Token", draft.adminToken ? "Configured" : "Not Set"],
            ]}
          />
        </CardContent>
      </Card>
    </div>
  )
}

function Field({
  label,
  value,
  placeholder,
  onChange,
  type = "text",
}: {
  label: string
  value: string
  placeholder: string
  onChange: (value: string) => void
  type?: string
}) {
  return (
    <label className="grid min-w-0 gap-2">
      <span className="text-sm font-medium">{label}</span>
      <Input
        type={type}
        value={value}
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
      />
    </label>
  )
}

export default App
