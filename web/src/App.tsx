import * as React from "react"
import { useQuery } from "@tanstack/react-query"
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
  Columns3,
  Gauge,
  KeyRound,
  ListFilter,
  RefreshCw,
  ShieldCheck,
  Split,
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
  approvals,
  coverage,
  events,
  histogram,
  type Effect,
  type SecurityEvent,
  type Surface,
} from "@/mock-data"

type View = "events" | "timeline" | "coverage" | "approvals"

const navItems: Array<{
  value: View
  label: string
  icon: React.ComponentType<{ className?: string }>
  badge?: number
}> = [
  { value: "events", label: "Events", icon: ListFilter, badge: events.length },
  { value: "timeline", label: "Timeline", icon: Split },
  { value: "coverage", label: "Coverage", icon: Gauge },
  { value: "approvals", label: "Approvals", icon: KeyRound, badge: approvals.length },
]

const effectVariant: Record<Effect, "default" | "secondary" | "destructive" | "outline"> = {
  allow_with_audit: "secondary",
  deny: "destructive",
  approval_required: "outline",
  rewrite: "default",
}

const surfaceVariant: Record<Surface, "default" | "secondary" | "outline"> = {
  input: "secondary",
  runtime: "outline",
  resource: "default",
}

const chartConfig = {
  input: { label: "input", color: "var(--chart-1)" },
  runtime: { label: "runtime", color: "var(--chart-2)" },
  resource: { label: "resource", color: "var(--chart-3)" },
} satisfies ChartConfig

const columns: ColumnDef<SecurityEvent>[] = [
  {
    accessorKey: "created_at",
    header: "created_at",
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
    header: "effect",
    cell: ({ row }) => (
      <Badge variant={effectVariant[row.original.effect]}>{row.original.effect}</Badge>
    ),
  },
  { accessorKey: "request_kind", header: "request_kind" },
  {
    accessorKey: "surface",
    header: "surface",
    cell: ({ row }) => (
      <Badge variant={surfaceVariant[row.original.surface]}>{row.original.surface}</Badge>
    ),
  },
  { accessorKey: "adapter_id", header: "adapter_id" },
  { accessorKey: "session_id", header: "session_id" },
  { accessorKey: "task_id", header: "task_id" },
  { accessorKey: "reason_code", header: "reason_code" },
  {
    accessorKey: "redacted_summary",
    header: "redacted_summary",
    cell: ({ row }) => (
      <span className="block max-w-[32rem] truncate">
        {row.original.redacted_summary}
      </span>
    ),
  },
]

function queryMock() {
  return Promise.resolve({ events, coverage, approvals, histogram })
}

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
  const [view, setView] = React.useState<View>("events")
  const [selectedId, setSelectedId] = React.useState(events[0]?.id)
  const [selectedTimelineId, setSelectedTimelineId] = React.useState(events[0]?.id)
  const [effectFilter, setEffectFilter] = React.useState("all")
  const [surfaceFilter, setSurfaceFilter] = React.useState("all")
  const [queryText, setQueryText] = React.useState("")
  const { data } = useQuery({
    queryKey: ["agentgate-console-mock"],
    queryFn: queryMock,
    initialData: { events, coverage, approvals, histogram },
  })

  const filteredEvents = React.useMemo(() => {
    return data.events.filter((event) => {
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
  }, [data.events, effectFilter, queryText, surfaceFilter])

  const selectedEvent =
    filteredEvents.find((event) => event.id === selectedId) ?? filteredEvents[0]

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
                  shadcn/ui mock
                </div>
              </div>
            </div>
          </SidebarHeader>
          <SidebarContent>
            <SidebarGroup>
              <SidebarGroupLabel>Console</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {navItems.map((item) => (
                    <SidebarMenuItem key={item.value}>
                      <SidebarMenuButton
                        type="button"
                        tooltip={item.label}
                        isActive={view === item.value}
                        onClick={() => setView(item.value)}
                      >
                        <item.icon />
                        <span>{item.label}</span>
                      </SidebarMenuButton>
                      {item.badge ? (
                        <SidebarMenuBadge>{item.badge}</SidebarMenuBadge>
                      ) : null}
                    </SidebarMenuItem>
                  ))}
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
                    <Badge variant={surfaceVariant[surface]}>{surface}</Badge>
                    <span className="text-muted-foreground">
                      {coverage.some((adapter) => adapter.surfaces.includes(surface))
                        ? "covered"
                        : "gap"}
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
                        Security events
                      </h1>
                      <Badge variant="outline">MOCK DATA</Badge>
                    </div>
                    <p className="truncate text-sm text-muted-foreground">
                      Dense event log, timeline, coverage, and approvals over mock AgentGate data.
                    </p>
                  </div>
                </div>
                <Toolbar
                  queryText={queryText}
                  effectFilter={effectFilter}
                  surfaceFilter={surfaceFilter}
                  onQueryText={setQueryText}
                  onEffectFilter={setEffectFilter}
                  onSurfaceFilter={setSurfaceFilter}
                />
              </div>
            </header>
            <main className="min-w-0 flex-1 p-4">
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
                  selectedTimelineId={selectedTimelineId}
                  onSelectedTimelineId={setSelectedTimelineId}
                />
              ) : null}
              {view === "coverage" ? <CoverageView /> : null}
              {view === "approvals" ? <ApprovalsView /> : null}
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
}: {
  queryText: string
  effectFilter: string
  surfaceFilter: string
  onQueryText: (value: string) => void
  onEffectFilter: (value: string) => void
  onSurfaceFilter: (value: string) => void
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
          <SelectValue placeholder="surface" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All surfaces</SelectItem>
          <SelectItem value="input">input</SelectItem>
          <SelectItem value="runtime">runtime</SelectItem>
          <SelectItem value="resource">resource</SelectItem>
        </SelectContent>
      </Select>
      <Select value={effectFilter} onValueChange={onEffectFilter}>
        <SelectTrigger className="sm:w-40">
          <SelectValue placeholder="effect" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All effects</SelectItem>
          <SelectItem value="allow_with_audit">allow_with_audit</SelectItem>
          <SelectItem value="deny">deny</SelectItem>
          <SelectItem value="approval_required">approval_required</SelectItem>
          <SelectItem value="rewrite">rewrite</SelectItem>
        </SelectContent>
      </Select>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button variant="outline" size="icon" aria-label="Refresh mock data">
            <RefreshCw />
          </Button>
        </TooltipTrigger>
        <TooltipContent>Refresh mock data</TooltipContent>
      </Tooltip>
    </div>
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
        <CardDescription>{events.length} matching security events</CardDescription>
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
                    {column.id}
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
                  No events.
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
          <CardTitle>Detail</CardTitle>
          <CardDescription>No selected event</CardDescription>
        </CardHeader>
      </Card>
    )
  }

  return (
    <Card className="min-w-0 xl:sticky xl:top-24 xl:self-start">
      <CardHeader className="border-b">
        <CardTitle>Selected event</CardTitle>
        <CardDescription>{event.decision_id}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-2">
          <Badge variant={effectVariant[event.effect]}>{event.effect}</Badge>
          <Badge variant={surfaceVariant[event.surface]}>{event.surface}</Badge>
          <Badge variant="outline">{event.request_kind}</Badge>
        </div>
        <DetailGrid
          rows={[
            ["created_at", formatDate(event.created_at)],
            ["adapter_id", event.adapter_id],
            ["session_id", event.session_id],
            ["task_id", event.task_id],
            ["attempt_id", event.attempt_id ?? "none"],
            ["approval_id", event.approval_id ?? "none"],
            ["reason_code", event.reason_code],
            ["latency_ms", `${event.latency_ms}`],
            ["policy_version", event.policy_version],
          ]}
        />
        <Separator />
        <EvidenceSection title="redacted evidence" items={[event.redacted_summary]} />
        <EvidenceSection title="applied_rules" items={event.applied_rules} />
        <EvidenceSection title="obligations" items={event.obligations} />
        <EvidenceSection title="findings / taints / data_classes" items={[...event.findings, ...event.taints, ...event.data_classes]} />
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
          <Badge variant="secondary">none</Badge>
        )}
      </div>
    </div>
  )
}

function TimelineView({
  selectedTimelineId,
  onSelectedTimelineId,
}: {
  selectedTimelineId?: string
  onSelectedTimelineId: (id: string) => void
}) {
  const [selectedMinute, setSelectedMinute] = React.useState<string>("all")
  const [expandedIds, setExpandedIds] = React.useState<string[]>([])
  const selectedTimelineEvent =
    events.find((event) => event.id === selectedTimelineId) ?? events[0]
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
            <CardTitle>Time flow</CardTitle>
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
                  All minutes
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
            <CardTitle>Session event tree</CardTitle>
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
                          <Badge variant={surfaceVariant[event.surface]}>
                            {event.surface}
                          </Badge>
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
                            ["created_at", formatDate(event.created_at)],
                            ["span_kind", `${event.request_kind} + ${event.surface}`],
                            ["duration", `${event.latency_ms}ms`],
                            ["summary", event.redacted_summary],
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
        <CardTitle>Selected span</CardTitle>
        <CardDescription>
          {event.session_id} / {event.task_id}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-2">
          <Badge variant={surfaceVariant[event.surface]}>{event.surface}</Badge>
          <Badge variant="outline">{event.request_kind}</Badge>
          <Badge variant={effectVariant[event.effect]}>{event.effect}</Badge>
        </div>
        <DetailGrid
          rows={[
            ["trace_id", event.session_id],
            ["task_trace", event.task_id],
            ["span_id", event.attempt_id ?? event.approval_id ?? event.decision_id],
            ["span_kind", `${event.request_kind} + ${event.surface}`],
            ["decision_id", event.decision_id],
            ["duration", `${event.latency_ms}ms`],
            ["reason_code", event.reason_code],
            ["created_at", formatDate(event.created_at)],
          ]}
        />
        <Separator />
        <EvidenceSection title="redacted evidence" items={[event.redacted_summary]} />
        <EvidenceSection title="obligations" items={event.obligations} />
        <EvidenceSection title="applied_rules" items={event.applied_rules} />
      </CardContent>
    </Card>
  )
}

function CoverageView() {
  return (
    <div className="grid min-w-0 gap-4 lg:grid-cols-2">
      {coverage.map((adapter) => (
        <Card key={adapter.adapter_id} className="min-w-0">
          <CardHeader className="border-b">
            <CardTitle>{adapter.adapter_id}</CardTitle>
            <CardDescription>
              {adapter.host} / {adapter.version}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <EvidenceSection title="surfaces" items={adapter.surfaces} />
            <EvidenceSection
              title="supporting_channels"
              items={adapter.supporting_channels}
            />
            <EvidenceSection title="capabilities" items={adapter.capabilities} />
            <DetailGrid rows={[["last_seen", formatDate(adapter.last_seen)]]} />
            <EvidenceSection title="coverage warnings" items={adapter.warnings} />
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

function ApprovalsView() {
  return (
    <Card className="min-w-0">
      <CardHeader className="border-b">
        <CardTitle>Pending approvals</CardTitle>
        <CardDescription>
          Operator transport state only; decisions stay in AgentGate Core.
        </CardDescription>
      </CardHeader>
      <CardContent className="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>approval_id</TableHead>
              <TableHead>created_at</TableHead>
              <TableHead>session_id</TableHead>
              <TableHead>task_id</TableHead>
              <TableHead>attempt_id</TableHead>
              <TableHead>operator_id</TableHead>
              <TableHead>reason</TableHead>
              <TableHead>status</TableHead>
              <TableHead>expires_in</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {approvals.map((approval) => (
              <TableRow key={approval.approval_id}>
                <TableCell className="font-mono">{approval.approval_id}</TableCell>
                <TableCell>{formatDate(approval.created_at)}</TableCell>
                <TableCell className="font-mono">{approval.session_id}</TableCell>
                <TableCell className="font-mono">{approval.task_id}</TableCell>
                <TableCell className="font-mono">{approval.attempt_id}</TableCell>
                <TableCell>{approval.operator_id}</TableCell>
                <TableCell>
                  <span className="block max-w-[32rem] truncate">
                    {approval.reason}
                  </span>
                </TableCell>
                <TableCell>
                  <Badge variant="outline">{approval.status}</Badge>
                </TableCell>
                <TableCell>{approval.expires_in}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

export default App
