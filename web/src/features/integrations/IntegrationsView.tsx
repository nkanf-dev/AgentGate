import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ChevronRight, Plus, Trash2 } from "lucide-react"

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
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  createIntegrationDefinition,
  deleteIntegrationDefinition,
  integrationDefinitions,
  updateIntegrationDefinition,
  type ConsoleConfig,
  type CoverageResponse,
  type IntegrationDefinition,
  type IntegrationDefinitionInput,
  type IntegrationHealthStatus,
  type Surface,
} from "@/lib/agentgate-api"
import {
  integrationHealthLabels,
  statusLabel,
  surfaceLabel,
} from "@/lib/display-labels"

type IntegrationPage = "list" | "detail" | "edit" | "new"

const integrationKindOptions = ["adapter", "transport", "resource_provider"]

const healthVariant: Record<
  IntegrationHealthStatus,
  "default" | "secondary" | "destructive" | "outline"
> = {
  connected: "secondary",
  stale: "outline",
  missing: "destructive",
  unmanaged: "outline",
  disabled: "outline",
}

const surfaceVariant: Record<Surface, "default" | "secondary" | "outline"> = {
  input: "secondary",
  runtime: "outline",
  resource: "default",
}

export function IntegrationsView({
  config,
  coverage,
}: {
  config: ConsoleConfig
  coverage?: CoverageResponse
}) {
  const queryClient = useQueryClient()
  const [page, setPage] = React.useState<IntegrationPage>("list")
  const [selectedId, setSelectedId] = React.useState<string>()
  const [editing, setEditing] = React.useState<IntegrationDefinitionInput>(() =>
    blankDefinition()
  )

  const queryKey = ["agentgate-integrations", config.baseUrl, config.adminToken]
  const integrationsQuery = useQuery({
    queryKey,
    queryFn: ({ signal }) =>
      integrationDefinitions(config.baseUrl, config.adminToken, signal),
    enabled: Boolean(config.adminToken),
    refetchInterval: 10_000,
  })

  const saveMutation = useMutation({
    mutationFn: (definition: IntegrationDefinitionInput) => {
      if (page === "new") {
        return createIntegrationDefinition(
          config.baseUrl,
          config.adminToken,
          definition
        )
      }
      return updateIntegrationDefinition(
        config.baseUrl,
        config.adminToken,
        selectedId ?? definition.id,
        definition
      )
    },
    onSuccess: (definition) => {
      void queryClient.invalidateQueries({ queryKey })
      setSelectedId(definition.id)
      setPage("detail")
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (integrationId: string) =>
      deleteIntegrationDefinition(config.baseUrl, config.adminToken, integrationId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey })
      setSelectedId(undefined)
      setPage("list")
    },
  })

  const definitions = integrationsQuery.data?.integrations ?? []
  const selected =
    definitions.find((definition) => definition.id === selectedId) ??
    definitions[0]

  React.useEffect(() => {
    if (!selectedId && definitions.length > 0 && page === "detail") {
      setSelectedId(definitions[0].id)
    }
  }, [definitions, page, selectedId])

  if (!config.adminToken) {
    return (
      <div className="min-w-0 space-y-4">
        <EmptyCard
          title="Expected Integrations"
          description="Set an admin token in Settings to manage expected integrations."
        />
        <LiveAdaptersCard coverage={coverage} />
      </div>
    )
  }

  if (page === "new" || page === "edit") {
    return (
      <IntegrationEditor
        definition={editing}
        mode={page}
        error={
          saveMutation.error instanceof Error ? saveMutation.error.message : undefined
        }
        pending={saveMutation.isPending}
        onBack={() => setPage(selectedId ? "detail" : "list")}
        onChange={setEditing}
        onSave={() => saveMutation.mutate(editing)}
      />
    )
  }

  if (page === "detail" && selected) {
    return (
      <IntegrationDetail
        definition={selected}
        coverage={coverage}
        deletePending={deleteMutation.isPending}
        deleteError={
          deleteMutation.error instanceof Error
            ? deleteMutation.error.message
            : undefined
        }
        onBack={() => setPage("list")}
        onEdit={() => {
          setEditing(toDefinitionInput(selected))
          setSelectedId(selected.id)
          setPage("edit")
        }}
        onDelete={() => deleteMutation.mutate(selected.id)}
      />
    )
  }

  return (
    <IntegrationList
      definitions={definitions}
      coverage={coverage}
      loading={integrationsQuery.isLoading}
      error={
        integrationsQuery.error instanceof Error
          ? integrationErrorMessage(integrationsQuery.error.message, config.baseUrl)
          : undefined
      }
      onCreate={() => {
        setEditing(blankDefinition())
        setSelectedId(undefined)
        setPage("new")
      }}
      onSelect={(definition) => {
        setSelectedId(definition.id)
        setPage("detail")
      }}
    />
  )
}

function IntegrationList({
  definitions,
  coverage,
  loading,
  error,
  onCreate,
  onSelect,
}: {
  definitions: IntegrationDefinition[]
  coverage?: CoverageResponse
  loading: boolean
  error?: string
  onCreate: () => void
  onSelect: (definition: IntegrationDefinition) => void
}) {
  const adapters = coverage?.adapters ?? []
  const supportingChannels = adapters.flatMap(
    (adapter) => adapter.supporting_channels ?? []
  )

  return (
    <div className="min-w-0 space-y-4">
      <Card className="min-w-0">
        <CardHeader className="border-b">
          <CardTitle>Integrations</CardTitle>
          <CardDescription>Expected integrations and live matches.</CardDescription>
          <CardAction>
            <Button type="button" onClick={onCreate}>
              <Plus className="size-4" />
              New Expected Integration
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-3">
          <Metric label="Expected" value={definitions.length} />
          <Metric label="Live Adapters" value={adapters.length} />
          <Metric label="Channels" value={supportingChannels.length} />
        </CardContent>
      </Card>

      {error ? <ErrorCard title="Integration Error" message={error} /> : null}

      <Card className="min-w-0">
        <CardHeader className="border-b">
          <CardTitle>Expected Integrations</CardTitle>
          <CardDescription>
            AgentGate declares expectations here. Adapters still appear only after
            registration.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Kind</TableHead>
                <TableHead>Health</TableHead>
                <TableHead>Enabled</TableHead>
                <TableHead className="text-right">Matched</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {definitions.map((definition) => (
                <TableRow
                  key={definition.id}
                  className="cursor-pointer"
                  onClick={() => onSelect(definition)}
                >
                  <TableCell>
                    <div className="font-medium">{definition.name}</div>
                    <div className="font-mono text-xs text-muted-foreground">
                      {definition.id}
                    </div>
                  </TableCell>
                  <TableCell>{statusLabel(definition.kind)}</TableCell>
                  <TableCell>
                    <HealthBadge status={definition.health.status} />
                  </TableCell>
                  <TableCell>{definition.enabled ? "Enabled" : "Disabled"}</TableCell>
                  <TableCell className="text-right font-mono">
                    {definition.health.matched_adapter_count ?? 0}
                  </TableCell>
                </TableRow>
              ))}
              {!definitions.length ? (
                <TableRow>
                  <TableCell
                    colSpan={5}
                    className="h-24 text-center text-sm text-muted-foreground"
                  >
                    {loading ? "Loading" : "No expected integrations yet."}
                  </TableCell>
                </TableRow>
              ) : null}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <LiveAdaptersCard coverage={coverage} />
    </div>
  )
}

function IntegrationDetail({
  definition,
  coverage,
  deletePending,
  deleteError,
  onBack,
  onEdit,
  onDelete,
}: {
  definition: IntegrationDefinition
  coverage?: CoverageResponse
  deletePending: boolean
  deleteError?: string
  onBack: () => void
  onEdit: () => void
  onDelete: () => void
}) {
  const actualSurfaces = uniqueSurfaces(
    (definition.matched_adapters ?? []).flatMap((adapter) => adapter.surfaces)
  )

  return (
    <div className="min-w-0 space-y-4">
      <Breadcrumb
        items={["Integrations", definition.name]}
        onBack={onBack}
      />

      <Card className="min-w-0">
        <CardHeader className="border-b">
          <CardTitle>{definition.name}</CardTitle>
          <CardDescription>{definition.id}</CardDescription>
          <CardAction className="flex gap-2">
            <Button type="button" variant="outline" onClick={onEdit}>
              Edit
            </Button>
            <Button
              type="button"
              variant="destructive"
              disabled={deletePending}
              onClick={onDelete}
            >
              <Trash2 className="size-4" />
              Delete
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 md:grid-cols-4">
            <DetailTile label="Kind" value={statusLabel(definition.kind)} />
            <DetailTile
              label="Health"
              value={
                <HealthBadge status={definition.health.status} />
              }
            />
            <DetailTile
              label="Enabled"
              value={definition.enabled ? "Enabled" : "Disabled"}
            />
            <DetailTile
              label="Matched"
              value={String(definition.health.matched_adapter_count ?? 0)}
            />
          </div>
          {deleteError ? (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
              {deleteError}
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Card className="min-w-0">
        <CardHeader className="border-b">
          <CardTitle>Surface Coverage</CardTitle>
          <CardDescription>Expected surfaces compared with matched adapters.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-3">
          {(["input", "runtime", "resource"] as Surface[]).map((surface) => {
            const expected = (definition.expected_surfaces ?? []).includes(surface)
            const actual = actualSurfaces.includes(surface)
            return (
              <div key={surface} className="rounded-lg border p-3">
                <div className="flex items-center justify-between gap-2">
                  <Badge variant={surfaceVariant[surface]}>
                    {surfaceLabel(surface)}
                  </Badge>
                  <Badge variant={actual ? "secondary" : "outline"}>
                    {actual ? "Covered" : "Not Connected"}
                  </Badge>
                </div>
                <div className="mt-2 text-xs text-muted-foreground">
                  {expected ? "Expected" : "Not Expected"}
                </div>
              </div>
            )
          })}
        </CardContent>
      </Card>

      <Card className="min-w-0">
        <CardHeader className="border-b">
          <CardTitle>Matched Adapters</CardTitle>
          <CardDescription>
            Match rule: adapter.integration_id equals definition.id.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Adapter ID</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Host</TableHead>
                <TableHead>Surfaces</TableHead>
                <TableHead>Last Seen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(definition.matched_adapters ?? []).map((adapter) => (
                <TableRow key={adapter.adapter_id}>
                  <TableCell className="font-mono">{adapter.adapter_id}</TableCell>
                  <TableCell>
                    <HealthBadge status={adapter.status} />
                  </TableCell>
                  <TableCell>
                    {adapter.host.kind}
                    {adapter.host.version ? ` / ${adapter.host.version}` : ""}
                  </TableCell>
                  <TableCell>
                    <SurfaceBadges surfaces={adapter.surfaces} />
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {formatDate(adapter.last_seen_at)}
                  </TableCell>
                </TableRow>
              ))}
              {!(definition.matched_adapters ?? []).length ? (
                <TableRow>
                  <TableCell
                    colSpan={5}
                    className="h-24 text-center text-sm text-muted-foreground"
                  >
                    No live adapter has registered with this integration_id.
                  </TableCell>
                </TableRow>
              ) : null}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {coverage?.warnings?.length ? (
        <ErrorCard title="Warnings" message={coverage.warnings.join("\n")} />
      ) : null}
    </div>
  )
}

function IntegrationEditor({
  definition,
  mode,
  error,
  pending,
  onBack,
  onChange,
  onSave,
}: {
  definition: IntegrationDefinitionInput
  mode: "new" | "edit"
  error?: string
  pending: boolean
  onBack: () => void
  onChange: (definition: IntegrationDefinitionInput) => void
  onSave: () => void
}) {
  const toggleSurface = (surface: Surface) => {
    const current = definition.expected_surfaces ?? []
    const next = current.includes(surface)
      ? current.filter((item) => item !== surface)
      : [...current, surface]
    onChange({ ...definition, expected_surfaces: next })
  }

  return (
    <div className="min-w-0 space-y-4">
      <Breadcrumb
        items={[
          "Integrations",
          mode === "new" ? "New Expected Integration" : definition.name,
        ]}
        onBack={onBack}
      />

      <Card className="min-w-0">
        <CardHeader className="border-b">
          <CardTitle>
            {mode === "new" ? "New Expected Integration" : "Edit Expected Integration"}
          </CardTitle>
          <CardDescription>
            Declare what should register. This does not create an adapter.
          </CardDescription>
          <CardAction>
            <Button type="button" disabled={pending} onClick={onSave}>
              Save
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="grid gap-4 md:grid-cols-2">
            <LabeledField label="Integration ID">
              <Input
                value={definition.id}
                disabled={mode === "edit"}
                placeholder="openclaw-main"
                onChange={(event) =>
                  onChange({ ...definition, id: event.target.value })
                }
              />
            </LabeledField>
            <LabeledField label="Name">
              <Input
                value={definition.name}
                placeholder="OpenClaw main adapter"
                onChange={(event) =>
                  onChange({ ...definition, name: event.target.value })
                }
              />
            </LabeledField>
            <LabeledField label="Kind">
              <Select
                value={definition.kind}
                onValueChange={(kind) => onChange({ ...definition, kind })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {integrationKindOptions.map((kind) => (
                    <SelectItem key={kind} value={kind}>
                      {statusLabel(kind)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </LabeledField>
            <LabeledField label="Enabled">
              <Select
                value={definition.enabled ? "true" : "false"}
                onValueChange={(value) =>
                  onChange({ ...definition, enabled: value === "true" })
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="true">Enabled</SelectItem>
                  <SelectItem value="false">Disabled</SelectItem>
                </SelectContent>
              </Select>
            </LabeledField>
          </div>

          <Separator />

          <div className="space-y-3">
            <div>
              <div className="text-sm font-medium">Expected Surfaces</div>
              <div className="text-sm text-muted-foreground">
                Coverage expectations only. Enforcement still comes from adapter
                registration and policy decisions.
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              {(["input", "runtime", "resource"] as Surface[]).map((surface) => {
                const active = (definition.expected_surfaces ?? []).includes(surface)
                return (
                  <Button
                    key={surface}
                    type="button"
                    variant={active ? "default" : "outline"}
                    onClick={() => toggleSurface(surface)}
                  >
                    {surfaceLabel(surface)}
                  </Button>
                )
              })}
            </div>
          </div>

          {error ? (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
              {error}
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  )
}

function Breadcrumb({
  items,
  onBack,
}: {
  items: string[]
  onBack: () => void
}) {
  return (
    <div className="flex min-w-0 items-center gap-2 text-sm">
      <Button type="button" variant="ghost" size="sm" onClick={onBack}>
        Back
      </Button>
      {items.map((item, index) => (
        <React.Fragment key={`${item}-${index}`}>
          {index > 0 ? <ChevronRight className="size-4 text-muted-foreground" /> : null}
          <span
            className={
              index === items.length - 1
                ? "truncate font-medium"
                : "text-muted-foreground"
            }
          >
            {item}
          </span>
        </React.Fragment>
      ))}
    </div>
  )
}

function LiveAdaptersCard({ coverage }: { coverage?: CoverageResponse }) {
  const adapters = coverage?.adapters ?? []
  return (
    <Card className="min-w-0">
      <CardHeader className="border-b">
        <CardTitle>Live Adapters</CardTitle>
        <CardDescription>Adapters appear here after /v1/register.</CardDescription>
      </CardHeader>
      <CardContent className="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Adapter ID</TableHead>
              <TableHead>Integration ID</TableHead>
              <TableHead>Host</TableHead>
              <TableHead>Surfaces</TableHead>
              <TableHead>Last Seen</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {adapters.map((adapter) => (
              <TableRow key={adapter.adapter_id}>
                <TableCell className="font-mono">{adapter.adapter_id}</TableCell>
                <TableCell className="font-mono">
                  {adapter.integration_id ?? "none"}
                </TableCell>
                <TableCell>
                  {adapter.host.kind}
                  {adapter.host.version ? ` / ${adapter.host.version}` : ""}
                </TableCell>
                <TableCell>
                  <SurfaceBadges surfaces={adapter.surfaces} />
                </TableCell>
                <TableCell className="font-mono text-xs">
                  {formatDate(adapter.last_seen_at)}
                </TableCell>
              </TableRow>
            ))}
            {!adapters.length ? (
              <TableRow>
                <TableCell
                  colSpan={5}
                  className="h-24 text-center text-sm text-muted-foreground"
                >
                  Adapters will appear after registration.
                </TableCell>
              </TableRow>
            ) : null}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

function HealthBadge({ status }: { status: IntegrationHealthStatus }) {
  return (
    <Badge variant={healthVariant[status]}>
      {integrationHealthLabels[status] ?? status}
    </Badge>
  )
}

function SurfaceBadges({ surfaces }: { surfaces: Surface[] }) {
  if (!surfaces.length) {
    return <span className="text-sm text-muted-foreground">None</span>
  }
  return (
    <div className="flex flex-wrap gap-1">
      {surfaces.map((surface) => (
        <Badge key={surface} variant={surfaceVariant[surface]}>
          {surfaceLabel(surface)}
        </Badge>
      ))}
    </div>
  )
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-1 font-mono text-lg">{value}</div>
    </div>
  )
}

function DetailTile({
  label,
  value,
}: {
  label: string
  value: React.ReactNode
}) {
  return (
    <div className="rounded-lg border p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-2 min-h-6 text-sm font-medium">{value}</div>
    </div>
  )
}

function LabeledField({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <label className="grid gap-2">
      <span className="text-sm font-medium">{label}</span>
      {children}
    </label>
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

function ErrorCard({ title, message }: { title: string; message: string }) {
  return (
    <Card className="min-w-0 border-destructive/40">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription className="whitespace-pre-wrap">{message}</CardDescription>
      </CardHeader>
    </Card>
  )
}

function blankDefinition(): IntegrationDefinitionInput {
  return {
    id: "",
    name: "",
    kind: "adapter",
    enabled: true,
    expected_surfaces: ["input", "runtime"],
  }
}

function toDefinitionInput(
  definition: IntegrationDefinition
): IntegrationDefinitionInput {
  return {
    id: definition.id,
    name: definition.name,
    kind: definition.kind,
    enabled: definition.enabled,
    expected_surfaces: definition.expected_surfaces ?? [],
  }
}

function uniqueSurfaces(surfaces: Surface[]) {
  return Array.from(new Set(surfaces))
}

function formatDate(value?: string) {
  if (!value) {
    return "Unknown"
  }
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return date.toLocaleString("en-US", { hour12: false })
}

function integrationErrorMessage(message: string, baseUrl: string) {
  if (!message.includes("404")) {
    return message
  }
  return `${message}\nCheck AgentGate Base URL in Settings. Expected integrations are served by AgentGate Core, not the web dev server. Current API target: ${baseUrl}`
}
