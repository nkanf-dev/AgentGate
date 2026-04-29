import * as React from "react"
import { ArrowLeft, ChevronRight, FileCheck, Save, ShieldCheck, Trash2 } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import {
  type Effect,
  type EventSurface,
  type PolicyBundle,
  type PolicyValidationResponse,
  type Surface,
} from "@/lib/agentgate-api"
import { surfaceLabel } from "@/lib/display-labels"

export const effectVariant: Record<Effect, "default" | "secondary" | "destructive" | "outline"> = {
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

export function SurfaceBadge({ surface }: { surface: EventSurface }) {
  if (surface === "none") {
    return <Badge variant="outline">{surfaceLabel(surface)}</Badge>
  }
  return <Badge variant={surfaceVariant[surface]}>{surfaceLabel(surface)}</Badge>
}

export function formatDate(value: string) {
  return new Date(value).toLocaleString("en-US", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  })
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

export function EmptyCard({
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

export function PolicyMetric({ label, value }: { label: string; value?: number }) {
  return (
    <div className="rounded-lg border p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-1 font-mono text-lg">{value ?? "..."}</div>
    </div>
  )
}

export function PolicyBreadcrumb({
  items,
  onBack,
}: {
  items: string[]
  onBack?: () => void
}) {
  return (
    <div className="flex min-w-0 items-center gap-2 text-sm text-muted-foreground">
      {onBack ? (
        <Button type="button" size="icon" variant="outline" onClick={onBack}>
          <ArrowLeft />
          <span className="sr-only">Back</span>
        </Button>
      ) : null}
      <div className="flex min-w-0 flex-wrap items-center gap-1">
        {items.map((item, index) => (
          <React.Fragment key={`${item}-${index}`}>
            {index > 0 ? <ChevronRight className="size-3" /> : null}
            <span
              className={
                index === items.length - 1
                  ? "font-medium text-foreground"
                  : undefined
              }
            >
              {item}
            </span>
          </React.Fragment>
        ))}
      </div>
    </div>
  )
}

export function PolicyError({ message }: { message: string }) {
  return (
    <div className="flex min-w-0 items-center gap-2 text-sm">
      <Badge variant="destructive">Policy Error</Badge>
      <span className="min-w-0 break-words text-muted-foreground">{message}</span>
    </div>
  )
}

export function PolicyActions({
  bundleId,
  onValidate,
  onSave,
  onPublish,
  onArchive,
  busy,
}: {
  bundleId?: string
  onValidate: () => void
  onSave: () => void
  onPublish: () => void
  onArchive: () => void
  busy: boolean
}) {
  return (
    <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto_auto_auto_auto]">
      <Input readOnly value={bundleId ?? "Unsaved Bundle"} />
      <Button type="button" variant="outline" onClick={onValidate} disabled={busy}>
        <FileCheck />
        Validate
      </Button>
      <Button type="button" variant="outline" onClick={onSave} disabled={busy}>
        <Save />
        Save
      </Button>
      <Button type="button" onClick={onPublish} disabled={!bundleId || busy}>
        <ShieldCheck />
        Publish & Activate
      </Button>
      <Button
        type="button"
        size="icon"
        variant="outline"
        disabled={!bundleId || busy}
        aria-label="Archive Bundle"
        onClick={onArchive}
      >
        <Trash2 />
        <span className="sr-only">Archive Bundle</span>
      </Button>
    </div>
  )
}

export function PolicyValidationPanel({
  validation,
}: {
  validation: PolicyValidationResponse
}) {
  return (
    <div className="rounded-lg border p-3 text-sm">
      <div className="flex items-center gap-2">
        <Badge variant={validation.valid ? "secondary" : "destructive"}>
          {validation.valid ? "Valid" : "Invalid"}
        </Badge>
        <span className="text-muted-foreground">
          {validation.rule_count ?? 0} rules checked
        </span>
      </div>
      <EvidenceSection title="Errors" items={validation.errors ?? []} />
      <EvidenceSection title="Warnings" items={validation.warnings ?? []} />
    </div>
  )
}

export function newPolicyBundle(): PolicyBundle {
  return {
    name: "New Bundle",
    description: "",
    priority: 100,
    version: 1,
    status: "inactive",
    issued_at: new Date().toISOString(),
    rules: [
      {
        id: "runtime.bash.requires_approval",
        priority: 100,
        surface: "runtime",
        request_kinds: ["tool_attempt"],
        effect: "approval_required",
        reason_code: "runtime_high_risk_requires_approval",
        when: { tools: ["bash"] },
      },
    ],
    input_policy: { secret_mode: "secret_handle" },
    resource_policy: { secret_handle_scope: "session_task" },
    runtime_policy: {},
    egress_policy: {},
    path_policy: {},
  }
}

export function surfaceRuleCount(bundle: PolicyBundle | undefined, surface: Surface) {
  return bundle?.rules.filter((rule) => rule.surface === surface).length
}

export function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : undefined
}
