import * as React from "react"
import { Plus, Trash2 } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import {
  type Effect,
  type PolicyCondition,
  type PolicyRule,
  type Surface,
} from "@/lib/agentgate-api"
import {
  effectLabel,
  requestKindLabel,
  statusLabel,
  surfaceLabel,
  dataClassLabel,
  taintLabel,
} from "@/lib/display-labels"
import {
  defaultObligationParams,
  obligationTypeOptions,
  policyDataClasses,
  policyRequestKinds,
  policyTaints,
  obligationCatalog,
  ruleFactSuggestions,
} from "./policyCatalog"

type PolicyObligation = NonNullable<PolicyRule["obligations"]>[number]
const obligationTypes = obligationTypeOptions()
const CelExpressionEditor = React.lazy(() =>
  import("./CelExpressionEditor").then((module) => ({
    default: module.CelExpressionEditor,
  }))
)

export function RuleEditor({
  rule,
  onChange,
  onRemove,
  canRemove,
}: {
  rule: PolicyRule
  onChange: (patch: Partial<PolicyRule>) => void
  onRemove: () => void
  canRemove: boolean
}) {
  return (
    <div className="space-y-4">
      <RuleIdentityEditor rule={rule} onChange={onChange} />
      <WhenEditor
        condition={rule.when ?? { tools: ["bash"] }}
        onChange={(when) => onChange({ when })}
      />
      <ObligationsEditor
        obligations={rule.obligations ?? []}
        onChange={(obligations) => onChange({ obligations })}
      />
      <div className="flex justify-end">
        <Button
          type="button"
          variant="outline"
          disabled={!canRemove}
          onClick={onRemove}
        >
          <Trash2 />
          Remove Rule
        </Button>
      </div>
    </div>
  )
}

function RuleIdentityEditor({
  rule,
  onChange,
}: {
  rule: PolicyRule
  onChange: (patch: Partial<PolicyRule>) => void
}) {
  return (
    <section className="space-y-3 rounded-md border p-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="text-sm font-medium">Rule Identity</div>
          <div className="text-xs text-muted-foreground">Priority, surface, and effect.</div>
        </div>
        <Badge variant="outline">{surfaceLabel(rule.surface)}</Badge>
      </div>
      <div className="grid gap-2 sm:grid-cols-2">
        <Input
          value={rule.id}
          placeholder="Rule ID"
          onChange={(event) => onChange({ id: event.target.value })}
        />
        <Input
          type="number"
          min={0}
          value={rule.priority}
          onChange={(event) => onChange({ priority: Number(event.target.value) })}
        />
        <Select
          value={rule.surface}
          onValueChange={(value) => onChange({ surface: value as Surface })}
        >
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="input">{surfaceLabel("input")}</SelectItem>
            <SelectItem value="runtime">{surfaceLabel("runtime")}</SelectItem>
            <SelectItem value="resource">{surfaceLabel("resource")}</SelectItem>
          </SelectContent>
        </Select>
        <Select
          value={rule.effect}
          onValueChange={(value) => onChange({ effect: value as Effect })}
        >
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="allow">{effectLabel("allow")}</SelectItem>
            <SelectItem value="allow_with_audit">{effectLabel("allow_with_audit")}</SelectItem>
            <SelectItem value="approval_required">{effectLabel("approval_required")}</SelectItem>
            <SelectItem value="deny">{effectLabel("deny")}</SelectItem>
            <SelectItem value="exclusion">{effectLabel("exclusion")}</SelectItem>
          </SelectContent>
        </Select>
        <Input
          value={rule.reason_code}
          placeholder="Reason Code"
          onChange={(event) => onChange({ reason_code: event.target.value })}
        />
        <Input
          value={(rule.request_kinds ?? []).join(", ")}
          placeholder="Request Kinds"
          onChange={(event) =>
            onChange({ request_kinds: commaList(event.target.value) })
          }
        />
      </div>
      <Input
        value={rule.description ?? ""}
        placeholder="Description"
        onChange={(event) => onChange({ description: event.target.value })}
      />
      <TokenPicker
        title="Request Kinds"
        value={rule.request_kinds ?? []}
        options={policyRequestKinds}
        formatOption={requestKindLabel}
        onChange={(request_kinds) => onChange({ request_kinds })}
      />
    </section>
  )
}

function WhenEditor({
  condition,
  onChange,
}: {
  condition: PolicyCondition
  onChange: (condition: PolicyCondition) => void
}) {
  const mode = condition.language === "cel" || condition.expression ? "cel" : "structured"

  return (
    <section className="space-y-3 rounded-md border p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-medium">Conditions</div>
          <div className="text-xs text-muted-foreground">Match against request facts.</div>
        </div>
        <Select
          value={mode}
          onValueChange={(value) => {
            if (value === "cel") {
              onChange({
                language: "cel",
                expression:
                  condition.expression ??
                  'action.tool == "bash" && action.side_effects.exists(x, x == "network_egress")',
              })
              return
            }
            onChange({ tools: condition.tools?.length ? condition.tools : ["bash"] })
          }}
        >
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="structured">Structured</SelectItem>
            <SelectItem value="cel">CEL</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {mode === "cel" ? (
        <React.Suspense fallback={<div className="rounded-md border p-3 text-sm text-muted-foreground">Loading CEL editor…</div>}>
          <CelExpressionEditor
            value={condition.expression ?? ""}
            onChange={(expression) =>
              onChange({
                ...condition,
                language: "cel",
                expression,
              })
            }
          />
        </React.Suspense>
      ) : (
        <StructuredWhenEditor condition={condition} onChange={onChange} />
      )}
    </section>
  )
}

function StructuredWhenEditor({
  condition,
  onChange,
}: {
  condition: PolicyCondition
  onChange: (condition: PolicyCondition) => void
}) {
  const update = (patch: Partial<PolicyCondition>) => {
    const next = { ...condition, ...patch }
    delete next.language
    delete next.expression
    onChange(removeEmptyConditionFields(next))
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-2 sm:grid-cols-2">
        <Select
          value={condition.always ? "always" : "facts"}
          onValueChange={(value) =>
            onChange(value === "always" ? { always: true } : { tools: ["bash"] })
          }
        >
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="facts">Match selected facts</SelectItem>
            <SelectItem value="always">Explicit catch-all</SelectItem>
          </SelectContent>
        </Select>
        <Select
          value={
            condition.open_world === undefined
              ? "unset"
              : condition.open_world
                ? "true"
                : "false"
          }
          disabled={Boolean(condition.always)}
          onValueChange={(value) =>
            update({
              open_world:
                value === "unset" ? undefined : value === "true",
            })
          }
        >
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="unset">Open world ignored</SelectItem>
            <SelectItem value="true">Open world true</SelectItem>
            <SelectItem value="false">Open world false</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <fieldset disabled={Boolean(condition.always)} className="space-y-4 disabled:opacity-50">
        <TokenPicker title="Tools" value={condition.tools ?? []} options={ruleFactSuggestions.tools} onChange={(tools) => update({ tools })} />
        <TokenPicker title="Operations" value={condition.operations ?? []} options={ruleFactSuggestions.operations} onChange={(operations) => update({ operations })} />
        <TokenPicker title="Any Side Effect" value={condition.side_effects_any ?? []} options={ruleFactSuggestions.sideEffects} onChange={(side_effects_any) => update({ side_effects_any })} />
        <TokenPicker title="All Side Effects" value={condition.side_effects_all ?? []} options={ruleFactSuggestions.sideEffects} onChange={(side_effects_all) => update({ side_effects_all })} />
        <TokenPicker title="Target Kinds" value={condition.target_kinds ?? []} options={ruleFactSuggestions.targetKinds} onChange={(target_kinds) => update({ target_kinds })} />
        <TokenPicker title="Taints" value={condition.taints_any ?? []} options={policyTaints} formatOption={taintLabel} onChange={(taints_any) => update({ taints_any })} />
        <TokenPicker title="Data Classes" value={condition.data_classes_any ?? []} options={policyDataClasses} formatOption={dataClassLabel} onChange={(data_classes_any) => update({ data_classes_any })} />
        <div className="grid gap-2 md:grid-cols-2">
          <ListInput title="Target Identifiers" value={condition.target_identifiers ?? []} onChange={(target_identifiers) => update({ target_identifiers })} />
          <ListInput title="Actor User IDs" value={condition.actor_user_ids ?? []} onChange={(actor_user_ids) => update({ actor_user_ids })} />
        </div>
      </fieldset>
    </div>
  )
}

function ObligationsEditor({
  obligations,
  onChange,
}: {
  obligations: PolicyObligation[]
  onChange: (obligations: PolicyObligation[]) => void
}) {
  const update = (index: number, obligation: PolicyObligation) => {
    onChange(obligations.map((item, itemIndex) => (itemIndex === index ? obligation : item)))
  }

  return (
    <section className="space-y-3 rounded-md border p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-medium">Obligations</div>
          <div className="text-xs text-muted-foreground">Actions executed on match.</div>
        </div>
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={() =>
            onChange([
              ...obligations,
              { type: "audit.redact", params: { fields: ["content.raw"] } },
            ])
          }
        >
          <Plus />
          Add
        </Button>
      </div>

      {obligations.length ? (
        <div className="space-y-3">
          {obligations.map((obligation, index) => (
            <ObligationRow
              key={`${obligation.type}-${index}`}
              obligation={obligation}
              onChange={(next) => update(index, next)}
              onRemove={() => onChange(obligations.filter((_, itemIndex) => itemIndex !== index))}
            />
          ))}
        </div>
      ) : (
        <div className="rounded-md border border-dashed p-3 text-sm text-muted-foreground">
          No custom actions configured.
        </div>
      )}
    </section>
  )
}

function ObligationRow({
  obligation,
  onChange,
  onRemove,
}: {
  obligation: PolicyObligation
  onChange: (obligation: PolicyObligation) => void
  onRemove: () => void
}) {
  const catalogItem = obligationCatalog.find((item) => item.type === obligation.type)

  return (
    <div className="space-y-3 rounded-md border p-3">
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <Badge variant="outline">{catalogItem?.executor ?? "Custom"}</Badge>
        <Badge variant={catalogItem?.status === "supported" ? "secondary" : "outline"}>
          {catalogItem ? statusLabel(catalogItem.status) : "Custom"}
        </Badge>
        {catalogItem?.description ? (
          <span className="min-w-0 text-xs text-muted-foreground">
            {catalogItem.description}
          </span>
        ) : null}
      </div>
      <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto]">
        <Select
          value={obligationTypes.includes(obligation.type) ? obligation.type : "custom"}
          onValueChange={(value) =>
            onChange({
              type: value === "custom" ? obligation.type : value,
              params: defaultObligationParams(value === "custom" ? obligation.type : value),
            })
          }
        >
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {obligationTypes.map((type) => (
              <SelectItem key={type} value={type}>
                {type}
              </SelectItem>
            ))}
            <SelectItem value="custom">Custom</SelectItem>
          </SelectContent>
        </Select>
        <Button type="button" size="icon" variant="outline" aria-label="Remove obligation" onClick={onRemove}>
          <Trash2 />
          <span className="sr-only">Remove obligation</span>
        </Button>
      </div>
      {!obligationTypes.includes(obligation.type) ? (
        <Input
          value={obligation.type}
          placeholder="custom.obligation_type"
          onChange={(event) => onChange({ ...obligation, type: event.target.value })}
        />
      ) : null}
      <ObligationParamsEditor obligation={obligation} onChange={onChange} />
    </div>
  )
}

function ObligationParamsEditor({
  obligation,
  onChange,
}: {
  obligation: PolicyObligation
  onChange: (obligation: PolicyObligation) => void
}) {
  const params = obligation.params ?? {}
  const updateParams = (patch: Record<string, unknown>) =>
    onChange({ ...obligation, params: removeEmptyObjectFields({ ...params, ...patch }) })

  switch (obligation.type) {
    case "approval.request":
      return (
        <div className="grid gap-2 md:grid-cols-2">
          <Select value={stringParam(params.scope, "attempt")} onValueChange={(scope) => updateParams({ scope })}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
          <SelectContent>
              <SelectItem value="attempt">Attempt</SelectItem>
              <SelectItem value="task">Task</SelectItem>
              <SelectItem value="session">Session</SelectItem>
            </SelectContent>
          </Select>
          <ListInput title="Choices" value={stringArrayParam(params.choices, ["deny", "allow_once"])} onChange={(choices) => updateParams({ choices })} />
        </div>
      )
    case "task_control":
      return (
        <Select value={stringParam(params.action, "pause_for_approval")} onValueChange={(action) => updateParams({ action })}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="pause_for_approval">Pause for Approval</SelectItem>
            <SelectItem value="abort_task">Abort Task</SelectItem>
          </SelectContent>
        </Select>
      )
    case "audit_event":
      return (
        <div className="grid gap-2 md:grid-cols-2">
          <Select value={stringParam(params.severity, "info")} onValueChange={(severity) => updateParams({ severity })}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="info">Info</SelectItem>
              <SelectItem value="warning">Warning</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
            </SelectContent>
          </Select>
          <Select value={stringParam(params.surface, "runtime")} onValueChange={(surface) => updateParams({ surface })}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="input">Input</SelectItem>
              <SelectItem value="runtime">Runtime</SelectItem>
              <SelectItem value="resource">Resource</SelectItem>
            </SelectContent>
          </Select>
        </div>
      )
    case "audit.redact":
    case "input.redact":
      return <ListInput title="Fields" value={stringArrayParam(params.fields, ["content.raw"])} onChange={(fields) => updateParams({ fields })} />
    case "adapter.report_required":
      return (
        <Input
          type="number"
          min={0}
          value={numberParam(params.timeout_ms, 30000)}
          onChange={(event) => updateParams({ timeout_ms: Number(event.target.value) })}
        />
      )
    case "secret.create_handle":
      return (
        <Select value={stringParam(params.scope, "session_task")} onValueChange={(scope) => updateParams({ scope })}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="attempt">Attempt</SelectItem>
            <SelectItem value="session_task">Session Task</SelectItem>
            <SelectItem value="session">Session</SelectItem>
          </SelectContent>
        </Select>
      )
    case "resource.resolve":
      return (
        <Input
          value={stringParam(params.provider, "default")}
          placeholder="Resource Provider"
          onChange={(event) => updateParams({ provider: event.target.value })}
        />
      )
    default:
      return (
        <Textarea
          className="min-h-28 font-mono text-xs"
          spellCheck={false}
          value={JSON.stringify(params, null, 2)}
          onChange={(event) => {
            try {
              onChange({ ...obligation, params: JSON.parse(event.target.value) as Record<string, unknown> })
            } catch {
              onChange({ ...obligation, params })
            }
          }}
        />
      )
  }
}

function TokenPicker({
  title,
  value,
  options,
  formatOption = (option) => option,
  onChange,
}: {
  title: string
  value: string[]
  options: readonly string[]
  formatOption?: (option: string) => string
  onChange: (value: string[]) => void
}) {
  const toggle = (option: string) => {
    onChange(value.includes(option) ? value.filter((item) => item !== option) : [...value, option])
  }

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-xs font-medium text-muted-foreground">{title}</div>
        <Badge variant="outline">{value.length}</Badge>
      </div>
      <div className="flex flex-wrap gap-2">
        {options.map((option) => (
          <Button
            key={option}
            type="button"
            size="sm"
            variant={value.includes(option) ? "default" : "outline"}
            onClick={() => toggle(option)}
          >
            {formatOption(option)}
          </Button>
        ))}
      </div>
      <Input value={value.join(", ")} onChange={(event) => onChange(commaList(event.target.value))} />
    </div>
  )
}

function ListInput({
  title,
  value,
  onChange,
}: {
  title: string
  value: string[]
  onChange: (value: string[]) => void
}) {
  return (
    <div className="space-y-2">
      <div className="text-xs font-medium text-muted-foreground">{title}</div>
      <Input value={value.join(", ")} onChange={(event) => onChange(commaList(event.target.value))} />
    </div>
  )
}

function commaList(value: string) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
}

function removeEmptyConditionFields(condition: PolicyCondition): PolicyCondition {
  return removeEmptyObjectFields(condition) as PolicyCondition
}

function removeEmptyObjectFields<T extends Record<string, unknown>>(value: T): T {
  return Object.fromEntries(
    Object.entries(value).filter(([, item]) => {
      if (Array.isArray(item)) {
        return item.length > 0
      }
      return item !== undefined && item !== ""
    })
  ) as T
}

function stringParam(value: unknown, fallback: string) {
  return typeof value === "string" ? value : fallback
}

function numberParam(value: unknown, fallback: number) {
  return typeof value === "number" ? value : fallback
}

function stringArrayParam(value: unknown, fallback: string[]) {
  return Array.isArray(value) && value.every((item) => typeof item === "string")
    ? value
    : fallback
}
