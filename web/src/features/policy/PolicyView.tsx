import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ArrowLeft, ChevronRight, Plus } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"
import {
  createPolicyBundle,
  defaultConfig,
  deletePolicyBundle,
  policyBundles,
  publishPolicyBundle,
  updatePolicyBundle,
  validatePolicy,
  type ConsoleConfig,
  type PolicyBundle,
  type PolicyRule,
  type PolicyValidationResponse,
} from "@/lib/agentgate-api"
import { effectLabel, statusLabel, surfaceLabel } from "@/lib/display-labels"

type PolicyPage = "bundles" | "bundle" | "rule"

import {
  effectVariant,
  EmptyCard,
  errorMessage,
  formatDate,
  newPolicyBundle,
  PolicyActions,
  PolicyBreadcrumb,
  PolicyError,
  PolicyMetric,
  PolicyValidationPanel,
  SurfaceBadge,
  surfaceRuleCount,
} from "./PolicyComponents"
import { RuleEditor } from "./PolicyRuleEditor"

export function PolicyView({ config }: { config: ConsoleConfig }) {
  const queryClient = useQueryClient()
  const baseUrl = config.baseUrl || defaultConfig.baseUrl
  const adminToken = config.adminToken
  const [page, setPage] = React.useState<PolicyPage>("bundles")
  const [selectedBundleId, setSelectedBundleId] = React.useState<string>()
  const [draft, setDraft] = React.useState("")
  const [selectedRuleIndex, setSelectedRuleIndex] = React.useState(0)
  const [ruleJsonDraft, setRuleJsonDraft] = React.useState("")
  const [savedDraft, setSavedDraft] = React.useState("")
  const [lastValidation, setLastValidation] = React.useState<
    PolicyValidationResponse | undefined
  >()
  const [draftError, setDraftError] = React.useState<string>()

  const bundlesQuery = useQuery({
    queryKey: ["agentgate-policy-bundles", baseUrl, adminToken],
    queryFn: ({ signal }) => policyBundles(baseUrl, adminToken, signal),
    enabled: Boolean(adminToken),
    retry: 1,
  })

  React.useEffect(() => {
    const selected = bundlesQuery.data?.bundles.find(
      (bundle) => bundle.bundle_id === selectedBundleId
    )
    if (selected) {
      const nextDraft = JSON.stringify(selected, null, 2)
      setDraft(nextDraft)
      setSavedDraft(nextDraft)
      setSelectedRuleIndex(0)
      setLastValidation(undefined)
      setDraftError(undefined)
    }
  }, [bundlesQuery.data?.bundles, selectedBundleId])

  const validateMutation = useMutation({
    mutationFn: (bundle: PolicyBundle) => validatePolicy(baseUrl, adminToken, bundle),
    onSuccess: (result) => setLastValidation(result),
  })

  const saveMutation = useMutation({
    mutationFn: (bundle: PolicyBundle) => {
      const bundleId = bundle.bundle_id?.trim()
      return bundleId
        ? updatePolicyBundle(baseUrl, adminToken, bundleId, bundle)
        : createPolicyBundle(baseUrl, adminToken, bundle)
    },
    onSuccess: (result) => {
      const nextDraft = JSON.stringify(result, null, 2)
      setSelectedBundleId(result.bundle_id)
      setDraft(nextDraft)
      setSavedDraft(nextDraft)
      setLastValidation(undefined)
      void queryClient.invalidateQueries({ queryKey: ["agentgate-policy-bundles"] })
      void queryClient.invalidateQueries({ queryKey: ["agentgate-console"] })
    },
  })

  const publishMutation = useMutation({
    mutationFn: (bundleId: string) => publishPolicyBundle(baseUrl, adminToken, bundleId),
    onSuccess: (result) => {
      const nextDraft = JSON.stringify(result, null, 2)
      setSelectedBundleId(result.bundle_id)
      setDraft(nextDraft)
      setSavedDraft(nextDraft)
      setLastValidation(undefined)
      void queryClient.invalidateQueries({ queryKey: ["agentgate-policy-bundles"] })
      void queryClient.invalidateQueries({ queryKey: ["agentgate-console"] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (bundleId: string) => deletePolicyBundle(baseUrl, adminToken, bundleId),
    onSuccess: () => {
      setSelectedBundleId(undefined)
      setDraft("")
      setLastValidation(undefined)
      void queryClient.invalidateQueries({ queryKey: ["agentgate-policy-bundles"] })
      void queryClient.invalidateQueries({ queryKey: ["agentgate-console"] })
    },
  })

  const parseDraft = () => {
    try {
      setDraftError(undefined)
      return JSON.parse(draft) as PolicyBundle
    } catch (error) {
      const message = error instanceof Error ? error.message : "invalid JSON"
      setDraftError(message)
      return undefined
    }
  }

  const draftBundle = React.useMemo(() => {
    try {
      return draft ? (JSON.parse(draft) as PolicyBundle) : undefined
    } catch {
      return undefined
    }
  }, [draft])

  const selectedRule = draftBundle?.rules[selectedRuleIndex]

  React.useEffect(() => {
    setRuleJsonDraft(selectedRule ? JSON.stringify(selectedRule, null, 2) : "")
  }, [selectedRule, selectedRuleIndex])

  const setDraftBundle = (bundle: PolicyBundle) => {
    setDraft(JSON.stringify(bundle, null, 2))
    setLastValidation(undefined)
    setDraftError(undefined)
  }

  const runValidate = () => {
    const bundle = parseDraft()
    if (!bundle) {
      return
    }
    validateMutation.mutate(bundle)
  }

  const runSave = () => {
    const bundle = parseDraft()
    if (!bundle) {
      return
    }
    saveMutation.mutate(bundle)
  }

  const runPublish = () => {
    const bundleId = draftBundle?.bundle_id
    if (!bundleId) {
      setDraftError("Save this Bundle before publishing it.")
      return
    }
    publishMutation.mutate(bundleId)
  }

  const startNewBundle = () => {
    const source = draftBundle ?? bundlesQuery.data?.bundles[0]
    const next = source ? structuredClone(source) : newPolicyBundle()
    delete next.bundle_id
    delete next.created_at
    delete next.updated_at
    next.name = source?.name ? `${source.name} copy` : "New Bundle"
    next.status = "inactive"
    next.priority = source?.priority ?? 100
    setSelectedBundleId(undefined)
    setPage("bundle")
    setDraftBundle(next)
    setSavedDraft("")
  }

  const addRule = () => {
    const bundle = draftBundle
    if (!bundle) {
      return
    }
    const nextRule: PolicyRule = {
      id: `rule.${Date.now()}`,
      priority: 100,
      surface: "runtime",
      request_kinds: ["tool_attempt"],
      effect: "approval_required",
      reason_code: "runtime_requires_approval",
      when: { language: "cel", expression: 'action.tool == "bash"' },
    }
    const next = { ...bundle, rules: [...bundle.rules, nextRule] }
    setSelectedRuleIndex(next.rules.length - 1)
    setPage("rule")
    setDraftBundle(next)
  }

  const updateRule = (index: number, patch: Partial<PolicyRule>) => {
    const bundle = draftBundle
    if (!bundle) {
      return
    }
    const rules = bundle.rules.map((rule, ruleIndex) =>
      ruleIndex === index ? { ...rule, ...patch } : rule
    )
    setDraftBundle({ ...bundle, rules })
  }

  const replaceRule = (index: number, nextRule: PolicyRule) => {
    const bundle = draftBundle
    if (!bundle) {
      return
    }
    const rules = bundle.rules.map((rule, ruleIndex) =>
      ruleIndex === index ? nextRule : rule
    )
    setDraftBundle({ ...bundle, rules })
  }

  const updateRuleJson = (value: string) => {
    setRuleJsonDraft(value)
    try {
      replaceRule(selectedRuleIndex, JSON.parse(value) as PolicyRule)
      setDraftError(undefined)
      setLastValidation(undefined)
    } catch (error) {
      const message = error instanceof Error ? error.message : "invalid JSON"
      setDraftError(`Rule JSON: ${message}`)
    }
  }

  const removeRule = (index: number) => {
    const bundle = draftBundle
    if (!bundle || bundle.rules.length <= 1) {
      return
    }
    const rules = bundle.rules.filter((_, ruleIndex) => ruleIndex !== index)
    setSelectedRuleIndex(Math.max(0, Math.min(index, rules.length - 1)))
    setDraftBundle({ ...bundle, rules })
  }

  const actionError =
    draftError ??
    errorMessage(bundlesQuery.error) ??
    errorMessage(validateMutation.error) ??
    errorMessage(saveMutation.error) ??
    errorMessage(publishMutation.error) ??
    errorMessage(deleteMutation.error)

  if (!adminToken) {
    return (
      <EmptyCard
        title="Policy"
        description="Set an admin token in Settings to continue."
      />
    )
  }

  const bundles = bundlesQuery.data?.bundles ?? []
  const activeBundles = bundles.filter((bundle) => bundle.status === "active")

  const bundleName = draftBundle?.name ?? draftBundle?.bundle_id ?? "Unsaved Bundle"
  const isDirty = draft !== savedDraft
  const busy =
    validateMutation.isPending ||
    saveMutation.isPending ||
    publishMutation.isPending ||
    deleteMutation.isPending
  const archiveCurrentBundle = () => {
    if (draftBundle?.bundle_id) {
      deleteMutation.mutate(draftBundle.bundle_id)
    }
  }
  const editBar = draftBundle ? (
    <div className="sticky top-[4.25rem] z-10 rounded-lg border bg-background/95 p-3 shadow-sm backdrop-blur">
      <div className="grid gap-3 xl:grid-cols-[auto_minmax(0,1fr)] xl:items-center">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant={isDirty ? "outline" : "secondary"}>
            {isDirty ? "Unsaved" : "Saved"}
          </Badge>
          {lastValidation ? (
            <Badge variant={lastValidation.valid ? "secondary" : "destructive"}>
              {lastValidation.valid ? "Validated" : "Invalid"}
            </Badge>
          ) : (
            <Badge variant="outline">Not Validated</Badge>
          )}
          <Badge variant="outline">{statusLabel(draftBundle.status)}</Badge>
        </div>
        <PolicyActions
          bundleId={draftBundle.bundle_id}
          onValidate={runValidate}
          onSave={runSave}
          onPublish={runPublish}
          onArchive={archiveCurrentBundle}
          busy={busy}
        />
      </div>
    </div>
  ) : null

  if (page === "bundles") {
    return (
      <div className="min-w-0 space-y-4">
        <PolicyBreadcrumb items={["Policy", "Bundles"]} />
        <Card className="min-w-0">
          <CardHeader className="border-b">
            <CardTitle>Bundles</CardTitle>
            <CardDescription>Active bundles execute in priority order.</CardDescription>
            <CardAction>
              <Button type="button" size="sm" onClick={startNewBundle}>
                <Plus />
                New Bundle
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent className="space-y-4">
            {actionError ? <PolicyError message={actionError} /> : null}
            <div className="grid gap-3 sm:grid-cols-3">
              <PolicyMetric label="Bundles" value={bundles.length} />
              <PolicyMetric label="Active" value={activeBundles.length} />
              <PolicyMetric
                label="Rules"
                value={bundles.reduce(
                  (total, bundle) => total + bundle.rules.length,
                  0
                )}
              />
            </div>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Bundle</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Priority</TableHead>
                  <TableHead>Rules</TableHead>
                  <TableHead>Last Updated</TableHead>
                  <TableHead className="w-10" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {bundles.length ? (
                  bundles.map((bundle) => (
                    <TableRow
                      key={bundle.bundle_id}
                      className="cursor-pointer"
                      onClick={() => {
                        setSelectedBundleId(bundle.bundle_id)
                        setPage("bundle")
                      }}
                    >
                      <TableCell>
                        <div className="font-medium">
                          {bundle.name ?? bundle.bundle_id ?? "Untitled Bundle"}
                        </div>
                        <div className="font-mono text-xs text-muted-foreground">
                          {bundle.bundle_id}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            bundle.status === "active" ? "secondary" : "outline"
                          }
                        >
                          {statusLabel(bundle.status)}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono">
                        {bundle.priority ?? 0}
                      </TableCell>
                      <TableCell className="font-mono">
                        {bundle.rules.length}
                      </TableCell>
                      <TableCell>
                        {formatDate(bundle.updated_at ?? bundle.issued_at)}
                      </TableCell>
                      <TableCell>
                        <ChevronRight className="size-4 text-muted-foreground" />
                      </TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={6} className="h-24 text-center">
                      No bundles yet.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (page === "rule" && draftBundle && selectedRule) {
    return (
      <div className="min-w-0 space-y-4">
        <PolicyBreadcrumb
          items={["Policy", "Bundles", bundleName, selectedRule.id]}
          onBack={() => setPage("bundle")}
        />
        {editBar}
        <Card className="min-w-0">
          <CardHeader className="border-b">
            <CardTitle>Rule Editor</CardTitle>
            <CardDescription>{bundleName} / Rule {selectedRuleIndex + 1}</CardDescription>
            <CardAction>
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={() => setPage("bundle")}
              >
                <ArrowLeft />
                Bundle
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent className="space-y-4">
            {actionError ? <PolicyError message={actionError} /> : null}
            <div className="space-y-4">
              <RuleEditor
                rule={selectedRule}
                onChange={(patch) => updateRule(selectedRuleIndex, patch)}
                onRemove={() => {
                  removeRule(selectedRuleIndex)
                  setPage("bundle")
                }}
                canRemove={draftBundle.rules.length > 1}
              />
              <Collapsible>
                <div className="rounded-md border">
                  <CollapsibleTrigger asChild>
                    <Button type="button" variant="ghost" className="w-full justify-between rounded-none px-4">
                      Rule JSON
                      <ChevronRight className="size-4" />
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="border-t p-4">
                    <Textarea
                      className="min-h-[22rem] resize-y font-mono text-xs leading-5"
                      spellCheck={false}
                      value={ruleJsonDraft}
                      onChange={(event) => updateRuleJson(event.target.value)}
                    />
                  </CollapsibleContent>
                </div>
              </Collapsible>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="min-w-0 space-y-4">
      <PolicyBreadcrumb
        items={["Policy", "Bundles", bundleName]}
        onBack={() => setPage("bundles")}
      />
      {editBar}
      <Card className="min-w-0">
        <CardHeader className="border-b">
          <CardTitle>Bundle Detail</CardTitle>
          <CardDescription>Save, validate, and publish.</CardDescription>
          <CardAction>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => setPage("bundles")}
            >
              <ArrowLeft />
              Bundles
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent className="space-y-4">
          {actionError ? <PolicyError message={actionError} /> : null}
          {lastValidation ? (
            <PolicyValidationPanel validation={lastValidation} />
          ) : null}

          {draftBundle ? (
            <>
              <div className="grid gap-4 xl:grid-cols-[minmax(0,24rem)_minmax(0,1fr)]">
                <div className="space-y-3 rounded-md border p-4">
                  <Input
                    value={draftBundle.name ?? ""}
                    placeholder="Bundle Name"
                    onChange={(event) =>
                      setDraftBundle({ ...draftBundle, name: event.target.value })
                    }
                  />
                  <Input
                    value={draftBundle.description ?? ""}
                    placeholder="Description"
                    onChange={(event) =>
                      setDraftBundle({
                        ...draftBundle,
                        description: event.target.value,
                      })
                    }
                  />
                  <div className="grid grid-cols-2 gap-2">
                    <Input
                      type="number"
                      min={0}
                      value={draftBundle.priority ?? 0}
                      onChange={(event) =>
                        setDraftBundle({
                          ...draftBundle,
                          priority: Number(event.target.value),
                        })
                      }
                    />
                    <Select
                      value={draftBundle.status ?? "inactive"}
                      onValueChange={(value) =>
                        setDraftBundle({ ...draftBundle, status: value })
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="active">{statusLabel("active")}</SelectItem>
                        <SelectItem value="inactive">{statusLabel("inactive")}</SelectItem>
                        <SelectItem value="archived">{statusLabel("archived")}</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid grid-cols-3 gap-2">
                    <PolicyMetric
                      label={surfaceLabel("input")}
                      value={surfaceRuleCount(draftBundle, "input")}
                    />
                    <PolicyMetric
                      label={surfaceLabel("runtime")}
                      value={surfaceRuleCount(draftBundle, "runtime")}
                    />
                    <PolicyMetric
                      label={surfaceLabel("resource")}
                      value={surfaceRuleCount(draftBundle, "resource")}
                    />
                  </div>
                </div>

                <div className="rounded-md border">
                  <div className="flex items-center justify-between gap-2 border-b p-4">
                    <div className="font-medium">Rules</div>
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      onClick={addRule}
                    >
                      <Plus />
                      Rule
                    </Button>
                  </div>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Rule</TableHead>
                        <TableHead>Surface</TableHead>
                        <TableHead>Effect</TableHead>
                        <TableHead>Priority</TableHead>
                        <TableHead className="w-10" />
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {draftBundle.rules.map((rule, index) => (
                        <TableRow
                          key={`${rule.id}-${index}`}
                          className="cursor-pointer"
                          onClick={() => {
                            setSelectedRuleIndex(index)
                            setPage("rule")
                          }}
                        >
                          <TableCell>
                            <div className="font-mono text-sm">{rule.id}</div>
                            <div className="text-xs text-muted-foreground">
                              {rule.reason_code}
                            </div>
                          </TableCell>
                          <TableCell>
                            <SurfaceBadge surface={rule.surface} />
                          </TableCell>
                          <TableCell>
                            <Badge variant={effectVariant[rule.effect]}>
                              {effectLabel(rule.effect)}
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono">
                            {rule.priority}
                          </TableCell>
                          <TableCell>
                            <ChevronRight className="size-4 text-muted-foreground" />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>

              <Collapsible>
                <div className="rounded-md border">
                  <CollapsibleTrigger asChild>
                    <Button type="button" variant="ghost" className="w-full justify-between rounded-none px-4">
                      Bundle JSON
                      <ChevronRight className="size-4" />
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="border-t p-4">
                    <Textarea
                      className="min-h-[20rem] resize-y font-mono text-xs leading-5"
                      spellCheck={false}
                      value={draft}
                      onChange={(event) => {
                        setDraft(event.target.value)
                        setLastValidation(undefined)
                        setDraftError(undefined)
                      }}
                    />
                  </CollapsibleContent>
                </div>
              </Collapsible>
            </>
          ) : (
            <div className="rounded-md border p-4 text-sm text-muted-foreground">
              Select or create a bundle to get started.
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
