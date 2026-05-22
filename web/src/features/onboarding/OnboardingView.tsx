import * as React from "react"
import { MessageSquare, Check, ArrowRight, BookOpen, Shield, Loader2 } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Separator } from "@/components/ui/separator"
import type { CoverageResponse, Surface } from "@/lib/agentgate-api"

function OpenClawIcon({ className }: { className?: string }) {
  return (
    <img src="/openclaw-icon.svg" alt="OpenClaw" className={className} />
  )
}

function FeishuIcon({ className }: { className?: string }) {
  return (
    <img src="/feishu-icon.svg" alt="Feishu" className={className} />
  )
}

const surfaces: Surface[] = ["input", "runtime", "resource"]

const surfaceLabels: Record<Surface, string> = {
  input: "Input",
  runtime: "Runtime",
  resource: "Resource",
}

// Agent definitions - extensible for future agents
const agentDefinitions = [
  {
    id: "openclaw",
    name: "OpenClaw",
    icon: OpenClawIcon,
    description: "AI coding agent with tool execution capabilities",
    supportedSurfaces: ["input", "runtime"] as Surface[],
    docsUrl: "https://github.com/agentgate/openclaw-adapter#readme",
  },
]

// Approval channel definitions - extensible for future channels
const channelDefinitions = [
  {
    id: "console",
    name: "Console",
    icon: MessageSquare,
    description: "Built-in approval via AgentGate Console",
    isDefault: true,
  },
  {
    id: "feishu",
    name: "Feishu",
    icon: FeishuIcon,
    description: "Approval via Feishu messaging",
    isDefault: false,
    docsUrl: "https://github.com/agentgate/feishu-adapter#readme",
  },
]

function SurfaceBadge({
  surface,
  supported,
}: {
  surface: Surface
  supported: boolean
}) {
  return (
    <Badge
      variant="outline"
      className={`text-xs ${
        supported
          ? "border-green-500 text-green-500"
          : "border-red-500 text-red-500"
      }`}
    >
      {surfaceLabels[surface]}
    </Badge>
  )
}

function ConnectModal({
  agent,
  open,
  onOpenChange,
}: {
  agent: (typeof agentDefinitions)[number]
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const [checking, setChecking] = React.useState(false)
  const [status, setStatus] = React.useState<"idle" | "success" | "error">("idle")

  const handleCheck = () => {
    setChecking(true)
    setStatus("idle")

    // TODO: Implement actual API call to check adapter registration
    // Should call GET /v1/coverage and check if agent is registered
    setTimeout(() => {
      setChecking(false)
      setStatus("error")
    }, 2000)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Connect {agent.name}</DialogTitle>
          <DialogDescription>
            {agent.description}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="rounded-lg border p-4 text-sm">
            <p className="mb-2 font-medium">Setup Instructions:</p>
            <ol className="list-inside list-decimal space-y-2 text-muted-foreground">
              <li>Install the {agent.name} adapter in your agent host</li>
              <li>Configure the adapter to connect to this AgentGate instance</li>
              <li>Start the adapter - it will register automatically</li>
              <li>Click "Check Connection" below to verify</li>
            </ol>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <Badge variant="outline">Surfaces</Badge>
            <div className="flex gap-1">
              {surfaces.map((surface) => (
                <SurfaceBadge
                  key={surface}
                  surface={surface}
                  supported={agent.supportedSurfaces.includes(surface)}
                />
              ))}
            </div>
          </div>
          {agent.docsUrl && (
            <a
              href={agent.docsUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
            >
              <BookOpen className="size-4" />
              View Documentation
            </a>
          )}
          <Separator />
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {status === "success" && (
                <Badge variant="default" className="gap-1">
                  <Check className="size-3" />
                  Connected
                </Badge>
              )}
              {status === "error" && (
                <Badge variant="destructive">Not Found</Badge>
              )}
            </div>
            <Button onClick={handleCheck} disabled={checking}>
              {checking ? (
                <>
                  <Loader2 className="mr-2 size-4 animate-spin" />
                  Checking...
                </>
              ) : status === "success" ? (
                <>
                  <Check className="mr-2 size-4" />
                  Done
                </>
              ) : (
                "Check Connection"
              )}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}

function AgentCard({
  agent,
  isConnected,
}: {
  agent: (typeof agentDefinitions)[number]
  isConnected: boolean
}) {
  const Icon = agent.icon
  const [showConnect, setShowConnect] = React.useState(false)

  return (
    <>
      <Card className="min-w-[200px] flex-1">
        <CardHeader className="text-center">
          <div className="mx-auto mb-2 flex size-12 items-center justify-center rounded-lg bg-muted">
            <Icon className="size-6" />
          </div>
          <CardTitle className="text-base">{agent.name}</CardTitle>
          <CardDescription className="text-sm">
            {agent.description}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex justify-center gap-2">
          {surfaces.map((surface) => (
            <SurfaceBadge
              key={surface}
              surface={surface}
              supported={agent.supportedSurfaces.includes(surface)}
            />
          ))}
        </CardContent>
        <CardFooter className="justify-center">
          {isConnected ? (
            <Badge variant="default" className="gap-1">
              <Check className="size-3" />
              Connected
            </Badge>
          ) : (
            <Button variant="outline" size="sm" onClick={() => setShowConnect(true)}>
              Connect
              <ArrowRight className="ml-1 size-3" />
            </Button>
          )}
        </CardFooter>
      </Card>
      <ConnectModal
        agent={agent}
        open={showConnect}
        onOpenChange={setShowConnect}
      />
    </>
  )
}

function ChannelConnectModal({
  channel,
  open,
  onOpenChange,
}: {
  channel: (typeof channelDefinitions)[number]
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const [checking, setChecking] = React.useState(false)
  const [status, setStatus] = React.useState<"idle" | "success" | "error">("idle")

  const handleCheck = () => {
    setChecking(true)
    setStatus("idle")

    // TODO: Implement actual API call to check channel adapter registration
    // Should call GET /v1/coverage and check if channel adapter is registered
    setTimeout(() => {
      setChecking(false)
      setStatus("error")
    }, 2000)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Connect {channel.name}</DialogTitle>
          <DialogDescription>
            {channel.description}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="rounded-lg border p-4 text-sm">
            <p className="mb-2 font-medium">Setup Instructions:</p>
            <ol className="list-inside list-decimal space-y-2 text-muted-foreground">
              <li>Deploy the {channel.name} approval adapter</li>
              <li>Configure the adapter with your {channel.name} credentials</li>
              <li>Connect the adapter to this AgentGate instance</li>
              <li>Click "Check Connection" below to verify</li>
            </ol>
          </div>
          {channel.docsUrl && (
            <a
              href={channel.docsUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
            >
              <BookOpen className="size-4" />
              View Documentation
            </a>
          )}
          <Separator />
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {status === "success" && (
                <Badge variant="default" className="gap-1">
                  <Check className="size-3" />
                  Connected
                </Badge>
              )}
              {status === "error" && (
                <Badge variant="destructive">Not Found</Badge>
              )}
            </div>
            <Button onClick={handleCheck} disabled={checking}>
              {checking ? (
                <>
                  <Loader2 className="mr-2 size-4 animate-spin" />
                  Checking...
                </>
              ) : status === "success" ? (
                <>
                  <Check className="mr-2 size-4" />
                  Done
                </>
              ) : (
                "Check Connection"
              )}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}

function ChannelCard({
  channel,
  isSelected,
  onSelect,
}: {
  channel: (typeof channelDefinitions)[number]
  isSelected: boolean
  onSelect: () => void
}) {
  const Icon = channel.icon
  const [showConnect, setShowConnect] = React.useState(false)

  return (
    <>
      <Card className={`min-w-[200px] flex-1 ${isSelected ? "border-primary" : ""}`}>
        <CardHeader className="text-center">
          <div className="mx-auto mb-2 flex size-12 items-center justify-center rounded-lg bg-muted">
            <Icon className="size-6" />
          </div>
          <CardTitle className="text-base">{channel.name}</CardTitle>
          <CardDescription className="text-sm">
            {channel.description}
          </CardDescription>
        </CardHeader>
        <CardFooter className="justify-center">
          {channel.isDefault ? (
            isSelected ? (
              <Badge variant="default" className="gap-1">
                <Check className="size-3" />
                Active
              </Badge>
            ) : (
              <Button variant="outline" size="sm" onClick={onSelect}>
                Select
                <ArrowRight className="ml-1 size-3" />
              </Button>
            )
          ) : isSelected ? (
            <Badge variant="default" className="gap-1">
              <Check className="size-3" />
              Connected
            </Badge>
          ) : (
            <Button variant="outline" size="sm" onClick={() => setShowConnect(true)}>
              Connect
              <ArrowRight className="ml-1 size-3" />
            </Button>
          )}
        </CardFooter>
      </Card>
      {!channel.isDefault && (
      <ChannelConnectModal
        channel={channel}
        open={showConnect}
        onOpenChange={setShowConnect}
      />
      )}
    </>
  )
}

export function OnboardingView({
  coverage,
  onComplete,
}: {
  coverage: CoverageResponse | undefined
  onComplete: () => void
}) {
  const [selectedChannel, setSelectedChannel] = React.useState<string>("console")
  const connectedAgents = coverage?.adapters.map((a) => a.integration_id) ?? []
  const hasConnectedAgent = connectedAgents.length > 0

  const isConfigured = hasConnectedAgent && selectedChannel !== null

  return (
    <div className="flex min-h-screen flex-col items-center justify-center p-4">
      <div className="mb-6">
        <img src="/agentgate-logo-horizontal.svg" alt="AgentGate" className="h-16 dark:invert" />
      </div>
      <p className="mb-8 max-w-md text-center text-muted-foreground">
        Security admission controller for AI agent input, runtime action, and
        resource boundaries.
      </p>
      <Card className="w-full max-w-4xl">
        <CardContent className="space-y-8">
          {/* Step 1: Connect an Agent */}
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="size-6 justify-center rounded-full p-0">
                1
              </Badge>
              <h3 className="text-lg font-medium">Connect an Agent</h3>
            </div>
            <div className="flex flex-wrap justify-center gap-4">
              {agentDefinitions.map((agent) => (
                <AgentCard
                  key={agent.id}
                  agent={agent}
                  isConnected={connectedAgents.includes(agent.id)}
                />
              ))}
            </div>
          </div>

          {/* Step 2: Configure Approval Channel */}
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="size-6 justify-center rounded-full p-0">
                2
              </Badge>
              <h3 className="text-lg font-medium">Configure Approval Channel</h3>
            </div>
            <div className="flex flex-wrap justify-center gap-4">
              {channelDefinitions.map((channel) => (
                <ChannelCard
                  key={channel.id}
                  channel={channel}
                  isSelected={selectedChannel === channel.id}
                  onSelect={() => setSelectedChannel(channel.id)}
                />
              ))}
            </div>
          </div>

          <Separator />

          {/* Resources */}
          <div className="space-y-3">
            <h3 className="text-sm font-medium text-muted-foreground">Resources</h3>
            <div className="flex flex-col gap-2 text-sm">
              {/* TODO: Link to actual documentation */}
              <span className="flex items-center gap-2 text-muted-foreground/50">
                <BookOpen className="size-4" />
                Documentation (not available)
              </span>
              {/* TODO: Link to policy configuration page */}
              <span className="flex items-center gap-2 text-muted-foreground/50">
                <Shield className="size-4" />
                Configure Policies (not available)
              </span>
            </div>
          </div>
        </CardContent>
        <CardFooter className="justify-between">
          <div>
            {/* TODO: Remove skip once Check Connection is implemented */}
            {!isConfigured && (
              <Button variant="ghost" onClick={onComplete}>
                Skip for now
              </Button>
            )}
          </div>
          <Button disabled={!isConfigured} onClick={onComplete}>
            Continue
            <ArrowRight className="ml-1 size-4" />
          </Button>
        </CardFooter>
      </Card>
    </div>
  )
}
