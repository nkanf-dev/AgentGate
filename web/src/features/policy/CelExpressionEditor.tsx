import * as React from "react"
import {
  acceptCompletion,
  autocompletion,
  completionKeymap,
  startCompletion,
  type Completion,
  type CompletionContext,
} from "@codemirror/autocomplete"
import { EditorState, Prec } from "@codemirror/state"
import { EditorView, keymap } from "@codemirror/view"

import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"
import {
  celFactCompletions,
  celKeywordCompletions,
  celMacroCompletions,
  celSnippets,
  type CelCompletionItem,
} from "./policyCatalog"

export function CelExpressionEditor({
  value,
  onChange,
}: {
  value: string
  onChange: (value: string) => void
}) {
  const containerRef = React.useRef<HTMLDivElement | null>(null)
  const viewRef = React.useRef<EditorView | null>(null)
  const onChangeRef = React.useRef(onChange)

  React.useEffect(() => {
    onChangeRef.current = onChange
  }, [onChange])

  React.useEffect(() => {
    if (!containerRef.current) {
      return
    }

    const view = new EditorView({
      parent: containerRef.current,
      state: EditorState.create({
        doc: value,
        extensions: [
          Prec.highest(
            keymap.of([
              { key: "Tab", run: acceptCompletion },
              { key: "Enter", run: acceptCompletion },
              { key: "Ctrl-Space", run: startCompletion },
              { key: "Mod-Space", run: startCompletion },
              ...completionKeymap,
            ])
          ),
          EditorState.tabSize.of(2),
          autocompletion({
            activateOnTyping: true,
            defaultKeymap: false,
            override: [celCompletionSource],
          }),
          EditorView.lineWrapping,
          EditorView.updateListener.of((update) => {
            if (update.docChanged) {
              onChangeRef.current(update.state.doc.toString())
            }
          }),
          celEditorTheme,
        ],
      }),
    })

    viewRef.current = view
    return () => {
      view.destroy()
      viewRef.current = null
    }
  }, [])

  React.useEffect(() => {
    const view = viewRef.current
    if (!view) {
      return
    }
    const current = view.state.doc.toString()
    if (current === value) {
      return
    }
    view.dispatch({
      changes: { from: 0, to: current.length, insert: value },
    })
  }, [value])

  return (
    <div className="space-y-3">
      <div
        ref={containerRef}
        className={cn(
          "overflow-hidden rounded-md border bg-background text-sm",
          "focus-within:ring-ring/50 focus-within:ring-[3px]"
        )}
      />
      <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_14rem]">
        <div className="flex min-w-0 flex-wrap gap-2">
          {celSnippets.map((snippet) => (
            <button
              key={snippet.label}
              type="button"
              className="rounded-md border px-2.5 py-1.5 text-left text-xs font-medium hover:bg-accent"
              onClick={() => onChange(snippet.expression)}
            >
              {snippet.label}
            </button>
          ))}
        </div>
        <div className="min-w-0 space-y-2 rounded-md border p-2">
          <div className="text-xs font-medium text-muted-foreground">Fact Model</div>
          <div className="grid gap-1.5">
            {celFactCompletions
              .filter((item) => item.label.includes("."))
              .slice(0, 8)
              .map((item) => (
                <div key={item.label} className="flex min-w-0 items-center gap-2 text-xs">
                  <Badge variant="outline" className="shrink-0">
                    {item.detail}
                  </Badge>
                  <span className="min-w-0 truncate font-mono">{item.label}</span>
                </div>
              ))}
          </div>
        </div>
      </div>
    </div>
  )
}

function celCompletionSource(context: CompletionContext) {
  const token = context.matchBefore(/[\w.]*$/)
  if (!token || (token.from === token.to && !context.explicit)) {
    return null
  }

  return {
    from: token.from,
    options: [
      ...toCompletions(celFactCompletions),
      ...toCompletions(celMacroCompletions),
      ...toCompletions(celKeywordCompletions),
      ...celSnippets.map((snippet) => ({
        label: snippet.label,
        type: "text",
        detail: "Snippet",
        apply: snippet.expression,
      })),
    ],
    validFor: /^[\w.]*$/,
  }
}

function toCompletions(items: readonly CelCompletionItem[]): Completion[] {
  return items.map((item) => ({
    label: item.label,
    type: item.type,
    detail: item.detail,
    info: item.info,
    apply: item.apply ?? item.label,
  }))
}

const celEditorTheme = EditorView.theme({
  "&": {
    minHeight: "9rem",
    fontSize: "13px",
  },
  ".cm-content": {
    minHeight: "9rem",
    padding: "12px",
    fontFamily:
      'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
  },
  ".cm-line": {
    lineHeight: "1.65",
  },
  ".cm-scroller": {
    fontFamily: "inherit",
  },
  ".cm-focused": {
    outline: "none",
  },
  ".cm-tooltip": {
    borderRadius: "8px",
    border: "1px solid var(--border)",
    overflow: "hidden",
    backgroundColor: "var(--popover)",
    color: "var(--popover-foreground)",
    boxShadow:
      "0 12px 32px color-mix(in oklch, var(--foreground) 14%, transparent)",
  },
  ".cm-tooltip-autocomplete": {
    fontFamily:
      'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
  },
  ".cm-tooltip-autocomplete ul": {
    maxHeight: "14rem",
  },
  ".cm-tooltip-autocomplete ul li": {
    padding: "6px 10px",
    borderLeft: "3px solid transparent",
  },
  ".cm-tooltip-autocomplete ul li[aria-selected='true']": {
    backgroundColor: "var(--primary)",
    color: "var(--primary-foreground)",
    borderLeftColor: "var(--ring)",
  },
  ".cm-tooltip-autocomplete ul li[aria-selected='true'] .cm-completionDetail": {
    color: "var(--primary-foreground)",
    opacity: "0.8",
  },
  ".cm-tooltip-autocomplete ul li[aria-selected='true'] .cm-completionIcon": {
    color: "var(--primary-foreground)",
    opacity: "0.9",
  },
  ".cm-tooltip-autocomplete .cm-completionMatchedText": {
    textDecoration: "none",
    fontWeight: "700",
  },
})
