// ─────────────────────────────────────────────────────────────────────────────
// SourceDocPanel — full documentation panel for a single source integration.
// Used in the Help page (Sources tab) and the Sources detail drawer.
// ─────────────────────────────────────────────────────────────────────────────

import { useState } from 'react'
import { CheckCircle2, ChevronLeft, Copy, Key, Terminal, Tag, Info } from 'lucide-react'
import { toast } from 'sonner'
import { SourceLogo } from './SourceLogo'
import { SOURCE_MAP, type SourceEntry, type SourceType } from '@/data/sourcesCatalog'
import { cn } from '@/utils/cn'

// ── Props ─────────────────────────────────────────────────────────────────────

export interface SourceDocPanelProps {
  sourceId: string
  onBack?: () => void
}

// ── Type badge colors ─────────────────────────────────────────────────────────

const TYPE_COLORS: Record<SourceType, string> = {
  SIEM:          'bg-violet-500/15 text-violet-400 border-violet-500/25',
  Cloud:         'bg-sky-500/15 text-sky-400 border-sky-500/25',
  EDR:           'bg-red-500/15 text-red-400 border-red-500/25',
  Identity:      'bg-blue-500/15 text-blue-400 border-blue-500/25',
  Network:       'bg-cyan-500/15 text-cyan-400 border-cyan-500/25',
  Email:         'bg-emerald-500/15 text-emerald-400 border-emerald-500/25',
  Enrichment:    'bg-amber-500/15 text-amber-400 border-amber-500/25',
  'IDS/IPS':     'bg-orange-500/15 text-orange-400 border-orange-500/25',
  OS:            'bg-slate-500/15 text-slate-400 border-slate-500/25',
  Vulnerability: 'bg-rose-500/15 text-rose-400 border-rose-500/25',
}

// ── Small reusable primitives (local, matching Help.tsx conventions) ───────────

function SectionHeading({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-3">
      {children}
    </h2>
  )
}

function InfoBox({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex gap-3 rounded-lg border border-blue-500/20 bg-blue-500/5 p-4 text-sm text-muted-foreground leading-relaxed">
      <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
      <span>{children}</span>
    </div>
  )
}

function CodeBlock({ code, language = 'bash' }: { code: string; language?: string }) {
  const [copied, setCopied] = useState(false)

  const copy = () => {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true)
      toast.success('Copied to clipboard')
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <div className="rounded-lg border border-border bg-background overflow-hidden">
      <div className="flex items-center justify-between px-4 py-1.5 border-b border-border bg-muted/30">
        <span className="text-xs text-muted-foreground font-mono">{language}</span>
        <button
          type="button"
          onClick={copy}
          className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          {copied
            ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            : <Copy className="w-3.5 h-3.5" />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="overflow-x-auto p-4 text-xs text-foreground leading-relaxed font-mono whitespace-pre-wrap break-all">
        <code>{code}</code>
      </pre>
    </div>
  )
}

function StepCard({ step, title, body }: { step: number; title: string; body: string }) {
  // Render body text, treating backtick-enclosed strings as inline <code>
  const parts = body.split(/(`[^`]+`)/)
  const rendered = parts.map((part, i) => {
    if (part.startsWith('`') && part.endsWith('`')) {
      return (
        <code
          key={i}
          className="text-blue-400 bg-blue-500/10 px-1 py-0.5 rounded text-[0.78em] font-mono"
        >
          {part.slice(1, -1)}
        </code>
      )
    }
    return <span key={i}>{part}</span>
  })

  return (
    <div className="flex gap-4">
      {/* Numbered circle */}
      <div className="shrink-0 flex flex-col items-center">
        <div className="w-8 h-8 rounded-full gradient-primary flex items-center justify-center text-white text-sm font-bold">
          {step}
        </div>
        {/* connector line — hidden on last child via CSS */}
        <div className="step-connector flex-1 w-px bg-border mt-1" />
      </div>
      {/* Content */}
      <div className="flex-1 pb-6 last:pb-0">
        <p className="font-medium text-foreground mb-1.5">{title}</p>
        <div className="text-sm text-muted-foreground leading-relaxed">{rendered}</div>
      </div>
    </div>
  )
}

// ── EnvKeyTable ───────────────────────────────────────────────────────────────

function EnvKeyTable({ source }: { source: SourceEntry }) {
  return (
    <div>
      <SectionHeading>
        <span className="flex items-center gap-2">
          <Key className="w-3.5 h-3.5" />
          Environment variables
        </span>
      </SectionHeading>
      <div className="rounded-lg border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/20">
              {['Variable', 'Label', 'Sensitive', 'Where to find'].map((h) => (
                <th
                  key={h}
                  className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {source.envKeys.map((ek) => (
              <tr key={ek.key} className="hover:bg-muted/20 align-top">
                <td className="px-4 py-3">
                  <code className="text-xs text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded font-mono whitespace-nowrap">
                    {ek.key}
                  </code>
                </td>
                <td className="px-4 py-3 text-foreground text-xs">{ek.label}</td>
                <td className="px-4 py-3">
                  {ek.sensitive ? (
                    <span className="inline-flex items-center gap-1 text-xs text-amber-400">
                      <span className="w-1.5 h-1.5 rounded-full bg-amber-400 inline-block" />
                      Secret
                    </span>
                  ) : (
                    <span className="text-xs text-muted-foreground/50">—</span>
                  )}
                </td>
                <td className="px-4 py-3 text-xs text-muted-foreground leading-relaxed max-w-xs">
                  {ek.hint}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── PushSection ───────────────────────────────────────────────────────────────

function PushSection({ source }: { source: SourceEntry }) {
  return (
    <div className="space-y-4">
      {source.examplePayload && (
        <div>
          <SectionHeading>
            <span className="flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5" />
              Example payload
            </span>
          </SectionHeading>
          <CodeBlock code={source.examplePayload} language="json" />
        </div>
      )}

      <div>
        <SectionHeading>Ingest endpoint</SectionHeading>
        <InfoBox>
          Push the JSON payload above to{' '}
          <code className="text-blue-300 bg-blue-500/10 px-1 py-0.5 rounded font-mono text-xs">
            POST /api/v1/ingest
          </code>{' '}
          with an{' '}
          <code className="text-blue-300 bg-blue-500/10 px-1 py-0.5 rounded font-mono text-xs">
            Authorization: Bearer YOUR_API_TOKEN
          </code>{' '}
          header. Generate an API token in Settings → API Tokens.
        </InfoBox>
      </div>
    </div>
  )
}

// ── Not-found state ───────────────────────────────────────────────────────────

function SourceNotFound({ sourceId, onBack }: { sourceId: string; onBack?: () => void }) {
  return (
    <div className="space-y-4">
      {onBack && (
        <button
          type="button"
          onClick={onBack}
          className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors"
        >
          <ChevronLeft className="w-4 h-4" />
          Back to all sources
        </button>
      )}
      <div className="rounded-lg border border-border bg-card p-8 text-center">
        <p className="text-muted-foreground text-sm">
          Source{' '}
          <code className="text-foreground bg-muted px-1.5 py-0.5 rounded font-mono text-xs">
            {sourceId}
          </code>{' '}
          is not in the catalog.
        </p>
      </div>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export function SourceDocPanel({ sourceId, onBack }: SourceDocPanelProps) {
  const source = SOURCE_MAP[sourceId]

  if (!source) {
    return <SourceNotFound sourceId={sourceId} onBack={onBack} />
  }

  const typeBadge = TYPE_COLORS[source.type] ?? 'bg-muted text-muted-foreground border-border'

  return (
    <div className="space-y-8 animate-fade-in">
      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex items-center gap-4">
          {/* Logo container */}
          <div
            className="flex items-center justify-center rounded-xl shrink-0 border border-border shadow-sm"
            style={{
              width: 56,
              height: 56,
              backgroundColor: source.logoBg,
            }}
          >
            <SourceLogo sourceId={source.id} size={36} />
          </div>

          <div>
            <h1 className="text-xl font-semibold text-foreground leading-tight">{source.name}</h1>
            <p className="text-sm text-muted-foreground mt-0.5">{source.vendor}</p>
            <div className="flex items-center gap-2 mt-1.5 flex-wrap">
              {/* Type badge */}
              <span
                className={cn(
                  'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border',
                  typeBadge
                )}
              >
                {source.type}
              </span>
              {/* Push / Pull badge */}
              <span
                className={cn(
                  'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border',
                  source.push
                    ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/25'
                    : 'bg-purple-500/15 text-purple-400 border-purple-500/25'
                )}
              >
                {source.push ? 'Push-based' : 'Pull-based'}
              </span>
            </div>
          </div>
        </div>

        {/* Back button */}
        {onBack && (
          <button
            type="button"
            onClick={onBack}
            className={cn(
              'inline-flex items-center gap-1.5 self-start shrink-0',
              'text-sm text-muted-foreground hover:text-foreground transition-colors',
              'px-3 py-1.5 rounded-lg border border-border bg-background hover:bg-muted/40'
            )}
          >
            <ChevronLeft className="w-4 h-4" />
            All sources
          </button>
        )}
      </div>

      {/* ── Overview ───────────────────────────────────────────────────────── */}
      <div className="space-y-3">
        <SectionHeading>Overview</SectionHeading>
        <InfoBox>{source.overview}</InfoBox>
      </div>

      {/* ── Prerequisites ──────────────────────────────────────────────────── */}
      <div className="space-y-3">
        <SectionHeading>Prerequisites</SectionHeading>
        <ul className="space-y-2">
          {source.prerequisites.map((prereq, i) => (
            <li key={i} className="flex items-start gap-3">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <span className="text-sm text-muted-foreground leading-relaxed">{prereq}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* ── Setup steps ────────────────────────────────────────────────────── */}
      <div className="space-y-3">
        <SectionHeading>Setup guide</SectionHeading>
        {/* Steps — last step hides the connector line */}
        <div className="[&_.step-connector:last-of-type]:hidden">
          {source.setupSteps.map((step, i) => (
            <StepCard key={i} step={i + 1} title={step.title} body={step.body} />
          ))}
        </div>
      </div>

      {/* ── Pull sources: env key table ─────────────────────────────────────── */}
      {!source.push && source.envKeys.length > 0 && (
        <EnvKeyTable source={source} />
      )}

      {/* ── Push sources: example payload + endpoint info ──────────────────── */}
      {source.push && <PushSection source={source} />}

      {/* ── Test command ───────────────────────────────────────────────────── */}
      {source.testCommand && (
        <div className="space-y-3">
          <SectionHeading>
            <span className="flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5" />
              Verify the connection
            </span>
          </SectionHeading>
          <CodeBlock code={source.testCommand} language="bash" />
        </div>
      )}

      {/* ── Tags ───────────────────────────────────────────────────────────── */}
      <div className="space-y-3">
        <SectionHeading>
          <span className="flex items-center gap-2">
            <Tag className="w-3.5 h-3.5" />
            Search tags
          </span>
        </SectionHeading>
        <div className="flex flex-wrap gap-2">
          {source.helpTags.map((tag) => (
            <span
              key={tag}
              className="inline-flex items-center px-2.5 py-1 rounded-full text-xs border border-border bg-muted/30 text-muted-foreground"
            >
              {tag}
            </span>
          ))}
        </div>
      </div>

      {/* ── Footer note ────────────────────────────────────────────────────── */}
      <p className="text-xs text-muted-foreground/60 border-t border-border pt-4">
        {source.push
          ? 'Kestrel will mark this source as Active automatically once it receives the first event on the ingest endpoint.'
          : 'Kestrel polls this source on a 5-minute interval. The source card updates to Active after the first successful pull.'}
      </p>
    </div>
  )
}
