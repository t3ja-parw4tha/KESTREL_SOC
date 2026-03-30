import { useState, useCallback, useMemo, useRef, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Crosshair, Play, Clock, Code, Search, Plus, Save, FileText,
  CheckCircle, XCircle, Loader2, ChevronRight, ChevronDown,
  PanelLeftClose, PanelLeftOpen, BookOpen, Table2, BarChart3,
  Filter, Copy, ArrowUp, ArrowDown,
  Database, Hash, Type, Calendar, ToggleLeft, Trash2,
  GripHorizontal,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, ResponsiveContainer,
  Tooltip as RechartsTooltip, Cell,
} from 'recharts'
import type { HuntQuery, HuntResult } from '@/api/hunting'
import { get, post, del } from '@/api/client'
import { toast } from 'sonner'
import { cn } from '@/utils/cn'

// ─── Schema Data per Language ──────────────────────────────────────────────────
const kqlSchema = [
  {
    table: 'DeviceProcessEvents',
    columns: [
      { name: 'Timestamp', type: 'datetime' },
      { name: 'DeviceId', type: 'string' },
      { name: 'DeviceName', type: 'string' },
      { name: 'ActionType', type: 'string' },
      { name: 'FileName', type: 'string' },
      { name: 'FolderPath', type: 'string' },
      { name: 'SHA256', type: 'string' },
      { name: 'ProcessCommandLine', type: 'string' },
      { name: 'AccountName', type: 'string' },
      { name: 'InitiatingProcessFileName', type: 'string' },
      { name: 'InitiatingProcessCommandLine', type: 'string' },
      { name: 'InitiatingProcessParentFileName', type: 'string' },
    ],
  },
  {
    table: 'DeviceNetworkEvents',
    columns: [
      { name: 'Timestamp', type: 'datetime' },
      { name: 'DeviceId', type: 'string' },
      { name: 'DeviceName', type: 'string' },
      { name: 'RemoteIP', type: 'string' },
      { name: 'RemotePort', type: 'int' },
      { name: 'RemoteUrl', type: 'string' },
      { name: 'LocalIP', type: 'string' },
      { name: 'LocalPort', type: 'int' },
      { name: 'Protocol', type: 'string' },
      { name: 'InitiatingProcessFileName', type: 'string' },
    ],
  },
  {
    table: 'DeviceFileEvents',
    columns: [
      { name: 'Timestamp', type: 'datetime' },
      { name: 'DeviceId', type: 'string' },
      { name: 'DeviceName', type: 'string' },
      { name: 'ActionType', type: 'string' },
      { name: 'FileName', type: 'string' },
      { name: 'FolderPath', type: 'string' },
      { name: 'SHA256', type: 'string' },
      { name: 'FileSize', type: 'long' },
      { name: 'InitiatingProcessFileName', type: 'string' },
    ],
  },
  {
    table: 'IdentityLogonEvents',
    columns: [
      { name: 'Timestamp', type: 'datetime' },
      { name: 'AccountName', type: 'string' },
      { name: 'AccountDomain', type: 'string' },
      { name: 'LogonType', type: 'string' },
      { name: 'DeviceName', type: 'string' },
      { name: 'IPAddress', type: 'string' },
      { name: 'FailureReason', type: 'string' },
      { name: 'IsSuccess', type: 'bool' },
    ],
  },
  {
    table: 'DeviceRegistryEvents',
    columns: [
      { name: 'Timestamp', type: 'datetime' },
      { name: 'DeviceName', type: 'string' },
      { name: 'ActionType', type: 'string' },
      { name: 'RegistryKey', type: 'string' },
      { name: 'RegistryValueName', type: 'string' },
      { name: 'RegistryValueData', type: 'string' },
      { name: 'InitiatingProcessFileName', type: 'string' },
    ],
  },
  {
    table: 'EmailEvents',
    columns: [
      { name: 'Timestamp', type: 'datetime' },
      { name: 'SenderFromAddress', type: 'string' },
      { name: 'RecipientEmailAddress', type: 'string' },
      { name: 'Subject', type: 'string' },
      { name: 'DeliveryAction', type: 'string' },
      { name: 'AttachmentCount', type: 'int' },
      { name: 'UrlCount', type: 'int' },
      { name: 'ThreatTypes', type: 'string' },
    ],
  },
]

const sigmaSchema = [
  {
    table: 'Log Sources',
    columns: [
      { name: 'category', type: 'keyword' },
      { name: 'product', type: 'keyword' },
      { name: 'service', type: 'keyword' },
    ],
  },
  {
    table: 'Detection Fields',
    columns: [
      { name: 'selection', type: 'map' },
      { name: 'filter', type: 'map' },
      { name: 'condition', type: 'logic' },
      { name: 'timeframe', type: 'duration' },
    ],
  },
  {
    table: 'Process Creation',
    columns: [
      { name: 'Image', type: 'string' },
      { name: 'CommandLine', type: 'string' },
      { name: 'ParentImage', type: 'string' },
      { name: 'ParentCommandLine', type: 'string' },
      { name: 'User', type: 'string' },
      { name: 'IntegrityLevel', type: 'string' },
      { name: 'OriginalFileName', type: 'string' },
      { name: 'Hashes', type: 'string' },
    ],
  },
  {
    table: 'Network Connection',
    columns: [
      { name: 'DestinationIp', type: 'string' },
      { name: 'DestinationPort', type: 'int' },
      { name: 'SourceIp', type: 'string' },
      { name: 'SourcePort', type: 'int' },
      { name: 'Protocol', type: 'string' },
      { name: 'Initiated', type: 'bool' },
    ],
  },
  {
    table: 'File Events',
    columns: [
      { name: 'TargetFilename', type: 'string' },
      { name: 'Image', type: 'string' },
      { name: 'CreationUtcTime', type: 'datetime' },
    ],
  },
  {
    table: 'Registry Events',
    columns: [
      { name: 'TargetObject', type: 'string' },
      { name: 'Details', type: 'string' },
      { name: 'EventType', type: 'keyword' },
    ],
  },
]

const yaraSchema = [
  {
    table: 'Rule Structure',
    columns: [
      { name: 'rule', type: 'keyword' },
      { name: 'meta', type: 'section' },
      { name: 'strings', type: 'section' },
      { name: 'condition', type: 'section' },
    ],
  },
  {
    table: 'String Types',
    columns: [
      { name: 'Text strings', type: '"text"' },
      { name: 'Hex strings', type: '{AA BB}' },
      { name: 'Regex strings', type: '/regex/' },
      { name: 'nocase', type: 'modifier' },
      { name: 'wide', type: 'modifier' },
      { name: 'ascii', type: 'modifier' },
      { name: 'fullword', type: 'modifier' },
    ],
  },
  {
    table: 'Condition Keywords',
    columns: [
      { name: 'and / or / not', type: 'logic' },
      { name: 'all of', type: 'quantifier' },
      { name: 'any of', type: 'quantifier' },
      { name: 'N of', type: 'quantifier' },
      { name: 'filesize', type: 'function' },
      { name: 'uint16 / uint32', type: 'function' },
      { name: 'at / in', type: 'position' },
      { name: 'entrypoint', type: 'function' },
    ],
  },
  {
    table: 'Meta Fields',
    columns: [
      { name: 'description', type: 'string' },
      { name: 'author', type: 'string' },
      { name: 'date', type: 'string' },
      { name: 'reference', type: 'string' },
      { name: 'severity', type: 'string' },
      { name: 'hash', type: 'string' },
    ],
  },
]

const customSchema = [
  {
    table: 'Available Tables',
    columns: [
      { name: 'DeviceProcessEvents', type: 'table' },
      { name: 'DeviceNetworkEvents', type: 'table' },
      { name: 'DeviceFileEvents', type: 'table' },
      { name: 'IdentityLogonEvents', type: 'table' },
      { name: 'DeviceRegistryEvents', type: 'table' },
      { name: 'EmailEvents', type: 'table' },
    ],
  },
  {
    table: 'Common Operators',
    columns: [
      { name: 'SELECT', type: 'keyword' },
      { name: 'FROM', type: 'keyword' },
      { name: 'WHERE', type: 'keyword' },
      { name: 'GROUP BY', type: 'keyword' },
      { name: 'ORDER BY', type: 'keyword' },
      { name: 'JOIN', type: 'keyword' },
      { name: 'LIMIT', type: 'keyword' },
    ],
  },
]

const schemaByLanguage: Record<string, typeof kqlSchema> = {
  kql: kqlSchema,
  sigma: sigmaSchema,
  yara: yaraSchema,
  custom: customSchema,
}

// Column type icon
function TypeIcon({ type }: { type: string }) {
  switch (type) {
    case 'datetime': return <Calendar className="h-3 w-3 text-muted-foreground shrink-0" />
    case 'int': case 'long': return <Hash className="h-3 w-3 text-muted-foreground shrink-0" />
    case 'bool': return <ToggleLeft className="h-3 w-3 text-muted-foreground shrink-0" />
    default: return <Type className="h-3 w-3 text-muted-foreground shrink-0" />
  }
}

// ─── Query Library ──────────────────────────────────────────────────────────────
const queryLibrary = [
  {
    name: 'Suspicious PS Execution',
    type: 'kql' as const,
    query: 'DeviceProcessEvents\n| where FileName == "powershell.exe"\n| where ProcessCommandLine has_any("-enc", "-encodedcommand", "-ep bypass")\n| project Timestamp, DeviceName, ProcessCommandLine, AccountName\n| sort by Timestamp desc',
  },
  {
    name: 'Failed Logons (Brute Force)',
    type: 'kql' as const,
    query: 'IdentityLogonEvents\n| where IsSuccess == false\n| summarize FailCount = count() by AccountName, IPAddress, bin(Timestamp, 1h)\n| where FailCount > 10\n| sort by FailCount desc',
  },
  {
    name: 'DNS Tunneling Detection',
    type: 'kql' as const,
    query: 'DeviceNetworkEvents\n| where RemotePort == 53\n| extend QueryLength = strlen(RemoteUrl)\n| where QueryLength > 50\n| project Timestamp, DeviceName, RemoteUrl, QueryLength\n| sort by QueryLength desc',
  },
  {
    name: 'Lateral Movement via RDP',
    type: 'kql' as const,
    query: 'DeviceNetworkEvents\n| where RemotePort == 3389\n| where LocalIP != RemoteIP\n| summarize ConnectionCount = count() by DeviceName, RemoteIP, bin(Timestamp, 1h)\n| where ConnectionCount > 3',
  },
  {
    name: 'LSASS Access Detection',
    type: 'sigma' as const,
    query: 'title: LSASS Memory Access\nstatus: experimental\nlogsource:\n  category: process_access\n  product: windows\ndetection:\n  selection:\n    TargetImage|endswith: "\\lsass.exe"\n    GrantedAccess:\n      - "0x1010"\n      - "0x1038"\n  condition: selection',
  },
  {
    name: 'Emotet YARA Rule',
    type: 'yara' as const,
    query: 'rule Emotet_Dropper {\n  meta:\n    description = "Detects Emotet dropper"\n    author = "Kestrel SOC"\n  strings:\n    $s1 = "CreateProcessW" ascii\n    $s2 = {6A 40 68 00 10 00 00}\n    $s3 = "RunDLL32" nocase\n  condition:\n    uint16(0) == 0x5A4D and\n    filesize < 500KB and\n    2 of ($s*)\n}',
  },
]

const timeRanges = [
  { label: 'Last 15 min', value: '15m' },
  { label: 'Last 1 hour', value: '1h' },
  { label: 'Last 4 hours', value: '4h' },
  { label: 'Last 24 hours', value: '24h' },
  { label: 'Last 7 days', value: '7d' },
  { label: 'Last 30 days', value: '30d' },
  { label: 'Custom', value: 'custom' },
]

// ─── Syntax Highlighter ─────────────────────────────────────────────────────────
function highlightSyntax(code: string, type: string): React.ReactNode[] {
  if (type === 'sigma' || type === 'yara') {
    return code.split('\n').map((line, i) => {
      if (line.trimStart().startsWith('#') || line.trimStart().startsWith('//')) {
        return <span key={i} className="text-muted-foreground italic">{line}</span>
      }
      if (type === 'sigma') {
        const yamlKey = line.match(/^(\s*)(\w[\w\s]*?)(: )/)
        if (yamlKey) {
          return (
            <span key={i}>
              <span className="text-muted-foreground">{yamlKey[1]}</span>
              <span className="text-primary">{yamlKey[2]}</span>
              <span className="text-muted-foreground">{yamlKey[3]}</span>
              {line.slice(yamlKey[0].length)}
            </span>
          )
        }
      }
      if (type === 'yara') {
        for (const kw of ['rule', 'meta', 'strings', 'condition', 'and', 'or', 'not', 'uint16', 'filesize']) {
          if (line.includes(kw)) {
            return (
              <span
                key={i}
                dangerouslySetInnerHTML={{
                  __html: line
                    .replace(new RegExp(`\\b(${kw})\\b`, 'g'), '<span class="text-primary font-semibold">$1</span>')
                    .replace(/"([^"]+)"/g, '<span class="text-green-400">"$1"</span>'),
                }}
              />
            )
          }
        }
      }
      return <span key={i}>{line}</span>
    })
  }

  // KQL
  return code.split('\n').map((line, i) => {
    let html = line
    html = html.replace(/"([^"]*)"/g, '<span class="text-green-400">"$1"</span>')
    html = html.replace(/'([^']*)'/g, "<span class=\"text-green-400\">'$1'</span>")
    html = html.replace(/(\|)/g, '<span class="text-primary font-bold">$1</span>')
    for (const kw of ['where', 'summarize', 'project', 'extend', 'join', 'union', 'sort', 'top', 'count', 'distinct', 'render', 'let', 'by', 'on', 'has', 'has_any', 'contains', 'startswith', 'endswith', 'bin', 'ago', 'now', 'desc', 'asc']) {
      html = html.replace(new RegExp(`\\b(${kw})\\b`, 'g'), '<span class="text-purple-400 font-medium">$1</span>')
    }
    html = html.replace(/\b(==|!=|>=|<=|>|<)\b/g, '<span class="text-yellow-400">$1</span>')
    html = html.replace(/\b(\d+)\b/g, '<span class="text-orange-400">$1</span>')
    if (line.trimStart().startsWith('//')) {
      html = `<span class="text-muted-foreground italic">${line}</span>`
    }
    return <span key={i} dangerouslySetInnerHTML={{ __html: html }} />
  })
}

// ─── Autocomplete suggestions ────────────────────────────────────────────────────
function getAutocompleteSuggestions(_text: string, cursorLine: string, queryType: string): string[] {
  if (queryType !== 'kql') return []
  const trimmed = cursorLine.trim()

  if (trimmed.endsWith('|') || trimmed.endsWith('| ')) {
    return ['where', 'summarize', 'project', 'extend', 'join', 'sort by', 'top', 'count', 'distinct', 'render']
  }

  if (trimmed === '' || !trimmed.includes('|')) {
    const tables = kqlSchema.map(s => s.table)
    const matching = tables.filter(t => t.toLowerCase().startsWith(trimmed.toLowerCase()))
    if (matching.length > 0) return matching
  }

  const afterOp = trimmed.match(/\|\s*(?:where|project|extend|summarize)\s+(.*)$/i)
  if (afterOp) {
    const partial = (afterOp[1] ?? '').split(/[,\s]+/).pop() || ''
    const allCols = kqlSchema.flatMap(s => s.columns.map(c => c.name))
    const unique = [...new Set(allCols)]
    return unique.filter(c => c.toLowerCase().startsWith(partial.toLowerCase())).slice(0, 10)
  }

  return []
}

// ─── Type badge helper ───────────────────────────────────────────────────────────
function TypeBadge({ type }: { type: string }) {
  const cls =
    type === 'kql' ? 'bg-primary/15 text-primary border-primary/30' :
    type === 'sigma' ? 'bg-purple-500/15 text-purple-400 border-purple-500/30' :
    'bg-orange-500/15 text-orange-400 border-orange-500/30'
  return (
    <span className={cn('inline-flex items-center px-1.5 py-0.5 rounded border text-[9px] font-semibold uppercase tracking-wide', cls)}>
      {type}
    </span>
  )
}

// ─── Context Menu ────────────────────────────────────────────────────────────────
interface CtxMenuState {
  x: number
  y: number
  row: HuntResult
}

// ─── Main Component ──────────────────────────────────────────────────────────────
export function ThreatHunting() {
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<'hunts' | 'editor'>('hunts')
  const [selectedHunt, setSelectedHunt] = useState<HuntQuery | null>(null)
  const [queryText, setQueryText] = useState('')
  const [queryType, setQueryType] = useState('kql')
  const [search, setSearch] = useState('')
  const [schemaSearch, setSchemaSearch] = useState('')
  const [expandedTables, setExpandedTables] = useState<Set<string>>(
    new Set(['DeviceProcessEvents', 'Log Sources', 'Rule Structure', 'Available Tables'])
  )
  const [schemaPanelOpen, setSchemaPanelOpen] = useState(true)
  const [queryLibraryOpen, setQueryLibraryOpen] = useState(false)
  const [timeRange, setTimeRange] = useState('24h')
  const [resultView, setResultView] = useState<'table' | 'chart'>('table')
  const [sortColumn, setSortColumn] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')
  const [liveResults, setLiveResults] = useState<HuntResult[]>([])
  const [hasResults, setHasResults] = useState(false)
  const [resultsPanelHeight, setResultsPanelHeight] = useState(280)
  const [showAutocomplete, setShowAutocomplete] = useState(false)
  const [autocompleteItems, setAutocompleteItems] = useState<string[]>([])
  const [autocompleteIdx, setAutocompleteIdx] = useState(0)
  const [ctxMenu, setCtxMenu] = useState<CtxMenuState | null>(null)
  const [showSaveModal, setShowSaveModal] = useState(false)
  const [saveName, setSaveName] = useState('')
  const editorRef = useRef<HTMLTextAreaElement>(null)
  const resizeRef = useRef<{ startY: number; startH: number } | null>(null)
  const libraryRef = useRef<HTMLDivElement>(null)

  // Close popover on outside click
  useEffect(() => {
    if (!queryLibraryOpen) return
    const handler = (e: MouseEvent) => {
      if (libraryRef.current && !libraryRef.current.contains(e.target as Node)) {
        setQueryLibraryOpen(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [queryLibraryOpen])

  // Close context menu on outside click
  useEffect(() => {
    if (!ctxMenu) return
    const handler = () => setCtxMenu(null)
    document.addEventListener('click', handler)
    return () => document.removeEventListener('click', handler)
  }, [ctxMenu])

  const { data: apiHunts, isError: huntsError } = useQuery({
    queryKey: ['hunts'],
    queryFn: () => get<HuntQuery[]>('/hunting/queries'),
    retry: 1,
    staleTime: 60_000,
  })

  const hunts = apiHunts ?? []

  const filteredHunts = hunts.filter(h =>
    !search ||
    h.name.toLowerCase().includes(search.toLowerCase()) ||
    h.description.toLowerCase().includes(search.toLowerCase())
  )

  const activeSchema = schemaByLanguage[queryType] || kqlSchema

  const filteredSchema = useMemo(
    () =>
      activeSchema.filter(
        s =>
          s.table.toLowerCase().includes(schemaSearch.toLowerCase()) ||
          s.columns.some(c => c.name.toLowerCase().includes(schemaSearch.toLowerCase()))
      ),
    [schemaSearch, activeSchema]
  )

  const handleSelectHunt = (hunt: HuntQuery) => {
    setSelectedHunt(hunt)
    setQueryText(hunt.query)
    setQueryType(hunt.type)
    setActiveTab('editor')
    setHasResults(false)
    setLiveResults([])
  }

  const toggleTable = (table: string) => {
    setExpandedTables(prev => {
      const next = new Set(prev)
      next.has(table) ? next.delete(table) : next.add(table)
      return next
    })
  }

  const insertText = useCallback((text: string) => {
    const editor = editorRef.current
    if (editor) {
      const start = editor.selectionStart
      const end = editor.selectionEnd
      const newText = queryText.slice(0, start) + text + queryText.slice(end)
      setQueryText(newText)
      setTimeout(() => {
        editor.focus()
        editor.selectionStart = editor.selectionEnd = start + text.length
      }, 0)
    } else {
      setQueryText(prev => prev + text)
    }
  }, [queryText])

  // ── Mutations ──────────────────────────────────────────────────────────────

  const saveMutation = useMutation({
    mutationFn: (data: { name: string; query: string; query_type: string }) =>
      post<HuntQuery>('/hunting/queries', data),
    onSuccess: (newHunt) => {
      void qc.invalidateQueries({ queryKey: ['hunts'] })
      setSelectedHunt(newHunt)
      setShowSaveModal(false)
      setSaveName('')
      toast.success(`Hunt "${newHunt.name}" saved`)
    },
    onError: (e: Error) => toast.error(e.message || 'Failed to save hunt'),
  })

  const runMutation = useMutation({
    mutationFn: (huntId: string) =>
      post<{ results: HuntResult[] }>(`/hunting/queries/${huntId}/run`),
    onSuccess: (data) => {
      void qc.invalidateQueries({ queryKey: ['hunts'] })
      const results = data.results ?? []
      setLiveResults(results)
      setHasResults(true)
      toast.success(`Hunt completed — ${results.length} results found`)
    },
    onError: () => {
      setLiveResults([])
      setHasResults(false)
      toast.error('Hunt execution failed')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (huntId: string) => del<void>(`/hunting/queries/${huntId}`),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['hunts'] })
      if (selectedHunt) {
        setSelectedHunt(null)
        setQueryText('')
        setActiveTab('hunts')
        setHasResults(false)
        setLiveResults([])
      }
      toast.success('Hunt deleted')
    },
    onError: () => toast.error('Failed to delete hunt'),
  })

  const handleRunHunt = async () => {
    if (!queryText.trim()) {
      toast.error('Please enter a query first')
      return
    }
    if (selectedHunt?.id && !selectedHunt.id.startsWith('HUNT-00')) {
      // Real saved hunt — run via API
      runMutation.mutate(selectedHunt.id)
    } else {
      // Unsaved query or demo hunt — prompt to save first or run as demo
      toast.info('Save the query first to run it against live data')
    }
  }

  const handleSaveQuery = () => {
    if (!queryText.trim()) {
      toast.error('Please enter a query first')
      return
    }
    setSaveName(selectedHunt?.name ?? '')
    setShowSaveModal(true)
  }

  const handleConfirmSave = () => {
    if (!saveName.trim()) {
      toast.error('Name is required')
      return
    }
    saveMutation.mutate({ name: saveName.trim(), query: queryText, query_type: queryType })
  }

  const displayedResults = liveResults

  const handleAddFilter = (field: string, value: string) => {
    const clause = `\n| where ${field} == "${value}"`
    setQueryText(prev => prev + clause)
    setCtxMenu(null)
    toast.success(`Filter added: ${field} == "${value}"`)
  }

  const sortedResults = useMemo(() => {
    if (!sortColumn) return displayedResults
    return [...displayedResults].sort((a, b) => {
      const aVal = (a as unknown as Record<string, unknown>)[sortColumn]
      const bVal = (b as unknown as Record<string, unknown>)[sortColumn]
      if (typeof aVal === 'number' && typeof bVal === 'number') {
        return sortDir === 'asc' ? aVal - bVal : bVal - aVal
      }
      return sortDir === 'asc'
        ? String(aVal).localeCompare(String(bVal))
        : String(bVal).localeCompare(String(aVal))
    })
  }, [sortColumn, sortDir, displayedResults])

  const handleSort = (col: string) => {
    if (sortColumn === col) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortColumn(col)
      setSortDir('desc')
    }
  }

  const chartData = useMemo(() => {
    const buckets: Record<string, number> = {}
    displayedResults.forEach(r => {
      const hour = new Date(r.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false })
      buckets[hour] = (buckets[hour] || 0) + 1
    })
    return Object.entries(buckets).map(([time, count]) => ({ time, count })).reverse()
  }, [displayedResults])

  const handleEditorKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    const textarea = e.currentTarget
    const currentLine = queryText.slice(0, textarea.selectionStart).split('\n').pop() || ''

    if (e.key === 'Tab') {
      e.preventDefault()
      insertText('  ')
      return
    }

    if (showAutocomplete && autocompleteItems.length > 0) {
      if (e.key === 'ArrowDown') { e.preventDefault(); setAutocompleteIdx(i => Math.min(i + 1, autocompleteItems.length - 1)); return }
      if (e.key === 'ArrowUp') { e.preventDefault(); setAutocompleteIdx(i => Math.max(i - 1, 0)); return }
      if (e.key === 'Enter') {
        e.preventDefault()
        const item = autocompleteItems[autocompleteIdx] ?? ''
        const partial = currentLine.split(/[\s|,]+/).pop() || ''
        insertText(item.slice(partial.length) + ' ')
        setShowAutocomplete(false)
        return
      }
      if (e.key === 'Escape') { setShowAutocomplete(false); return }
    }
  }

  const handleEditorChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const val = e.target.value
    setQueryText(val)
    const currentLine = val.slice(0, e.target.selectionStart).split('\n').pop() || ''
    const suggestions = getAutocompleteSuggestions(val, currentLine, queryType)
    if (suggestions.length > 0) {
      setAutocompleteItems(suggestions)
      setAutocompleteIdx(0)
      setShowAutocomplete(true)
    } else {
      setShowAutocomplete(false)
    }
  }

  const handleResizeMouseDown = (e: React.MouseEvent) => {
    e.preventDefault()
    resizeRef.current = { startY: e.clientY, startH: resultsPanelHeight }
    const onMove = (ev: MouseEvent) => {
      if (!resizeRef.current) return
      const delta = resizeRef.current.startY - ev.clientY
      setResultsPanelHeight(Math.max(150, Math.min(600, resizeRef.current.startH + delta)))
    }
    const onUp = () => {
      resizeRef.current = null
      document.removeEventListener('mousemove', onMove)
      document.removeEventListener('mouseup', onUp)
    }
    document.addEventListener('mousemove', onMove)
    document.addEventListener('mouseup', onUp)
  }

  const lines = queryText.split('\n')

  // ──────────────────────────────────────────────────────────────────────────────
  // RENDER
  // ──────────────────────────────────────────────────────────────────────────────
  return (
    <div className="space-y-4 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold tracking-tight flex items-center gap-2 text-foreground">
            <Crosshair className="h-5 w-5 text-primary" /> Threat Hunting
          </h1>
          <p className="text-xs text-muted-foreground">Proactive threat hunting across your environment</p>
        </div>
        <button
          type="button"
          onClick={() => { setSelectedHunt(null); setQueryText(''); setActiveTab('editor'); setHasResults(false) }}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border bg-card text-foreground text-xs hover:bg-accent transition-colors"
        >
          <Plus className="h-3 w-3" /> New Hunt
        </button>
      </div>

      {huntsError && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-400">
          Could not load saved hunts from API. No demo hunt data is shown.
        </div>
      )}

      {/* Tabs */}
      <div className="space-y-3">
        <div className="flex items-center gap-0.5 bg-muted/50 rounded-lg p-1 w-fit">
          {(['hunts', 'editor'] as const).map(tab => (
            <button
              key={tab}
              type="button"
              onClick={() => setActiveTab(tab)}
              className={cn(
                'px-3 py-1.5 rounded-md text-xs font-medium transition-all flex items-center gap-1.5',
                activeTab === tab
                  ? 'bg-background text-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              )}
            >
              {tab === 'editor' && <Code className="h-3 w-3" />}
              {tab === 'hunts' ? 'Saved Hunts' : 'Query Workspace'}
            </button>
          ))}
        </div>

        {/* ═══════════ SAVED HUNTS ═══════════ */}
        {activeTab === 'hunts' && (
          <div className="space-y-4">
            <div className="relative max-w-sm">
              <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground pointer-events-none" />
              <input
                type="search"
                placeholder="Search hunts..."
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 rounded-lg border border-border bg-muted/50 text-foreground text-xs placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/40 focus:border-primary/60 transition-all"
              />
            </div>
            <div className="space-y-3">
              {filteredHunts.map(hunt => (
                <div
                  key={hunt.id}
                  className="glass-card-hover cursor-pointer p-4"
                  onClick={() => handleSelectHunt(hunt)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={e => e.key === 'Enter' && handleSelectHunt(hunt)}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0 space-y-1.5">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[10px] text-muted-foreground">{hunt.id}</span>
                        {hunt.status === 'completed' && <CheckCircle className="h-3 w-3 text-green-400" />}
                        {hunt.status === 'running' && <Loader2 className="h-3 w-3 text-yellow-400 animate-spin" />}
                        {hunt.status === 'failed' && <XCircle className="h-3 w-3 text-destructive" />}
                        {hunt.status === 'saved' && <Save className="h-3 w-3 text-muted-foreground" />}
                        <TypeBadge type={hunt.type} />
                      </div>
                      <h3 className="text-sm font-semibold text-foreground">{hunt.name}</h3>
                      <p className="text-xs text-muted-foreground">{hunt.description}</p>
                      <div className="flex items-center gap-4 text-[10px] text-muted-foreground">
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {hunt.last_run ? `Run ${new Date(hunt.last_run).toLocaleDateString()}` : 'Never run'}
                        </span>
                        <span>{hunt.results_count} results</span>
                        <span>by {hunt.created_by}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      <button
                        type="button"
                        title="Open in editor"
                        onClick={e => { e.stopPropagation(); handleSelectHunt(hunt) }}
                        className="h-7 w-7 flex items-center justify-center rounded-md text-green-400 hover:text-green-300 hover:bg-green-500/10 transition-colors"
                      >
                        <Play className="h-3 w-3" />
                      </button>
                      {!hunt.id.startsWith('HUNT-00') && (
                        <button
                          type="button"
                          title="Delete hunt"
                          onClick={e => {
                            e.stopPropagation()
                            if (window.confirm('Delete this hunt query?')) deleteMutation.mutate(hunt.id)
                          }}
                          className="h-7 w-7 flex items-center justify-center rounded-md text-muted-foreground hover:text-red-400 hover:bg-red-500/10 transition-colors"
                        >
                          <Trash2 className="h-3 w-3" />
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
              {filteredHunts.length === 0 && (
                <div className="glass-card p-10 text-center">
                  <FileText className="h-8 w-8 text-muted-foreground mx-auto mb-3 opacity-50" />
                  <p className="text-sm text-muted-foreground">No hunts match your search</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ═══════════ IDE WORKSPACE ═══════════ */}
        {activeTab === 'editor' && (
          <div className="space-y-0">
            {/* ── Toolbar ── */}
            <div className="flex items-center gap-2 mb-3 flex-wrap">
              <button
                type="button"
                onClick={() => setSchemaPanelOpen(p => !p)}
                className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-xs text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
              >
                {schemaPanelOpen ? <PanelLeftClose className="h-3.5 w-3.5" /> : <PanelLeftOpen className="h-3.5 w-3.5" />}
                Schema
              </button>

              <div className="w-px h-5 bg-border/60" />

              {/* Query type select */}
              <select
                value={queryType}
                onChange={e => setQueryType(e.target.value)}
                className="h-7 px-2 pr-7 rounded-md border border-border/50 bg-muted/30 text-foreground text-[11px] focus:outline-none focus:ring-2 focus:ring-primary/40 appearance-none cursor-pointer"
              >
                <option value="kql">KQL</option>
                <option value="sigma">Sigma</option>
                <option value="yara">YARA</option>
                <option value="custom">Custom</option>
              </select>

              <div className="flex-1" />

              {/* Time range */}
              <select
                value={timeRange}
                onChange={e => setTimeRange(e.target.value)}
                className="h-7 px-2 pr-7 rounded-md border border-border/50 bg-muted/30 text-foreground text-[11px] focus:outline-none focus:ring-2 focus:ring-primary/40 appearance-none cursor-pointer"
              >
                {timeRanges.map(t => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>

              {/* Query library popover */}
              <div className="relative" ref={libraryRef}>
                <button
                  type="button"
                  title="Query Library"
                  onClick={() => setQueryLibraryOpen(p => !p)}
                  className="h-7 w-7 flex items-center justify-center rounded-md text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
                >
                  <BookOpen className="h-3.5 w-3.5" />
                </button>
                {queryLibraryOpen && (
                  <div className="absolute right-0 top-9 z-50 w-[360px] glass-card-elevated rounded-xl border border-border/50 shadow-xl overflow-hidden">
                    <div className="px-3 py-2.5 border-b border-border/30">
                      <p className="text-xs font-semibold text-foreground">Query Library</p>
                      <p className="text-[10px] text-muted-foreground">Click to insert a saved snippet</p>
                    </div>
                    <div className="max-h-[320px] overflow-y-auto scrollbar-thin p-1.5 space-y-0.5">
                      {queryLibrary.map((q, i) => (
                        <button
                          key={i}
                          type="button"
                          className="w-full text-left px-3 py-2 rounded-md hover:bg-muted/40 transition-colors"
                          onClick={() => {
                            setQueryText(q.query)
                            setQueryType(q.type)
                            setQueryLibraryOpen(false)
                            toast.success(`Loaded: ${q.name}`)
                          }}
                        >
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-medium text-foreground">{q.name}</span>
                            <TypeBadge type={q.type} />
                          </div>
                          <p className="text-[10px] text-muted-foreground font-mono mt-1 truncate">{q.query.split('\n')[0]}</p>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              <div className="w-px h-5 bg-border/60" />

              <button
                type="button"
                onClick={handleSaveQuery}
                disabled={saveMutation.isPending}
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md border border-border text-foreground text-xs hover:bg-accent transition-colors disabled:opacity-50"
              >
                {saveMutation.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Save className="h-3 w-3" />} Save
              </button>

              <button
                type="button"
                onClick={handleRunHunt}
                disabled={runMutation.isPending}
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md gradient-primary text-white text-xs font-medium disabled:opacity-60 hover:opacity-90 transition-opacity"
              >
                {runMutation.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
                Run Hunt
              </button>
            </div>

            {/* ── Main IDE Layout ── */}
            <div
              className="flex gap-0 border border-border/40 rounded-xl overflow-hidden"
              style={{ height: 'calc(100vh - 260px)' }}
            >
              {/* ── Schema Browser (Left) ── */}
              {schemaPanelOpen && (
                <div className="w-[280px] border-r border-border/40 bg-card/30 shrink-0 flex flex-col">
                  <div className="px-3 py-2.5 border-b border-border/30">
                    <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                      {queryType === 'kql' ? 'KQL Tables' : queryType === 'sigma' ? 'Sigma Fields' : queryType === 'yara' ? 'YARA Reference' : 'Custom Reference'}
                    </span>
                  </div>
                  <div className="px-3 py-2 border-b border-border/30">
                    <div className="relative">
                      <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground pointer-events-none" />
                      <input
                        type="search"
                        placeholder="Search schema..."
                        value={schemaSearch}
                        onChange={e => setSchemaSearch(e.target.value)}
                        className="w-full pl-8 pr-3 py-1.5 rounded-md border-0 bg-muted/30 text-foreground text-xs placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/40 transition-all"
                      />
                    </div>
                  </div>
                  <div className="flex-1 overflow-y-auto scrollbar-thin p-2 space-y-1">
                    {filteredSchema.map(schema => {
                      const isExpanded = expandedTables.has(schema.table)
                      return (
                        <div key={schema.table}>
                          <button
                            type="button"
                            className="w-full flex items-center gap-2 px-2.5 py-2 rounded-md text-left hover:bg-muted/40 transition-colors"
                            onClick={() => toggleTable(schema.table)}
                          >
                            {isExpanded
                              ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                              : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground shrink-0" />}
                            <Database className="h-3.5 w-3.5 text-primary shrink-0" />
                            <span className="text-sm font-medium text-foreground truncate flex-1">{schema.table}</span>
                          </button>
                          {isExpanded && (
                            <div className="ml-6 space-y-0.5 pb-1">
                              {schema.columns.map(col => (
                                <button
                                  key={col.name}
                                  type="button"
                                  className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded text-left hover:bg-muted/30 transition-colors"
                                  onClick={() => insertText(col.name)}
                                  title={`Insert ${col.name} (${col.type})`}
                                >
                                  <TypeIcon type={col.type} />
                                  <span className="text-xs text-foreground/80 truncate flex-1">{col.name}</span>
                                  <span className="text-[11px] text-muted-foreground/60 font-mono shrink-0">{col.type}</span>
                                </button>
                              ))}
                            </div>
                          )}
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}

              {/* ── Editor + Results (Center) ── */}
              <div className="flex-1 flex flex-col min-w-0">
                {/* Code editor */}
                <div className="flex-1 relative overflow-hidden bg-[hsl(222,47%,5%)]">
                  <div className="absolute inset-0 flex overflow-auto scrollbar-thin">
                    {/* Line numbers */}
                    <div className="shrink-0 bg-[hsl(222,47%,4%)] border-r border-border/20 px-2 pt-3 select-none text-right min-w-[40px]">
                      {lines.map((_, i) => (
                        <div key={i} className="text-[11px] leading-[20px] text-muted-foreground/40 font-mono">
                          {i + 1}
                        </div>
                      ))}
                    </div>

                    {/* Syntax overlay + textarea */}
                    <div className="flex-1 relative min-w-0">
                      {/* Highlighted code (display layer) */}
                      <pre className="absolute inset-0 px-3 pt-3 text-[12px] leading-[20px] font-mono pointer-events-none overflow-hidden whitespace-pre-wrap break-words text-foreground/90">
                        {highlightSyntax(queryText, queryType).map((line, i) => (
                          <div key={i} className="min-h-[20px]">{line || '\u200B'}</div>
                        ))}
                      </pre>

                      {/* Actual textarea (input layer) */}
                      <textarea
                        ref={editorRef}
                        value={queryText}
                        onChange={handleEditorChange}
                        onKeyDown={handleEditorKeyDown}
                        onBlur={() => setTimeout(() => setShowAutocomplete(false), 150)}
                        className="absolute inset-0 w-full h-full px-3 pt-3 text-[12px] leading-[20px] font-mono bg-transparent text-transparent caret-primary resize-none outline-none selection:bg-primary/30"
                        placeholder={
                          queryType === 'kql'
                            ? 'DeviceProcessEvents\n| where FileName == "powershell.exe"\n| project Timestamp, DeviceName, ProcessCommandLine'
                            : 'Enter your query...'
                        }
                        spellCheck={false}
                      />

                      {/* Autocomplete dropdown */}
                      {showAutocomplete && autocompleteItems.length > 0 && (
                        <div
                          className="absolute left-3 z-50 mt-1 rounded-md border border-border/50 bg-card shadow-xl overflow-hidden"
                          style={{
                            top: `${(queryText.slice(0, editorRef.current?.selectionStart || 0).split('\n').length) * 20 + 12}px`,
                          }}
                        >
                          {autocompleteItems.slice(0, 8).map((item, i) => (
                            <button
                              key={item}
                              type="button"
                              className={cn(
                                'w-full text-left px-3 py-1.5 text-[11px] font-mono flex items-center gap-2 transition-colors',
                                i === autocompleteIdx ? 'bg-primary/20 text-primary' : 'text-foreground hover:bg-muted/40'
                              )}
                              onMouseDown={e => {
                                e.preventDefault()
                                const currentLine = queryText.slice(0, editorRef.current?.selectionStart || 0).split('\n').pop() || ''
                                const partial = currentLine.split(/[\s|,]+/).pop() || ''
                                insertText(item.slice(partial.length) + ' ')
                                setShowAutocomplete(false)
                              }}
                            >
                              <Code className="h-3 w-3 text-muted-foreground shrink-0" />
                              {item}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Editor status bar */}
                  <div className="absolute bottom-0 left-0 right-0 flex items-center gap-3 px-3 py-1 bg-[hsl(222,47%,4%)] border-t border-border/20 text-[10px] text-muted-foreground">
                    <span>Ln {lines.length}, Col {(queryText.split('\n').pop()?.length || 0) + 1}</span>
                    <span>{queryType.toUpperCase()}</span>
                    <span className="ml-auto">{queryText.length} chars</span>
                    <span>UTF-8</span>
                  </div>
                </div>

                {/* ── Resize Handle ── */}
                {hasResults && (
                  <div
                    className="h-[6px] bg-border/20 hover:bg-primary/30 cursor-row-resize flex items-center justify-center transition-colors"
                    onMouseDown={handleResizeMouseDown}
                  >
                    <GripHorizontal className="h-3 w-3 text-muted-foreground/30" />
                  </div>
                )}

                {/* ── Results Panel ── */}
                {hasResults && (
                  <div
                    className="border-t border-border/30 bg-card/30 flex flex-col shrink-0"
                    style={{ height: resultsPanelHeight }}
                  >
                    {/* Results header */}
                    <div className="flex items-center gap-2 px-3 py-1.5 border-b border-border/20 shrink-0">
                      <span className="text-[11px] font-semibold text-foreground">Results</span>
                      <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-muted/50 text-[9px] text-muted-foreground">
                        {displayedResults.length} rows
                      </span>
                      <div className="flex-1" />
                      <div className="flex items-center gap-0.5 bg-muted/30 rounded p-0.5">
                        <button
                          type="button"
                          onClick={() => setResultView('table')}
                          title="Table view"
                          className={cn(
                            'h-6 w-6 flex items-center justify-center rounded transition-colors',
                            resultView === 'table' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'
                          )}
                        >
                          <Table2 className="h-3 w-3" />
                        </button>
                        <button
                          type="button"
                          onClick={() => setResultView('chart')}
                          title="Chart view"
                          className={cn(
                            'h-6 w-6 flex items-center justify-center rounded transition-colors',
                            resultView === 'chart' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'
                          )}
                        >
                          <BarChart3 className="h-3 w-3" />
                        </button>
                      </div>
                    </div>

                    {/* Results content */}
                    <div className="flex-1 overflow-auto scrollbar-thin">
                      {resultView === 'table' ? (
                        <table className="w-full text-left border-collapse">
                          <thead className="sticky top-0 bg-muted/20">
                            <tr>
                              {['timestamp', 'source', 'host', 'event_type', 'details', 'risk_score'].map(col => (
                                <th
                                  key={col}
                                  className="px-3 py-2 text-[10px] font-semibold text-muted-foreground cursor-pointer hover:text-foreground transition-colors whitespace-nowrap border-b border-border/20"
                                  onClick={() => handleSort(col)}
                                >
                                  <span className="flex items-center gap-1">
                                    {col.replace('_', ' ').toUpperCase()}
                                    {sortColumn === col && (
                                      sortDir === 'asc'
                                        ? <ArrowUp className="h-2.5 w-2.5" />
                                        : <ArrowDown className="h-2.5 w-2.5" />
                                    )}
                                  </span>
                                </th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {sortedResults.map(r => (
                              <tr
                                key={r.id}
                                className="hover:bg-muted/20 cursor-pointer border-b border-border/10 transition-colors"
                                onContextMenu={e => { e.preventDefault(); setCtxMenu({ x: e.clientX, y: e.clientY, row: r }) }}
                              >
                                <td className="px-3 py-2 text-[10px] font-mono whitespace-nowrap text-foreground">
                                  {new Date(r.timestamp).toLocaleTimeString()}
                                </td>
                                <td className="px-3 py-2 text-[10px]">
                                  <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/50 bg-muted/30 text-[9px] text-muted-foreground">
                                    {r.source}
                                  </span>
                                </td>
                                <td className="px-3 py-2 text-[10px] font-mono text-foreground">{r.host}</td>
                                <td className="px-3 py-2 text-[10px] text-foreground">{r.event_type}</td>
                                <td className="px-3 py-2 text-[10px] font-mono max-w-[200px] truncate text-muted-foreground">
                                  {r.details}
                                </td>
                                <td className="px-3 py-2 text-right">
                                  <span className={cn(
                                    'text-[10px] font-bold',
                                    r.risk_score >= 90 ? 'severity-critical' :
                                    r.risk_score >= 75 ? 'severity-high' :
                                    r.risk_score >= 50 ? 'severity-medium' :
                                    'severity-low'
                                  )}>
                                    {r.risk_score}
                                  </span>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      ) : (
                        <div className="p-4 h-full min-h-[200px]">
                          <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={chartData}>
                              <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 33% 17%)" />
                              <XAxis dataKey="time" tick={{ fontSize: 10, fill: 'hsl(215 20% 65%)' }} />
                              <YAxis tick={{ fontSize: 10, fill: 'hsl(215 20% 65%)' }} />
                              <RechartsTooltip
                                contentStyle={{
                                  background: 'hsl(222 47% 9%)',
                                  border: '1px solid hsl(217 33% 17%)',
                                  borderRadius: '8px',
                                  fontSize: '11px',
                                }}
                              />
                              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                                {chartData.map((_, i) => (
                                  <Cell key={i} fill="hsl(217 91% 60%)" />
                                ))}
                              </Bar>
                            </BarChart>
                          </ResponsiveContainer>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Save Query Modal */}
      {showSaveModal && (
        <div
          className="fixed inset-0 z-[130] bg-black/60 backdrop-blur-sm flex items-center justify-center p-4"
          onClick={() => setShowSaveModal(false)}
          role="dialog"
          aria-modal="true"
        >
          <div
            className="w-full max-w-md rounded-xl border border-border bg-card shadow-2xl p-5 space-y-4"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
                <Save className="h-4 w-4 text-primary" /> Save Hunt Query
              </h3>
            </div>
            <div>
              <label className="block text-xs font-medium text-muted-foreground mb-1">Query Name</label>
              <input
                type="text"
                value={saveName}
                onChange={e => setSaveName(e.target.value)}
                placeholder="e.g., PowerShell Empire Detection"
                className="w-full px-3 py-2 bg-background border border-border rounded-lg text-foreground text-sm focus:outline-none focus:border-primary"
                autoFocus
                onKeyDown={e => e.key === 'Enter' && handleConfirmSave()}
              />
            </div>
            <div className="flex justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={() => setShowSaveModal(false)}
                className="px-3 py-1.5 rounded-lg border border-border text-xs text-muted-foreground hover:text-foreground"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmSave}
                disabled={saveMutation.isPending || !saveName.trim()}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg gradient-primary text-white text-xs font-medium disabled:opacity-50"
              >
                {saveMutation.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Save className="h-3 w-3" />}
                Save
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Context Menu */}
      {ctxMenu && (
        <div
          className="fixed z-[100] glass-card-elevated rounded-lg border border-border/50 shadow-xl py-1 min-w-[200px]"
          style={{ left: ctxMenu.x, top: ctxMenu.y }}
          onClick={e => e.stopPropagation()}
        >
          <button type="button" className="w-full flex items-center gap-2 px-3 py-2 text-xs text-foreground hover:bg-muted/40 transition-colors" onClick={() => handleAddFilter('source', ctxMenu.row.source)}>
            <Filter className="h-3 w-3" /> Filter by source: {ctxMenu.row.source}
          </button>
          <button type="button" className="w-full flex items-center gap-2 px-3 py-2 text-xs text-foreground hover:bg-muted/40 transition-colors" onClick={() => handleAddFilter('host', ctxMenu.row.host)}>
            <Filter className="h-3 w-3" /> Filter by host: {ctxMenu.row.host}
          </button>
          <button type="button" className="w-full flex items-center gap-2 px-3 py-2 text-xs text-foreground hover:bg-muted/40 transition-colors" onClick={() => handleAddFilter('event_type', ctxMenu.row.event_type)}>
            <Filter className="h-3 w-3" /> Filter by event: {ctxMenu.row.event_type}
          </button>
          <div className="my-1 h-px bg-border/40" />
          <button
            type="button"
            className="w-full flex items-center gap-2 px-3 py-2 text-xs text-foreground hover:bg-muted/40 transition-colors"
            onClick={() => { navigator.clipboard.writeText(ctxMenu.row.details); toast.success('Copied to clipboard'); setCtxMenu(null) }}
          >
            <Copy className="h-3 w-3" /> Copy details
          </button>
        </div>
      )}
    </div>
  )
}
