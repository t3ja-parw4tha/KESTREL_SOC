import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { AlertTable } from '@/components/alerts/AlertTable'
import type { Alert } from '@/types/alert'

const mockNavigate = vi.fn()
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return { ...actual, useNavigate: () => mockNavigate }
})

function makeAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: `alert-${Math.random().toString(36).slice(2)}`,
    title: 'Test Alert',
    source: 'suricata',
    severity: 'Medium',
    category: 'network',
    status: 'open',
    assigned_to: null,
    asset_id: null,
    user_id: null,
    source_ip: null,
    dest_ip: null,
    mitre_techniques: [],
    risk_score: 50,
    risk_level: 'medium',
    confidence: 0.8,
    incident_group_id: null,
    ai_summary: null,
    ai_key_facts: null,
    ai_remediation: null,
    ai_next_steps: null,
    enrichment: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...overrides,
  }
}

function renderTable(props: Partial<React.ComponentProps<typeof AlertTable>> = {}) {
  return render(
    <MemoryRouter>
      <AlertTable alerts={[]} {...props} />
    </MemoryRouter>
  )
}

describe('AlertTable', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows empty state when no alerts', () => {
    renderTable({ alerts: [] })
    expect(screen.getByText('No alerts match your filters')).toBeInTheDocument()
  })

  it('renders rows for each alert', () => {
    const alerts = [makeAlert({ title: 'Alert A' }), makeAlert({ title: 'Alert B' }), makeAlert({ title: 'Alert C' })]
    renderTable({ alerts })
    expect(screen.getByText('Alert A')).toBeInTheDocument()
    expect(screen.getByText('Alert B')).toBeInTheDocument()
    expect(screen.getByText('Alert C')).toBeInTheDocument()
  })

  it('shows loading skeleton when loading=true', () => {
    renderTable({ alerts: [], loading: true })
    // Skeleton shows, no empty state message
    expect(screen.queryByText('No alerts match your filters')).not.toBeInTheDocument()
  })

  it('toggles a single row checkbox', () => {
    const alert = makeAlert({ id: 'alert-1' })
    const onSelectionChange = vi.fn()
    renderTable({ alerts: [alert], selectedIds: new Set(), onSelectionChange })

    fireEvent.click(screen.getByRole('button', { name: /Select alert-1/i }))
    expect(onSelectionChange).toHaveBeenCalledWith(new Set(['alert-1']))
  })

  it('select-all toggles all rows on page', () => {
    const alerts = [makeAlert({ id: 'a1' }), makeAlert({ id: 'a2' })]
    const onSelectionChange = vi.fn()
    renderTable({ alerts, selectedIds: new Set(), onSelectionChange })

    fireEvent.click(screen.getByRole('button', { name: /Select all/i }))
    expect(onSelectionChange).toHaveBeenCalledWith(new Set(['a1', 'a2']))
  })

  it('shows bulk action bar when items are selected', () => {
    const alert = makeAlert({ id: 'alert-1' })
    const onBulkAction = vi.fn()
    renderTable({ alerts: [alert], selectedIds: new Set(['alert-1']), onBulkAction })
    // Bulk bar + table footer both show selection count
    expect(screen.getAllByText(/1 selected/i).length).toBeGreaterThanOrEqual(1)
    expect(screen.getByRole('button', { name: 'Set In Progress' })).toBeInTheDocument()
  })

  it('navigates to alert detail on row click', () => {
    const alert = makeAlert({ id: 'detail-id', title: 'Click Me' })
    renderTable({ alerts: [alert] })
    fireEvent.click(screen.getByText('Click Me'))
    expect(mockNavigate).toHaveBeenCalledWith('/app/alerts/detail-id')
  })

  it('disables Previous button on page 1', () => {
    // Need total > pageSize for pagination to render
    const alerts = Array.from({ length: 10 }, () => makeAlert())
    renderTable({ alerts, total: 100, page: 1, pageSize: 10, onPageChange: vi.fn() })
    expect(screen.getByRole('button', { name: 'Previous' })).toBeDisabled()
  })

  it('enables Next button when more pages exist', () => {
    const alerts = Array.from({ length: 10 }, () => makeAlert())
    renderTable({ alerts, total: 100, page: 1, pageSize: 10, onPageChange: vi.fn() })
    expect(screen.getByRole('button', { name: 'Next' })).not.toBeDisabled()
  })

  it('disables Next button on last page', () => {
    // total=100, pageSize=10, page=10 → last page
    const alerts = Array.from({ length: 10 }, () => makeAlert())
    renderTable({ alerts, total: 100, page: 10, pageSize: 10, onPageChange: vi.fn() })
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
  })

  it('enables Previous button on page 2', () => {
    const alerts = Array.from({ length: 10 }, () => makeAlert())
    renderTable({ alerts, total: 100, page: 2, pageSize: 10, onPageChange: vi.fn() })
    expect(screen.getByRole('button', { name: 'Previous' })).not.toBeDisabled()
  })

  it('sorts by severity ascending puts Low before Critical', () => {
    const low = makeAlert({ id: 'l', title: 'Low Alert', severity: 'Low' })
    const crit = makeAlert({ id: 'c', title: 'Critical Alert', severity: 'Critical' })
    renderTable({ alerts: [crit, low], sortKey: 'severity', sortDir: 'asc' })
    const rows = screen.getAllByRole('row')
    // rows[0] = header, rows[1] = first data row
    expect(rows[1]).toHaveTextContent('Low Alert')
    expect(rows[2]).toHaveTextContent('Critical Alert')
  })
})
