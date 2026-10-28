import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import toast from 'react-hot-toast'
import PageHeader from '../components/PageHeader.jsx'
import Spinner from '../components/Spinner.jsx'
import Button from '../components/Button.jsx'
import { Card, CardBody } from '../components/Card.jsx'
import { SeverityBadge } from '../components/Badge.jsx'
import { Table, THead, TBody, Tr, Th, Td } from '../components/Table.jsx'
import { findings as findingsApi } from '../services/api.js'
import { useAuth } from '../context/AuthContext.jsx'
import { can } from '../hooks/permissions.js'
import { formatError } from '../utils/format.jsx'

// Stable display order so the risk filter and the badge colours always
// line up with the dashboard's risk-distribution widget.
const RISK_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const STATUS_LEVELS = ['open', 'in_progress', 'verified', 'resolved', 'accepted_risk']
const PAGE_SIZE = 20

function readFilters(searchParams) {
  return {
    risk: searchParams.get('risk') || '',
    status: searchParams.get('status') || '',
    q: searchParams.get('q') || '',
    page: Math.max(1, parseInt(searchParams.get('page') || '1', 10) || 1),
  }
}

function relativeTime(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  const diff = Math.round((Date.now() - d.getTime()) / 1000)
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

export default function FindingsPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const filters = useMemo(() => readFilters(searchParams), [searchParams])
  const [results, setResults] = useState(null)
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [inputQ, setInputQ] = useState(filters.q)
  const [busyId, setBusyId] = useState(null)
  const [acceptFor, setAcceptFor] = useState(null)
  const [acceptReason, setAcceptReason] = useState('')
  const { user } = useAuth()
  const canUpdate = can(user, 'finding_update')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params = {
        page: filters.page,
        page_size: PAGE_SIZE,
      }
      if (filters.risk) params.risk = filters.risk
      if (filters.status) params.status = filters.status
      if (filters.q) params.q = filters.q
      const [list, s] = await Promise.all([findingsApi.list(params), findingsApi.stats()])
      setResults(list)
      setStats(s)
    } catch (e) {
      toast.error(formatError(e, 'Failed to load findings'))
    } finally {
      setLoading(false)
    }
  }, [filters.page, filters.risk, filters.status, filters.q])

  useEffect(() => { load() }, [load])

  const updateFilter = useCallback((patch) => {
    const next = new URLSearchParams(searchParams)
    for (const [k, v] of Object.entries(patch)) {
      if (v === '' || v == null) next.delete(k)
      else next.set(k, v)
    }
    // any filter change resets the page
    if (!('page' in patch)) next.set('page', '1')
    setSearchParams(next)
  }, [searchParams, setSearchParams])

  const setPage = (p) => updateFilter({ page: p })

  // Debounce free-text search so each keystroke doesn't fire a request.
  useEffect(() => {
    const t = setTimeout(() => {
      if (inputQ !== filters.q) updateFilter({ q: inputQ })
    }, 450)
    return () => clearTimeout(t)
  }, [inputQ])

  const changeStatus = async (f, newStatus) => {
    if (!canUpdate) return toast.error('Analyst or admin only')
    setBusyId(f.id)
    try {
      await findingsApi.update(f.id, { status: newStatus })
      toast.success(`Finding ${f.vulnerability_cve_id} → ${newStatus}`)
      load()
    } catch (e) {
      toast.error(formatError(e, 'Update failed'))
    } finally {
      setBusyId(null)
    }
  }

  const submitAcceptRisk = async () => {
    if (!acceptFor) return
    if (!acceptReason.trim()) return toast.error('Reason required')
    setBusyId(acceptFor.id)
    try {
      await findingsApi.acceptRisk(acceptFor.id, acceptReason.trim())
      toast.success(`Accepted risk for ${acceptFor.vulnerability_cve_id}`)
      setAcceptFor(null)
      setAcceptReason('')
      load()
    } catch (e) {
      toast.error(formatError(e, 'Accept-risk failed'))
    } finally {
      setBusyId(null)
    }
  }

  const total = results?.total || 0
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE))

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        eyebrow="Risk Engine"
        title="Findings"
        subtitle="Every (CVE × asset) match the engine has scored. Highest risk first."
      />

      {/* Headline counters — wired straight from /api/findings/stats */}
      {stats && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard label="Open HIGH/CRITICAL" value={stats.open_high_or_critical} accent="danger" />
          <StatCard label="Open KEV" value={stats.kev_open} accent="warning" />
          <StatCard label="Total findings" value={stats.total} accent="brand" />
          <StatCard
            label="Resolved"
            value={stats.by_status?.resolved || 0}
            accent="success"
          />
        </div>
      )}

      {/* Filters */}
      <Card>
        <CardBody className="space-y-3">
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <label className="block">
              <span className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Search</span>
              <input
                type="text"
                value={inputQ}
                onChange={(e) => setInputQ(e.target.value)}
                placeholder="CVE id, title, description…"
                className="w-full rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5 text-sm"
              />
            </label>
            <label className="block">
              <span className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Risk</span>
              <select
                value={filters.risk}
                onChange={(e) => updateFilter({ risk: e.target.value })}
                className="w-full rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5 text-sm"
              >
                <option value="">All</option>
                {RISK_LEVELS.map((r) => <option key={r} value={r}>{r}</option>)}
              </select>
            </label>
            <label className="block">
              <span className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Status</span>
              <select
                value={filters.status}
                onChange={(e) => updateFilter({ status: e.target.value })}
                className="w-full rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5 text-sm"
              >
                <option value="">All</option>
                {STATUS_LEVELS.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </label>
            <div className="flex items-end">
              <Button variant="secondary" size="sm" onClick={() => { setInputQ(''); updateFilter({ q: '', risk: '', status: '' }) }}>
                Clear filters
              </Button>
            </div>
          </div>
        </CardBody>
      </Card>

      {/* Table */}
      <Card>
        <CardBody className="p-0">
          {loading || !results ? (
            <div className="flex items-center justify-center min-h-[40vh]">
              <Spinner label="Loading findings…" />
            </div>
          ) : results.items.length === 0 ? (
            <div className="p-10 text-center text-sm text-slate-500 dark:text-slate-400">
              No findings match your filters. Try clearing them or running a sync.
            </div>
          ) : (
            <Table>
              <THead>
                <Tr>
                  <Th>CVE</Th>
                  <Th>Asset</Th>
                  <Th>Risk</Th>
                  <Th>Status</Th>
                  <Th>Source</Th>
                  <Th>Created</Th>
                  {canUpdate && <Th>Actions</Th>}
                </Tr>
              </THead>
              <TBody>
                {results.items.map((f) => (
                  <Tr key={f.id}>
                    <Td>
                      <Link
                        to={`/cve/${encodeURIComponent(f.vulnerability_cve_id)}`}
                        className="font-mono text-xs font-semibold text-brand-700 dark:text-brand-300 hover:underline"
                      >
                        {f.vulnerability_cve_id}
                      </Link>
                      {f.cve_title && (
                        <p className="text-xs text-slate-500 dark:text-slate-400 line-clamp-1 mt-0.5">
                          {f.cve_title}
                        </p>
                      )}
                    </Td>
                    <Td>
                      <Link
                        to={`/assets/${f.asset_id}`}
                        className="text-sm font-medium text-slate-800 dark:text-slate-200 hover:underline"
                      >
                        {f.asset_label || `#${f.asset_id}`}
                      </Link>
                    </Td>
                    <Td>
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={f.risk_label} />
                        <span className="text-xs text-slate-500 dark:text-slate-400 tabular-nums">{f.risk_score}</span>
                      </div>
                    </Td>
                    <Td>
                      <span className="text-xs font-medium text-slate-700 dark:text-slate-300">{f.status}</span>
                    </Td>
                    <Td>
                      <span className="text-xs text-slate-500 dark:text-slate-400">{f.source}</span>
                    </Td>
                    <Td>
                      <span className="text-xs text-slate-500 dark:text-slate-400">{relativeTime(f.created_at)}</span>
                    </Td>
                    {canUpdate && (
                      <Td>
                        <div className="flex items-center gap-1.5">
                          {f.status === 'open' && (
                            <Button size="xs" variant="secondary" loading={busyId === f.id} onClick={() => changeStatus(f, 'in_progress')}>
                              Start
                            </Button>
                          )}
                          {f.status === 'in_progress' && (
                            <Button size="xs" variant="secondary" loading={busyId === f.id} onClick={() => changeStatus(f, 'verified')}>
                              Verify
                            </Button>
                          )}
                          {f.status === 'verified' && (
                            <Button size="xs" variant="primary" loading={busyId === f.id} onClick={() => changeStatus(f, 'resolved')}>
                              Resolve
                            </Button>
                          )}
                          {(f.status === 'open' || f.status === 'in_progress' || f.status === 'verified') && (
                            <Button size="xs" variant="ghost" loading={busyId === f.id} onClick={() => { setAcceptFor(f); setAcceptReason('') }}>
                              Accept risk
                            </Button>
                          )}
                        </div>
                      </Td>
                    )}
                  </Tr>
                ))}
              </TBody>
            </Table>
          )}
        </CardBody>
      </Card>

      {/* Pagination */}
      {results && results.items.length > 0 && (
        <div className="flex items-center justify-between text-xs text-slate-600 dark:text-slate-400">
          <span>Page {filters.page} of {pageCount} · {total} finding(s)</span>
          <div className="flex gap-2">
            <Button size="xs" variant="secondary" disabled={filters.page <= 1} onClick={() => setPage(filters.page - 1)}>Prev</Button>
            <Button size="xs" variant="secondary" disabled={filters.page >= pageCount} onClick={() => setPage(filters.page + 1)}>Next</Button>
          </div>
        </div>
      )}

      {/* Accept-risk modal */}
      {acceptFor && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 p-4">
          <div className="w-full max-w-md rounded-xl bg-white dark:bg-slate-900 p-5 shadow-2xl border border-slate-200 dark:border-slate-700">
            <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">Accept risk</h3>
            <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
              <span className="font-mono">{acceptFor.vulnerability_cve_id}</span> on{' '}
              <span className="font-medium">{acceptFor.asset_label}</span> will be marked as <em>accepted_risk</em> and excluded from open queues.
            </p>
            <textarea
              value={acceptReason}
              onChange={(e) => setAcceptReason(e.target.value)}
              placeholder="Reason (required, e.g. compensating control, accepted by CISO)"
              rows={3}
              className="mt-3 w-full rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm"
            />
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="secondary" size="sm" onClick={() => setAcceptFor(null)}>Cancel</Button>
              <Button variant="primary" size="sm" loading={busyId === acceptFor.id} onClick={submitAcceptRisk}>
                Accept risk
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function StatCard({ label, value, accent }) {
  const accentMap = {
    danger: 'text-red-600 dark:text-red-400',
    warning: 'text-amber-600 dark:text-amber-400',
    brand: 'text-brand-600 dark:text-brand-300',
    success: 'text-emerald-600 dark:text-emerald-400',
  }
  return (
    <Card>
      <CardBody>
        <div className="text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400">{label}</div>
        <div className={`text-2xl font-semibold mt-1 ${accentMap[accent] || ''}`}>{value}</div>
      </CardBody>
    </Card>
  )
}
