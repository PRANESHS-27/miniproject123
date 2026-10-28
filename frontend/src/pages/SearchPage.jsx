import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import toast from 'react-hot-toast'
import PageHeader from '../components/PageHeader.jsx'
import Spinner from '../components/Spinner.jsx'
import EmptyState from '../components/EmptyState.jsx'
import Button from '../components/Button.jsx'
import { Card, CardHeader, CardTitle, CardBody } from '../components/Card.jsx'
import { SeverityBadge } from '../components/Badge.jsx'
import { formatScore, formatShortDate } from '../utils/format.jsx'
import { Table, THead, TBody, Tr, Th, Td } from '../components/Table.jsx'
import { vulnerabilities as vulnApi } from '../services/api.js'

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'NONE']
const PAGE_SIZE = 20

function readFilters(searchParams) {
  return {
    q: searchParams.get('q') || '',
    severity: searchParams.get('severity') || '',
    in_kev: searchParams.get('in_kev') || '',
    vendor: searchParams.get('vendor') || '',
    days: searchParams.get('days') || '',
    page: Math.max(1, parseInt(searchParams.get('page') || '1', 10) || 1),
  }
}

export default function SearchPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const filters = useMemo(() => readFilters(searchParams), [searchParams])
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(true)
  // Debounced query keeps URL state stable while the user types; the URL
  // updates only after the user pauses so we don't burn NVD lookups on
  // every keystroke.
  const [inputQ, setInputQ] = useState(filters.q)
  const [searchSeq, setSearchSeq] = useState(0) // bump to force a search when the user hits Search

  const updateFilter = useCallback((patch) => {
    const next = new URLSearchParams(searchParams)
    for (const [k, v] of Object.entries(patch)) {
      if (v === '' || v === null || v === undefined) next.delete(k)
      else next.set(k, v)
    }
    if (!('page' in patch)) next.set('page', '1')
    setSearchParams(next, { replace: false })
  }, [searchParams, setSearchParams])

  // Push inputQ -> URL `q` after 450ms of idleness.
  useEffect(() => {
    if (inputQ === filters.q) return
    const h = setTimeout(() => updateFilter({ q: inputQ }), 450)
    return () => clearTimeout(h)
  }, [inputQ, filters.q, updateFilter])

  const runSearch = useCallback(async (signal) => {
    setLoading(true)
    try {
      const params = {
        q: filters.q || undefined,
        severity: filters.severity || undefined,
        in_kev: filters.in_kev === '' ? undefined : filters.in_kev === 'true',
        vendor: filters.vendor || undefined,
        days: filters.days ? Number(filters.days) : undefined,
        limit: PAGE_SIZE,
        offset: (filters.page - 1) * PAGE_SIZE,
      }
      const data = await vulnApi.search(params, { signal })
      setResults(data)
    } catch (err) {
      if (err && (err.name === 'CanceledError' || err.name === 'AbortError' || err.code === 'ERR_CANCELED')) return
      toast.error('Search failed')
    } finally {
      setLoading(false)
    }
  }, [filters])

  // Re-run on filter or searchSeq change. Abort previous in-flight request
  // so a slow earlier response can't overwrite a newer one.
  useEffect(() => {
    const controller = new AbortController()
    runSearch(controller.signal)
    return () => controller.abort('search updated')
  }, [runSearch, searchSeq])

  const total = results?.total ?? 0
  const totalPages = total > 0 ? Math.ceil(total / PAGE_SIZE) : 1
  const start = total === 0 ? 0 : (filters.page - 1) * PAGE_SIZE + 1
  const end = Math.min(total, filters.page * PAGE_SIZE)

  const reset = () => {
    setInputQ('')
    setSearchParams(new URLSearchParams(), { replace: true })
  }

  const activeFilterCount = (filters.severity ? 1 : 0)
    + (filters.in_kev ? 1 : 0)
    + (filters.vendor ? 1 : 0)
    + (filters.days ? 1 : 0)
    + (filters.q ? 1 : 0)

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="Search vulnerabilities"
        subtitle="Filter the CVE database by keyword, severity, vendor, or CISA KEV status."
      />

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between w-full flex-wrap gap-2">
            <CardTitle>Filters</CardTitle>
            {activeFilterCount > 0 && (
              <span className="text-[11px] font-semibold uppercase tracking-wide text-brand-600 dark:text-brand-300">
                {activeFilterCount} active
              </span>
            )}
          </div>
        </CardHeader>
        <CardBody className="pt-0 space-y-3">
          <div className="grid md:grid-cols-5 gap-3">
            <input
              className="input md:col-span-2"
              placeholder="Search keyword, CVE id, vendor, product, CWE…"
              value={inputQ}
              onChange={(e) => setInputQ(e.target.value)}
            />
            <select className="input" value={filters.severity} onChange={(e) => updateFilter({ severity: e.target.value })}>
              <option value="">All severities</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <select className="input" value={filters.in_kev} onChange={(e) => updateFilter({ in_kev: e.target.value })}>
              <option value="">KEV — any</option>
              <option value="true">In CISA KEV</option>
              <option value="false">Not in KEV</option>
            </select>
            <Button variant="primary" onClick={() => setSearchSeq((s) => s + 1)} leftIcon={
              <svg viewBox="0 0 24 24" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="7" /><path d="m21 21-4.3-4.3" />
              </svg>
            }>
              Search
            </Button>
          </div>
          <div className="grid md:grid-cols-3 gap-3">
            <input className="input" placeholder="Vendor (e.g. apache)" value={filters.vendor} onChange={(e) => updateFilter({ vendor: e.target.value })} />
            <input className="input" placeholder="Last N days" type="number" min="1" value={filters.days} onChange={(e) => updateFilter({ days: e.target.value })} />
            <Button variant="ghost" onClick={reset}>Reset filters</Button>
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between w-full flex-wrap gap-2">
            <div className="flex items-center gap-2">
              <CardTitle>
                {loading ? 'Searching…' : `${total.toLocaleString()} result${total === 1 ? '' : 's'} found`}
              </CardTitle>
            </div>
            <span className="text-xs text-slate-500 dark:text-slate-400">
              {total > 0
                ? <>Showing <span className="font-semibold text-slate-700 dark:text-slate-200">{start.toLocaleString()}</span>–<span className="font-semibold text-slate-700 dark:text-slate-200">{end.toLocaleString()}</span> of <span className="font-semibold text-slate-700 dark:text-slate-200">{total.toLocaleString()}</span></>
                : 'No results'}
            </span>
          </div>
        </CardHeader>
        <CardBody className="pt-0">
          {loading && !results ? (
            <div className="py-12"><Spinner label="Loading results…" /></div>
          ) : total === 0 ? (
            <EmptyState
              title="No matches"
              description="Try widening the keyword, dropping the severity filter, or clearing the vendor filter."
            />
          ) : (
            <Table>
              <THead>
                <tr>
                  <Th>CVE</Th>
                  <Th>Severity</Th>
                  <Th>CVSS</Th>
                  <Th>Published</Th>
                  <Th>KEV</Th>
                  <Th>Title</Th>
                </tr>
              </THead>
              <TBody>
                {results.results.map((r) => (
                  <Tr key={r.cve_id}>
                    <Td>
                      <Link to={`/cve/${encodeURIComponent(r.cve_id)}`} className="link-underline font-mono">
                        {r.cve_id}
                      </Link>
                    </Td>
                    <Td><SeverityBadge severity={r.severity} /></Td>
                    <Td className="text-slate-700 dark:text-slate-200 tabular-nums">{formatScore(r.cvss_v3_score)}</Td>
                    <Td className="text-slate-500 dark:text-slate-400">{formatShortDate(r.published)}</Td>
                    <Td>{r.in_kev ? <span className="badge bg-danger-50 text-danger-700 border-danger-200 dark:bg-danger-950/40 dark:text-danger-300 dark:border-danger-800/60">Yes</span> : <span className="text-slate-400">—</span>}</Td>
                    <Td className="max-w-md truncate">{r.title}</Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          )}
        </CardBody>
        {results && total > 0 && (
          <div className="flex flex-wrap justify-between items-center gap-2 border-t border-slate-100 dark:border-slate-800 px-5 py-3 text-sm bg-slate-50/60 dark:bg-slate-900/40 rounded-b-2xl">
            <Button variant="secondary" size="sm" disabled={filters.page <= 1} onClick={() => updateFilter({ page: String(filters.page - 1) })}>
              ← Previous
            </Button>
            <span className="text-slate-500 dark:text-slate-400">
              Page <span className="font-semibold text-slate-700 dark:text-slate-200">{filters.page}</span> of <span className="font-semibold text-slate-700 dark:text-slate-200">{totalPages}</span>
            </span>
            <Button variant="secondary" size="sm" disabled={filters.page >= totalPages} onClick={() => updateFilter({ page: String(filters.page + 1) })}>
              Next →
            </Button>
          </div>
        )}
      </Card>
    </div>
  )
}
