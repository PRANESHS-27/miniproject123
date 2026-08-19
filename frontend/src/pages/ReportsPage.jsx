import { useState } from 'react'
import toast from 'react-hot-toast'
import PageHeader from '../components/PageHeader.jsx'
import { Card, CardBody, CardHeader, CardTitle } from '../components/Card.jsx'
import { reports as reportsApi } from '../services/api.js'
import { useAuth } from '../context/AuthContext.jsx'
import { can } from '../hooks/permissions.js'

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'NONE']

export default function ReportsPage() {
  const { user } = useAuth()
  const [filters, setFilters] = useState({ severity: '', kev: '', days: '' })
  const [busy, setBusy] = useState(false)
  const [last, setLast] = useState(null)

  const isAdmin = can(user, 'report_generate')
  const update = (k) => (e) => setFilters((f) => ({ ...f, [k]: e.target.value }))

  const params = {
    severity: filters.severity || undefined,
    kev: filters.kev === '' ? undefined : filters.kev === 'true',
    days: filters.days || undefined,
  }

  const download = async (kind) => {
    if (!isAdmin) {
      toast.error('Admin access required.')
      return
    }
    if (busy) return
    setBusy(true)
    try {
      const filename = kind === 'pdf'
        ? await reportsApi.pdf(params)
        : await reportsApi.csv(params)
      toast.success(`Downloaded ${filename}`)
      setLast({ kind, filename, at: new Date() })
    } catch (e) {
      toast.error(e.response?.data?.detail || 'Report generation failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="Reports"
        subtitle="Export filtered vulnerability data as PDF or CSV — useful for compliance and audits."
      />

      {!isAdmin && (
        <Card className="bg-amber-50 border-amber-200 dark:bg-amber-950/30 dark:border-amber-900/60">
          <CardBody className="flex items-start gap-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-amber-100 text-amber-700 dark:bg-amber-950/60 dark:text-amber-300">
              <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                <path d="M12 9v4M12 17h.01" />
              </svg>
            </span>
            <div>
              <p className="font-semibold text-amber-900 dark:text-amber-200">Admin access required</p>
              <p className="text-sm text-amber-800 dark:text-amber-300">You can still browse data on the dashboard. Reports are restricted to admins.</p>
            </div>
          </CardBody>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Filters</CardTitle>
        </CardHeader>
        <CardBody className="pt-0">
          <div className="grid md:grid-cols-3 gap-3">
            <div>
              <label className="label">Severity</label>
              <select className="input" value={filters.severity} onChange={update('severity')}>
                <option value="">All severities</option>
                {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="label">KEV status</label>
              <select className="input" value={filters.kev} onChange={update('kev')}>
                <option value="">Any</option>
                <option value="true">In CISA KEV</option>
                <option value="false">Not in KEV</option>
              </select>
            </div>
            <div>
              <label className="label">Window</label>
              <input className="input" placeholder="Last N days" type="number" min="1" value={filters.days} onChange={update('days')} />
            </div>
          </div>
          <div className="mt-4 flex flex-wrap gap-2 pt-4 border-t border-slate-100 dark:border-slate-800">
            <button
              className="inline-flex items-center justify-center gap-2 font-medium transition-all
                         focus-visible:outline-none disabled:opacity-50 disabled:cursor-not-allowed
                         h-10 px-4 text-sm rounded-lg bg-gradient-to-b from-brand-500 to-brand-600
                         hover:from-brand-600 hover:to-brand-700 text-white shadow-sm shadow-brand-700/20
                         disabled:from-brand-500 disabled:to-brand-600"
              disabled={!isAdmin || busy}
              onClick={() => download('pdf')}
            >
              {busy ? (
                <span className="h-3 w-3 inline-block animate-spin rounded-full border-2 border-white/40 border-t-white" />
              ) : (
                <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" />
                  <path d="M14 3v6h6" />
                </svg>
              )}
              {busy ? 'Generating…' : 'Generate PDF'}
            </button>
            <button
              className="inline-flex items-center justify-center gap-2 font-medium transition-all
                         focus-visible:outline-none disabled:opacity-50 disabled:cursor-not-allowed
                         h-10 px-4 text-sm rounded-lg bg-white border border-slate-200 text-slate-700
                         hover:bg-slate-50 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-100 dark:hover:bg-slate-700
                         disabled:opacity-50"
              disabled={!isAdmin || busy}
              onClick={() => download('csv')}
            >
              <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                <path d="m7 10 5 5 5-5" />
                <path d="M12 15V3" />
              </svg>
              Download CSV
            </button>
          </div>
        </CardBody>
      </Card>

      {last && (
        <Card>
          <CardBody className="py-3.5 flex items-center gap-3 text-sm text-slate-600 dark:text-slate-300">
            <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-success-50 text-success-600 dark:bg-success-950/40 dark:text-success-300">
              <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M20 6 9 17l-5-5" />
              </svg>
            </span>
            <span>
              <span className="font-medium text-slate-700 dark:text-slate-200">Last download:</span>{' '}
              <span className="font-mono">{last.filename}</span> · {last.kind.toUpperCase()} · {last.at.toLocaleString()}
            </span>
          </CardBody>
        </Card>
      )}
    </div>
  )
}
