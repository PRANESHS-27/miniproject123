import { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js'
import { Bar, Doughnut } from 'react-chartjs-2'
import toast from 'react-hot-toast'
import PageHeader from '../components/PageHeader.jsx'
import Stat from '../components/Stat.jsx'
import Spinner from '../components/Spinner.jsx'
import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '../components/Card.jsx'
import { SeverityBadge } from '../components/Badge.jsx'
import Button from '../components/Button.jsx'
import { formatScore, formatNumber, formatShortDate } from '../utils/format.jsx'
import { vulnerabilities as vulnApi, sync as syncApi } from '../services/api.js'
import { useAuth } from '../context/AuthContext.jsx'
import { can } from '../hooks/permissions.js'

ChartJS.register(CategoryScale, LinearScale, BarElement, ArcElement, Title, Tooltip, Legend)

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'NONE']

function chartPalette(isDark) {
  return {
    severity: isDark
      ? ['#FCA5A5', '#FDBA74', '#FCD34D', '#86EFAC', '#7DD3FC', '#94A3B8']
      : ['#DC2626', '#F97316', '#EAB308', '#22C55E', '#0EA5E9', '#64748B'],
    bar: isDark ? '#60a5fa' : '#2563EB',
    barHover: isDark ? '#3b82f6' : '#1d4ed8',
    grid: isDark ? 'rgba(148, 163, 184, 0.12)' : 'rgba(148, 163, 184, 0.25)',
    text: isDark ? '#cbd5e1' : '#1f2937',
  }
}

function useIsDark() {
  const [isDark, setIsDark] = useState(() => document.documentElement.classList.contains('dark'))
  useEffect(() => {
    const obs = new MutationObserver(() => setIsDark(document.documentElement.classList.contains('dark')))
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
    return () => obs.disconnect()
  }, [])
  return isDark
}

function formatRelative(date) {
  if (!date) return ''
  const diff = Math.round((Date.now() - date.getTime()) / 1000)
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

export default function DashboardPage() {
  const { user } = useAuth()
  const canSync = can(user, 'sync_trigger')
  const [stats, setStats] = useState(null)
  const [syncing, setSyncing] = useState(false)
  const [syncKind, setSyncKind] = useState(null)
  const [syncMeta, setSyncMeta] = useState(null)
  const [, setTick] = useState(0)
  const isDark = useIsDark()

  const loadStats = useCallback(() => {
    return vulnApi.dashboard().then(setStats).catch(() => toast.error('Failed to load dashboard'))
  }, [])

  useEffect(() => { loadStats() }, [loadStats])

  // Refresh the "last sync" relative time every 30s
  useEffect(() => {
    const h = setInterval(() => setTick((t) => t + 1), 30_000)
    return () => clearInterval(h)
  }, [])

  const runSync = async (kind) => {
    if (!canSync) return toast.error('Admin only')
    if (syncing) return
    setSyncing(true)
    setSyncKind(kind)
    try {
      const fn = kind === 'full' ? syncApi.nvdFull : syncApi.nvdIncremental
      const res = await fn()
      toast.success(res.message || 'Sync started')
      setSyncMeta({ kind, at: new Date() })
      setTimeout(() => loadStats(), 8000)
    } catch (e) {
      toast.error(e.response?.data?.detail || 'Sync failed')
    } finally {
      setSyncing(false)
      setSyncKind(null)
    }
  }

  const runKev = async () => {
    if (!canSync) return
    if (syncing) return
    setSyncing(true)
    setSyncKind('kev')
    try {
      await syncApi.kev()
      toast.success('KEV refresh started')
      setSyncMeta({ kind: 'kev', at: new Date() })
      setTimeout(() => loadStats(), 6000)
    } catch (e) {
      toast.error(e.response?.data?.detail || 'KEV sync failed')
    } finally {
      setSyncing(false)
      setSyncKind(null)
    }
  }

  if (!stats) return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <Spinner label="Loading dashboard…" size="lg" />
    </div>
  )

  const palette = chartPalette(isDark)
  const recent = stats.recent_cves || []

  // Stable severity ordering for the doughnut so the colour mapping never jumps
  const severityCounts = SEVERITY_ORDER.map((k) => stats.severity_distribution?.[k] || 0)
  const severityLabels = SEVERITY_ORDER
  const sevData = {
    labels: severityLabels,
    datasets: [{
      data: severityCounts,
      backgroundColor: palette.severity,
      borderColor: 'transparent',
      borderWidth: 0,
      hoverOffset: 6,
    }],
  }
  const vendorsData = {
    labels: (stats.top_vendors_for_assets || []).map((v) => v.vendor),
    datasets: [{
      label: 'CVEs',
      data: (stats.top_vendors_for_assets || []).map((v) => v.count),
      backgroundColor: palette.bar,
      hoverBackgroundColor: palette.barHover,
      borderRadius: 6,
      borderSkipped: false,
      maxBarThickness: 26,
      barPercentage: 0.7,
      categoryPercentage: 0.85,
    }],
  }
  const totalSeverityCount = severityCounts.reduce((a, b) => a + b, 0)

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        eyebrow="Live"
        title="Threat posture"
        subtitle="Continuous NVD + CISA KEV ingest with company-asset risk roll-up."
        actions={
          canSync && (
            <>
              <Button variant="secondary" size="sm" loading={syncing && syncKind === 'kev'} disabled={syncing && syncKind !== 'kev'} onClick={runKev}>
                Sync KEV
              </Button>
              <Button variant="secondary" size="sm" loading={syncing && syncKind === 'incremental'} disabled={syncing && syncKind !== 'incremental'} onClick={() => runSync('incremental')}>
                Sync recent
              </Button>
              <Button variant="primary" size="sm" loading={syncing && syncKind === 'full'} disabled={syncing && syncKind !== 'full'} onClick={() => runSync('full')}>
                Full backfill
              </Button>
            </>
          )
        }
      />

      {/* Primary KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Stat label="Total CVEs" value={formatNumber(stats.total_cves)} accent="brand" />
        <Stat label="Critical" value={formatNumber(stats.critical)} accent="danger" />
        <Stat label="High" value={formatNumber(stats.high)} accent="warning" />
        <Stat label="In CISA KEV" value={formatNumber(stats.kev_count)} accent="info" />
      </div>

      {/* Secondary KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Stat label="Medium" value={formatNumber(stats.medium)} accent="amber" size="sm" />
        <Stat label="Low" value={formatNumber(stats.low)} accent="success" size="sm" />
        <Stat label="Active assets" value={formatNumber(stats.active_assets)} accent="brand" size="sm" />
        <Stat label="Open findings" value={formatNumber(stats.open_findings)} accent="warning" size="sm" />
      </div>

      <div className="grid lg:grid-cols-3 gap-4">
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Severity mix</CardTitle>
              <CardSubtitle>Distribution across the indexed CVE store.</CardSubtitle>
            </div>
          </CardHeader>
          <CardBody className="pt-0">
            {totalSeverityCount > 0 ? (
              <Doughnut
                data={sevData}
                options={{
                  plugins: {
                    legend: {
                      position: 'bottom',
                      labels: { color: palette.text, font: { size: 11 }, boxWidth: 8, boxHeight: 8, padding: 12 },
                    },
                  },
                  cutout: '65%',
                  maintainAspectRatio: true,
                }}
              />
            ) : (
              <div className="py-10 text-center text-sm text-slate-500 dark:text-slate-400">
                No data yet — run a sync to populate.
              </div>
            )}
          </CardBody>
        </Card>
        <Card className="lg:col-span-2">
          <CardHeader>
            <div className="min-w-0">
              <CardTitle>Vendors affecting your stack</CardTitle>
              <CardSubtitle>CVEs matched against technologies detected on your assets.</CardSubtitle>
            </div>
          </CardHeader>
          <CardBody className="pt-0">
            {stats.top_vendors_for_assets?.length ? (
              <div className="relative" style={{ minHeight: Math.max(180, stats.top_vendors_for_assets.length * 38) }}>
                <Bar
                  data={vendorsData}
                  options={{
                    indexAxis: 'y',
                    plugins: { legend: { display: false } },
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                      x: {
                        ticks: { color: palette.text, precision: 0 },
                        grid: { color: palette.grid, drawBorder: false },
                        beginAtZero: true,
                      },
                      y: {
                        ticks: { color: palette.text, autoSkip: false },
                        grid: { display: false },
                      },
                    },
                  }}
                />
              </div>
            ) : (
              <div className="py-10 text-center text-sm text-slate-500 dark:text-slate-400">
                No detected technologies on active assets yet. Run a scan on an active asset to populate this chart.
              </div>
            )}
          </CardBody>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between flex-wrap gap-3 w-full">
            <div>
              <CardTitle>Recent CVEs</CardTitle>
              <CardSubtitle>Latest entries ingested from NVD.</CardSubtitle>
            </div>
            {syncMeta && (
              <span className="inline-flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
                <span className="h-1.5 w-1.5 rounded-full bg-success-500" />
                Last sync: <span className="font-medium text-slate-700 dark:text-slate-200 capitalize">{syncMeta.kind}</span> · {formatRelative(syncMeta.at)} · {syncMeta.at.toLocaleTimeString()}
              </span>
            )}
          </div>
        </CardHeader>
        <CardBody className="pt-0">
          {recent.length ? (
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3">
              {recent.slice(0, 5).map((r) => (
                <Link
                  key={r.cve_id}
                  to={`/cve/${encodeURIComponent(r.cve_id)}`}
                  className="group block rounded-xl border border-slate-200/80 bg-white p-3 transition-all hover:-translate-y-0.5 hover:border-brand-300 hover:shadow-card-hover dark:border-slate-800 dark:bg-slate-900 dark:hover:border-brand-700"
                >
                  <div className="flex items-center justify-between mb-1.5 gap-2">
                    <span className="font-mono text-xs font-semibold text-brand-700 dark:text-brand-300 truncate">{r.cve_id}</span>
                    <SeverityBadge severity={r.severity} />
                  </div>
                  <p className="text-xs text-slate-500 dark:text-slate-400 line-clamp-2 min-h-[2.5em]">
                    {r.title || 'No summary available'}
                  </p>
                  <div className="mt-2 flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400">
                    <span>CVSS {formatScore(r.cvss_v3_score)}</span>
                    <span>{formatShortDate(r.published)}</span>
                  </div>
                </Link>
              ))}
            </div>
          ) : (
            <div className="py-10 text-center text-sm text-slate-500 dark:text-slate-400">
              No vulnerabilities yet — run a sync to populate.
            </div>
          )}
        </CardBody>
      </Card>
    </div>
  )
}
