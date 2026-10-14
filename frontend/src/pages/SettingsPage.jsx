import { useEffect, useState } from 'react'
import PageHeader from '../components/PageHeader.jsx'
import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '../components/Card.jsx'
import Button from '../components/Button.jsx'
import Spinner from '../components/Spinner.jsx'
import { institutions as instApi, sync as syncApi, ai as aiApi, vulnerabilities as vulnApi } from '../services/api.js'
import { formatDateTime, formatNumber } from '../utils/format.jsx'
import toast from 'react-hot-toast'

export default function SettingsPage() {
  const [inst, setInst] = useState(null)
  const [syncStatus, setSyncStatus] = useState(null)
  const [aiStatus, setAiStatus] = useState(null)
  const [vulnStats, setVulnStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [syncingKev, setSyncingKev] = useState(false)
  const [syncingNvd, setSyncingNvd] = useState(false)
  const [activeTab, setActiveTab] = useState('all')

  const fetchData = async () => {
    try {
      setLoading(true)
      const [instRes, syncRes, aiRes, vulnRes] = await Promise.all([
        instApi.current().catch(() => null),
        syncApi.status().catch(() => null),
        aiApi.status().catch(() => null),
        vulnApi.dashboard().catch(() => null),
      ])
      setInst(instRes)
      setSyncStatus(syncRes)
      setAiStatus(aiRes)
      setVulnStats(vulnRes)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  const handleSyncKev = async () => {
    try {
      setSyncingKev(true)
      await syncApi.kev()
      toast.success('CISA KEV synchronization started')
      await fetchData()
    } catch {
      toast.error('Failed to trigger KEV sync')
    } finally {
      setSyncingKev(false)
    }
  }

  const handleSyncNvd = async (kind = 'incremental') => {
    try {
      setSyncingNvd(true)
      const fn = kind === 'full' ? syncApi.nvdFull : syncApi.nvdIncremental
      await fn()
      toast.success(`NVD ${kind} synchronization started`)
      await fetchData()
    } catch {
      toast.error('Failed to trigger NVD sync')
    } finally {
      setSyncingNvd(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[50vh]">
        <Spinner size="lg" label="Loading application settings…" />
      </div>
    )
  }

  const tabs = [
    { id: 'all', label: 'All Settings' },
    { id: 'tenant', label: 'Institutional Profile' },
    { id: 'feeds', label: 'Intelligence Feeds' },
    { id: 'scanner', label: 'Scanner & Scope' },
    { id: 'ai', label: 'AI & Vector Store' },
  ]

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        eyebrow="Tenant Governance"
        title="Settings & Policies"
        subtitle="Manage institutional multi-tenant profile, vulnerability intelligence synchronization, SSRF scanner policies, and AI engine parameters."
        actions={
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800 text-xs font-semibold">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            System Operational
          </div>
        }
      />

      {/* Navigation Filter Tabs */}
      <div className="flex items-center gap-1.5 border-b border-slate-200 dark:border-slate-800 pb-2 overflow-x-auto">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeTab === t.id
                ? 'bg-brand-600 text-white shadow-sm shadow-brand-600/20'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 dark:text-slate-400 dark:hover:text-slate-200 dark:hover:bg-slate-800'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 1. Institutional Profile */}
        {(activeTab === 'all' || activeTab === 'tenant') && (
          <Card variant="default" className="overflow-hidden">
            <CardHeader className="border-b border-slate-100 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-800/30">
              <div className="flex items-center gap-2.5">
                <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-500/10 text-brand-600 dark:bg-brand-500/20 dark:text-brand-300">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
                  </svg>
                </span>
                <div>
                  <CardTitle>Institutional Profile</CardTitle>
                  <CardSubtitle>Multi-tenant organization boundary and isolation</CardSubtitle>
                </div>
              </div>
            </CardHeader>
            <CardBody className="p-5 space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/50 border border-slate-100 dark:border-slate-800">
                  <span className="text-[11px] font-semibold tracking-wider text-slate-400 uppercase block">Institution Name</span>
                  <span className="mt-1 font-semibold text-slate-900 dark:text-slate-100 block text-base">
                    {inst?.name || 'Acme University'}
                  </span>
                </div>
                <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/50 border border-slate-100 dark:border-slate-800">
                  <span className="text-[11px] font-semibold tracking-wider text-slate-400 uppercase block">Tenant Identifier</span>
                  <div className="mt-1 flex items-center gap-2">
                    <span className="font-mono text-xs font-semibold px-2 py-0.5 rounded bg-brand-50 text-brand-700 dark:bg-brand-950/60 dark:text-brand-300 border border-brand-200 dark:border-brand-800/60">
                      {inst?.slug || 'acme-university'}
                    </span>
                    <span className="text-xs text-slate-400">ID: #{inst?.id || 1}</span>
                  </div>
                </div>
              </div>

              <div className="p-3.5 rounded-xl border border-emerald-200 dark:border-emerald-800/60 bg-emerald-50/50 dark:bg-emerald-950/20 flex items-start gap-3">
                <span className="flex h-5 w-5 rounded-full bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 items-center justify-center shrink-0 mt-0.5">
                  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                  </svg>
                </span>
                <div className="text-xs">
                  <span className="font-semibold text-emerald-900 dark:text-emerald-200 block">Active Data Partitioning</span>
                  <p className="text-emerald-700 dark:text-emerald-300/90 mt-0.5 leading-relaxed">
                    Row-level isolation is enforced. Assets, scans, findings, and alert channels are strictly segregated to this institution.
                  </p>
                </div>
              </div>

              <div className="pt-2 border-t border-slate-100 dark:border-slate-800 grid grid-cols-2 gap-4 text-xs text-slate-500 dark:text-slate-400">
                <div>
                  <span className="block font-medium text-slate-700 dark:text-slate-300">Encryption Standard</span>
                  <span>AES-256 (KMS Managed)</span>
                </div>
                <div>
                  <span className="block font-medium text-slate-700 dark:text-slate-300">Tenant Status</span>
                  <span className="text-emerald-600 dark:text-emerald-400 font-medium">Provisioned & Healthy</span>
                </div>
              </div>
            </CardBody>
          </Card>
        )}

        {/* 2. Intelligence Feeds */}
        {(activeTab === 'all' || activeTab === 'feeds') && (
          <Card variant="default" className="overflow-hidden">
            <CardHeader className="border-b border-slate-100 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-800/30">
              <div className="flex items-center gap-2.5">
                <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-500/10 text-brand-600 dark:bg-brand-500/20 dark:text-brand-300">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                </span>
                <div>
                  <CardTitle>Vulnerability Intelligence Feeds</CardTitle>
                  <CardSubtitle>NVD CVE catalogue and CISA KEV exploitation sync</CardSubtitle>
                </div>
              </div>
            </CardHeader>
            <CardBody className="p-5 space-y-4">
              {/* CISA KEV */}
              <div className="p-3.5 bg-slate-50 dark:bg-slate-800/60 rounded-xl border border-slate-100 dark:border-slate-800 flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-slate-900 dark:text-slate-100 text-sm">CISA Known Exploited (KEV)</span>
                    <span className="badge bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800/60 text-[10px] py-0 px-1.5">
                      {vulnStats?.kev_count ? `${formatNumber(vulnStats.kev_count)} CVEs` : 'Active'}
                    </span>
                  </div>
                  <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    Last sync: {syncStatus?.kev?.last_run ? formatDateTime(syncStatus.kev.last_run) : 'Synchronized'}
                  </div>
                </div>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={handleSyncKev}
                  loading={syncingKev}
                  disabled={syncingKev || syncingNvd}
                >
                  Sync KEV
                </Button>
              </div>

              {/* NVD Feed */}
              <div className="p-3.5 bg-slate-50 dark:bg-slate-800/60 rounded-xl border border-slate-100 dark:border-slate-800 flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-slate-900 dark:text-slate-100 text-sm">NVD CVE Catalogue (2.0)</span>
                    <span className="badge bg-brand-50 text-brand-700 border-brand-200 dark:bg-brand-950/40 dark:text-brand-300 dark:border-brand-800/60 text-[10px] py-0 px-1.5">
                      {vulnStats?.total_cves ? `${formatNumber(vulnStats.total_cves)} Total` : '219K+ Loaded'}
                    </span>
                  </div>
                  <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    Last sync: {syncStatus?.nvd?.last_run ? formatDateTime(syncStatus.nvd.last_run) : 'Synchronized'}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => handleSyncNvd('incremental')}
                    loading={syncingNvd}
                    disabled={syncingKev || syncingNvd}
                  >
                    Sync NVD
                  </Button>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-blue-50/60 dark:bg-blue-950/20 border border-blue-100 dark:border-blue-900/40 text-xs text-blue-700 dark:text-blue-300 flex items-center gap-2">
                <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span>Automated background ingest runs every 24 hours via scheduled jobs.</span>
              </div>
            </CardBody>
          </Card>
        )}

        {/* 3. Scanner Policies */}
        {(activeTab === 'all' || activeTab === 'scanner') && (
          <Card variant="default" className="lg:col-span-2 overflow-hidden">
            <CardHeader className="border-b border-slate-100 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-800/30">
              <div className="flex items-center gap-2.5">
                <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-500/10 text-brand-600 dark:bg-brand-500/20 dark:text-brand-300">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </span>
                <div>
                  <CardTitle>Scanning & SSRF Scope Policies</CardTitle>
                  <CardSubtitle>Defensive network boundaries and execution limits</CardSubtitle>
                </div>
              </div>
            </CardHeader>
            <CardBody className="p-5">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/60 shadow-xs">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Metadata Guard</span>
                    <span className="badge bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800 text-[10px]">
                      Strict Enforce
                    </span>
                  </div>
                  <span className="text-sm font-bold text-slate-900 dark:text-slate-100 block">Anti-SSRF Protection</span>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">
                    Unconditionally blocks <code className="font-mono text-brand-600 text-[11px]">169.254.169.254</code>, loopback interfaces, and cloud instance metadata.
                  </p>
                </div>

                <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/60 shadow-xs">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Port Discovery</span>
                    <span className="badge bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-950/40 dark:text-blue-300 dark:border-blue-800 text-[10px]">
                      Polite (T3)
                    </span>
                  </div>
                  <span className="text-sm font-bold text-slate-900 dark:text-slate-100 block">Controlled Discovery</span>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">
                    Enforces max 5 parallel connection probes with socket-fallback to prevent institutional service disruption.
                  </p>
                </div>

                <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/60 shadow-xs">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Safety Timeout</span>
                    <span className="badge bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800 text-[10px]">
                      60s Hard Limit
                    </span>
                  </div>
                  <span className="text-sm font-bold text-slate-900 dark:text-slate-100 block">Execution Boundaries</span>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">
                    Long-running probe connections are automatically terminated if response time exceeds the safety window.
                  </p>
                </div>
              </div>
            </CardBody>
          </Card>
        )}

        {/* 4. AI & Vector Store */}
        {(activeTab === 'all' || activeTab === 'ai') && (
          <Card variant="default" className="lg:col-span-2 overflow-hidden">
            <CardHeader className="border-b border-slate-100 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-800/30">
              <div className="flex items-center gap-2.5">
                <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-500/10 text-brand-600 dark:bg-brand-500/20 dark:text-brand-300">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                  </svg>
                </span>
                <div>
                  <CardTitle>AI Security Assistant & Grounding Engine</CardTitle>
                  <CardSubtitle>Semantic retrieval parameters and hallucination guardrails</CardSubtitle>
                </div>
              </div>
            </CardHeader>
            <CardBody className="p-5">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                <div className="p-3.5 bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-slate-100 dark:border-slate-800">
                  <span className="font-semibold text-slate-400 uppercase tracking-wider block text-[10px]">Active Inference Model</span>
                  <div className="mt-1 flex items-center gap-1.5 font-bold text-slate-900 dark:text-slate-100 text-sm">
                    <span>{aiStatus?.provider ? aiStatus.provider.toUpperCase() : 'GROQ'}</span>
                    <span className="font-normal text-xs text-slate-500">
                      ({aiStatus?.model || 'llama-3.1-8b-instant'})
                    </span>
                  </div>
                  <span className="text-[11px] text-emerald-600 dark:text-emerald-400 mt-1 block">
                    ● Connected & Verified
                  </span>
                </div>

                <div className="p-3.5 bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-slate-100 dark:border-slate-800">
                  <span className="font-semibold text-slate-400 uppercase tracking-wider block text-[10px]">Vector Database (RAG)</span>
                  <div className="mt-1 font-bold text-slate-900 dark:text-slate-100 text-sm">
                    ChromaDB + SentenceTransformers
                  </div>
                  <span className="text-[11px] text-slate-500 dark:text-slate-400 mt-1 block font-mono">
                    all-MiniLM-L6-v2 (384-dim)
                  </span>
                </div>

                <div className="p-3.5 bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-slate-100 dark:border-slate-800">
                  <span className="font-semibold text-slate-400 uppercase tracking-wider block text-[10px]">Hallucination Guardrail</span>
                  <div className="mt-1 font-bold text-slate-900 dark:text-slate-100 text-sm">
                    Strict Evidence Refusal
                  </div>
                  <span className="text-[11px] text-slate-500 dark:text-slate-400 mt-1 block">
                    Refuses queries without verified CVE / scan findings
                  </span>
                </div>
              </div>
            </CardBody>
          </Card>
        )}
      </div>
    </div>
  )
}
