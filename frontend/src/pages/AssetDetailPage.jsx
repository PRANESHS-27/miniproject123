import { useEffect, useRef, useState, useCallback } from 'react'
import { useParams, Link, useSearchParams } from 'react-router-dom'
import toast from 'react-hot-toast'
import { api, assets as assetsApi } from '../services/api.js'
import PageHeader from '../components/PageHeader.jsx'
import Tabs from '../components/Tabs.jsx'
import Stat from '../components/Stat.jsx'
import Spinner from '../components/Spinner.jsx'
import EmptyState from '../components/EmptyState.jsx'
import Button from '../components/Button.jsx'
import { FindingBadge, SeverityBadge } from '../components/Badge.jsx'
import { Card, CardHeader, CardTitle, CardBody } from '../components/Card.jsx'
import { Table, THead, TBody, Tr, Th, Td } from '../components/Table.jsx'
import { formatDate, formatShortDate, formatScore, formatError } from '../utils/format.jsx'
import { useAuth } from '../context/AuthContext.jsx'
import { can } from '../hooks/permissions.js'

const TAB_DEFS = [
  { key: 'overview', label: 'Overview' },
  { key: 'techs',    label: 'Technologies' },
  { key: 'findings', label: 'Findings' },
  { key: 'cves',     label: 'CVEs' },
  { key: 'scans',    label: 'Scan History' },
]

const ENV_BADGE = {
  production: 'bg-danger-50 text-danger-700 border-danger-200 dark:bg-danger-950/40 dark:text-danger-300 dark:border-danger-800/60',
  staging:    'bg-warning-50 text-warning-700 border-warning-200 dark:bg-warning-950/40 dark:text-warning-300 dark:border-warning-800/60',
  dev:        'bg-info-50 text-info-700 border-info-200 dark:bg-info-950/40 dark:text-info-300 dark:border-info-800/60',
}

export default function AssetDetailPage() {
  const { id } = useParams()
  const [searchParams] = useSearchParams()
  const tab = searchParams.get('tab') || 'overview'
  const { user } = useAuth()
  const canScan = can(user, 'asset_scan')
  const canResolve = can(user, 'asset_finding_resolve')

  const [asset, setAsset] = useState(null)
  const [findings, setFindings] = useState(null)
  const [cves, setCves] = useState(null)
  const [scans, setScans] = useState(null)
  const [filterType, setFilterType] = useState('')
  const [filterSev, setFilterSev] = useState('')
  const [filterStatus, setFilterStatus] = useState('open')
  const [resolvingId, setResolvingId] = useState(null)
  const [scanning, setScanning] = useState(false)
  const [latestScanId, setLatestScanId] = useState(null)

  // Two separate refs so the asset GET never gets cancelled by a tab switch
  // (they were previously sharing `tabReqRef`, which meant switching tabs
  // killed the in-flight asset load and left the page stuck on the spinner).
  const assetReqRef = useRef(null)
  const tabReqRef = useRef(null)

  const loadAsset = useCallback(() => {
    // Cancel any in-flight asset GET first — otherwise an older request
    // can resolve after a newer one and overwrite the UI with stale data.
    if (assetReqRef.current) {
      assetReqRef.current.abort('reload')
    }
    const controller = new AbortController()
    assetReqRef.current = controller
    assetsApi.get(id, { signal: controller.signal })
      .then(setAsset)
      .catch((err) => {
        if (err && (err.name === 'CanceledError' || err.name === 'AbortError' || err.code === 'ERR_CANCELED')) return
        toast.error('Failed to load asset')
      })
  }, [id])

  useEffect(() => { loadAsset() }, [loadAsset])

  useEffect(() => () => {
    assetReqRef.current?.abort('unmount')
    tabReqRef.current?.abort('unmount')
  }, [])

  // Tab-specific loads, with cancellation when the tab or filter changes.
  useEffect(() => {
    if (tab === 'overview' || tab === 'techs') return
    if (tabReqRef.current) tabReqRef.current.abort('tab switch')
    const controller = new AbortController()
    tabReqRef.current = controller

    const handleErr = (err) => {
      if (err && (err.name === 'CanceledError' || err.name === 'AbortError' || err.code === 'ERR_CANCELED')) return
      toast.error(`Failed to load ${tab}`)
    }

    if (tab === 'findings') {
      const params = {}
      if (filterType) params.type = filterType
      if (filterSev) params.severity = filterSev
      if (filterStatus) params.status = filterStatus
      setFindings(null) // clear stale entries so the spinner reflects the new filter
      api.get(`/api/assets/${id}/findings`, { params, signal: controller.signal })
        .then((r) => setFindings(r.data))
        .catch(handleErr)
    } else if (tab === 'cves') {
      setCves(null)
      api.get(`/api/assets/${id}/cves`, { signal: controller.signal })
        .then((r) => setCves(r.data))
        .catch(handleErr)
    } else if (tab === 'scans') {
      setScans(null)
      api.get('/api/assets/scans/recent', { params: { limit: 100 }, signal: controller.signal })
        .then((r) => setScans((r.data || []).filter((s) => String(s.asset_id) === String(id))))
        .catch(handleErr)
    }
  }, [tab, id, filterType, filterSev, filterStatus])

  // Polling lifecycle — single interval on mount; cleanup is a real return.
  const pollHandleRef = useRef(null)
  useEffect(() => () => {
    if (pollHandleRef.current) {
      clearInterval(pollHandleRef.current)
      pollHandleRef.current = null
    }
  }, [])

  const onScan = async () => {
    if (scanning) return
    setScanning(true)
    try {
      const r = await assetsApi.scan(id)
      toast.success(r.message || 'Scan started')
      const POLL_INTERVAL_MS = 2_000
      const POLL_TIMEOUT_MS = 90_000
      const pollStart = Date.now()

      if (pollHandleRef.current) {
        clearInterval(pollHandleRef.current)
        pollHandleRef.current = null
      }

      pollHandleRef.current = setInterval(async () => {
        if (Date.now() - pollStart > POLL_TIMEOUT_MS) {
          clearInterval(pollHandleRef.current)
          pollHandleRef.current = null
          setScanning(false)
          toast.error('Scan timed out after 90s')
          return
        }
        try {
          const all = await assetsApi.recentScans({ limit: 5 })
          const mine = (all || []).filter((s) => String(s.asset_id) === String(id))
          if (mine[0]) {
            setLatestScanId(mine[0].id)
            if (tab === 'scans') {
              setScans((all || []).filter((s) => String(s.asset_id) === String(id)))
            }
            if (mine[0].status === 'success' || mine[0].status === 'failed') {
              clearInterval(pollHandleRef.current)
              pollHandleRef.current = null
              setScanning(false)
              loadAsset()
              if (mine[0].status === 'failed') {
                toast.error(`Scan failed: ${mine[0].error || 'unknown error'}`)
              } else {
                toast.success(
                  `Scan complete · ${mine[0].technologies_detected} techs · ${mine[0].items_found} findings · ${mine[0].cves_matched} CVEs`,
                )
              }
            }
          }
        } catch {
          /* ignore transient errors */
        }
      }, POLL_INTERVAL_MS)
    } catch (e) {
      toast.error(formatError(e, 'Scan failed'))
      setScanning(false)
    }
  }

  const onResolve = async (fid) => {
    if (resolvingId) return
    setResolvingId(fid)
    try {
      await assetsApi.resolveFinding(id, fid)
      toast.success('Finding marked resolved')
      // Immediate local state update so the user gets instant visual confirmation:
      // button converts to the green "Resolved" badge immediately.
      setFindings((prev) => (prev || []).map((f) => (f.id === fid ? { ...f, resolved_at: new Date().toISOString() } : f)))
      setAsset((prev) => prev ? {
        ...prev,
        open_findings_count: Math.max(0, (prev.open_findings_count || 1) - 1),
      } : prev)
      loadAsset()
    } catch (e) {
      toast.error(formatError(e, 'Resolve failed'))
    } finally {
      setResolvingId(null)
    }
  }

  if (!asset) return (
    <div className="flex items-center justify-center min-h-[60vh]"><Spinner label="Loading asset…" size="lg" /></div>
  )

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        eyebrow="Asset"
        title={asset.label}
        subtitle={asset.url}
        breadcrumbs={[{ label: 'Assets', to: '/assets' }, { label: asset.label }]}
        actions={
          <>
            <span className={`badge font-medium ${ENV_BADGE[asset.env] || 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300'}`}>{asset.env}</span>
            {!asset.is_active && <span className="badge bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-300">inactive</span>}
            {canScan && <ScanButton scanning={scanning} onClick={onScan} />}
          </>
        }
      />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Stat label="Open findings" value={asset.open_findings_count ?? 0} accent={asset.critical_findings_count > 0 ? 'danger' : 'brand'} size="sm" />
        <Stat label="Critical" value={asset.critical_findings_count ?? 0} accent="danger" size="sm" />
        <Stat label="CVEs matched" value={asset.cves_matched_count ?? 0} accent="amber" size="sm" />
        <Stat label="Last scan" value={asset.last_scanned_at ? formatDate(asset.last_scanned_at) : 'Never'} accent="info" size="sm" />
      </div>

      <Tabs
        items={TAB_DEFS.map((t) => ({
          ...t,
          count: t.key === 'findings' ? asset.open_findings_count
              : t.key === 'cves' ? asset.cves_matched_count
              : undefined,
        }))}
        value={tab}
      />

      {tab === 'overview' && <OverviewTab asset={asset} onScan={canScan ? onScan : null} scanning={scanning} />}
      {tab === 'techs' && <TechsTab technologies={asset.technologies} onScan={canScan ? onScan : null} scanning={scanning} lastScannedAt={asset.last_scanned_at} />}
      {tab === 'findings' && (
        <FindingsTab
          findings={findings}
          isAdmin={canResolve}
          onResolve={onResolve}
          resolvingId={resolvingId}
          filterType={filterType}
          setFilterType={setFilterType}
          filterSev={filterSev}
          setFilterSev={setFilterSev}
          filterStatus={filterStatus}
          setFilterStatus={setFilterStatus}
        />
      )}
      {tab === 'cves' && <CvesTab cves={cves} />}
      {tab === 'scans' && <ScansTab scans={scans} latestScanId={latestScanId} scanning={scanning} asset={asset} />}
    </div>
  )
}

function OverviewTab({ asset, onScan, scanning }) {
  return (
    <div className="grid lg:grid-cols-3 gap-6">
      <Card className="lg:col-span-2">
        <CardHeader><CardTitle>Configuration</CardTitle></CardHeader>
        <CardBody className="pt-0">
          <dl className="divide-y divide-slate-100 dark:divide-slate-800">
            <Row label="URL" value={<span className="font-mono break-all">{asset.url}</span>} />
            <Row label="Environment" value={<span className={`badge font-medium ${ENV_BADGE[asset.env] || 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300'}`}>{asset.env}</span>} />
            <Row label="Status" value={asset.is_active
              ? <span className="badge bg-success-50 text-success-700 border-success-200 dark:bg-success-950/40 dark:text-success-300 dark:border-success-800/60">Active</span>
              : <span className="badge bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-300">Inactive</span>} />
            <Row label="Created" value={formatShortDate(asset.created_at)} />
            <Row label="Last scanned" value={asset.last_scanned_at ? formatShortDate(asset.last_scanned_at) : 'Never'} />
            <Row label="Last status" value={asset.last_scan_status || '—'} />
            <Row label="Tags" value={asset.tags?.length ? (
              <div className="flex flex-wrap gap-1 justify-end">
                {asset.tags.map((t) => <span key={t} className="badge bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300">{t}</span>)}
              </div>
            ) : '—'} />
          </dl>
        </CardBody>
      </Card>
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Quick actions</CardTitle>
            <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">Re-scan to re-fingerprint and re-match CVEs.</p>
          </div>
        </CardHeader>
        <CardBody className="pt-0">
          {onScan
            ? <ScanButton scanning={scanning} onClick={onScan} label="Run scan now" block />
            : <p className="text-sm text-slate-500 dark:text-slate-400">You don't have permission to scan assets.</p>}
          <div className="mt-4 text-xs text-slate-500 dark:text-slate-400 space-y-1">
            <p>• Detects tech, headers, TLS, exposed admin paths</p>
            <p>• Re-matches the CVE store against the detected stack</p>
            <p>• Updates open findings and the asset's risk rollup</p>
          </div>
        </CardBody>
      </Card>
    </div>
  )
}

function Row({ label, value }) {
  return (
    <div className="flex items-center justify-between gap-4 py-2.5">
      <dt className="text-sm text-slate-500 dark:text-slate-400">{label}</dt>
      <dd className="text-sm text-slate-800 dark:text-slate-100 text-right max-w-[60%]">{value}</dd>
    </div>
  )
}

function TechsTab({ technologies, onScan, scanning, lastScannedAt }) {
  if (!technologies?.length) {
    return (
      <EmptyState
        title="No technologies detected yet"
        description={
          lastScannedAt
            ? "The last scan didn't pick up any stack signatures. Run a fresh scan — the site may have changed, or the previous scan failed before the fingerprinting step."
            : "This asset hasn't been scanned yet. Kick off a scan to detect the tech stack, headers, and TLS configuration."
        }
        icon={
          <svg viewBox="0 0 24 24" className="h-6 w-6" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
            <path d="M3.27 6.96 12 12.01l8.73-5.05" />
            <path d="M12 22.08V12" />
          </svg>
        }
        action={onScan ? <Button variant="primary" onClick={onScan} loading={scanning}>{scanning ? 'Scanning…' : 'Run a scan'}</Button> : null}
      />
    )
  }
  return (
    <Card>
      <CardBody className="p-0">
        <Table>
          <THead>
            <tr>
              <Th>Vendor</Th>
              <Th>Product</Th>
              <Th>Version</Th>
              <Th>Source</Th>
              <Th>Confidence</Th>
            </tr>
          </THead>
          <TBody>
            {technologies.map((t) => (
              <Tr key={t.id}>
                <Td className="font-medium text-slate-800 dark:text-slate-100">{t.vendor}</Td>
                <Td className="text-slate-700 dark:text-slate-200">{t.product}</Td>
                <Td className="font-mono text-xs text-slate-700 dark:text-slate-200">{t.version || '—'}</Td>
                <Td><span className="badge bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300">{t.source}</span></Td>
                <Td>
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 w-16 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
                      <div className="h-full bg-gradient-to-r from-brand-400 to-brand-600" style={{ width: `${Math.round((t.confidence || 0) * 100)}%` }} />
                    </div>
                    <span className="text-xs text-slate-700 dark:text-slate-200 tabular-nums">{Math.round((t.confidence || 0) * 100)}%</span>
                  </div>
                </Td>
              </Tr>
            ))}
          </TBody>
        </Table>
      </CardBody>
    </Card>
  )
}

function FindingsTab({
  findings,
  isAdmin,
  onResolve,
  resolvingId,
  filterType,
  setFilterType,
  filterSev,
  setFilterSev,
  filterStatus,
  setFilterStatus,
}) {
  return (
    <div className="space-y-3">
      <Card>
        <CardBody className="p-3 flex flex-wrap gap-2 items-center">
          <span className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mr-1">Filter</span>
          <select className="input max-w-[160px]" value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)}>
            <option value="open">Open findings</option>
            <option value="resolved">Resolved findings</option>
            <option value="all">All findings</option>
          </select>
          <select className="input max-w-[160px]" value={filterType} onChange={(e) => setFilterType(e.target.value)}>
            <option value="">All types</option>
            <option value="tls">TLS</option>
            <option value="header">Headers</option>
            <option value="admin_path">Admin paths</option>
            <option value="js_lib">JS libraries</option>
            <option value="cve">CVE</option>
          </select>
          <select className="input max-w-[160px]" value={filterSev} onChange={(e) => setFilterSev(e.target.value)}>
            <option value="">All severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
          {(filterType || filterSev || filterStatus !== 'open') && (
            <Button variant="ghost" size="sm" onClick={() => { setFilterType(''); setFilterSev(''); setFilterStatus('open') }}>
              Clear
            </Button>
          )}
        </CardBody>
      </Card>

      {findings === null ? (
        <Card><CardBody className="py-12"><Spinner label="Loading findings…" /></CardBody></Card>
      ) : findings.length === 0 ? (
        <Card><CardBody className="py-12"><EmptyState title="No findings match the current filters" /></CardBody></Card>
      ) : (
        <div className="space-y-2">
          {findings.map((f) => (
            <Card key={f.id} className="hover:shadow-card-hover transition-shadow">
              <CardBody className="p-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <FindingBadge type={f.finding_type} />
                      <SeverityBadge severity={f.severity} />
                      <span className="font-medium text-slate-800 dark:text-slate-100">{f.title}</span>
                    </div>
                    {f.remediation && (
                      <p className="text-sm text-slate-600 dark:text-slate-300 mt-1">💡 {f.remediation}</p>
                    )}
                    {f.details && Object.keys(f.details).length > 0 && (
                      <details className="text-xs text-slate-500 dark:text-slate-400 mt-2">
                        <summary className="cursor-pointer hover:text-slate-700 dark:hover:text-slate-200">Details</summary>
                        <pre className="mt-1 bg-slate-50 dark:bg-slate-800 p-2 rounded overflow-x-auto">{JSON.stringify(f.details, null, 2)}</pre>
                      </details>
                    )}
                    <p className="text-xs text-slate-400 mt-2">
                      Discovered {formatDate(f.discovered_at)} · Last seen {formatDate(f.last_seen_at)}
                    </p>
                  </div>
                  {isAdmin && !f.resolved_at && (
                    <Button
                      variant="secondary"
                      size="sm"
                      loading={resolvingId === f.id}
                      disabled={resolvingId === f.id}
                      onClick={() => onResolve(f.id)}
                    >
                      Resolve
                    </Button>
                  )}
                  {f.resolved_at && (
                    <span className="badge bg-success-50 text-success-700 border-success-200 dark:bg-success-950/40 dark:text-success-300 dark:border-success-800/60">
                      Resolved
                    </span>
                  )}
                </div>
              </CardBody>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}

function CvesTab({ cves }) {
  if (cves === null) return <Card><CardBody className="py-12"><Spinner label="Loading CVEs…" /></CardBody></Card>
  if (cves.length === 0) {
    return <Card><CardBody className="py-12"><EmptyState title="No CVEs matched" description="No CVEs matched against the detected technology stack yet." /></CardBody></Card>
  }
  return (
    <Card>
      <CardBody className="p-0">
        <Table>
          <THead>
            <tr>
              <Th>CVE</Th>
              <Th>Severity</Th>
              <Th>CVSS</Th>
              <Th>Matched tech</Th>
              <Th>Title</Th>
            </tr>
          </THead>
          <TBody>
            {cves.map((c) => (
              <Tr key={c.cve_id}>
                <Td>
                  <Link to={`/cve/${encodeURIComponent(c.cve_id)}`} className="link-underline font-mono">
                    {c.cve_id}
                  </Link>
                </Td>
                <Td><SeverityBadge severity={c.cve_severity} /></Td>
                <Td className="tabular-nums text-slate-700 dark:text-slate-200">{formatScore(c.cve_cvss_v3_score)}</Td>
                <Td className="text-xs text-slate-600 dark:text-slate-300">
                  {c.technology_vendor && c.technology_product ? `${c.technology_vendor} / ${c.technology_product}` : '—'}
                </Td>
                <Td className="max-w-[400px] truncate text-slate-700 dark:text-slate-200">{c.cve_title || '—'}</Td>
              </Tr>
            ))}
          </TBody>
        </Table>
      </CardBody>
    </Card>
  )
}

function ScansTab({ scans, latestScanId, scanning, asset }) {
  if (scans === null) return <Card><CardBody className="py-12"><Spinner label="Loading scans…" /></CardBody></Card>
  const latest = scans.find((s) => s.id === latestScanId) || scans[0]
  const assetCvesTotal = asset?.cves_matched_count
  return (
    <div className="space-y-4">
      {scanning && (
        <Card variant="flat" className="bg-brand-50/60 border-brand-200 dark:bg-brand-950/20 dark:border-brand-800/60">
          <CardBody className="p-4">
            <div className="flex items-center gap-2 text-brand-700 dark:text-brand-300 text-sm">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-brand-400 opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-brand-500" />
              </span>
              <span className="font-medium">Scan in progress…</span>
              <span className="text-slate-500 dark:text-slate-400">· refreshing automatically</span>
            </div>
          </CardBody>
        </Card>
      )}
      {latest && <LatestScanCard scan={latest} assetCvesTotal={assetCvesTotal} />}
      {scans.length === 0 ? (
        <Card><CardBody className="py-12"><EmptyState title="No scans yet" /></CardBody></Card>
      ) : (
        <Card>
          <CardBody className="p-0">
            <Table>
              <THead>
                <tr>
                  <Th>Started</Th>
                  <Th>Duration</Th>
                  <Th>Status</Th>
                  <Th>Trigger</Th>
                  <Th>Techs</Th>
                  <Th>Findings</Th>
                  <Th>CVEs</Th>
                </tr>
              </THead>
              <TBody>
                {scans.map((s) => {
                  const isLatest = s.id === latestScanId
                  const duration = s.finished_at && s.started_at
                    ? Math.round((new Date(s.finished_at) - new Date(s.started_at)) / 1000)
                    : null
                  return (
                    <Tr key={s.id} className={isLatest ? 'bg-brand-50/40 dark:bg-brand-950/20' : ''}>
                      <Td className="text-slate-700 dark:text-slate-200">
                        <span className="tabular-nums">{formatDate(s.started_at)}</span>
                        {isLatest && <span className="ml-2 badge bg-brand-100 text-brand-700 dark:bg-brand-900/40 dark:text-brand-200">latest</span>}
                      </Td>
                      <Td className="text-xs text-slate-700 dark:text-slate-200">
                        {duration !== null ? <span className="tabular-nums">{duration}s</span> : <span className="text-slate-400 animate-pulse">running…</span>}
                      </Td>
                      <Td>
                        <ScanStatusBadge status={s.status} error={s.error} />
                      </Td>
                      <Td><span className="badge bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300">{s.triggered_by}</span></Td>
                      <Td className="tabular-nums text-slate-700 dark:text-slate-200">{s.technologies_detected}</Td>
                      <Td className="tabular-nums text-slate-700 dark:text-slate-200">{s.items_found}</Td>
                      <Td className="tabular-nums text-slate-700 dark:text-slate-200">{s.cves_matched}</Td>
                    </Tr>
                  )
                })}
              </TBody>
            </Table>
          </CardBody>
        </Card>
      )}
    </div>
  )
}

function ScanStatusBadge({ status, error }) {
  const map = {
    success: 'bg-success-50 text-success-700 border-success-200 dark:bg-success-950/40 dark:text-success-300 dark:border-success-800/60',
    failed:  'bg-danger-50 text-danger-700 border-danger-200 dark:bg-danger-950/40 dark:text-danger-300 dark:border-danger-800/60',
    running: 'bg-brand-50 text-brand-700 border-brand-200 animate-pulse dark:bg-brand-950/40 dark:text-brand-300 dark:border-brand-800/60',
  }
  return (
    <div>
      <span className={`badge ${map[status] || 'bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700'}`}>
        {status === 'running' ? 'scanning' : status}
      </span>
      {status === 'failed' && error && (
        <div className="mt-1 text-xs text-danger-700 dark:text-danger-300 max-w-[300px]">{error}</div>
      )}
    </div>
  )
}

function LatestScanCard({ scan, assetCvesTotal }) {
  const finished = scan.finished_at && scan.started_at
  const duration = finished ? Math.round((new Date(scan.finished_at) - new Date(scan.started_at)) / 1000) : null
  const isRunning = !finished
  return (
    <Card variant="elevated">
      <CardBody className="p-5">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div>
            <h2 className="font-semibold text-slate-800 dark:text-slate-100">{isRunning ? 'Scan in progress…' : 'Latest scan'}</h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Started {formatDate(scan.started_at)}
              {duration !== null
                ? <> · took <span className="tabular-nums">{duration}s</span></>
                : isRunning ? <> · <ElapsedTimer startedAt={scan.started_at} /></>
                : ''}
            </p>
          </div>
          <ScanStatusBadge status={scan.status} error={scan.error} />
        </div>
        <div className="grid grid-cols-3 gap-3 mt-4">
          <Mini label="Technologies" value={scan.technologies_detected} />
          <Mini
            label="Findings"
            value={scan.items_found}
            sub={
              scan.inserted_count != null && (scan.inserted_count + (scan.re_seen_count || 0)) > 0
                ? `${scan.inserted_count} new · ${scan.re_seen_count || 0} re-seen · ${scan.closed_count || 0} closed`
                : null
            }
          />
          <Mini
            label="CVEs matched"
            value={scan.cves_matched}
            sub={scan.cves_matched === 0 && assetCvesTotal ? `${assetCvesTotal} total` : null}
          />
        </div>
        {scan.status === 'failed' && scan.error && (
          <p className="mt-3 text-sm text-danger-700 dark:text-danger-300 bg-danger-50 dark:bg-danger-950/30 border border-danger-200 dark:border-danger-800/60 rounded p-3">
            {scan.error}
          </p>
        )}
      </CardBody>
    </Card>
  )
}

function ElapsedTimer({ startedAt }) {
  const [now, setNow] = useState(Date.now())
  useEffect(() => {
    const h = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(h)
  }, [])
  const elapsed = Math.max(0, Math.round((now - new Date(startedAt).getTime()) / 1000))
  return <span className="font-mono tabular-nums">{elapsed}s elapsed</span>
}

function Mini({ label, value, sub }) {
  return (
    <div className="rounded-xl bg-slate-50 dark:bg-slate-800/50 p-3 text-center">
      <div className="text-[10px] uppercase tracking-wide text-slate-500 dark:text-slate-400 font-semibold">{label}</div>
      <div className="text-2xl font-bold mt-1 text-slate-800 dark:text-slate-100 tabular-nums">{value}</div>
      {sub && <div className="text-[10px] text-slate-500 dark:text-slate-400 mt-1 leading-tight">{sub}</div>}
    </div>
  )
}

function ScanButton({ scanning, onClick, label = 'Scan now', block }) {
  return (
    <Button variant="primary" onClick={onClick} disabled={scanning} loading={scanning} block={block}>
      {label}
    </Button>
  )
}
