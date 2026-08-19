import { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import toast from 'react-hot-toast'
import PageHeader from '../components/PageHeader.jsx'
import EmptyState from '../components/EmptyState.jsx'
import Modal from '../components/Modal.jsx'
import Button from '../components/Button.jsx'
import Spinner from '../components/Spinner.jsx'
import { Card, CardBody } from '../components/Card.jsx'
import { formatDate, formatShortDate } from '../utils/format.jsx'
import { assets as assetsApi } from '../services/api.js'
import { useAuth } from '../context/AuthContext.jsx'
import { can } from '../hooks/permissions.js'

const ENV_OPTIONS = [
  { value: '', label: 'All envs' },
  { value: 'production', label: 'Production' },
  { value: 'staging', label: 'Staging' },
  { value: 'dev', label: 'Dev' },
]

const ENV_BADGE = {
  production: 'bg-danger-50 text-danger-700 border-danger-200 dark:bg-danger-950/40 dark:text-danger-300 dark:border-danger-800/60',
  staging:    'bg-warning-50 text-warning-700 border-warning-200 dark:bg-warning-950/40 dark:text-warning-300 dark:border-warning-800/60',
  dev:        'bg-info-50 text-info-700 border-info-200 dark:bg-info-950/40 dark:text-info-300 dark:border-info-800/60',
}

function severityDot(count) {
  if (count > 0) return 'bg-danger-500 ring-danger-200/70 dark:ring-danger-800/60'
  return 'bg-success-500 ring-success-200/70 dark:ring-success-800/60'
}

function statusBadge(status) {
  const map = {
    success: 'bg-success-50 text-success-700 border-success-200 dark:bg-success-950/40 dark:text-success-300 dark:border-success-800/60',
    failed:  'bg-danger-50 text-danger-700 border-danger-200 dark:bg-danger-950/40 dark:text-danger-300 dark:border-danger-800/60',
    running: 'bg-brand-50 text-brand-700 border-brand-200 animate-pulse dark:bg-brand-950/40 dark:text-brand-300 dark:border-brand-800/60',
  }
  return map[status] || 'bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700'
}

export default function AssetsPage() {
  const { user } = useAuth()
  const canCreate = can(user, 'asset_create')
  const canScan = can(user, 'asset_scan')
  const canDelete = can(user, 'asset_delete')

  const [rows, setRows] = useState(null)
  const [scanningId, setScanningId] = useState(null)
  const [showAdd, setShowAdd] = useState(false)
  const [includeInactive, setIncludeInactive] = useState(false)
  const [filter, setFilter] = useState('')
  const [envFilter, setEnvFilter] = useState('')
  const [criticalOnly, setCriticalOnly] = useState(false)

  const load = useCallback(() => {
    assetsApi.list({ include_inactive: includeInactive })
      .then(setRows)
      .catch(() => toast.error('Failed to load assets'))
  }, [includeInactive])

  useEffect(() => { load() }, [load])

  const onScan = async (id) => {
    if (scanningId === id) return
    setScanningId(id)
    try {
      const r = await assetsApi.scan(id)
      toast.success(r.message || 'Scan started')
      setTimeout(load, 4000)
    } catch (e) {
      toast.error(e.response?.data?.detail || 'Scan failed')
    } finally {
      setScanningId(null)
    }
  }

  const onDelete = async (id, label) => {
    if (!window.confirm(`Deactivate asset "${label}"? It can be reactivated later.`)) return
    try {
      await assetsApi.delete(id)
      toast.success('Asset deactivated')
      load()
    } catch (e) {
      toast.error(e.response?.data?.detail || 'Delete failed')
    }
  }

  const filtered = (rows || []).filter((a) => {
    if (criticalOnly && !(a.critical_findings_count > 0)) return false
    if (envFilter && a.env !== envFilter) return false
    if (filter) {
      const q = filter.toLowerCase()
      if (!a.label.toLowerCase().includes(q) && !(a.url || '').toLowerCase().includes(q)) return false
    }
    return true
  })

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        eyebrow="Inventory"
        title="Monitored assets"
        subtitle="Websites you own. VulnWatch scans them for tech, TLS, headers, exposed paths, and matched CVEs."
        actions={canCreate && (
          <Button variant="primary" onClick={() => setShowAdd(true)} leftIcon={
            <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 5v14M5 12h14" />
            </svg>
          }>Add asset</Button>
        )}
      />

      <Card>
        <CardBody className="p-3 flex flex-wrap gap-2 items-center">
          <div className="relative flex-1 min-w-[220px]">
            <svg viewBox="0 0 24 24" className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400 pointer-events-none" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="7" /><path d="m21 21-4.3-4.3" />
            </svg>
            <input
              className="input pl-9"
              placeholder="Filter by label or URL…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
          </div>
          <select className="input max-w-[160px]" value={envFilter} onChange={(e) => setEnvFilter(e.target.value)}>
            {ENV_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          <label className="flex items-center gap-2 px-3 py-1.5 rounded-xl border border-slate-200/80 dark:border-slate-700 text-sm text-slate-700 dark:text-slate-200 cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors">
            <input type="checkbox" checked={criticalOnly} onChange={(e) => setCriticalOnly(e.target.checked)} className="accent-danger-500" />
            Critical only
          </label>
          <label className="flex items-center gap-2 px-3 py-1.5 rounded-xl border border-slate-200/80 dark:border-slate-700 text-sm text-slate-700 dark:text-slate-200 cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors">
            <input type="checkbox" checked={includeInactive} onChange={(e) => setIncludeInactive(e.target.checked)} className="accent-brand-500" />
            Include inactive
          </label>
        </CardBody>
      </Card>

      {rows === null ? (
        <Card><CardBody className="py-12"><Spinner label="Loading assets…" /></CardBody></Card>
      ) : filtered.length === 0 ? (
        <Card><CardBody className="py-12">
          <EmptyState
            title={filter || criticalOnly || envFilter ? 'No assets match your filters' : 'No assets yet'}
            description={filter || criticalOnly || envFilter ? null : 'Add the first website you want VulnWatch to monitor.'}
            action={canCreate && !filter && !criticalOnly && !envFilter ? (
              <Button variant="primary" onClick={() => setShowAdd(true)}>Add your first asset</Button>
            ) : null}
          />
        </CardBody></Card>
      ) : (
        <div className="grid sm:grid-cols-2 xl:grid-cols-3 gap-4">
          {filtered.map((a) => (
            <AssetCard
              key={a.id}
              asset={a}
              canScan={canScan}
              canDelete={canDelete}
              scanning={scanningId === a.id}
              onScan={() => onScan(a.id)}
              onDelete={() => onDelete(a.id, a.label)}
            />
          ))}
        </div>
      )}

      {showAdd && (
        <AddAssetModal
          onClose={() => setShowAdd(false)}
          onCreated={() => { setShowAdd(false); load() }}
        />
      )}
    </div>
  )
}

function AssetCard({ asset, canScan, canDelete, scanning, onScan, onDelete }) {
  return (
    <Card interactive className="hover:shadow-card-hover transition-shadow">
      <CardBody className="p-4">
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex items-center gap-2 min-w-0">
            <span className={`h-2.5 w-2.5 rounded-full ring-4 ${severityDot(asset.critical_findings_count)}`} />
            <Link to={`/assets/${asset.id}`} className="font-semibold text-slate-800 dark:text-slate-100 hover:text-brand-700 dark:hover:text-brand-300 truncate">
              {asset.label}
            </Link>
            {!asset.is_active && <span className="badge bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-300">inactive</span>}
          </div>
          <span className={`badge font-medium shrink-0 ${ENV_BADGE[asset.env] || 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300'}`}>{asset.env}</span>
        </div>

        <div className="font-mono text-xs text-slate-500 dark:text-slate-400 truncate mb-3" title={asset.url}>{asset.url}</div>

        <div className="grid grid-cols-3 gap-2 mb-3">
          <Metric label="Open" value={asset.open_findings_count ?? 0} accent={asset.open_findings_count > 0 ? 'warning' : 'slate'} />
          <Metric label="Critical" value={asset.critical_findings_count ?? 0} accent={asset.critical_findings_count > 0 ? 'danger' : 'slate'} />
          <Metric label="CVEs" value={asset.cves_matched_count ?? 0} accent={asset.cves_matched_count > 0 ? 'amber' : 'slate'} />
        </div>

        <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 mb-3">
          <span>
            Last scan: {asset.last_scanned_at ? formatShortDate(asset.last_scanned_at) : 'Never'}
          </span>
          {asset.last_scan_status && (
            <span className={`badge ${statusBadge(asset.last_scan_status)}`}>{asset.last_scan_status}</span>
          )}
        </div>

        <div className="flex items-center gap-2 pt-3 border-t border-slate-100 dark:border-slate-800">
          <Link to={`/assets/${asset.id}`} className="flex-1">
            <Button variant="secondary" size="sm" block>View</Button>
          </Link>
          {canScan && (
            <Button variant="primary" size="sm" loading={scanning} onClick={onScan}>Scan</Button>
          )}
          {canDelete && (
            <Button variant="ghost" size="sm" onClick={onDelete} title="Deactivate asset" leftIcon={
              <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6" />
              </svg>
            }>
              <span className="sr-only">Deactivate</span>
            </Button>
          )}
        </div>
      </CardBody>
    </Card>
  )
}

function Metric({ label, value, accent }) {
  const accentClass = {
    danger: 'text-danger-700 dark:text-danger-300',
    warning: 'text-warning-700 dark:text-warning-300',
    amber: 'text-amber-700 dark:text-amber-300',
    slate: 'text-slate-700 dark:text-slate-200',
  }[accent] || 'text-slate-700 dark:text-slate-200'
  return (
    <div className="rounded-lg bg-slate-50 dark:bg-slate-800/50 px-2 py-1.5 text-center">
      <div className="text-[10px] uppercase tracking-wide text-slate-500 dark:text-slate-400 font-semibold">{label}</div>
      <div className={`text-lg font-bold tabular-nums ${accentClass}`}>{value}</div>
    </div>
  )
}

function AddAssetModal({ onClose, onCreated }) {
  const [label, setLabel] = useState('')
  const [url, setUrl] = useState('https://')
  const [env, setEnv] = useState('production')
  const [tags, setTags] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    if (!label.trim() || !url.trim()) {
      toast.error('Label and URL are required')
      return
    }
    setBusy(true)
    try {
      await assetsApi.create({
        label: label.trim(),
        url: url.trim(),
        env,
        tags: tags.split(',').map((t) => t.trim()).filter(Boolean),
      })
      toast.success('Asset created')
      onCreated()
    } catch (e) {
      toast.error(e.response?.data?.detail || 'Create failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="Add asset"
      description="VulnWatch will fingerprint the site, scan for headers, TLS, and exposed admin paths, then match CVEs to the detected stack."
      actions={
        <>
          <Button variant="secondary" onClick={onClose} type="button">Cancel</Button>
          <Button variant="primary" type="submit" form="add-asset-form" loading={busy}>
            {busy ? 'Creating…' : 'Create asset'}
          </Button>
        </>
      }
    >
      <form id="add-asset-form" onSubmit={submit} className="space-y-3">
        <div>
          <label className="label">Label</label>
          <input className="input" placeholder="Acme Corp website" value={label} onChange={(e) => setLabel(e.target.value)} required />
        </div>
        <div>
          <label className="label">URL</label>
          <input className="input font-mono" placeholder="https://example.com" value={url} onChange={(e) => setUrl(e.target.value)} required />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="label">Environment</label>
            <select className="input" value={env} onChange={(e) => setEnv(e.target.value)}>
              <option value="production">production</option>
              <option value="staging">staging</option>
              <option value="dev">dev</option>
            </select>
          </div>
          <div>
            <label className="label">Tags <span className="text-slate-400 font-normal">(comma-sep)</span></label>
            <input className="input" placeholder="web, blog" value={tags} onChange={(e) => setTags(e.target.value)} />
          </div>
        </div>
      </form>
    </Modal>
  )
}
