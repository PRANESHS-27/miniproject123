import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import PageHeader from '../components/PageHeader.jsx'
import Card from '../components/Card.jsx'
import Button from '../components/Button.jsx'
import Modal from '../components/Modal.jsx'
import Badge from '../components/Badge.jsx'
import Spinner from '../components/Spinner.jsx'
import EmptyState from '../components/EmptyState.jsx'
import { assets as assetsApi, scans as scansApi } from '../services/api.js'
import { formatDateTime, formatError } from '../utils/format.jsx'
import toast from 'react-hot-toast'

export default function ScansPage() {
  const [scansList, setScansList] = useState([])
  const [totalScans, setTotalScans] = useState(0)
  const [loading, setLoading] = useState(true)
  const [statusFilter, setStatusFilter] = useState('')
  const [modalOpen, setModalOpen] = useState(false)
  const [selectedScan, setSelectedScan] = useState(null)
  const [scanFindings, setScanFindings] = useState([])
  const [loadingFindings, setLoadingFindings] = useState(false)

  // Start scan modal state
  const [availableAssets, setAvailableAssets] = useState([])
  const [selectedAssetId, setSelectedAssetId] = useState('')
  const [selectedProfile, setSelectedProfile] = useState('web_standard')
  const [submitting, setSubmitting] = useState(false)

  const fetchScans = async () => {
    try {
      setLoading(true)
      const params = {}
      if (statusFilter) params.status = statusFilter
      const res = await scansApi.list(params)
      setScansList(res.items || [])
      setTotalScans(res.total || 0)
    } catch {
      toast.error('Failed to load scan jobs')
    } finally {
      setLoading(false)
    }
  }

  const loadAssetsForScan = async () => {
    try {
      const res = await assetsApi.list({ is_active: true, limit: 100 })
      const items = res.items || []
      setAvailableAssets(items)
      if (items.length > 0 && !selectedAssetId) {
        setSelectedAssetId(items[0].id)
      }
    } catch {
      toast.error('Failed to load assets list')
    }
  }

  useEffect(() => {
    fetchScans()
  }, [statusFilter])

  const handleOpenStartModal = () => {
    loadAssetsForScan()
    setModalOpen(true)
  }

  const handleStartScan = async (e) => {
    e.preventDefault()
    if (!selectedAssetId) {
      toast.error('Please select an asset to scan')
      return
    }
    try {
      setSubmitting(true)
      await scansApi.start({
        asset_id: parseInt(selectedAssetId, 10),
        profile: selectedProfile,
      })
      toast.success('Security scan queued successfully')
      setModalOpen(false)
      fetchScans()
    } catch (err) {
      toast.error(formatError(err, 'Failed to start scan'))
    } finally {
      setSubmitting(false)
    }
  }

  const handleViewScan = async (scan) => {
    setSelectedScan(scan)
    setLoadingFindings(true)
    try {
      const res = await scansApi.findings(scan.id)
      setScanFindings(res || [])
    } catch {
      setScanFindings([])
    } finally {
      setLoadingFindings(false)
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Scans"
        description="Authorized network discovery, service fingerprinting, and controlled vulnerability scanning."
        action={
          <Button variant="primary" onClick={handleOpenStartModal}>
            <svg className="w-4 h-4 mr-1.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Start Scan
          </Button>
        }
      />

      {/* Filter bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm">
        <div className="flex items-center gap-3">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Filter Status:</span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-1.5 text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            <option value="">All Statuses</option>
            <option value="running">Running</option>
            <option value="success">Success / Completed</option>
            <option value="failed">Failed</option>
          </select>
        </div>
        <div className="text-xs text-slate-500 font-medium">
          Total Recorded Scans: <span className="font-semibold text-slate-800 dark:text-slate-200">{totalScans}</span>
        </div>
      </div>

      {/* Scans Table */}
      <Card>
        {loading ? (
          <div className="p-12 flex justify-center">
            <Spinner size="lg" />
          </div>
        ) : scansList.length === 0 ? (
          <EmptyState
            title="No scan records found"
            description="Run an authorized security assessment against one of your registered institutional assets."
            action={
              <Button variant="secondary" onClick={handleOpenStartModal}>
                Start First Scan
              </Button>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50 dark:bg-slate-800/60 text-xs font-semibold text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="px-4 py-3">Scan ID</th>
                  <th className="px-4 py-3">Target Asset</th>
                  <th className="px-4 py-3">Profile</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Duration</th>
                  <th className="px-4 py-3">Findings</th>
                  <th className="px-4 py-3">Started At</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {scansList.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-50/60 dark:hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-3.5 font-mono text-xs text-slate-600 dark:text-slate-400">
                      #{s.id}
                    </td>
                    <td className="px-4 py-3.5">
                      <Link to={`/assets/${s.asset_id}`} className="font-medium text-brand-600 hover:underline">
                        {s.asset_label}
                      </Link>
                      <div className="text-xs text-slate-400 font-mono truncate max-w-xs">{s.asset_url}</div>
                    </td>
                    <td className="px-4 py-3.5">
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                        {s.scan_profile}
                      </span>
                    </td>
                    <td className="px-4 py-3.5">
                      {s.status === 'success' && (
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-emerald-50 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300">
                          ● Completed
                        </span>
                      )}
                      {s.status === 'running' && (
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-blue-50 text-blue-700 dark:bg-blue-950/40 dark:text-blue-300 animate-pulse">
                          ○ Running…
                        </span>
                      )}
                      {s.status === 'failed' && (
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-red-50 text-red-700 dark:bg-red-950/40 dark:text-red-300">
                          ✕ Failed
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3.5 text-xs text-slate-600 dark:text-slate-400">
                      {s.duration_seconds ? `${s.duration_seconds}s` : '—'}
                    </td>
                    <td className="px-4 py-3.5 text-xs">
                      <span className="font-semibold text-slate-800 dark:text-slate-200">{s.items_found} total</span>
                      <span className="text-slate-400 ml-1">({s.inserted_count} new · {s.cves_matched} CVEs)</span>
                    </td>
                    <td className="px-4 py-3.5 text-xs text-slate-500">
                      {formatDateTime(s.started_at)}
                    </td>
                    <td className="px-4 py-3.5 text-right">
                      <Button variant="ghost" size="sm" onClick={() => handleViewScan(s)}>
                        View Details
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Start Scan Modal */}
      <Modal open={modalOpen} onClose={() => setModalOpen(false)} title="Queue Authorized Security Scan">
        <form onSubmit={handleStartScan} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 uppercase mb-1">
              Select Target Asset
            </label>
            <select
              value={selectedAssetId}
              onChange={(e) => setSelectedAssetId(e.target.value)}
              required
              className="w-full text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-brand-500"
            >
              {availableAssets.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.label} ({a.url}) — {a.criticality} criticality
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 uppercase mb-1">
              Scan Profile
            </label>
            <select
              value={selectedProfile}
              onChange={(e) => setSelectedProfile(e.target.value)}
              className="w-full text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-brand-500"
            >
              <option value="web_standard">Web Standard (HTTP Headers, TLS, JS, Path Probing)</option>
              <option value="quick">Quick Probe (Light Header & TLS check)</option>
              <option value="network_discovery">Network Discovery (Service port probes)</option>
              <option value="vulnerability_audit">Vulnerability Audit (Nuclei + CPE correlation)</option>
              <option value="full">Full Assessment (Comprehensive Discovery & Audit)</option>
            </select>
            <p className="text-xs text-slate-500 mt-1">
              Target scope is verified prior to probe dispatch. SSRF and metadata protection are actively enforced.
            </p>
          </div>

          <div className="pt-4 flex justify-end gap-2 border-t border-slate-200 dark:border-slate-800">
            <Button variant="ghost" onClick={() => setModalOpen(false)} type="button">
              Cancel
            </Button>
            <Button variant="primary" type="submit" disabled={submitting}>
              {submitting ? 'Queuing…' : 'Start Authorized Scan'}
            </Button>
          </div>
        </form>
      </Modal>

      {/* Scan Detail Modal */}
      {selectedScan && (
        <Modal open={Boolean(selectedScan)} onClose={() => setSelectedScan(null)} title={`Scan #${selectedScan.id} Summary`}>
          <div className="space-y-4 text-sm">
            <div className="grid grid-cols-2 gap-3 p-3 bg-slate-50 dark:bg-slate-800/50 rounded-lg">
              <div>
                <span className="text-xs text-slate-400 block">Target Asset:</span>
                <span className="font-semibold text-slate-800 dark:text-slate-200">{selectedScan.asset_label}</span>
              </div>
              <div>
                <span className="text-xs text-slate-400 block">Profile:</span>
                <span className="font-semibold text-slate-800 dark:text-slate-200">{selectedScan.scan_profile}</span>
              </div>
              <div>
                <span className="text-xs text-slate-400 block">Status:</span>
                <span className="font-semibold text-slate-800 dark:text-slate-200 uppercase">{selectedScan.status}</span>
              </div>
              <div>
                <span className="text-xs text-slate-400 block">Duration:</span>
                <span className="font-semibold text-slate-800 dark:text-slate-200">{selectedScan.duration_seconds || '—'}s</span>
              </div>
            </div>

            {selectedScan.error && (
              <div className="p-3 bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-300 rounded-lg text-xs font-mono">
                Error: {selectedScan.error}
              </div>
            )}

            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2">
                Observed Findings ({scanFindings.length})
              </h4>
              {loadingFindings ? (
                <div className="py-4 text-center"><Spinner size="sm" /></div>
              ) : scanFindings.length === 0 ? (
                <p className="text-xs text-slate-400">No findings detected during this scan.</p>
              ) : (
                <div className="max-h-60 overflow-y-auto space-y-2">
                  {scanFindings.map((f) => (
                    <div key={f.id} className="p-2.5 border border-slate-200 dark:border-slate-800 rounded-lg flex items-start justify-between gap-2">
                      <div>
                        <div className="font-medium text-xs text-slate-800 dark:text-slate-200">{f.title}</div>
                        <div className="text-[11px] text-slate-400">{f.remediation || 'No remediation note'}</div>
                      </div>
                      <Badge variant={f.severity === 'CRITICAL' ? 'danger' : f.severity === 'HIGH' ? 'warning' : 'info'}>
                        {f.severity}
                      </Badge>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="pt-3 flex justify-end border-t border-slate-200 dark:border-slate-800">
              <Button variant="secondary" onClick={() => setSelectedScan(null)}>
                Close
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  )
}
