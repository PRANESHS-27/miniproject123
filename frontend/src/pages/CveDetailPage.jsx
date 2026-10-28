import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import toast from 'react-hot-toast'
import PageHeader from '../components/PageHeader.jsx'
import Spinner from '../components/Spinner.jsx'
import Button from '../components/Button.jsx'
import { Card, CardHeader, CardTitle, CardBody } from '../components/Card.jsx'
import { SeverityBadge } from '../components/Badge.jsx'
import { formatDate } from '../utils/format.jsx'
import { vulnerabilities as vulnApi } from '../services/api.js'

function CvssRing({ score }) {
  if (score == null) return null
  const pct = Math.max(0, Math.min(100, (Number(score) / 10) * 100))
  // SVG ring with brand->danger gradient
  const r = 26
  const c = 2 * Math.PI * r
  const dash = (pct / 100) * c
  return (
    <div className="relative h-16 w-16 shrink-0">
      <svg viewBox="0 0 64 64" className="h-16 w-16 -rotate-90">
        <defs>
          <linearGradient id="cvss" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#22C55E" />
            <stop offset="50%" stopColor="#F59E0B" />
            <stop offset="100%" stopColor="#DC2626" />
          </linearGradient>
        </defs>
        <circle cx="32" cy="32" r={r} stroke="currentColor" className="text-slate-200 dark:text-slate-800" strokeWidth="6" fill="none" />
        <circle cx="32" cy="32" r={r} stroke="url(#cvss)" strokeWidth="6" fill="none"
          strokeLinecap="round" strokeDasharray={`${dash} ${c - dash}`} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-base font-bold tabular-nums text-slate-900 dark:text-slate-50">{Number(score).toFixed(1)}</span>
        <span className="text-[9px] uppercase tracking-wider text-slate-500 dark:text-slate-400">CVSS</span>
      </div>
    </div>
  )
}

export default function CveDetailPage() {
  const { cveId } = useParams()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    setError(null)
    setData(null)
    vulnApi.detail(cveId, { signal: controller.signal })
      .then((d) => { setData(d); setLoading(false) })
      .catch((err) => {
        if (err?.name === 'CanceledError' || err?.code === 'ERR_CANCELED' || err?.name === 'AbortError') return
        // Differentiate "not found" (404) from transport/server errors so
        // the toast and the empty-state UI can react appropriately.
        if (err?.response?.status === 404) {
          setError('not_found')
        } else {
          setError('load_failed')
          toast.error('Failed to load CVE')
        }
        setLoading(false)
      })
    return () => controller.abort('cve changed')
  }, [cveId])

  if (loading) return (
    <div className="flex items-center justify-center min-h-[60vh]"><Spinner label="Loading CVE…" size="lg" /></div>
  )
  if (error === 'not_found') {
    return (
      <div className="space-y-6 animate-fade-in">
        <PageHeader eyebrow="CVE detail" title={cveId} />
        <Card>
          <CardBody className="py-12 text-center">
            <p className="text-base font-medium text-slate-900 dark:text-slate-50">CVE not found</p>
            <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
              {cveId} is not in the local CVE database yet. It may not have been fetched from NVD yet.
            </p>
            <div className="mt-4">
              <Link to="/search"><Button variant="secondary" size="sm">← Back to search</Button></Link>
            </div>
          </CardBody>
        </Card>
      </div>
    )
  }
  if (error === 'load_failed') {
    return (
      <div className="space-y-6 animate-fade-in">
        <PageHeader eyebrow="CVE detail" title={cveId} />
        <Card>
          <CardBody className="py-12 text-center">
            <p className="text-base font-medium text-slate-900 dark:text-slate-50">Could not load CVE</p>
            <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">A transient error occurred. Try refreshing.</p>
          </CardBody>
        </Card>
      </div>
    )
  }
  if (!data) return null

  // The backend stores `title` as the first 120 chars of the description
  // when the CVE has no explicit summary. Only show it when it's actually
  // shorter than the description (otherwise it's redundant).
  const descLen = (data.description || '').length
  const showTitle = data.title && (!data.description || data.title.length < descLen - 20)

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        eyebrow="CVE detail"
        title={data.cve_id}
        breadcrumbs={[{ label: 'Search', to: '/search' }, { label: data.cve_id }]}
        actions={<Link to="/search"><Button variant="secondary" size="sm">← Back to search</Button></Link>}
      />

      <div className="grid lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <Card variant="elevated">
            <CardBody className="p-6">
              <div className="flex items-start gap-4 mb-4 flex-wrap">
                <CvssRing score={data.cvss_v3_score} />
                <div className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2 mb-2">
                    <SeverityBadge severity={data.severity} />
                    <span className="badge bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300 font-mono">{data.cve_id}</span>
                    {data.in_kev && (
                      <span className="badge bg-danger-50 text-danger-700 border-danger-200 dark:bg-danger-950/40 dark:text-danger-300 dark:border-danger-800/60">
                        ⚠ In CISA KEV
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-slate-500 dark:text-slate-400">
                    <span className="text-slate-700 dark:text-slate-200 font-medium">CVSS v3:</span>{' '}
                    <span className="font-mono">{data.cvss_v3_score != null ? Number(data.cvss_v3_score).toFixed(1) : '—'}</span>
                    {data.cvss_v3_vector && <span className="ml-2 font-mono text-[10px] text-slate-500 dark:text-slate-400 break-all">{data.cvss_v3_vector}</span>}
                  </div>
                </div>
              </div>
              {showTitle && (
                <h2 className="text-xl font-semibold mb-2 text-slate-900 dark:text-slate-50">{data.title}</h2>
              )}
              <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-2">Description</h3>
              <p className="prose-fix whitespace-pre-wrap text-slate-700 dark:text-slate-200">
                {data.description || 'No description available.'}
              </p>
            </CardBody>
          </Card>

          {data.references?.length > 0 && (
            <Card>
              <CardHeader>
                <div>
                  <CardTitle>References &amp; Patches</CardTitle>
                  <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">External advisories and patch links from the NVD feed.</p>
                </div>
              </CardHeader>
              <CardBody className="pt-0">
                <ul className="text-sm space-y-1.5">
                  {data.references.slice(0, 15).map((r, i) => (
                    <li key={i} className="flex items-start gap-2 py-1.5 border-b border-slate-100 dark:border-slate-800 last:border-0">
                      <svg viewBox="0 0 24 24" className="h-3.5 w-3.5 mt-0.5 text-slate-400 shrink-0" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
                        <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.72-1.71" />
                      </svg>
                      <a href={r.url} target="_blank" rel="noreferrer" className="link-underline break-all font-mono text-xs">
                        {r.url}
                      </a>
                      {r.tags?.length > 0 && (
                        <span className="text-xs text-slate-500 dark:text-slate-400 ml-auto shrink-0">{r.tags.join(', ')}</span>
                      )}
                    </li>
                  ))}
                </ul>
              </CardBody>
            </Card>
          )}
        </div>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <div>
                <CardTitle>Affected products</CardTitle>
                <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{(data.affected_products || []).length} total</p>
              </div>
            </CardHeader>
            <CardBody className="pt-0">
              {data.affected_products?.length ? (
                <ul className="text-sm space-y-1 max-h-80 overflow-y-auto pr-1">
                  {data.affected_products.slice(0, 30).map((p, i) => (
                    <li key={i} className="font-mono text-xs text-slate-700 dark:text-slate-300">
                      {p.vendor}:{p.product}{' '}
                      <span className="text-slate-500 dark:text-slate-400">({p.version || '—'})</span>
                    </li>
                  ))}
                  {data.affected_products.length > 30 && (
                    <li className="text-slate-500 dark:text-slate-400 text-xs">… and {data.affected_products.length - 30} more</li>
                  )}
                </ul>
              ) : (
                <p className="text-sm text-slate-500 dark:text-slate-400">No affected products listed.</p>
              )}
            </CardBody>
          </Card>

          <div className="sticky top-24">
            <Card>
              <CardHeader><CardTitle>Metadata</CardTitle></CardHeader>
              <CardBody className="pt-0">
                <dl className="text-sm grid grid-cols-2 gap-y-2.5 gap-x-3">
                  <dt className="text-slate-500 dark:text-slate-400">Published</dt>
                  <dd className="text-slate-700 dark:text-slate-200">{formatDate(data.published)}</dd>
                  <dt className="text-slate-500 dark:text-slate-400">Last modified</dt>
                  <dd className="text-slate-700 dark:text-slate-200">{formatDate(data.last_modified)}</dd>
                  <dt className="text-slate-500 dark:text-slate-400">CWEs</dt>
                  <dd className="text-slate-700 dark:text-slate-200">{(data.cwe_ids || []).join(', ') || '—'}</dd>
                  <dt className="text-slate-500 dark:text-slate-400">KEV due date</dt>
                  <dd className="text-slate-700 dark:text-slate-200">{formatDate(data.kev_due_date)}</dd>
                </dl>
              </CardBody>
            </Card>
          </div>
        </div>
      </div>
    </div>
  )
}
