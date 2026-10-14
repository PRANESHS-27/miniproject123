import { useEffect, useState } from 'react'
import PageHeader from '../components/PageHeader.jsx'
import Card from '../components/Card.jsx'
import Spinner from '../components/Spinner.jsx'
import EmptyState from '../components/EmptyState.jsx'
import Badge from '../components/Badge.jsx'
import { auditLogs as auditApi } from '../services/api.js'
import { formatDateTime } from '../utils/format.jsx'
import toast from 'react-hot-toast'

export default function AuditLogsPage() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [category, setCategory] = useState('all')
  const [total, setTotal] = useState(0)

  const fetchLogs = async () => {
    try {
      setLoading(true)
      const res = await auditApi.list({ category })
      setLogs(res.items || [])
      setTotal(res.total || 0)
    } catch {
      toast.error('Failed to load audit logs')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchLogs()
  }, [category])

  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit Logs"
        description="Comprehensive audit trail recording authentication attempts, privileged operations, scans, and finding resolutions."
      />

      {/* Filter Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm">
        <div className="flex items-center gap-2">
          {['all', 'login', 'scan', 'security'].map((cat) => (
            <button
              key={cat}
              onClick={() => setCategory(cat)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold uppercase tracking-wider transition-colors ${
                category === cat
                  ? 'bg-brand-600 text-white shadow-sm'
                  : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
        <div className="text-xs text-slate-500">
          Showing <span className="font-semibold text-slate-800 dark:text-slate-200">{logs.length}</span> of {total} records
        </div>
      </div>

      <Card>
        {loading ? (
          <div className="p-12 flex justify-center"><Spinner size="lg" /></div>
        ) : logs.length === 0 ? (
          <EmptyState
            title="No audit events found"
            description="No actions matching the selected category have been recorded."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50 dark:bg-slate-800/60 text-xs font-semibold text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">Actor</th>
                  <th className="px-4 py-3">Action</th>
                  <th className="px-4 py-3">Target / Resource</th>
                  <th className="px-4 py-3">IP Address</th>
                  <th className="px-4 py-3">Outcome</th>
                  <th className="px-4 py-3">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800 font-mono text-xs">
                {logs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-50/60 dark:hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-3 font-sans text-slate-500 whitespace-nowrap">
                      {formatDateTime(log.timestamp)}
                    </td>
                    <td className="px-4 py-3 font-semibold text-slate-800 dark:text-slate-200">
                      {log.actor || 'anonymous'}
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                        {log.action}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-600 dark:text-slate-400">
                      {log.resource_type} {log.resource_id ? `#${log.resource_id}` : ''}
                    </td>
                    <td className="px-4 py-3 text-slate-500">
                      {log.ip || '—'}
                    </td>
                    <td className="px-4 py-3">
                      {log.outcome === 'success' && (
                        <Badge variant="success">Success</Badge>
                      )}
                      {log.outcome === 'failure' && (
                        <Badge variant="danger">Failed</Badge>
                      )}
                      {log.outcome === 'rate_limited' && (
                        <Badge variant="warning">Rate Limited</Badge>
                      )}
                      {!['success', 'failure', 'rate_limited'].includes(log.outcome) && (
                        <Badge variant="neutral">{log.outcome}</Badge>
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate-400 font-sans max-w-xs truncate">
                      {JSON.stringify(log.details || {})}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}
