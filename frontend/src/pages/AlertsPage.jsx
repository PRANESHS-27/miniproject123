import { useEffect, useState } from 'react'
import PageHeader from '../components/PageHeader.jsx'
import Card from '../components/Card.jsx'
import Button from '../components/Button.jsx'
import Badge from '../components/Badge.jsx'
import Spinner from '../components/Spinner.jsx'
import EmptyState from '../components/EmptyState.jsx'
import { alerts as alertsApi } from '../services/api.js'
import { formatDateTime } from '../utils/format.jsx'
import toast from 'react-hot-toast'

export default function AlertsPage() {
  const [alertsList, setAlertsList] = useState([])
  const [summary, setSummary] = useState({ active_alerts: 0, unread_alerts: 0, critical_unread: 0 })
  const [loading, setLoading] = useState(true)
  const [unreadOnly, setUnreadOnly] = useState(false)
  const [severityFilter, setSeverityFilter] = useState('')

  const fetchAlerts = async () => {
    try {
      setLoading(true)
      const params = {}
      if (unreadOnly) params.unread_only = true
      if (severityFilter) params.severity = severityFilter

      const [listRes, sumRes] = await Promise.all([
        alertsApi.list(params),
        alertsApi.summary(),
      ])
      setAlertsList(listRes.items || [])
      setSummary(sumRes || { active_alerts: 0, unread_alerts: 0, critical_unread: 0 })
    } catch {
      toast.error('Failed to load security alerts')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAlerts()
  }, [unreadOnly, severityFilter])

  const handleAcknowledge = async (id) => {
    try {
      await alertsApi.acknowledge(id)
      toast.success('Alert marked as acknowledged')
      fetchAlerts()
    } catch {
      toast.error('Failed to acknowledge alert')
    }
  }

  const handleDismiss = async (id) => {
    try {
      await alertsApi.dismiss(id)
      toast.success('Alert dismissed')
      fetchAlerts()
    } catch {
      toast.error('Failed to dismiss alert')
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Alerts"
        description="High-priority alerts triggered by Critical CVE discoveries, KEV known-exploited matches, and risk engine thresholds."
      />

      {/* Summary counters */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-4 rounded-xl shadow-sm">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">Active Alerts</div>
          <div className="text-2xl font-bold text-slate-900 dark:text-slate-100 mt-1">{summary.active_alerts}</div>
        </div>
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-4 rounded-xl shadow-sm">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">Unread Alerts</div>
          <div className="text-2xl font-bold text-brand-600 mt-1">{summary.unread_alerts}</div>
        </div>
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-4 rounded-xl shadow-sm">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">Critical Unread</div>
          <div className="text-2xl font-bold text-red-600 mt-1">{summary.critical_unread}</div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm">
        <div className="flex items-center gap-4">
          <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={unreadOnly}
              onChange={(e) => setUnreadOnly(e.target.checked)}
              className="rounded border-slate-300 text-brand-600 focus:ring-brand-500"
            />
            <span className="text-xs font-medium">Show Unread Only</span>
          </label>

          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-semibold uppercase">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-2.5 py-1 text-slate-800 dark:text-slate-200 focus:outline-none"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
            </select>
          </div>
        </div>
      </div>

      {/* Alerts list */}
      <Card>
        {loading ? (
          <div className="p-12 flex justify-center"><Spinner size="lg" /></div>
        ) : alertsList.length === 0 ? (
          <EmptyState
            title="No alerts to display"
            description="All high-priority risks and critical vulnerability findings are acknowledged or resolved."
          />
        ) : (
          <div className="divide-y divide-slate-200 dark:divide-slate-800">
            {alertsList.map((alert) => (
              <div
                key={alert.id}
                className={`p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-colors ${
                  !alert.is_read ? 'bg-blue-50/30 dark:bg-blue-950/20' : ''
                }`}
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <Badge variant={alert.severity === 'CRITICAL' ? 'danger' : 'warning'}>
                      {alert.severity}
                    </Badge>
                    {!alert.is_read && (
                      <span className="inline-block w-2 h-2 rounded-full bg-blue-600" title="Unread" />
                    )}
                    <h4 className="font-semibold text-sm text-slate-900 dark:text-slate-100">{alert.title}</h4>
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-400">{alert.message}</p>
                  <div className="text-[11px] text-slate-400">
                    Triggered {formatDateTime(alert.created_at)}
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  {!alert.is_read && (
                    <Button variant="secondary" size="sm" onClick={() => handleAcknowledge(alert.id)}>
                      Acknowledge
                    </Button>
                  )}
                  <Button variant="ghost" size="sm" onClick={() => handleDismiss(alert.id)}>
                    Dismiss
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
