// Single Badge component for severity, finding-type, and status pills.
// Reads from the centralised severity palette (utils/severity.jsx) so
// colour rules live in exactly one place.

import { severityClasses } from '../utils/severity.jsx'

const FINDING_TYPE_STYLES = {
  tls:        { light: 'bg-purple-50 text-purple-700 border-purple-200',  dark: 'bg-purple-950/40 text-purple-300 border-purple-800/60' },
  header:     { light: 'bg-info-50 text-info-700 border-info-200',         dark: 'bg-info-950/40 text-info-300 border-info-800/60' },
  admin_path: { light: 'bg-warning-50 text-warning-700 border-warning-200', dark: 'bg-warning-950/40 text-warning-300 border-warning-800/60' },
  js_lib:     { light: 'bg-amber-50 text-amber-700 border-amber-200',      dark: 'bg-amber-950/40 text-amber-300 border-amber-800/60' },
  cve:        { light: 'bg-danger-50 text-danger-700 border-danger-200',   dark: 'bg-danger-950/40 text-danger-300 border-danger-800/60' },
}

const FINDING_TYPE_LABELS = {
  tls: 'TLS',
  header: 'Header',
  admin_path: 'Admin Path',
  js_lib: 'JS Library',
  cve: 'CVE',
}

const STATUS_STYLES = {
  success:   { light: 'bg-success-50 text-success-700 border-success-200', dark: 'bg-success-950/40 text-success-300 border-success-800/60' },
  failed:    { light: 'bg-danger-50 text-danger-700 border-danger-200',    dark: 'bg-danger-950/40 text-danger-300 border-danger-800/60' },
  running:   { light: 'bg-info-50 text-info-700 border-info-200',          dark: 'bg-info-950/40 text-info-300 border-info-800/60' },
  pending:   { light: 'bg-slate-100 text-slate-600 border-slate-200',      dark: 'bg-slate-800 text-slate-300 border-slate-700' },
  active:    { light: 'bg-success-50 text-success-700 border-success-200', dark: 'bg-success-950/40 text-success-300 border-success-800/60' },
  inactive:  { light: 'bg-slate-100 text-slate-600 border-slate-200',      dark: 'bg-slate-800 text-slate-400 border-slate-700' },
  resolved:  { light: 'bg-success-50 text-success-700 border-success-200', dark: 'bg-success-950/40 text-success-300 border-success-800/60' },
}

function SeverityIcon({ severity }) {
  const fill = {
    CRITICAL: 'bg-danger-500',
    HIGH:     'bg-warning-500',
    MEDIUM:   'bg-amber-400',
    LOW:      'bg-success-500',
    INFO:     'bg-info-500',
    NONE:     'bg-slate-400',
    UNKNOWN:  'bg-slate-400',
  }[severity] || 'bg-slate-400'
  return <span className={`h-1.5 w-1.5 rounded-full ${fill}`} aria-hidden="true" />
}

export function SeverityBadge({ severity, className = '', withDot = true }) {
  const cls = severityClasses(severity)
  return (
    <span className={`badge ${cls} ${className}`}>
      {withDot && <SeverityIcon severity={severity} />}
      <span className="tracking-wide">{severity || 'UNKNOWN'}</span>
    </span>
  )
}

export function FindingBadge({ type, className = '' }) {
  const style = FINDING_TYPE_STYLES[type]
  const cls = style ? style.light : 'bg-slate-100 text-slate-600 border-slate-200'
  const label = FINDING_TYPE_LABELS[type] || type
  return (
    <span className={`badge ${cls} font-mono ${className}`}>
      {label}
    </span>
  )
}

export function StatusBadge({ status, children, className = '' }) {
  const normalized = (status || '').toLowerCase()
  const style = STATUS_STYLES[normalized] || STATUS_STYLES.active
  const cls = style ? style.light : 'bg-slate-100 text-slate-600 border-slate-200'
  return (
    <span className={`badge ${cls} ${className}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current opacity-75" aria-hidden="true" />
      <span>{children || status}</span>
    </span>
  )
}

export default function Badge({ kind = 'severity', value, variant, children, className = '' }) {
  if (children || variant) {
    return <StatusBadge status={variant || value || 'active'} className={className}>{children || value}</StatusBadge>
  }
  if (kind === 'finding') return <FindingBadge type={value} className={className} />
  if (kind === 'status')  return <StatusBadge status={value} className={className} />
  return <SeverityBadge severity={value} className={className} />
}
