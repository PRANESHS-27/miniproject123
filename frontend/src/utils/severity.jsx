// Single source of truth for severity colors, used by every badge,
// chart, and stat card. Matches the backend's Severity enum (CRITICAL,
// HIGH, MEDIUM, LOW, NONE, INFO, UNKNOWN).

// Each entry returns { light, dark, label }. Components compose them
// into Tailwind classes.

export const SEVERITY_PALETTE = {
  CRITICAL: { label: 'CRITICAL', light: 'bg-danger-50 text-danger-700 border-danger-200',      dark: 'bg-danger-950/40 text-danger-300 border-danger-800/60' },
  HIGH:     { label: 'HIGH',     light: 'bg-warning-50 text-warning-700 border-warning-200',  dark: 'bg-warning-950/40 text-warning-300 border-warning-800/60' },
  MEDIUM:   { label: 'MEDIUM',   light: 'bg-amber-50 text-amber-700 border-amber-200',         dark: 'bg-amber-950/40 text-amber-300 border-amber-800/60' },
  LOW:      { label: 'LOW',      light: 'bg-success-50 text-success-700 border-success-200',  dark: 'bg-success-950/40 text-success-300 border-success-800/60' },
  INFO:     { label: 'INFO',     light: 'bg-info-50 text-info-700 border-info-200',            dark: 'bg-info-950/40 text-info-300 border-info-800/60' },
  NONE:     { label: 'NONE',     light: 'bg-slate-100 text-slate-600 border-slate-200',        dark: 'bg-slate-800 text-slate-300 border-slate-700' },
  UNKNOWN:  { label: 'UNKNOWN',  light: 'bg-slate-100 text-slate-500 border-slate-200',        dark: 'bg-slate-800 text-slate-400 border-slate-700' },
}

export function severityClasses(severity, { dark = false } = {}) {
  const entry = SEVERITY_PALETTE[severity] || SEVERITY_PALETTE.UNKNOWN
  return dark ? entry.dark : entry.light
}

// Severity for sorting (lower index = worse). Unknowns sort last.
export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'NONE', 'UNKNOWN']

// Semantic accent colour per severity, used by Stat cards and chart fills.
export function severityAccent(severity) {
  switch (severity) {
    case 'CRITICAL': return 'danger'
    case 'HIGH':     return 'warning'
    case 'MEDIUM':   return 'amber'
    case 'LOW':      return 'success'
    case 'INFO':     return 'info'
    default:         return 'slate'
  }
}
