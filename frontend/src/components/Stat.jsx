// Stat — single KPI card. Modern, restrained, semantic accent. The
// accent shows through as a soft radial wash so each card reads as
// "this metric, this severity" without shouting.

const ACCENTS = {
  brand:   { dot: 'bg-brand-500',    tint: 'from-brand-500/10',   text: 'text-brand-700 dark:text-brand-300' },
  cyan:    { dot: 'bg-cyan-500',     tint: 'from-cyan-500/10',    text: 'text-cyan-700 dark:text-cyan-300' },
  danger:  { dot: 'bg-danger-500',   tint: 'from-danger-500/10',  text: 'text-danger-700 dark:text-danger-300' },
  warning: { dot: 'bg-warning-500',  tint: 'from-warning-500/10', text: 'text-warning-700 dark:text-warning-300' },
  amber:   { dot: 'bg-amber-500',    tint: 'from-amber-500/10',   text: 'text-amber-700 dark:text-amber-300' },
  success: { dot: 'bg-success-500',  tint: 'from-success-500/10', text: 'text-success-700 dark:text-success-300' },
  slate:   { dot: 'bg-slate-400',    tint: 'from-slate-400/10',   text: 'text-slate-700 dark:text-slate-200' },
  info:    { dot: 'bg-info-500',     tint: 'from-info-500/10',    text: 'text-info-700 dark:text-info-300' },
}

export default function Stat({
  label,
  value,
  hint = null,
  delta = null, // { value: '+12%', direction: 'up' | 'down' | 'flat' }
  accent = 'brand',
  icon = null,
  size = 'lg',
  className = '',
}) {
  const a = ACCENTS[accent] || ACCENTS.brand
  const isSmall = size === 'sm'
  const deltaCls =
    delta?.direction === 'up'   ? 'text-success-700 dark:text-success-300' :
    delta?.direction === 'down' ? 'text-danger-700 dark:text-danger-300'   :
                                  'text-slate-500 dark:text-slate-400'
  return (
    <div className={`group relative overflow-hidden rounded-2xl border border-slate-200/80 bg-white p-5 shadow-card transition-all hover:shadow-card-hover hover:-translate-y-0.5 dark:border-slate-800 dark:bg-slate-900 ${className}`}>
      <div
        className={`pointer-events-none absolute -top-12 -right-12 h-36 w-36 rounded-full bg-gradient-to-br ${a.tint} to-transparent opacity-80 dark:opacity-40 transition-opacity group-hover:opacity-100`}
        aria-hidden="true"
      />
      <div className="relative">
        <div className="flex items-center justify-between text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
          <span className="flex items-center gap-2">
            <span className={`h-1.5 w-1.5 rounded-full ${a.dot}`} aria-hidden="true" />
            {label}
          </span>
          {icon && <span className={`opacity-80 ${a.text}`}>{icon}</span>}
        </div>
        <div className={`mt-3 font-bold tabular-nums tracking-tight text-slate-900 dark:text-slate-50 ${isSmall ? 'text-2xl' : 'text-3xl'}`}>
          {value ?? '—'}
        </div>
        {(delta || hint) && (
          <div className="mt-1.5 flex items-center gap-2 text-xs">
            {delta && (
              <span className={`inline-flex items-center gap-0.5 font-semibold ${deltaCls}`}>
                {delta.direction === 'up'   ? '↑' :
                 delta.direction === 'down' ? '↓' : '·'} {delta.value}
              </span>
            )}
            {hint && <span className="text-slate-500 dark:text-slate-400">{hint}</span>}
          </div>
        )}
      </div>
    </div>
  )
}
