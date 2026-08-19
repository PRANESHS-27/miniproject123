// Tabs — URL-driven tabs using useSearchParams. Deep-linkable via
// `?tab=findings` etc. Two visual variants:
//   - `variant="underline"` (default) — classic underlined tabs for the
//     asset detail page where the tab labels are longer.
//   - `variant="segmented"` — pill-segmented control, great for 2–5
//     short tabs in tight areas.

import { useSearchParams } from 'react-router-dom'

export default function Tabs({
  value,
  onChange,
  items,
  variant = 'underline',
  className = '',
}) {
  const [params, setParams] = useSearchParams()
  const active = value || params.get('tab') || items[0]?.key

  const handleSelect = (key) => {
    if (key === active) return
    if (onChange) onChange(key)
    const next = new URLSearchParams(params)
    next.set('tab', key)
    // ``replace: true`` so tab switches don't pollute the history stack.
    // Without this, clicking through 5 tabs requires 5 back-button presses
    // just to leave the page.
    setParams(next, { replace: true })
  }

  if (variant === 'segmented') {
    return (
      <div
        className={`inline-flex items-center gap-1 p-1 rounded-xl bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 ${className}`}
        role="tablist"
      >
        {items.map((item) => {
          const isActive = item.key === active
          return (
            <button
              key={item.key}
              type="button"
              role="tab"
              aria-selected={isActive}
              onClick={() => handleSelect(item.key)}
              className={`relative inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium rounded-lg transition-all ${
                isActive
                  ? 'bg-white text-slate-900 shadow-sm dark:bg-slate-900 dark:text-slate-50'
                  : 'text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200'
              }`}
            >
              {item.icon && <span className="shrink-0">{item.icon}</span>}
              {item.label}
              {typeof item.count === 'number' && (
                <span
                  className={`rounded-full px-1.5 py-0.5 text-xs font-semibold tabular-nums ${
                    isActive
                      ? 'bg-brand-100 text-brand-700 dark:bg-brand-900/40 dark:text-brand-200'
                      : 'bg-slate-200 text-slate-600 dark:bg-slate-700 dark:text-slate-300'
                  }`}
                >
                  {item.count}
                </span>
              )}
            </button>
          )
        })}
      </div>
    )
  }

  // underline variant
  return (
    <div className={`border-b border-slate-200 dark:border-slate-800 ${className}`} role="tablist">
      <nav className="-mb-px flex flex-wrap gap-1" aria-label="Tabs">
        {items.map((item) => {
          const isActive = item.key === active
          return (
            <button
              type="button"
              key={item.key}
              role="tab"
              aria-selected={isActive}
              onClick={() => handleSelect(item.key)}
              className={`group inline-flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
                isActive
                  ? 'border-brand-600 text-brand-700 dark:border-brand-400 dark:text-brand-300'
                  : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300 dark:text-slate-400 dark:hover:text-slate-200 dark:hover:border-slate-700'
              }`}
            >
              {item.icon && <span className="shrink-0">{item.icon}</span>}
              {item.label}
              {typeof item.count === 'number' && (
                <span
                  className={`rounded-full px-2 py-0.5 text-xs font-semibold tabular-nums ${
                    isActive
                      ? 'bg-brand-100 text-brand-700 dark:bg-brand-900/40 dark:text-brand-200'
                      : 'bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-300'
                  }`}
                >
                  {item.count}
                </span>
              )}
            </button>
          )
        })}
      </nav>
    </div>
  )
}
