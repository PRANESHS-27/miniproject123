// PageHeader — title + breadcrumbs + contextual actions. Used at the
// top of every page in the main content area.

import { Link } from 'react-router-dom'

export default function PageHeader({
  title,
  subtitle = null,
  eyebrow = null,
  breadcrumbs = [],
  actions = null,
}) {
  return (
    <header className="mb-6">
      {breadcrumbs.length > 0 && (
        <nav
          className="mb-2 flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400"
          aria-label="Breadcrumb"
        >
          <Link to="/dashboard" className="hover:text-slate-700 dark:hover:text-slate-200 transition-colors">
            Dashboard
          </Link>
          {breadcrumbs.map((b, i) => (
            <span key={i} className="flex items-center gap-1">
              <span aria-hidden="true" className="text-slate-300 dark:text-slate-600">/</span>
              {b.to ? (
                <Link to={b.to} className="hover:text-slate-700 dark:hover:text-slate-200 transition-colors">
                  {b.label}
                </Link>
              ) : (
                <span className="text-slate-700 dark:text-slate-200 font-medium">{b.label}</span>
              )}
            </span>
          ))}
        </nav>
      )}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          {eyebrow && (
            <div className="mb-1.5 inline-flex items-center gap-2">
              <span className="h-1.5 w-1.5 rounded-full bg-brand-500" />
              <p className="text-[11px] font-semibold uppercase tracking-wider text-brand-600 dark:text-brand-300">
                {eyebrow}
              </p>
            </div>
          )}
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-50">
            {title}
          </h1>
          {subtitle && (
            <p className="mt-1.5 text-sm text-slate-500 dark:text-slate-400 max-w-2xl leading-relaxed">
              {subtitle}
            </p>
          )}
        </div>
        {actions && (
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            {actions}
          </div>
        )}
      </div>
    </header>
  )
}
