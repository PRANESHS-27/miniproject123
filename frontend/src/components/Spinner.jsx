// Standardized loading state. `inline` mode uses currentColor so the
// spinner tints itself to whatever text colour the surrounding element
// already has — important when the spinner lives inside a Button.

export default function Spinner({ label = 'Loading…', size = 'md', inline = false, className = '' }) {
  const dim = { xs: 'h-3 w-3', sm: 'h-4 w-4', md: 'h-5 w-5', lg: 'h-8 w-8' }[size] || 'h-5 w-5'
  const ring = inline
    ? `${dim} inline-block animate-spin rounded-full border-2 border-current border-r-transparent`
    : `${dim} inline-block animate-spin rounded-full border-2 border-slate-200 dark:border-slate-700 border-t-brand-500 dark:border-t-brand-400`
  if (inline) {
    return <span className={`${ring} ${className}`} aria-hidden="true" />
  }
  return (
    <div
      className={`flex items-center gap-3 text-slate-500 dark:text-slate-300 ${className}`}
      role="status" aria-live="polite"
    >
      <span className={ring} aria-hidden="true" />
      <span className="text-sm">{label}</span>
    </div>
  )
}
