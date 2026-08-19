// Modal — focus-trapped dialog with ESC handling and a backdrop click
// to close. Keeps a tight entrance animation and a "described-by" hook
// for screen readers.

import { useEffect, useRef } from 'react'

export default function Modal({
  open,
  onClose,
  title,
  description = null,
  children,
  actions = null,
  size = 'md',
}) {
  const ref = useRef(null)
  const previouslyFocused = useRef(null)

  useEffect(() => {
    if (!open) return
    previouslyFocused.current = document.activeElement
    const node = ref.current
    if (node) {
      const focusables = node.querySelectorAll(
        'a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
      )
      focusables[0]?.focus()
    }
    const onKey = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        onClose?.()
        return
      }
      if (e.key !== 'Tab' || !ref.current) return
      const items = Array.from(
        ref.current.querySelectorAll(
          'a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
        )
      )
      if (!items.length) return
      const first = items[0]
      const last = items[items.length - 1]
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault()
        last.focus()
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', onKey)
    // Save the previous value so we restore exactly what was there
    // (e.g. a page that itself sets ``overflow:hidden`` for a sticky
    // banner). Overwriting with ``''`` would silently drop the original.
    const prevOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = prevOverflow
      // Only restore focus to an element that's still in the DOM and
      // focusable — otherwise we end up focusing ``<body>`` and lose
      // keyboard scroll position.
      const prev = previouslyFocused.current
      if (prev && typeof prev.focus === 'function' && document.contains(prev)) {
        prev.focus()
      }
    }
  }, [open, onClose])

  if (!open) return null

  const widthClass = {
    sm: 'max-w-md',
    md: 'max-w-lg',
    lg: 'max-w-2xl',
    xl: 'max-w-4xl',
  }[size] || 'max-w-lg'

  const descId = description ? 'modal-desc' : undefined

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 animate-fade-in" aria-labelledby="modal-title">
      <div
        className="absolute inset-0 bg-slate-900/50 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden="true"
      />
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
        aria-describedby={descId}
        className={`relative w-full ${widthClass} rounded-2xl bg-white dark:bg-slate-900 shadow-pop border border-slate-200/80 dark:border-slate-800 animate-slide-up`}
      >
        <div className="flex items-start justify-between gap-3 border-b border-slate-200/80 dark:border-slate-800/80 px-6 py-4">
          <div className="min-w-0">
            <h2 id="modal-title" className="text-base font-semibold text-slate-900 dark:text-slate-50">
              {title}
            </h2>
            {description && (
              <p id="modal-desc" className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                {description}
              </p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="shrink-0 rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200 transition-colors"
            aria-label="Close"
          >
            <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M6 6l12 12M6 18 18 6" />
            </svg>
          </button>
        </div>
        <div className="px-6 py-5 text-sm text-slate-700 dark:text-slate-200">{children}</div>
        {actions && (
          <div className="flex flex-wrap justify-end gap-2 border-t border-slate-200/80 dark:border-slate-800/80 px-6 py-4 bg-slate-50/60 dark:bg-slate-900/40 rounded-b-2xl">
            {actions}
          </div>
        )}
      </div>
    </div>
  )
}
