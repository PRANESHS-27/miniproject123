// Card — compound primitive. Three variants (flat, default, elevated)
// plus optional interactive hover. Pieces are intentionally small so
// callers compose them without prop-explosion.

import { forwardRef } from 'react'

const VARIANTS = {
  flat:     'bg-white border border-slate-200/80 dark:bg-slate-900 dark:border-slate-800',
  default:  'bg-white border border-slate-200/80 shadow-card dark:bg-slate-900 dark:border-slate-800',
  elevated: 'bg-white border border-slate-200/80 shadow-card-hover dark:bg-slate-900 dark:border-slate-800',
  glass:    'bg-white/70 dark:bg-slate-900/60 backdrop-blur-md border border-white/60 dark:border-slate-700/50 shadow-card',
}

export const Card = forwardRef(function Card(
  { variant = 'default', interactive = false, className = '', title, subtitle, headerAction, children, ...rest },
  ref,
) {
  const baseCls = VARIANTS[variant] || VARIANTS.default
  const hoverCls = interactive
    ? 'hover:border-brand-300 hover:shadow-card-hover hover:-translate-y-0.5 transition-all duration-200 cursor-pointer dark:hover:border-brand-700'
    : ''
  return (
    <div ref={ref} className={`rounded-2xl ${baseCls} ${hoverCls} ${className}`} {...rest}>
      {(title || subtitle || headerAction) && (
        <CardHeader>
          <div>
            {title && <CardTitle>{title}</CardTitle>}
            {subtitle && <CardSubtitle>{subtitle}</CardSubtitle>}
          </div>
          {headerAction && <div>{headerAction}</div>}
        </CardHeader>
      )}
      {children}
    </div>
  )
})

export function CardHeader({ className = '', children, ...rest }) {
  return (
    <div
      className={`flex items-start justify-between gap-3 px-5 pt-5 pb-3 ${className}`}
      {...rest}
    >
      {children}
    </div>
  )
}

export function CardTitle({ className = '', children }) {
  return <h3 className={`text-sm font-semibold text-slate-900 dark:text-slate-50 ${className}`}>{children}</h3>
}

export function CardSubtitle({ className = '', children }) {
  return <p className={`mt-0.5 text-xs text-slate-500 dark:text-slate-400 ${className}`}>{children}</p>
}

export function CardBody({ className = '', children, ...rest }) {
  return <div className={`px-5 py-4 ${className}`} {...rest}>{children}</div>
}

export function CardFooter({ className = '', children }) {
  return (
    <div
      className={`flex items-center justify-end gap-2 px-5 py-3 border-t border-slate-100 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-900/40 rounded-b-2xl ${className}`}
    >
      {children}
    </div>
  )
}

export default Card
