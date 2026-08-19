// Table — compound primitive that replaces the inline <table> blocks
// scattered through the search and asset pages. Centralises the header
// styling, row hover, and cell padding so every table feels like part
// of the same product.

import { forwardRef } from 'react'

export const Table = forwardRef(function Table({ className = '', children, ...rest }, ref) {
  return (
    <div className="overflow-x-auto">
      <table ref={ref} className={`w-full text-sm ${className}`} {...rest}>
        {children}
      </table>
    </div>
  )
})

export function THead({ className = '', children }) {
  return (
    <thead
      className={`text-left text-xs font-medium uppercase tracking-wide text-slate-500 bg-slate-50/70 border-b border-slate-200 dark:bg-slate-800/50 dark:text-slate-400 dark:border-slate-800 ${className}`}
    >
      {children}
    </thead>
  )
}

export function TBody({ className = '', children }) {
  return (
    <tbody className={`divide-y divide-slate-100 dark:divide-slate-800 ${className}`}>
      {children}
    </tbody>
  )
}

export function Tr({ className = '', children, ...rest }) {
  return (
    <tr
      className={`transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/40 ${className}`}
      {...rest}
    >
      {children}
    </tr>
  )
}

export function Th({ className = '', children, align = 'left' }) {
  const alignCls = align === 'right' ? 'text-right' : align === 'center' ? 'text-center' : 'text-left'
  return <th className={`py-2.5 px-4 ${alignCls} font-medium ${className}`}>{children}</th>
}

export function Td({ className = '', children, align = 'left', ...rest }) {
  const alignCls = align === 'right' ? 'text-right' : align === 'center' ? 'text-center' : 'text-left'
  return <td className={`py-3 px-4 align-middle text-slate-700 dark:text-slate-200 ${alignCls} ${className}`} {...rest}>{children}</td>
}

export default Table
