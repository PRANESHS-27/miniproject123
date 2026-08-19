// Button — single primitive for every interactive action in the app.
// Replaces the ad-hoc .btn-primary / .btn-secondary / .btn-ghost classes
// with a real component so we get consistent focus rings, loading
// affordance, icon-only support, and dark-mode handling.

import { forwardRef } from 'react'
import Spinner from './Spinner.jsx'

const VARIANTS = {
  primary:
    'bg-gradient-to-b from-brand-500 to-brand-600 hover:from-brand-600 hover:to-brand-700 ' +
    'text-white shadow-sm shadow-brand-700/20 ' +
    'dark:from-brand-500 dark:to-brand-600 dark:hover:from-brand-400 dark:hover:to-brand-500',
  secondary:
    'bg-white border border-slate-200 text-slate-700 hover:bg-slate-50 ' +
    'dark:bg-slate-800 dark:border-slate-700 dark:text-slate-100 dark:hover:bg-slate-700',
  ghost:
    'text-slate-500 hover:text-slate-800 hover:bg-slate-100 ' +
    'dark:text-slate-300 dark:hover:text-slate-100 dark:hover:bg-slate-800',
  danger:
    'bg-gradient-to-b from-danger-500 to-danger-600 hover:from-danger-600 hover:to-danger-700 text-white shadow-sm',
  soft:
    'bg-brand-50 text-brand-700 hover:bg-brand-100 ' +
    'dark:bg-brand-950/40 dark:text-brand-200 dark:hover:bg-brand-950/60',
  outline:
    'bg-transparent border border-brand-300 text-brand-700 hover:bg-brand-50 ' +
    'dark:border-brand-700 dark:text-brand-300 dark:hover:bg-brand-950/40',
}

const SIZES = {
  xs: 'h-7 px-2.5 text-xs rounded-md',
  sm: 'h-8 px-3 text-xs rounded-lg',
  md: 'h-9 px-4 text-sm rounded-lg',
  lg: 'h-11 px-5 text-sm rounded-xl',
}

const Button = forwardRef(function Button(
  {
    as: Component = 'button',
    variant = 'secondary',
    size = 'md',
    iconOnly = false,
    block = false,
    loading = false,
    leftIcon = null,
    rightIcon = null,
    className = '',
    children,
    disabled,
    type = 'button',
    ...rest
  },
  ref,
) {
  const variantCls = VARIANTS[variant] || VARIANTS.secondary
  const sizeCls = SIZES[size] || SIZES.md
  const iconPad = iconOnly
    ? (size === 'xs' ? 'w-7 px-0' : size === 'sm' ? 'w-8 px-0' : size === 'lg' ? 'w-11 px-0' : 'w-9 px-0')
    : ''
  const isDisabled = disabled || loading
  const blockCls = block ? 'w-full' : ''

  return (
    <Component
      ref={ref}
      type={Component === 'button' ? type : undefined}
      disabled={isDisabled}
      aria-busy={loading || undefined}
      className={
        'inline-flex items-center justify-center gap-2 font-medium transition-all ' +
        'focus-visible:outline-none disabled:opacity-50 disabled:cursor-not-allowed ' +
        variantCls + ' ' + sizeCls + ' ' + iconPad + ' ' + blockCls + ' ' + className
      }
      {...rest}
    >
      {loading ? (
        <Spinner size="xs" inline className="text-current" />
      ) : (
        leftIcon
      )}
      {!iconOnly && children}
      {iconOnly && !loading && children}
      {!loading && rightIcon}
    </Component>
  )
})

export default Button
