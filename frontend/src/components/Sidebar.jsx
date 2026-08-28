// Sidebar — persistent left navigation, collapsible to icon-only.
// Role-aware: items the user can't access are hidden. The active route
// gets a brand-colored rail marker so the user can see where they are
// at a glance, even when the sidebar is collapsed.

import { useState } from 'react'
import { Link, NavLink } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'
import { can } from '../hooks/permissions.js'

function cx(...args) {
  const out = []
  for (const a of args) {
    if (!a) continue
    if (typeof a === 'string') out.push(a)
    else if (Array.isArray(a)) out.push(cx(...a))
    else if (typeof a === 'object') {
      for (const k of Object.keys(a)) if (a[k]) out.push(k)
    }
  }
  return out.join(' ')
}

const ALL_NAV = [
  { to: '/dashboard',   label: 'Dashboard',  icon: DotsIcon,    permission: 'dashboard' },
  { to: '/search',      label: 'Search',     icon: SearchIcon,  permission: 'vulnerability' },
  { to: '/assets',      label: 'Assets',     icon: AssetIcon,   permission: 'asset' },
  { to: '/findings',    label: 'Findings',   icon: FindingsIcon, permission: 'finding_read' },
  { to: '/ai',          label: 'AI Analyst', icon: SparkleIcon, permission: 'ai_ask' },
  { to: '/reports',     label: 'Reports',    icon: ReportIcon,  permission: 'report_generate' },
  { to: '/admin/users', label: 'Users',      icon: UsersIcon,   permission: 'user_manage' },
]

export default function Sidebar() {
  const { user } = useAuth()
  const [collapsed, setCollapsed] = useState(false)
  const items = ALL_NAV.filter((n) => can(user, n.permission))

  return (
    <aside
      className={cx(
        'sticky top-0 h-screen flex flex-col border-r border-slate-200/80 bg-white/90 backdrop-blur-md',
        'dark:border-slate-800/80 dark:bg-slate-900/80',
        'transition-[width] duration-200 ease-out',
        collapsed ? 'w-[68px]' : 'w-60',
      )}
      aria-label="Primary"
    >
      <div className="flex h-16 items-center gap-3 border-b border-slate-200/80 dark:border-slate-800/80 px-4">
        <Link to="/dashboard" className="flex items-center gap-2.5 text-slate-900 dark:text-slate-50 min-w-0">
          <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-brand-500 to-brand-700 text-white shadow-sm shadow-brand-700/20 shrink-0">
            <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 2 4 6v6c0 5 3.5 9.5 8 10 4.5-.5 8-5 8-10V6l-8-4z" />
              <path d="m9 12 2 2 4-4" />
            </svg>
          </span>
          {!collapsed && (
            <span className="text-sm font-semibold tracking-tight truncate">VulnWatch</span>
          )}
        </Link>
        <button
          type="button"
          onClick={() => setCollapsed((c) => !c)}
          className="ml-auto rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-700
                     dark:hover:bg-slate-800 dark:hover:text-slate-200 transition-colors"
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          title={collapsed ? 'Expand' : 'Collapse'}
        >
          <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2">
            {collapsed ? <path d="M9 6l6 6-6 6" /> : <path d="M15 6l-6 6 6 6" />}
          </svg>
        </button>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-4" aria-label="Sidebar">
        {!collapsed && (
          <p className="px-3 mb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
            Navigation
          </p>
        )}
        <ul className="space-y-0.5">
          {items.map((item) => (
            <li key={item.to} className="relative">
              <NavLink
                to={item.to}
                className={({ isActive }) =>
                  cx(
                    'group relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all',
                    isActive
                      ? 'bg-gradient-to-r from-brand-50 to-transparent text-brand-700 dark:from-brand-950/50 dark:to-transparent dark:text-brand-200'
                      : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100',
                  )
                }
                title={collapsed ? item.label : undefined}
              >
                {({ isActive }) => (
                  <>
                    {isActive && <span className="nav-active-bar" aria-hidden="true" />}
                    <item.icon className={cx('h-[18px] w-[18px] shrink-0', isActive && 'text-brand-600 dark:text-brand-300')} />
                    {!collapsed && <span className="truncate">{item.label}</span>}
                  </>
                )}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>

      {!collapsed && (
        <div className="border-t border-slate-200/80 dark:border-slate-800/80 p-4">
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-gradient-to-br from-slate-50 to-white dark:from-slate-800/40 dark:to-slate-900 p-3">
            <div className="flex items-center gap-2">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success-400 opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-success-500" />
              </span>
              <p className="text-xs font-medium text-slate-700 dark:text-slate-200">Live feed</p>
            </div>
            <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
              NVD + CISA KEV sync every 30 min
            </p>
          </div>
        </div>
      )}
    </aside>
  )
}

/* ---- Icons ---- */
function DotsIcon(props) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <rect x="3" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" />
      <rect x="14" y="14" width="7" height="7" rx="1.5" />
    </svg>
  )
}
function SearchIcon(props) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <circle cx="11" cy="11" r="7" />
      <path d="m20 20-3.5-3.5" />
    </svg>
  )
}
function AssetIcon(props) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="M3 21h18" />
      <path d="M5 21V7l7-4 7 4v14" />
      <path d="M9 9h2M13 9h2M9 13h2M13 13h2M9 17h2M13 17h2" />
    </svg>
  )
}
function FindingsIcon(props) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="M12 2 4 6v6c0 5 3.5 9.5 8 10 4.5-.5 8-5 8-10V6l-8-4z" />
      <path d="M12 8v4" />
      <path d="M12 16h.01" />
    </svg>
  )
}
function SparkleIcon(props) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M5.6 18.4l2.1-2.1M16.3 7.7l2.1-2.1" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  )
}
function ReportIcon(props) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" />
      <path d="M14 3v6h6" />
      <path d="M9 13h6M9 17h6" />
    </svg>
  )
}
function UsersIcon(props) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M22 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  )
}
