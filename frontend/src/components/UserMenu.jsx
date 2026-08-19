// UserMenu — avatar + dropdown with display name, role badge, sign out.

import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'
import { roleBadgeStyle } from '../hooks/permissions.js'

function initials(name) {
  if (!name) return '?'
  return String(name)
    .split(/\s+/)
    .map((s) => s[0])
    .filter(Boolean)
    .slice(0, 2)
    .join('')
    .toUpperCase()
}

export default function UserMenu() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    function onClick(e) {
      if (!ref.current) return
      if (!ref.current.contains(e.target)) setOpen(false)
    }
    function onEsc(e) { if (e.key === 'Escape') setOpen(false) }
    if (open) {
      document.addEventListener('mousedown', onClick)
      document.addEventListener('keydown', onEsc)
      return () => {
        document.removeEventListener('mousedown', onClick)
        document.removeEventListener('keydown', onEsc)
      }
    }
  }, [open])

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  const name = user?.full_name || user?.username || '?'

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex h-10 items-center gap-2 rounded-xl border border-slate-200 bg-white pl-1.5 pr-3 hover:bg-slate-50 hover:shadow-sm dark:border-slate-800 dark:bg-slate-900 dark:hover:bg-slate-800 transition-all"
        aria-haspopup="menu"
        aria-expanded={open}
      >
        <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-gradient-to-br from-brand-500 to-brand-700 text-xs font-semibold text-white shadow-sm">
          {initials(name)}
        </span>
        <span className="hidden text-sm font-medium text-slate-700 dark:text-slate-200 sm:inline">
          {user?.username}
        </span>
        <svg viewBox="0 0 24 24" className={`h-3.5 w-3.5 text-slate-400 transition-transform ${open ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" strokeWidth="2">
          <path d="m6 9 6 6 6-6" />
        </svg>
      </button>
      {open && (
        <div
          role="menu"
          className="absolute right-0 z-40 mt-2 w-64 overflow-hidden rounded-xl border border-slate-200/80 bg-white shadow-pop dark:border-slate-800 dark:bg-slate-900 animate-slide-up"
        >
          <div className="px-4 py-3 border-b border-slate-200/80 dark:border-slate-800/80 bg-gradient-to-b from-slate-50/60 to-transparent dark:from-slate-800/40">
            <p className="text-sm font-semibold text-slate-900 dark:text-slate-50 truncate">{name}</p>
            <p className="text-xs text-slate-500 dark:text-slate-400 truncate">{user?.email || '—'}</p>
            {user?.role && (
              <span className={`mt-2 inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-bold uppercase border ${roleBadgeStyle(user.role)}`}>
                {user.role}
              </span>
            )}
          </div>
          <button
            type="button"
            role="menuitem"
            onClick={handleLogout}
            className="flex w-full items-center gap-2 px-4 py-2.5 text-left text-sm text-slate-700 hover:bg-slate-50 dark:text-slate-200 dark:hover:bg-slate-800 transition-colors"
          >
            <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
              <path d="m16 17 5-5-5-5M21 12H9" />
            </svg>
            Sign out
          </button>
        </div>
      )}
    </div>
  )
}
