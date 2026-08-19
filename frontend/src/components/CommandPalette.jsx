// CommandPalette — ⌘K modal that lets the user jump to a page, run a
// search, or open an asset. Backed by `/api/vulnerabilities/search` and
// `/api/assets` so the index isn't shipped client-side.

import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import Modal from './Modal.jsx'
import { vulnerabilities as vulnApi, assets as assetsApi } from '../services/api.js'
import { useAuth } from '../context/AuthContext.jsx'
import { can } from '../hooks/permissions.js'

const PAGES = [
  { to: '/dashboard',  label: 'Dashboard',  permission: 'dashboard' },
  { to: '/search',     label: 'Search',     permission: 'vulnerability' },
  { to: '/assets',     label: 'Assets',     permission: 'asset' },
  { to: '/ai',         label: 'AI Analyst', permission: 'ai_ask' },
  { to: '/reports',    label: 'Reports',    permission: 'report_generate' },
  { to: '/admin/users',label: 'Users',      permission: 'user_manage' },
]

// Tiny subsequence matcher — used to highlight matches in the dropdown
// without pulling in a fuzzy-search dependency.
function score(query, text) {
  if (!query) return 1
  const q = query.toLowerCase()
  const t = text.toLowerCase()
  if (t.startsWith(q)) return 100 - t.length
  if (t.includes(q)) return 50 - t.length
  let i = 0
  let qi = 0
  while (i < t.length && qi < q.length) {
    if (t[i] === q[qi]) qi += 1
    i += 1
  }
  return qi === q.length ? 10 - i : 0
}

export default function CommandPalette({ open, onClose }) {
  const { user } = useAuth()
  const navigate = useNavigate()
  const [q, setQ] = useState('')
  const [results, setResults] = useState({ cves: [], assets: [] })
  const [loading, setLoading] = useState(false)
  const [activeIdx, setActiveIdx] = useState(0)
  const inputRef = useRef(null)

  useEffect(() => {
    if (!open) {
      setQ('')
      setActiveIdx(0)
      return
    }
    setTimeout(() => inputRef.current?.focus(), 30)
  }, [open])

  useEffect(() => {
    if (!open) return
    if (!q.trim()) {
      setResults({ cves: [], assets: [] })
      return
    }
    let cancelled = false
    const handle = setTimeout(async () => {
      setLoading(true)
      try {
        const [cves, assets] = await Promise.all([
          vulnApi.search({ q, limit: 5 }).catch(() => ({ results: [] })),
          assetsApi.list({ q, limit: 5 }).catch(() => []),
        ])
        if (cancelled) return
        setResults({ cves: cves.results || [], assets: assets || [] })
        setActiveIdx(0)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }, 200)
    return () => { cancelled = true; clearTimeout(handle) }
  }, [q, open])

  const pageResults = useMemo(() => {
    const allowed = PAGES.filter((p) => can(user, p.permission))
    if (!q.trim()) return allowed.slice(0, 4)
    return allowed
      .map((p) => ({ ...p, _score: score(q, p.label) }))
      .filter((p) => p._score > 0)
      .sort((a, b) => b._score - a._score)
      .slice(0, 4)
  }, [q, user])

  const items = useMemo(() => {
    const out = []
    pageResults.forEach((p) => out.push({ type: 'page', ...p, key: 'p:' + p.to }))
    results.cves.forEach((c) => out.push({
      type: 'cve', key: 'c:' + c.cve_id, cve_id: c.cve_id,
      label: c.cve_id, sub: c.title || '', severity: c.severity, cvss: c.cvss_v3_score,
    }))
    results.assets.forEach((a) => out.push({
      type: 'asset', key: 'a:' + a.id, id: a.id,
      label: a.label, sub: a.url, is_active: a.is_active,
    }))
    return out
  }, [pageResults, results])

  useEffect(() => {
    if (!open) return
    setActiveIdx((i) => Math.min(i, Math.max(0, items.length - 1)))
  }, [items, open])

  const onKeyDown = (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActiveIdx((i) => Math.min(i + 1, items.length - 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActiveIdx((i) => Math.max(i - 1, 0)) }
    else if (e.key === 'Enter' && items[activeIdx]) {
      e.preventDefault()
      const it = items[activeIdx]
      if (it.type === 'page') navigate(it.to)
      else if (it.type === 'cve') navigate(`/cve/${encodeURIComponent(it.cve_id)}`)
      else if (it.type === 'asset') navigate(`/assets/${it.id}`)
      onClose?.()
    }
  }

  return (
    <Modal open={open} onClose={onClose} size="lg" title={null}>
      <div className="-m-5">
        <div className="flex items-center gap-3 px-5 py-3 border-b border-slate-200 dark:border-slate-800">
          <svg viewBox="0 0 24 24" className="h-4 w-4 text-slate-400" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="7" />
            <path d="m20 20-3.5-3.5" />
          </svg>
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="Jump to a page, search a CVE, or open an asset…"
            className="flex-1 bg-transparent text-sm outline-none placeholder-slate-400 dark:placeholder-slate-500 text-slate-900 dark:text-slate-100"
          />
          {loading && <span className="text-xs text-slate-400">searching…</span>}
        </div>
        <div className="max-h-80 overflow-y-auto py-2">
          {items.length === 0 ? (
            <p className="px-5 py-10 text-center text-sm text-slate-500 dark:text-slate-400">
              {q.trim() ? 'No matches. Try a different keyword.' : 'Start typing to search…'}
            </p>
          ) : (
            <ul className="text-sm">
              {items.map((it, i) => {
                const isActive = i === activeIdx
                const baseCls = 'flex items-center gap-3 px-5 py-2.5 cursor-pointer transition-colors'
                const hoverCls = isActive
                  ? 'bg-brand-50 text-brand-900 dark:bg-brand-950/40 dark:text-brand-100'
                  : 'text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800/40'
                return (
                  <li
                    key={it.key}
                    className={`${baseCls} ${hoverCls}`}
                    onMouseEnter={() => setActiveIdx(i)}
                    onClick={() => {
                      if (it.type === 'page') navigate(it.to)
                      else if (it.type === 'cve') navigate(`/cve/${encodeURIComponent(it.cve_id)}`)
                      else if (it.type === 'asset') navigate(`/assets/${it.id}`)
                      onClose?.()
                    }}
                  >
                    {it.type === 'page' && (
                      <>
                        <span className="flex h-7 w-7 items-center justify-center rounded-md bg-slate-100 dark:bg-slate-800 text-slate-500">
                          <svg viewBox="0 0 24 24" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" />
                            <path d="M14 3v6h6" />
                          </svg>
                        </span>
                        <span className="font-medium">Go to {it.label}</span>
                      </>
                    )}
                    {it.type === 'cve' && (
                      <>
                        <span className="flex h-7 w-7 items-center justify-center rounded-md bg-danger-50 text-danger-600 dark:bg-danger-950/40 dark:text-danger-300 font-mono text-xs font-bold">C</span>
                        <div className="min-w-0">
                          <p className="font-mono font-medium truncate">{it.label}</p>
                          <p className="text-xs text-slate-500 dark:text-slate-400 truncate">{it.sub || '—'}</p>
                        </div>
                        {it.severity && (
                          <span className="ml-auto text-xs font-semibold text-slate-500">{it.severity}</span>
                        )}
                      </>
                    )}
                    {it.type === 'asset' && (
                      <>
                        <span className="flex h-7 w-7 items-center justify-center rounded-md bg-info-50 text-info-600 dark:bg-info-950/40 dark:text-info-300">
                          <svg viewBox="0 0 24 24" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M3 21h18M5 21V7l7-4 7 4v14" />
                          </svg>
                        </span>
                        <div className="min-w-0">
                          <p className="font-medium truncate">{it.label}</p>
                          <p className="text-xs text-slate-500 dark:text-slate-400 truncate font-mono">{it.sub}</p>
                        </div>
                      </>
                    )}
                  </li>
                )
              })}
            </ul>
          )}
        </div>
        <div className="flex items-center justify-between gap-3 border-t border-slate-200 dark:border-slate-800 px-5 py-2 text-[11px] text-slate-500 dark:text-slate-400">
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1">
              <kbd className="rounded border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-1 font-mono">↑↓</kbd>
              navigate
            </span>
            <span className="flex items-center gap-1">
              <kbd className="rounded border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-1 font-mono">↵</kbd>
              open
            </span>
            <span className="flex items-center gap-1">
              <kbd className="rounded border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-1 font-mono">esc</kbd>
              close
            </span>
          </div>
          <span className="font-mono">{items.length} result{items.length === 1 ? '' : 's'}</span>
        </div>
      </div>
    </Modal>
  )
}
