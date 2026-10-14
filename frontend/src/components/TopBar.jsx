// TopBar — the page's global header. Holds the page search trigger
// (opens CommandPalette on ⌘K / Ctrl-K), theme toggle, and the user menu.

import { useEffect, useState } from 'react'
import UserMenu from './UserMenu.jsx'
import ThemeToggle from './ThemeToggle.jsx'
import ColorPalettePicker from './ColorPalettePicker.jsx'

export default function TopBar({ onOpenSearch }) {
  const [shortcut, setShortcut] = useState('Ctrl K')

  useEffect(() => {
    const isMac = typeof navigator !== 'undefined' && /Mac|iPod|iPhone|iPad/.test(navigator.platform)
    setShortcut(isMac ? '⌘ K' : 'Ctrl K')
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        onOpenSearch?.()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onOpenSearch])

  return (
    <header className="sticky top-0 z-30 flex h-16 items-center gap-3 border-b border-slate-200/80 bg-white/70 px-6 backdrop-blur-md dark:border-slate-800/80 dark:bg-slate-900/70">
      <button
        type="button"
        onClick={onOpenSearch}
        className="group flex h-10 flex-1 max-w-xl items-center gap-3 rounded-xl border border-slate-200 bg-slate-50/80 px-3 text-left text-sm text-slate-500
                   hover:border-slate-300 hover:bg-white hover:shadow-sm
                   dark:border-slate-800 dark:bg-slate-800/50 dark:text-slate-400
                   dark:hover:border-slate-700 dark:hover:bg-slate-800 transition-all"
      >
        <svg viewBox="0 0 24 24" className="h-4 w-4 text-slate-400 group-hover:text-slate-500" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="11" cy="11" r="7" />
          <path d="m20 20-3.5-3.5" />
        </svg>
        <span className="flex-1">Search CVEs, assets, pages…</span>
        <kbd className="hidden items-center gap-1 rounded-md border border-slate-200 bg-white px-1.5 py-0.5 font-mono text-[10px] font-semibold text-slate-500 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400 sm:inline-flex">
          {shortcut}
        </kbd>
      </button>

      <div className="ml-auto flex items-center gap-2">
        <ColorPalettePicker />
        <ThemeToggle />
        <UserMenu />
      </div>
    </header>
  )
}
