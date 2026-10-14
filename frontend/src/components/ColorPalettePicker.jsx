import { useState, useRef, useEffect } from 'react'
import useColorPalette from '../hooks/useColorPalette.js'

export default function ColorPalettePicker() {
  const { palette, selectPalette, palettes } = useColorPalette()
  const [open, setOpen] = useState(false)
  const menuRef = useRef(null)

  useEffect(() => {
    const handleOutside = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handleOutside)
    return () => document.removeEventListener('mousedown', handleOutside)
  }, [])

  const current = palettes.find((p) => p.id === palette) || palettes[0]

  return (
    <div className="relative" ref={menuRef}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex h-10 items-center gap-2 rounded-xl border border-slate-200 bg-white px-2.5 text-slate-600 hover:bg-slate-50 hover:text-slate-900 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300 dark:hover:bg-slate-800 transition-colors shadow-xs"
        aria-label="Change UI Theme Color"
        title="Change UI Theme Color"
      >
        <span
          className="h-3.5 w-3.5 rounded-full shadow-inner ring-2 ring-white dark:ring-slate-900"
          style={{ backgroundColor: current.hex }}
        />
        <span className="hidden md:inline text-xs font-medium">{current.name.split(' ')[0]}</span>
        <svg className="w-3.5 h-3.5 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-56 rounded-2xl border border-slate-200 bg-white p-2 shadow-pop dark:border-slate-800 dark:bg-slate-900 z-50 animate-fade-in">
          <div className="px-2.5 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 border-b border-slate-100 dark:border-slate-800 mb-1">
            Accent Theme
          </div>
          <div className="space-y-1">
            {palettes.map((p) => {
              const active = p.id === palette
              return (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => {
                    selectPalette(p.id)
                    setOpen(false)
                  }}
                  className={`w-full flex items-center justify-between gap-3 px-2.5 py-2 rounded-xl text-left text-xs font-medium transition-all ${
                    active
                      ? 'bg-slate-100 text-slate-900 dark:bg-slate-800 dark:text-slate-100 shadow-xs'
                      : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800/60 dark:hover:text-slate-200'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <span
                      className="h-3.5 w-3.5 rounded-full ring-2 ring-white dark:ring-slate-800 shadow-xs shrink-0"
                      style={{ backgroundColor: p.hex }}
                    />
                    <div>
                      <div className="font-medium text-slate-900 dark:text-slate-100">{p.name}</div>
                      <div className="text-[10px] text-slate-400 font-normal">{p.desc}</div>
                    </div>
                  </div>
                  {active && (
                    <svg className="w-4 h-4 text-emerald-600 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                    </svg>
                  )}
                </button>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
