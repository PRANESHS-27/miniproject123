import { useCallback, useEffect, useState } from 'react'

const STORAGE_KEY = 'vulnwatch_palette'

export const PALETTES = [
  { id: 'emerald', name: 'Cyber Emerald', hex: '#10b981', desc: 'SOC / Defense Green' },
  { id: 'indigo', name: 'Indigo Enterprise', hex: '#6366f1', desc: 'Modern High-Tech' },
  { id: 'blue', name: 'Royal Blue', hex: '#2563eb', desc: 'Classic Institutional' },
  { id: 'cyan', name: 'Cyberpunk Teal', hex: '#06b6d4', desc: 'Electric Terminal' },
  { id: 'violet', name: 'Deep Violet', hex: '#8b5cf6', desc: 'Executive Security' },
  { id: 'rose', name: 'Crimson Alert', hex: '#f43f5e', desc: 'High-Alert Focus' },
]

function readInitial() {
  if (typeof window === 'undefined') return 'emerald'
  const stored = window.localStorage.getItem(STORAGE_KEY)
  if (PALETTES.some((p) => p.id === stored)) return stored
  return 'emerald' // Default to Cyber Emerald for a rich cybersecurity look!
}

function applyPalette(id) {
  if (typeof document === 'undefined') return
  const root = document.documentElement
  root.setAttribute('data-color', id)
}

export default function useColorPalette() {
  const [palette, setPalette] = useState(readInitial)

  useEffect(() => {
    applyPalette(palette)
    try {
      window.localStorage.setItem(STORAGE_KEY, palette)
    } catch {
      // ignore in private browsing
    }
  }, [palette])

  const selectPalette = useCallback((id) => {
    setPalette(id)
  }, [])

  return { palette, selectPalette, palettes: PALETTES }
}
