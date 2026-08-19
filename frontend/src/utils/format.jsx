// Date / number formatting helpers. Severity / color helpers live in
// severity.jsx; this file stays focused on display formatting.

const dateOpts = { day: 'numeric', month: 'short', year: 'numeric' }
const dateTimeOpts = {
  day: 'numeric',
  month: 'short',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
}

export function formatDate(d) {
  if (!d) return '—'
  try {
    return new Date(d).toLocaleString(undefined, dateTimeOpts)
  } catch {
    return String(d)
  }
}

export function formatShortDate(d) {
  if (!d) return '—'
  try {
    return new Date(d).toLocaleDateString(undefined, dateOpts)
  } catch {
    return String(d)
  }
}

export function formatScore(s) {
  if (s == null) return '—'
  return Number(s).toFixed(1)
}

export function formatNumber(n) {
  if (n == null) return '—'
  return new Intl.NumberFormat().format(n)
}
