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

export const formatDateTime = formatDate

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

/**
 * Safely extracts a user-readable error string from an error or API response.
 * Handles FastAPI / Pydantic validation errors (array of { loc, msg, type } objects),
 * standard Error instances, strings, and generic objects so React never crashes
 * trying to render an object as a child.
 */
export function formatError(err, fallback = 'An error occurred') {
  if (!err) return fallback
  if (typeof err === 'string') return err

  const detail = err?.response?.data?.detail ?? err?.detail ?? err?.message
  if (!detail) return fallback
  if (typeof detail === 'string') return detail

  if (Array.isArray(detail)) {
    const messages = detail
      .map((d) => {
        if (!d) return ''
        if (typeof d === 'string') return d
        if (typeof d === 'object') {
          // Pydantic v2 format: { loc: ['body', 'field'], msg: '...', type: '...' }
          const field = Array.isArray(d.loc) && d.loc.length ? d.loc[d.loc.length - 1] : ''
          const msg = d.msg || d.message || JSON.stringify(d)
          return field ? `${field}: ${msg}` : msg
        }
        return String(d)
      })
      .filter(Boolean)
    return messages.length > 0 ? messages.join('; ') : fallback
  }

  if (typeof detail === 'object') {
    return detail.msg || detail.message || JSON.stringify(detail)
  }

  return String(detail)
}

