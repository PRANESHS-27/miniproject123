import axios from 'axios'

// In dev, vite proxy forwards /api to the backend.
// In prod, set VITE_API_BASE to your API domain.
const baseURL = import.meta.env.VITE_API_BASE || ''

export const api = axios.create({
  baseURL,
  headers: { 'Content-Type': 'application/json' },
})
// Attach JWT to every request when present
api.interceptors.request.use((config) => {
  try {
    const token = localStorage.getItem('vulnwatch_token')
    if (token) config.headers.Authorization = `Bearer ${token}`
  } catch { /* localStorage may be unavailable */ }
  return config
})

// Centralized 401 handler. We don't hard-redirect to /login — the auth
// context reacts to this flag and clears the user. The Router component
// itself decides whether to render the login page based on the auth
// state, which keeps the redirect out of interceptor side effects.
api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      try {
        localStorage.removeItem('vulnwatch_token')
        localStorage.removeItem('vulnwatch_user')
      } catch { /* ignore */ }
      // Notify AuthContext via a custom event so it can re-render.
      window.dispatchEvent(new CustomEvent('vulnwatch:auth-expired'))
    }
    return Promise.reject(err)
  },
)

// ----- Auth -----
export const auth = {
  login: (username, password) => api.post('/api/auth/login', { username, password }).then((r) => r.data),
  register: (payload) => api.post('/api/auth/register', payload).then((r) => r.data),
  me: () => api.get('/api/auth/me').then((r) => r.data),
}

// ----- Vulnerabilities -----
export const vulnerabilities = {
  dashboard: () => api.get('/api/vulnerabilities/dashboard').then((r) => r.data),
  search: (params) => api.get('/api/vulnerabilities/search', { params }).then((r) => r.data),
  detail: (cveId, config = {}) => api.get(`/api/vulnerabilities/${encodeURIComponent(cveId)}`, config).then((r) => r.data),
}

// ----- AI -----
export const ai = {
  ask: (question) => api.post('/api/ai/ask', { question }).then((r) => r.data),
  status: () => api.get('/api/ai/status').then((r) => r.data),
}

// ----- Reports -----
// The backend streams reports with the JWT in the Authorization header.
// We fetch as a blob, create a temporary URL, and trigger a click. This
// avoids ever putting the token in the URL bar (or in browser history).
export const reports = {
  async download(kind, params) {
    // ``kind`` is hardcoded at the call sites, but defensively reject
    // anything unexpected so a future caller can't smuggle path segments.
    const allowed = new Set(['pdf', 'csv'])
    if (!allowed.has(kind)) {
      throw new Error(`Unknown report kind: ${kind}`)
    }
    const cleanParams = Object.fromEntries(
      Object.entries(params || {}).filter(([, v]) => v !== '' && v !== null && v !== undefined)
    )
    const url = `/api/reports/${kind}`
    const response = await api.get(url, {
      params: cleanParams,
      responseType: 'blob',
    })
    // Pull the filename out of the Content-Disposition header.
    const disp = response.headers['content-disposition'] || ''
    const m = /filename="([^"]+)"/.exec(disp)
    const filename = m ? m[1] : `vuln-report.${kind}`
    const blobUrl = window.URL.createObjectURL(response.data)
    try {
      const a = document.createElement('a')
      a.href = blobUrl
      a.download = filename
      a.style.display = 'none'
      document.body.appendChild(a)
      a.click()
      a.remove()
    } finally {
      window.URL.revokeObjectURL(blobUrl)
    }
    return filename
  },
  pdf: (params) => reports.download('pdf', params),
  csv: (params) => reports.download('csv', params),
}

// ----- Sync (admin only) -----
export const sync = {
  nvdFull: () => api.post('/api/sync/nvd/full').then((r) => r.data),
  nvdIncremental: () => api.post('/api/sync/nvd/incremental').then((r) => r.data),
  kev: () => api.post('/api/sync/kev').then((r) => r.data),
  status: () => api.get('/api/sync/status').then((r) => r.data),
}

// ----- Assets (company-owned websites) -----
export const assets = {
  list: (params) => api.get('/api/assets', { params }).then((r) => r.data),
  get: (id, config = {}) => api.get(`/api/assets/${id}`, config).then((r) => r.data),
  create: (payload) => api.post('/api/assets', payload).then((r) => r.data),
  update: (id, payload) => api.patch(`/api/assets/${id}`, payload).then((r) => r.data),
  delete: (id) => api.delete(`/api/assets/${id}`).then((r) => r.data),
  scan: (id) => api.post(`/api/assets/${id}/scan`).then((r) => r.data),
  findings: (id, params) => api.get(`/api/assets/${id}/findings`, { params }).then((r) => r.data),
  resolveFinding: (id, fid) => api.patch(`/api/assets/${id}/findings/${fid}/resolve`).then((r) => r.data),
  cves: (id) => api.get(`/api/assets/${id}/cves`).then((r) => r.data),
  recentScans: (params) => api.get('/api/assets/scans/recent', { params }).then((r) => r.data),
  stats: () => api.get('/api/assets/stats').then((r) => r.data),
}

// ----- Admin: user management -----
export const admin = {
  listUsers: (params) => api.get('/api/admin/users', { params }).then((r) => r.data),
  createUser: (payload) => api.post('/api/admin/users', payload).then((r) => r.data),
  updateUser: (id, payload) => api.patch(`/api/admin/users/${id}`, payload).then((r) => r.data),
  deleteUser: (id) => api.delete(`/api/admin/users/${id}`).then((r) => r.data),
}

// ----- Findings (Phase 4 — Risk Engine output) -----
export const findings = {
  list: (params) => api.get('/api/findings', { params }).then((r) => r.data),
  stats: () => api.get('/api/findings/stats').then((r) => r.data),
  get: (id) => api.get(`/api/findings/${id}`).then((r) => r.data),
  update: (id, payload) => api.patch(`/api/findings/${id}`, payload).then((r) => r.data),
  acceptRisk: (id, reason) => api.post(`/api/findings/${id}/accept-risk`, { reason }).then((r) => r.data),
}