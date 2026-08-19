// Frontend permission matrix. Mirrors backend/app/core/permissions.py
// so the UI hides things the user can't do — but the backend still
// enforces the same matrix, so a stale UI can't grant access.

export const ROLES = ['admin', 'analyst', 'viewer']

const PERMISSIONS = {
  // Dashboard / read-only data
  dashboard: ['admin', 'analyst', 'viewer'],
  vulnerability: ['admin', 'analyst', 'viewer'],
  asset: ['admin', 'analyst', 'viewer'],
  asset_finding: ['admin', 'analyst', 'viewer'],
  cve_match: ['admin', 'analyst', 'viewer'],
  // Mutations
  asset_scan: ['admin', 'analyst'],
  asset_finding_resolve: ['admin', 'analyst'],
  asset_create: ['admin'],
  asset_update: ['admin'],
  asset_delete: ['admin'],
  ai_ask: ['admin', 'analyst', 'viewer'],
  report_generate: ['admin'],
  sync_trigger: ['admin'],
  user_manage: ['admin'],
}

export function role(user) {
  return user?.role || 'viewer'
}

export function can(user, action) {
  const allowed = PERMISSIONS[action]
  if (!allowed) return false
  return allowed.includes(role(user))
}

export function isAdmin(user) {
  return role(user) === 'admin'
}

export function roleBadgeStyle(r) {
  switch (r) {
    case 'admin':
      return 'bg-warning-50 text-warning-700 border-warning-200 dark:bg-warning-950/40 dark:text-warning-300 dark:border-warning-800/60'
    case 'analyst':
      return 'bg-info-50 text-info-700 border-info-200 dark:bg-info-950/40 dark:text-info-300 dark:border-info-800/60'
    default:
      return 'bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700'
  }
}
