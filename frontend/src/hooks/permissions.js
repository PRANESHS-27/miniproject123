// Frontend permission matrix. Mirrors backend/app/core/permissions.py
// so the UI hides things the user can't do — but the backend still
// enforces the same matrix, so a stale UI can't grant access.
//
// RBAC 23 — 4-tier role model:
//   super_admin          > institution_admin > security_analyst > viewer
// Higher tiers implicitly get every permission assigned to a lower tier
// (mirrors the backend ``_expand_with_inheritance``).

export const ROLES = [
  'super_admin',
  'institution_admin',
  'security_analyst',
  'viewer',
]

// Legacy tier aliases kept so previously-cached users don't lose access
// during the upgrade window. The backend normalises them via role_tier().
const ROLE_ALIASES = {
  admin: 'institution_admin',
  analyst: 'security_analyst',
}

// Tier ordering — higher index = higher privilege.
const TIER_ORDER = ['viewer', 'security_analyst', 'institution_admin', 'super_admin']

export function tierIndex(t) {
  const canonical = ROLE_ALIASES[t] || t
  const idx = TIER_ORDER.indexOf(canonical)
  return idx === -1 ? 0 : idx
}

const PERMISSIONS = {
  // Dashboard / read-only data — every authenticated user.
  dashboard: ['viewer'],
  vulnerability: ['viewer'],
  asset: ['viewer'],
  asset_finding: ['viewer'],
  cve_match: ['viewer'],
  finding_read: ['viewer'],
  ai_ask: ['viewer'],

  // Analyst tier (and above).
  asset_scan: ['security_analyst'],
  asset_finding_resolve: ['security_analyst'],
  finding_update: ['security_analyst'],
  report_generate: ['security_analyst'],

  // Institution-admin tier (and above).
  asset_create: ['institution_admin'],
  asset_update: ['institution_admin'],
  asset_delete: ['institution_admin'],
  sync_trigger: ['institution_admin'],
  user_manage: ['institution_admin'],

  // Super-admin only — cross-tenant operations.
  institution_manage: ['super_admin'],
}

// Pre-expand each permission row so runtime checks are O(1).
const EFFECTIVE_PERMISSIONS = Object.fromEntries(
  Object.entries(PERMISSIONS).map(([key, minimumTiers]) => {
    const out = new Set()
    for (const t of minimumTiers) {
      const idx = TIER_ORDER.indexOf(t)
      if (idx >= 0) TIER_ORDER.slice(idx).forEach((x) => out.add(x))
    }
    return [key, Array.from(out)]
  }),
)

export function role(user) {
  return user?.role || 'viewer'
}

// Canonical tier for a user, mapping legacy aliases.
export function userTier(user) {
  const r = role(user)
  return ROLE_ALIASES[r] || r
}

export function can(user, action) {
  const allowed = EFFECTIVE_PERMISSIONS[action]
  if (!allowed) return false
  return allowed.includes(userTier(user))
}

export function isSuperAdmin(user) {
  return userTier(user) === 'super_admin'
}

export function isInstitutionAdmin(user) {
  const t = userTier(user)
  return t === 'institution_admin' || t === 'super_admin'
}

// Returns the list of role values the *current* user is allowed to
// grant when creating or editing another user. Mirrors the backend
// ``_assert_can_grant_role`` rule: only super admins can grant
// super_admin.
export function grantableRoles(user) {
  if (isSuperAdmin(user)) return ROLES
  if (isInstitutionAdmin(user)) {
    return ROLES.filter((r) => r !== 'super_admin')
  }
  return []
}

export function roleBadgeStyle(r) {
  const tier = ROLE_ALIASES[r] || r
  switch (tier) {
    case 'super_admin':
      return 'bg-purple-50 text-purple-700 border-purple-200 dark:bg-purple-950/40 dark:text-purple-300 dark:border-purple-800/60'
    case 'institution_admin':
      return 'bg-warning-50 text-warning-700 border-warning-200 dark:bg-warning-950/40 dark:text-warning-300 dark:border-warning-800/60'
    case 'security_analyst':
      return 'bg-info-50 text-info-700 border-info-200 dark:bg-info-950/40 dark:text-info-300 dark:border-info-800/60'
    default:
      return 'bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700'
  }
}

export function roleLabel(r) {
  const tier = ROLE_ALIASES[r] || r
  switch (tier) {
    case 'super_admin':
      return 'Super Admin'
    case 'institution_admin':
      return 'Institution Admin'
    case 'security_analyst':
      return 'Security Analyst'
    default:
      return 'Viewer'
  }
}
