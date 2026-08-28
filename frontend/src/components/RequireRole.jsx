// RequireRole — render `children` only when the user matches the role
// list. Redirects unauthenticated users to /login; returns a friendly
// 403 view for authenticated-but-wrong-role.
//
// RBAC 23 — accepts tier names ("super_admin", "institution_admin",
// "security_analyst", "viewer") and the legacy aliases ("admin",
// "analyst"). We canonicalise on the fly so old call sites still work.

import { Navigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'
import PageHeader from './PageHeader.jsx'
import { Card, CardBody } from './Card.jsx'
import {
  roleBadgeStyle,
  roleLabel,
  userTier,
} from '../hooks/permissions.js'

const TIER_ORDER = ['viewer', 'security_analyst', 'institution_admin', 'super_admin']
const ROLE_ALIASES = {
  admin: 'institution_admin',
  analyst: 'security_analyst',
}

function canonical(r) {
  return ROLE_ALIASES[r] || r
}

function tierSatisfies(actual, allowed) {
  // True when the user's tier is at least one of the allowed tiers.
  const actualIdx = TIER_ORDER.indexOf(actual)
  if (actualIdx === -1) return false
  return allowed
    .map(canonical)
    .some((t) => TIER_ORDER.indexOf(t) <= actualIdx)
}

export default function RequireRole({ roles, children, minTier }) {
  const { user } = useAuth()
  if (!user) return <Navigate to="/login" replace />

  const actual = userTier(user)

  // ``minTier`` is the modern way: a single tier name. If the call site
  // still passes ``roles=[...]``, we honour it (treating the list as
  // the set of acceptable minimums).
  const allowedTiers = minTier
    ? [minTier]
    : (roles || []).map(canonical)

  if (!tierSatisfies(actual, allowedTiers)) {
    return (
      <div className="space-y-6 animate-fade-in">
        <PageHeader
          title="Access denied"
          subtitle="You don't have permission to view this page."
        />
        <Card className="max-w-lg">
          <CardBody className="p-6">
            <p className="text-slate-700 dark:text-slate-200">
              This page is restricted to:
            </p>
            <div className="mt-3 flex flex-wrap gap-2">
              {allowedTiers.map((r) => (
                <span key={r} className={`badge ${roleBadgeStyle(r)}`}>
                  {roleLabel(r)}
                </span>
              ))}
            </div>
            <p className="mt-4 text-sm text-slate-500 dark:text-slate-400">
              Your current role is{' '}
              <span className={`badge ${roleBadgeStyle(actual)}`}>
                {roleLabel(actual)}
              </span>
              . Ask an institution admin to elevate your access if you
              need this page.
            </p>
          </CardBody>
        </Card>
      </div>
    )
  }
  return children
}
