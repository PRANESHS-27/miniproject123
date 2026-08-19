// RequireRole — render `children` only when the user matches the role
// list. Redirects unauthenticated users to /login; returns a friendly
// 403 view for authenticated-but-wrong-role.

import { Navigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'
import PageHeader from './PageHeader.jsx'
import { Card, CardBody } from './Card.jsx'
import { roleBadgeStyle } from '../hooks/permissions.js'

export default function RequireRole({ roles, children }) {
  const { user } = useAuth()
  if (!user) return <Navigate to="/login" replace />
  const current = user.role || 'viewer'
  if (!roles.includes(current)) {
    return (
      <div className="space-y-6 animate-fade-in">
        <PageHeader title="Access denied" subtitle="You don't have permission to view this page." />
        <Card className="max-w-lg">
          <CardBody className="p-6">
            <p className="text-slate-700 dark:text-slate-200">
              This page is restricted to:
            </p>
            <div className="mt-3 flex flex-wrap gap-2">
              {roles.map((r) => (
                <span key={r} className={`badge ${roleBadgeStyle(r)}`}>{r}</span>
              ))}
            </div>
            <p className="mt-4 text-sm text-slate-500 dark:text-slate-400">
              Your current role is{' '}
              <span className={`badge ${roleBadgeStyle(current)}`}>{current}</span>.
              Ask an admin to elevate your access if you need this page.
            </p>
          </CardBody>
        </Card>
      </div>
    )
  }
  return children
}
