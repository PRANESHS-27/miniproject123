import { useCallback, useEffect, useState } from 'react'
import toast from 'react-hot-toast'
import PageHeader from '../components/PageHeader.jsx'
import DataTable from '../components/DataTable.jsx'
import Modal from '../components/Modal.jsx'
import Spinner from '../components/Spinner.jsx'
import EmptyState from '../components/EmptyState.jsx'
import Button from '../components/Button.jsx'
import { formatDate, formatError } from '../utils/format.jsx'
import { Card, CardBody } from '../components/Card.jsx'
import { admin } from '../services/api.js'
import { useAuth } from '../context/AuthContext.jsx'
import {
  grantableRoles,
  roleBadgeStyle,
  roleLabel,
} from '../hooks/permissions.js'

export default function AdminUsersPage() {
  const { user: me } = useAuth()
  const [rows, setRows] = useState(null)
  const [q, setQ] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const [editing, setEditing] = useState(null)

  const load = useCallback(() => {
    admin.listUsers({ q: q || undefined, limit: 200 })
      .then(setRows)
      .catch((e) => {
        toast.error(formatError(e, 'Failed to load users'))
        // Stop the spinner even on error so the user sees the empty
        // state and the retry button instead of an eternal spinner.
        setRows([])
      })
  }, [q])

  useEffect(() => {
    // Debounce search input.
    const h = setTimeout(load, 400)
    return () => clearTimeout(h)
  }, [load])

  const onToggleActive = async (u) => {
    try {
      await admin.updateUser(u.id, { is_active: !u.is_active })
      toast.success(u.is_active ? `${u.username} deactivated` : `${u.username} activated`)
      load()
    } catch (e) {
      toast.error(formatError(e, 'Update failed'))
    }
  }

  const onDelete = async (u) => {
    if (!window.confirm(`Delete user "${u.username}"? This cannot be undone.`)) return
    try {
      await admin.deleteUser(u.id)
      toast.success('User deleted')
      load()
    } catch (e) {
      toast.error(formatError(e, 'Delete failed'))
    }
  }

  const columns = [
    { key: 'username', header: 'User', render: (u) => (
      <div>
        <div className="font-medium text-slate-800 dark:text-slate-100">{u.username}{u.id === me?.id && <span className="ml-2 text-xs text-slate-500 dark:text-slate-400">(you)</span>}</div>
        <div className="text-xs text-slate-500 dark:text-slate-400">{u.full_name || '—'}</div>
      </div>
    ) },
    { key: 'email', header: 'Email', render: (u) => <span className="font-mono text-xs text-slate-700 dark:text-slate-200">{u.email}</span> },
    { key: 'role', header: 'Role', render: (u) => <span className={`badge ${roleBadgeStyle(u.role)}`}>{roleLabel(u.role)}</span> },
    { key: 'status', header: 'Status', render: (u) => (
      <span className={`badge capitalize ${u.is_active
        ? 'bg-success-50 text-success-700 border-success-200 dark:bg-success-950/40 dark:text-success-300 dark:border-success-800/60'
        : 'bg-slate-100 text-slate-500 border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700'}`}>
        {u.is_active ? 'active' : 'inactive'}
      </span>
    ) },
    { key: 'created_at', header: 'Created', render: (u) => <span className="text-xs text-slate-500 dark:text-slate-400">{formatDate(u.created_at)}</span> },
    { key: 'actions', header: '', className: 'text-right', render: (u) => (
      <div className="flex justify-end gap-1">
        <Button size="xs" variant="ghost" onClick={() => setEditing(u)}>Edit</Button>
        <Button size="xs" variant="ghost" onClick={() => onToggleActive(u)}>
          {u.is_active ? 'Deactivate' : 'Activate'}
        </Button>
        <Button size="xs" variant="ghost" onClick={() => onDelete(u)} className="text-danger-600 hover:bg-danger-50 dark:hover:bg-danger-950/40">Delete</Button>
      </div>
    ) },
  ]

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="User Management"
        subtitle={`Create, edit, and disable user accounts. Your role (${roleLabel(me?.role)}) can grant the roles shown below.`}
        actions={
          <Button variant="primary" onClick={() => setShowCreate(true)} leftIcon={
            <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
              <circle cx="9" cy="7" r="4" />
              <path d="M19 8v6M22 11h-6" />
            </svg>
          }>Add user</Button>
        }
      />

      <Card>
        <CardBody className="p-4">
          <div className="relative">
            <svg viewBox="0 0 24 24" className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400 pointer-events-none" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="7" /><path d="m21 21-4.3-4.3" />
            </svg>
            <input
              className="input pl-9"
              placeholder="Search by username or email…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </div>
        </CardBody>
      </Card>

      {rows === null ? (
        <div className="flex items-center justify-center py-16"><Spinner label="Loading users…" /></div>
      ) : rows.length === 0 ? (
        <EmptyState title="No users" description={q ? 'No users match your search.' : 'Create the first user via the Add user button above.'} />
      ) : (
        <DataTable
          columns={columns}
          rows={rows}
          emptyTitle="No users"
        />
      )}

      {showCreate && (
        <CreateUserModal
          onClose={() => setShowCreate(false)}
          onCreated={() => { setShowCreate(false); load() }}
        />
      )}
      {editing && (
        <EditUserModal
          user={editing}
          onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); load() }}
        />
      )}
    </div>
  )
}

function CreateUserModal({ onClose, onCreated }) {
  const { user: me } = useAuth()
  const options = grantableRoles(me)
  const [form, setForm] = useState({
    username: '',
    email: '',
    full_name: '',
    password: '',
    role: options[options.length - 1] || 'viewer',
    is_active: true,
  })
  const [busy, setBusy] = useState(false)

  const onChange = (e) => {
    const { name, value, type, checked } = e.target
    setForm((f) => ({ ...f, [name]: type === 'checkbox' ? checked : value }))
  }

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true)
    try {
      await admin.createUser({
        username: form.username.trim(),
        email: form.email.trim(),
        full_name: form.full_name.trim() || undefined,
        password: form.password,
        role: form.role,
        is_active: form.is_active,
      })
      toast.success('User created')
      onCreated()
    } catch (err) {
      toast.error(formatError(err, 'Create failed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="Add a new user"
      actions={
        <>
          <Button variant="secondary" onClick={onClose} type="button">Cancel</Button>
          <Button variant="primary" type="submit" form="create-user-form" loading={busy}>
            {busy ? 'Creating…' : 'Create user'}
          </Button>
        </>
      }
    >
      <form id="create-user-form" onSubmit={submit} className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="label">Username</label>
            <input className="input" name="username" value={form.username} onChange={onChange} required minLength={3} autoComplete="off" />
          </div>
          <div>
            <label className="label">Email</label>
            <input className="input" type="email" name="email" value={form.email} onChange={onChange} required autoComplete="off" />
          </div>
        </div>
        <div>
          <label className="label">Full name <span className="text-slate-400 font-normal">(optional)</span></label>
          <input className="input" name="full_name" value={form.full_name} onChange={onChange} autoComplete="off" />
        </div>
        <div>
          <label className="label">Password</label>
          <input className="input" type="password" name="password" value={form.password} onChange={onChange} required minLength={8} autoComplete="new-password" />
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">Minimum 8 characters.</p>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="label">Role</label>
            <select className="input" name="role" value={form.role} onChange={onChange}>
              {options.map((r) => (
                <option key={r} value={r}>{roleLabel(r)}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="label">Status</label>
            <label className="flex items-center gap-2 mt-2 text-sm">
              <input type="checkbox" name="is_active" checked={form.is_active} onChange={onChange} className="accent-brand-500" />
              Active
            </label>
          </div>
        </div>
      </form>
    </Modal>
  )
}

function EditUserModal({ user, onClose, onSaved }) {
  const { user: me } = useAuth()
  const options = grantableRoles(me)
  const currentRole = user?.role === 'analyst' ? 'security_analyst' : (user?.role === 'admin' ? 'institution_admin' : user?.role)
  // Pre-filter: if the current actor can't grant the user's existing
  // role, hide that option but keep the value as-is (the backend will
  // refuse the change anyway, so it's a no-op edit).
  const roleOptions = options.includes(currentRole)
    ? options
    : [currentRole, ...options]
  const [role, setRole] = useState(currentRole)
  const [isActive, setIsActive] = useState(user.is_active)
  const [busy, setBusy] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true)
    try {
      await admin.updateUser(user.id, { role, is_active: isActive })
      toast.success('User updated')
      onSaved()
    } catch (err) {
      toast.error(formatError(err, 'Update failed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={`Edit ${user.username}`}
      actions={
        <>
          <Button variant="secondary" onClick={onClose} type="button">Cancel</Button>
          <Button variant="primary" type="submit" form="edit-user-form" loading={busy}>
            {busy ? 'Saving…' : 'Save changes'}
          </Button>
        </>
      }
    >
      <form id="edit-user-form" onSubmit={submit} className="space-y-3">
        <div>
          <label className="label">Role</label>
          <select className="input" value={role} onChange={(e) => setRole(e.target.value)}>
            {roleOptions.map((r) => (
              <option key={r} value={r}>{roleLabel(r)}</option>
            ))}
          </select>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Super Admin = cross-tenant · Institution Admin = manage users &amp; assets · Security Analyst = scan/AI/resolve · Viewer = read-only.
          </p>
        </div>
        <div>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={isActive} onChange={(e) => setIsActive(e.target.checked)} className="accent-brand-500" />
            Active
          </label>
        </div>
      </form>
    </Modal>
  )
}
