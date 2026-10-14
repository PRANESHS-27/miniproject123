import { useMemo, useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import toast from 'react-hot-toast'
import { useAuth } from '../context/AuthContext.jsx'
import Button from '../components/Button.jsx'
import { Card } from '../components/Card.jsx'

function strength(pwd) {
  if (!pwd) return { score: 0, label: '—' }
  let score = 0
  if (pwd.length >= 8) score += 1
  if (/[A-Z]/.test(pwd)) score += 1
  if (/[a-z]/.test(pwd)) score += 1
  if (/[0-9]/.test(pwd)) score += 1
  if (/[^A-Za-z0-9]/.test(pwd)) score += 1
  const labels = ['very weak', 'weak', 'okay', 'good', 'strong', 'excellent']
  return { score, label: labels[score] }
}

const STRENGTH_BAR = [
  'bg-danger-500 w-1/5',
  'bg-danger-500 w-2/5',
  'bg-warning-500 w-3/5',
  'bg-amber-500 w-4/5',
  'bg-success-500 w-full',
  'bg-success-600 w-full',
]
const STRENGTH_TEXT = [
  'text-danger-600',
  'text-danger-600',
  'text-warning-600',
  'text-amber-600',
  'text-success-600',
  'text-success-700',
]

export default function LoginPage() {
  const { login, register, loading } = useAuth()
  const [mode, setMode] = useState('login')
  const [form, setForm] = useState({
    username: '',
    email: '',
    password: '',
    full_name: '',
    role: 'viewer',
  })
  const navigate = useNavigate()
  const location = useLocation()
  const from = location.state?.from?.pathname || '/dashboard'

  const onChange = (e) => setForm((f) => ({ ...f, [e.target.name]: e.target.value }))
  const pwdStrength = useMemo(() => strength(form.password), [form.password])

  const onSubmit = async (e) => {
    e.preventDefault()
    const username = form.username.trim()
    const email = form.email.trim()
    try {
      if (mode === 'login') {
        if (!username) return toast.error('Username is required')
        await login(username, form.password)
        toast.success('Signed in')
        navigate(from, { replace: true })
        return
      }
      if (!username || !email) return toast.error('Username and email are required')
      const res = await register({
        username,
        email,
        password: form.password,
        full_name: form.full_name.trim() || undefined,
        role: form.role,
      })
      if (res && res.access_token && res.user) {
        toast.success('Account created — welcome to VulnWatch.')
        navigate(from, { replace: true })
        return
      }
      toast.success('Account created — please sign in.')
      setMode('login')
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Authentication failed')
    }
  }

  return (
    <div className="min-h-screen grid grid-cols-1 lg:grid-cols-2 app-shell-bg">
      {/* Brand panel */}
      <div className="hidden lg:flex flex-col justify-between p-12 bg-gradient-to-br from-brand-700 via-brand-600 to-brand-900 text-white relative overflow-hidden">
        <div className="absolute inset-0 opacity-30 pointer-events-none"
             style={{ backgroundImage: 'radial-gradient(circle at 20% 20%, rgba(255,255,255,0.25), transparent 50%), radial-gradient(circle at 80% 80%, rgba(6,182,212,0.25), transparent 50%)' }}
             aria-hidden="true" />
        <div className="relative flex items-center gap-3 text-xl font-bold">
          <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-white/15 backdrop-blur">
            <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 2 4 6v6c0 5 3.5 9.5 8 10 4.5-.5 8-5 8-10V6l-8-4z" />
              <path d="m9 12 2 2 4-4" />
            </svg>
          </span>
          VulnWatch
        </div>
        <div className="relative max-w-md">
          <h2 className="text-3xl font-semibold leading-tight tracking-tight">
            AI-powered vulnerability monitoring for the apps you actually run.
          </h2>
          <p className="mt-4 text-white/85 leading-relaxed">
            Continuous NVD &amp; CISA KEV sync, asset fingerprinting, and a
            context-aware analyst that explains what to patch first.
          </p>

          <div className="mt-8 grid grid-cols-3 gap-3 text-xs">
            {[
              { k: '24/7', v: 'Live NVD feed' },
              { k: 'RAG', v: 'Contextual answers' },
              { k: 'KEV', v: 'CISA prioritised' },
            ].map((it) => (
              <div key={it.k} className="rounded-xl border border-white/15 bg-white/5 backdrop-blur px-3 py-2.5">
                <div className="text-base font-semibold text-white">{it.k}</div>
                <div className="text-white/70 mt-0.5">{it.v}</div>
              </div>
            ))}
          </div>
        </div>
        <div className="relative text-xs text-white/60">
          Institutional Vulnerability Management &amp; Intelligence Platform
        </div>
      </div>

      {/* Form panel */}
      <div className="flex items-center justify-center px-4 py-12">
        <Card className="w-full max-w-md" variant="elevated">
          <div className="p-8">
            <div className="mb-6 flex items-center gap-2.5 text-brand-600 dark:text-brand-400">
              <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-brand-500 to-brand-700 text-white shadow-sm shadow-brand-700/20">
                <svg viewBox="0 0 24 24" className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                  <path d="M9 12l2 2 4-4" />
                </svg>
              </span>
              <span className="text-lg font-bold tracking-tight">VulnWatch</span>
            </div>
            <h1 className="text-xl font-semibold tracking-tight text-slate-900 dark:text-slate-50 mb-1">
              {mode === 'login' ? 'Sign in to your account' : 'Create your account'}
            </h1>
            <p className="text-sm text-slate-500 dark:text-slate-400 mb-6">
              {mode === 'login'
                ? 'Welcome back. Use your credentials to continue.'
                : 'The first registered user becomes admin automatically.'}
            </p>

            <form onSubmit={onSubmit} className="space-y-4">
              <div>
                <label className="label">Username</label>
                <input
                  className="input"
                  name="username"
                  value={form.username}
                  onChange={onChange}
                  required
                  minLength={3}
                  autoComplete="username"
                />
              </div>
              {mode === 'register' && (
                <>
                  <div>
                    <label className="label">Email</label>
                    <input
                      className="input"
                      type="email"
                      name="email"
                      value={form.email}
                      onChange={onChange}
                      required
                      autoComplete="email"
                    />
                  </div>
                  <div>
                    <label className="label">Full name <span className="text-slate-400 font-normal">(optional)</span></label>
                    <input className="input" name="full_name" value={form.full_name} onChange={onChange} autoComplete="name" />
                  </div>
                  <div>
                    <label className="label">Role</label>
                    <select className="input" name="role" value={form.role} onChange={onChange}>
                      <option value="viewer">Viewer — read-only access</option>
                      <option value="analyst">Analyst — can scan + run AI + resolve findings</option>
                    </select>
                    <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                      The first user to register is promoted to admin automatically.
                    </p>
                  </div>
                </>
              )}
              <div>
                <label className="label">Password</label>
                <input
                  className="input"
                  type="password"
                  name="password"
                  value={form.password}
                  onChange={onChange}
                  minLength={8}
                  required
                  autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                />
                {mode === 'register' && (
                  <div className="mt-2">
                    <div className="h-1 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                      <div className={`h-full transition-all duration-300 ${STRENGTH_BAR[pwdStrength.score] || STRENGTH_BAR[0]}`} />
                    </div>
                    <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                      Strength: <span className={`font-medium ${STRENGTH_TEXT[pwdStrength.score] || 'text-slate-500'}`}>{pwdStrength.label}</span>
                    </p>
                  </div>
                )}
              </div>
              <Button type="submit" variant="primary" size="lg" loading={loading} block>
                {mode === 'login' ? 'Sign in' : 'Create account'}
              </Button>
            </form>

            <p className="text-sm text-slate-500 dark:text-slate-400 mt-5 text-center">
              {mode === 'login' ? (
                <>
                  New here?{' '}
                  <button
                    className="text-brand-600 hover:text-brand-700 hover:underline font-medium dark:text-brand-300"
                    onClick={() => setMode('register')}
                    type="button"
                  >Create an account</button>
                </>
              ) : (
                <>
                  Already have an account?{' '}
                  <button
                    className="text-brand-600 hover:text-brand-700 hover:underline font-medium dark:text-brand-300"
                    onClick={() => setMode('login')}
                    type="button"
                  >Sign in</button>
                </>
              )}
            </p>
          </div>
        </Card>
      </div>
    </div>
  )
}
