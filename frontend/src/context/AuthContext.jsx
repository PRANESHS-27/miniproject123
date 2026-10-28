import { createContext, useContext, useEffect, useState, useCallback } from 'react'
import { auth as authApi } from '../services/api.js'

const AuthContext = createContext(null)

// Read the cached user from localStorage defensively. Anything invalid
// (corrupted JSON, partial write, schema drift) clears the slot so we
// don't crash on mount.
function readCachedUser() {
  if (typeof window === 'undefined') return null
  const raw = window.localStorage.getItem('vulnwatch_user')
  if (!raw) return null
  try {
    const parsed = JSON.parse(raw)
    if (parsed && typeof parsed === 'object') return parsed
  } catch {
    /* fall through */
  }
  try { window.localStorage.removeItem('vulnwatch_user') } catch { /* ignore */ }
  return null
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(readCachedUser)
  const [loading, setLoading] = useState(false)
  // ``initializing`` is true until the first /auth/me resolves. The
  // App router uses it to render a spinner instead of briefly redirecting
  // to /login on a cold reload with a cached (still-valid) token.
  const [initializing, setInitializing] = useState(
    () => readCachedUser() !== null,
  )

  const persist = useCallback((token, userObj) => {
    try {
      if (token) localStorage.setItem('vulnwatch_token', token)
      if (userObj) localStorage.setItem('vulnwatch_user', JSON.stringify(userObj))
    } catch {
      /* localStorage may be unavailable in private mode */
    }
    setUser(userObj || null)
  }, [])

  const login = useCallback(async (username, password) => {
    setLoading(true)
    try {
      const data = await authApi.login(username, password)
      persist(data.access_token, data.user)
      return data.user
    } finally {
      setLoading(false)
    }
  }, [persist])

  const register = useCallback(async (payload) => {
    setLoading(true)
    try {
      const data = await authApi.register(payload)
      // Auto-login if the backend hands us a token (it does on success).
      if (data && data.access_token && data.user) {
        persist(data.access_token, data.user)
      }
      return data
    } finally {
      setLoading(false)
    }
  }, [persist])

  const logout = useCallback(() => {
    try {
      localStorage.removeItem('vulnwatch_token')
      localStorage.removeItem('vulnwatch_user')
    } catch { /* ignore */ }
    setUser(null)
  }, [])

  // Validate the cached token on first mount. Guarded against React 18
  // StrictMode double-invocation so we don't kick off two concurrent
  // /auth/me calls and race on the response.
  useEffect(() => {
    if (!user) {
      setInitializing(false)
      return
    }
    let isCurrent = true
    authApi.me()
      .then((fresh) => {
        if (!isCurrent) return
        if (fresh && typeof fresh === 'object') {
          setUser(fresh)
          try {
            localStorage.setItem('vulnwatch_user', JSON.stringify(fresh))
          } catch { /* ignore */ }
        }
      })
      .catch(() => {
        if (!isCurrent) return
        logout()
      })
      .finally(() => {
        setInitializing(false)
      })

    // Safety timeout: never leave initializing true for more than 1.5 seconds
    const timer = setTimeout(() => {
      setInitializing(false)
    }, 1500)

    return () => {
      isCurrent = false
      clearTimeout(timer)
      setInitializing(false)
    }
  }, [logout])

  // Listen for 401s fired by the axios interceptor. AuthContext is the
  // single source of truth for the user state, so when the token is gone
  // we clear it here.
  useEffect(() => {
    const onExpired = () => logout()
    window.addEventListener('vulnwatch:auth-expired', onExpired)
    return () => window.removeEventListener('vulnwatch:auth-expired', onExpired)
  }, [logout])

  return (
    <AuthContext.Provider
      value={{ user, loading, initializing, login, register, logout }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)