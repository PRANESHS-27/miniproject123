import { useState } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import Sidebar from './components/Sidebar.jsx'
import TopBar from './components/TopBar.jsx'
import CommandPalette from './components/CommandPalette.jsx'
import ProtectedRoute from './components/ProtectedRoute.jsx'
import RequireRole from './components/RequireRole.jsx'
import LoginPage from './pages/LoginPage.jsx'
import DashboardPage from './pages/DashboardPage.jsx'
import SearchPage from './pages/SearchPage.jsx'
import CveDetailPage from './pages/CveDetailPage.jsx'
import AiPage from './pages/AiPage.jsx'
import ReportsPage from './pages/ReportsPage.jsx'
import AssetsPage from './pages/AssetsPage.jsx'
import FindingsPage from './pages/FindingsPage.jsx'
import AssetDetailPage from './pages/AssetDetailPage.jsx'
import AdminUsersPage from './pages/AdminUsersPage.jsx'
import { useAuth } from './context/AuthContext.jsx'

function Shell({ children, onOpenSearch }) {
  return (
    <div className="flex min-h-screen app-shell-bg">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar onOpenSearch={onOpenSearch} />
        <main className="min-w-0 flex-1 px-6 py-6 md:px-8 md:py-8 max-w-[1440px] mx-auto w-full">
          {children}
        </main>
      </div>
    </div>
  )
}

export default function App() {
  const { user, initializing } = useAuth()
  const location = useLocation()
  const [paletteOpen, setPaletteOpen] = useState(false)

  // On cold load with a cached token, show a spinner instead of briefly
  // redirecting to /login while /auth/me is in flight. This avoids the
  // login-page flicker when reloading a tab you're already signed into.
  if (initializing) {
    return (
      <div
        role="status"
        aria-live="polite"
        className="flex min-h-screen items-center justify-center app-shell-bg"
      >
        <div className="h-10 w-10 animate-spin rounded-full border-2 border-slate-300 border-t-blue-500" />
        <span className="sr-only">Loading…</span>
      </div>
    )
  }

  if (location.pathname === '/login' || !user) {
    return (
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    )
  }

  return (
    <>
      <Shell onOpenSearch={() => setPaletteOpen(true)}>
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<ProtectedRoute><DashboardPage /></ProtectedRoute>} />
          <Route path="/search" element={<ProtectedRoute><SearchPage /></ProtectedRoute>} />
          <Route path="/cve/:cveId" element={<ProtectedRoute><CveDetailPage /></ProtectedRoute>} />
          <Route path="/ai" element={<ProtectedRoute><AiPage /></ProtectedRoute>} />
          <Route path="/reports" element={<RequireRole minTier="security_analyst"><ReportsPage /></RequireRole>} />
          <Route path="/assets" element={<ProtectedRoute><AssetsPage /></ProtectedRoute>} />
          <Route path="/assets/:id" element={<ProtectedRoute><AssetDetailPage /></ProtectedRoute>} />
          <Route path="/findings" element={<ProtectedRoute><FindingsPage /></ProtectedRoute>} />
          <Route path="/admin/users" element={<RequireRole roles={['admin']}><AdminUsersPage /></RequireRole>} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </Shell>
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </>
  )
}
