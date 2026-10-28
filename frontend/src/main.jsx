import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import App from './App.jsx'
import ErrorBoundary from './components/ErrorBoundary.jsx'
import { AuthProvider } from './context/AuthContext.jsx'
import './styles/index.css'

// Apply the persisted theme before React mounts so we don't get a flash
// of light content when the user picked dark mode.
(function applyInitialTheme() {
  try {
    const stored = window.localStorage.getItem('vulnwatch_theme')
    const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
    const theme = stored === 'light' || stored === 'dark'
      ? stored
      : (prefersDark ? 'dark' : 'light')
    if (theme === 'dark') document.documentElement.classList.add('dark')
  } catch { /* localStorage unavailable */ }
})()

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ErrorBoundary>
      <BrowserRouter>
        <AuthProvider>
          <App />
          <Toaster
            position="top-right"
            toastOptions={{
              style: {
                background: 'var(--toast-bg, #FFFFFF)',
                color: 'var(--toast-fg, #1F2937)',
                border: '1px solid var(--toast-border, #E5E7EB)',
              },
              success: { iconTheme: { primary: '#10B981', secondary: '#FFFFFF' } },
              error:   { iconTheme: { primary: '#F43F5E', secondary: '#FFFFFF' } },
            }}
          />
        </AuthProvider>
      </BrowserRouter>
    </ErrorBoundary>
  </React.StrictMode>,
)
