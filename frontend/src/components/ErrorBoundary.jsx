import { Component } from 'react'

/**
 * Catches any uncaught render-time error and displays it inline so a
 * blank page is never silent. Shows the component stack and the message.
 */
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { error: null, info: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    // eslint-disable-next-line no-console
    console.error('[ErrorBoundary]', error, info)
    this.setState({ info })
  }

  render() {
    if (!this.state.error) return this.props.children
    const { error, info } = this.state
    return (
      <div className="min-h-screen flex items-center justify-center p-6 bg-slate-50 dark:bg-slate-950">
        <div className="max-w-2xl w-full rounded-2xl bg-white dark:bg-slate-900 border border-danger-200 dark:border-danger-900/60 shadow-card p-6">
          <div className="flex items-center gap-3 mb-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-danger-100 text-danger-700 dark:bg-danger-950/60 dark:text-danger-300">
              <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 9v4M12 17h.01" />
                <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
              </svg>
            </span>
            <div>
              <h1 className="text-base font-semibold text-slate-900 dark:text-slate-50">Something went wrong</h1>
              <p className="text-xs text-slate-500 dark:text-slate-400">The page hit an error while rendering.</p>
            </div>
          </div>
          <pre className="bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 rounded-lg p-3 overflow-auto whitespace-pre-wrap text-xs text-slate-700 dark:text-slate-200 font-mono">
            <strong>{error?.name}: {error?.message}</strong>
            {'\n\n'}
            {error?.stack || '(no stack)'}
            {'\n\n'}
            {info?.componentStack || '(no componentStack)'}
          </pre>
          <button
            onClick={() => window.location.reload()}
            className="mt-4 inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-brand-600 hover:bg-brand-700 text-white text-sm font-medium"
          >
            Reload page
          </button>
        </div>
      </div>
    )
  }
}
