import { useEffect, useRef, useState } from 'react'
import toast from 'react-hot-toast'
import PageHeader from '../components/PageHeader.jsx'
import Button from '../components/Button.jsx'
import { Card, CardBody } from '../components/Card.jsx'
import { SeverityBadge } from '../components/Badge.jsx'
import { ai as aiApi } from '../services/api.js'

const EXAMPLES = [
  'Show Apache vulnerabilities from 2025',
  'What is CVE-2024-3094 and how do I fix it?',
  'Which Microsoft CVEs are in CISA KEV?',
  'Summarize recent Linux kernel vulnerabilities',
]

export default function AiPage() {
  const [question, setQuestion] = useState('')
  const [answer, setAnswer] = useState(null)
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState(null)
  const reqRef = useRef(0)
  const scrollRef = useRef(null)

  useEffect(() => {
    aiApi.status().then(setStatus).catch(() => setStatus({ provider: 'unknown', configured: false }))
  }, [])

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' })
  }, [answer, loading])

  const ask = async (q) => {
    const query = (q ?? question).trim()
    if (!query) return
    const reqId = ++reqRef.current
    // Reset to a fresh state for this question — don't carry the previous
    // answer's `sources` into the loading view of the next one.
    setQuestion(query)
    setAnswer({ question: query, thinking: true })
    setLoading(true)
    try {
      const data = await aiApi.ask(query)
      if (reqId !== reqRef.current) return
      setAnswer({ question: query, ...data })
    } catch {
      if (reqId !== reqRef.current) return
      toast.error('AI request failed — check that OPENAI_API_KEY / GROQ_API_KEY is configured.')
      setAnswer(null)
    } finally {
      if (reqId === reqRef.current) setLoading(false)
    }
  }

  const showEmpty = !answer && !loading

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        eyebrow="AI"
        title="Security assistant"
        subtitle="Ask natural-language questions about stored vulnerabilities. Responses are generated from indexed CVE data (RAG) and cite CVE IDs."
        actions={status && (
          <span
            className={
              'badge ' + (
                status.configured
                  ? 'bg-success-50 text-success-700 border-success-200 dark:bg-success-950/40 dark:text-success-300 dark:border-success-800/60'
                  : 'bg-warning-50 text-warning-700 border-warning-200 dark:bg-warning-950/40 dark:text-warning-300 dark:border-warning-800/60'
              )
            }
            title="Which model is wired up"
          >
            {status.configured ? '● ' : '⚠ '}
            {status.provider}
          </span>
        )}
      />

      {!status?.configured && (
        <Card variant="flat" className="bg-warning-50/50 border-warning-200 dark:bg-warning-950/20 dark:border-warning-800/60">
          <CardBody>
            <p className="font-semibold text-warning-900 dark:text-warning-200">No LLM configured</p>
            <p className="mt-1 text-sm text-warning-800 dark:text-warning-300">
              Set <code className="font-mono">GROQ_API_KEY</code> (free, fastest),{' '}
              <code className="font-mono">GEMINI_API_KEY</code>,{' '}
              <code className="font-mono">OPENAI_API_KEY</code>, or run{' '}
              <code className="font-mono">OLLAMA_HOST=http://localhost:11434</code> with{' '}
              <code className="font-mono">ollama pull llama3.1</code>. Answers fall back to a plain CVE list until then.
            </p>
          </CardBody>
        </Card>
      )}

      <Card variant="elevated">
        <CardBody className="p-4">
          <div ref={scrollRef} className="max-h-[420px] overflow-y-auto pr-1">
            {showEmpty && (
              <div className="py-10 px-4 text-center">
                <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-to-br from-brand-500/15 to-brand-700/15 text-brand-600 dark:from-brand-500/20 dark:to-brand-700/20 dark:text-brand-300">
                  <svg viewBox="0 0 24 24" className="h-6 w-6" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M5.6 18.4l2.1-2.1M16.3 7.7l2.1-2.1" /><circle cx="12" cy="12" r="3" /></svg>
                </div>
                <p className="text-base font-semibold text-slate-900 dark:text-slate-50">What can I ask?</p>
                <p className="mt-1 text-sm text-slate-500 dark:text-slate-400 max-w-md mx-auto">
                  Try a CVE id, a vendor, or a topic — the assistant searches the database and synthesises an answer.
                </p>
                <div className="mt-6 grid sm:grid-cols-2 gap-2 max-w-2xl mx-auto">
                  {EXAMPLES.map((ex) => (
                    <button
                      key={ex}
                      type="button"
                      onClick={() => ask(ex)}
                      className="text-left text-sm px-3 py-2.5 rounded-xl border border-slate-200/80 dark:border-slate-700 hover:border-brand-300 hover:bg-brand-50 dark:hover:border-brand-700 dark:hover:bg-brand-950/30 transition-colors text-slate-700 dark:text-slate-200"
                    >
                      <span className="font-mono text-brand-600 dark:text-brand-300 mr-1">›</span>
                      {ex}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {answer && (
              <div className="space-y-4">
                <div className="flex items-start justify-end">
                  <div className="max-w-[80%] rounded-2xl rounded-tr-md bg-gradient-to-br from-brand-500 to-brand-700 text-white px-4 py-3 shadow-sm">
                    <p className="text-sm whitespace-pre-wrap">{answer.question}</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <div className="shrink-0 flex h-8 w-8 items-center justify-center rounded-xl bg-gradient-to-br from-brand-500 to-brand-700 text-white shadow-sm">
                    <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 3v3M12 18v3M3 12h3M18 12h3" /></svg>
                  </div>
                  <div className="max-w-[85%] rounded-2xl rounded-tl-md bg-slate-100 dark:bg-slate-800 px-4 py-3 text-sm text-slate-800 dark:text-slate-100">
                    {answer.thinking || (loading && !answer.answer) ? (
                      <div className="flex items-center gap-2">
                        <span className="flex gap-1">
                          <span className="h-2 w-2 rounded-full bg-slate-400 animate-pulse" />
                          <span className="h-2 w-2 rounded-full bg-slate-400 animate-pulse" style={{ animationDelay: '120ms' }} />
                          <span className="h-2 w-2 rounded-full bg-slate-400 animate-pulse" style={{ animationDelay: '240ms' }} />
                        </span>
                        <span className="text-slate-500 dark:text-slate-400">Thinking…</span>
                      </div>
                    ) : (
                      <p className="whitespace-pre-wrap leading-relaxed">{answer.answer || 'No answer was returned.'}</p>
                    )}
                  </div>
                </div>

                {answer.sources?.length > 0 && (
                  <div className="ml-11 mt-2">
                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-2">Sources</p>
                    <ul className="space-y-2">
                      {answer.sources.map((s, i) => (
                        <li key={i} className="rounded-xl border-l-2 border-brand-500 dark:border-brand-400 bg-slate-50 dark:bg-slate-800/40 pl-3 py-2 pr-3">
                          <div className="flex items-center gap-2 mb-1">
                            <a href={`/cve/${encodeURIComponent(s.cve_id)}`} className="font-mono text-brand-700 hover:underline font-semibold dark:text-brand-300">
                              {s.cve_id}
                            </a>
                            <SeverityBadge severity={s.severity} />
                          </div>
                          <p className="text-xs text-slate-600 dark:text-slate-300 line-clamp-3">{s.snippet}…</p>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardBody>
          <textarea
            className="input min-h-[80px]"
            placeholder="Ask anything… e.g. 'How to mitigate CVE-2024-1234?'"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && (e.metaKey || e.ctrlKey || (!e.shiftKey))) {
                e.preventDefault()
                ask()
              }
            }}
          />
          <div className="mt-3 flex items-center justify-between flex-wrap gap-3">
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Press <kbd className="font-mono px-1.5 py-0.5 rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800">↵</kbd> to send · Shift+↵ for newline
            </p>
            <Button variant="primary" loading={loading} disabled={!question.trim()} onClick={() => ask()}>
              {loading ? 'Thinking…' : 'Ask'}
            </Button>
          </div>
        </CardBody>
      </Card>
    </div>
  )
}
