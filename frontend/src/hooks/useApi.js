// useApi — cancel-token-aware wrapper around axios for React components.
//
// Returns { data, error, loading, refetch, cancel }. The hook cancels any
// in-flight request when the component unmounts or when `deps` change.
// Each invocation is tagged with a monotonic reqId so a slow earlier
// response can't overwrite a newer one (the classic "stale response"
// race that hits the search page when a user types fast).

import { useCallback, useEffect, useRef, useState } from 'react'

export default function useApi(fetcher, deps = []) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)
  const [tick, setTick] = useState(0)
  const reqIdRef = useRef(0)

  const refetch = useCallback(() => {
    setTick((t) => t + 1)
  }, [])

  useEffect(() => {
    const reqId = ++reqIdRef.current
    const controller = new AbortController()
    setLoading(true)
    setError(null)

    fetcher({ signal: controller.signal })
      .then((res) => {
        // Only commit if this is still the latest request — otherwise the
        // newer in-flight response will win and overwrite us safely.
        if (reqId !== reqIdRef.current) return
        setData(res)
      })
      .catch((err) => {
        if (err && (err.name === 'CanceledError' || err.name === 'AbortError' || err.code === 'ERR_CANCELED')) return
        if (reqId !== reqIdRef.current) return
        setError(err)
      })
      .finally(() => {
        if (reqId !== reqIdRef.current) return
        setLoading(false)
      })

    return () => {
      controller.abort('useApi cleanup')
    }
  }, [tick, ...deps])

  return { data, error, loading, refetch }
}
