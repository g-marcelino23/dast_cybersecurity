import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { api, errorMessage } from './api'
import type { Finding, Scan, Target } from './types'
interface Data { targets: Target[]; scans: Scan[]; findings: Finding[]; loading: boolean; error: string; refresh: () => Promise<void> }
const Context = createContext<Data | null>(null)
export function DataProvider({ children }: { children: ReactNode }) {
  const [data, setData] = useState({ targets: [] as Target[], scans: [] as Scan[], findings: [] as Finding[] })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const active = useRef<Promise<void> | null>(null)
  const refresh = useCallback((): Promise<void> => {
    if (active.current) return active.current
    const task = Promise.all([api.targets(), api.scans(), api.findings()]).then(([targets, scans, findings]) => {
      setData({ targets, scans, findings }); setError('')
    }).catch((e: unknown) => setError(errorMessage(e))).finally(() => { setLoading(false); active.current = null })
    active.current = task
    return task
  }, [])
  useEffect(() => { void refresh(); const timer = window.setInterval(() => void refresh(), 15000); return () => clearInterval(timer) }, [refresh])
  return <Context.Provider value={{ ...data, loading, error, refresh }}>{children}</Context.Provider>
}
export function useData() { const data = useContext(Context); if (!data) throw new Error('Missing DataProvider'); return data }
