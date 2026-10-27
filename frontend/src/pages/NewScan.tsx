import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { Bug, FileChartColumn, Globe2, Radar, Search, ShieldCheck } from 'lucide-react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { api, errorMessage } from '../api'
import { useData } from '../data'
import { ErrorBox, PageTitle } from '../components/ui'

function normalizeUrl(value: string) {
  const parsed = new URL(value.trim())
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Informe uma URL começando com http:// ou https://.')
  }
  if (parsed.username || parsed.password) {
    throw new Error('Não inclua usuário ou senha na URL.')
  }
  parsed.hash = ''
  const normalized = parsed.toString()
  return normalized.endsWith('/') ? normalized.slice(0, -1) : normalized
}

function targetName(value: string) {
  const parsed = new URL(value)
  const path = parsed.pathname === '/' ? '' : parsed.pathname.replace(/\/$/, '')
  return `${parsed.host}${path}`.slice(0, 120)
}

export function NewScan() {
  const { targets, refresh } = useData()
  const [params] = useSearchParams()
  const [url, setUrl] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const navigate = useNavigate()
  const targetParam = params.get('target')

  useEffect(() => {
    if (!targetParam || url) return
    const selected = targets.find(target => target.id === Number(targetParam))
    if (selected) setUrl(selected.base_url)
  }, [targetParam, targets, url])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setError('')
    let scanId: number | null = null

    try {
      const baseUrl = normalizeUrl(url)
      let target = targets.find(item => {
        try { return normalizeUrl(item.base_url) === baseUrl }
        catch { return false }
      })

      if (!target) {
        target = await api.createTarget({
          name: targetName(baseUrl),
          base_url: baseUrl,
          api_url: null,
          components: [],
          description: 'Cadastrado automaticamente pelo scan rápido.',
          environment: 'LOCAL',
          is_protected_target: false,
          safe_scan_mode: true,
        })
      }

      if (target.requires_ownership_verification && target.ownership_verification_status !== 'VERIFIED') {
        await refresh()
        setError('Este domínio público precisa da verificação de propriedade antes do scan. Alvos locais são liberados automaticamente.')
        return
      }

      const scan = await api.createScan(
        target.id,
        undefined,
        undefined,
        'SAFE_ACTIVE',
        undefined,
        true,
      )
      scanId = scan.id
      await api.startScan(scan.id)
      await refresh()
      navigate(`/scans/${scan.id}`)
    } catch (caught) {
      setError(errorMessage(caught))
      await refresh()
      if (scanId) navigate(`/scans/${scanId}`)
    } finally {
      setBusy(false)
    }
  }

  return <>
    <PageTitle
      eyebrow="SCAN RÁPIDO"
      title="Escaneie uma aplicação pela URL."
      description="Informe o endereço do seu site. A DAST cuida do cadastro, descoberta, análise e relatório."
    />
    <div className="quick-scan-layout">
      <section className="panel quick-scan-card">
        <div className="quick-scan-icon"><Radar size={30}/></div>
        <div>
          <span className="tiny-tag">SAFE ACTIVE</span>
          <h2>Qual aplicação você quer analisar?</h2>
          <p>Use localhost, uma aplicação da rede privada ou um domínio HTTPS cuja propriedade possa ser verificada.</p>
        </div>
        <form onSubmit={submit}>
          <label htmlFor="quick-scan-url">URL do site ou aplicação</label>
          <div className="quick-url-row">
            <span><Globe2 size={18}/></span>
            <input
              id="quick-scan-url"
              type="url"
              required
              maxLength={2048}
              autoFocus
              placeholder="http://localhost:3000"
              value={url}
              disabled={busy}
              onChange={event => setUrl(event.target.value)}
            />
            <button className="button" disabled={busy || !url.trim()}>
              {busy ? <Radar size={17} className="spin"/> : <Radar size={17}/>}
              {busy ? 'Iniciando…' : 'Escanear agora'}
            </button>
          </div>
          <ErrorBox message={error}/>
          <p className="quick-consent"><ShieldCheck size={14}/> Ao iniciar, você confirma que tem autorização para analisar este alvo. O scan usa somente GET, HEAD e OPTIONS, não envia formulários e não segue redirects externos.</p>
        </form>
      </section>

      <section className="panel quick-scan-steps">
        <div className="step-label">PROCESSO AUTOMÁTICO</div>
        <h2>Da URL ao relatório</h2>
        <div className="quick-step"><span>01</span><Search size={18}/><div><strong>Descoberta</strong><small>Mapeia páginas, APIs, formulários e scripts.</small></div></div>
        <div className="quick-step"><span>02</span><ShieldCheck size={18}/><div><strong>Análise segura</strong><small>Verifica configurações e executa probes controlados.</small></div></div>
        <div className="quick-step"><span>03</span><Bug size={18}/><div><strong>Vulnerabilidades</strong><small>Agrupa os achados por severidade, CWE e OWASP.</small></div></div>
        <div className="quick-step"><span>04</span><FileChartColumn size={18}/><div><strong>Relatório</strong><small>Apresenta evidências sanitizadas e recomendações.</small></div></div>
      </section>
    </div>
  </>
}
