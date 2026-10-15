import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { Check, Radar, ShieldCheck } from 'lucide-react'
import { api, errorMessage } from '../api'
import { useData } from '../data'
import { Empty, ErrorBox, PageTitle } from '../components/ui'
import type { ApiRequestRuntimeValues, ApiRequestTemplate, AuthProfile, ScanModule, ScanPreset } from '../types'

type RuntimeValueGroup = Omit<ApiRequestRuntimeValues, 'template_id'>

function pathParameterNames(path: string) {
  return Array.from(path.matchAll(/{([A-Za-z_][A-Za-z0-9_.-]{0,127})}/g), match => match[1])
}

export function NewScan() {
  const { targets, refresh } = useData()
  const [params] = useSearchParams()
  const [targetId, setTargetId] = useState(params.get('target') || '')
  const [profileId, setProfileId] = useState('')
  const [profiles, setProfiles] = useState<AuthProfile[]>([])
  const [apiRequests, setApiRequests] = useState<ApiRequestTemplate[]>([])
  const [runtimeValues, setRuntimeValues] = useState<Record<number, RuntimeValueGroup>>({})
  const [experimentLabel, setExperimentLabel] = useState('')
  const [preset, setPreset] = useState<ScanPreset>('PASSIVE')
  const [modules, setModules] = useState<ScanModule[]>([])
  const [selectedModules, setSelectedModules] = useState<string[]>([])
  const [activeConfirmation, setActiveConfirmation] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const navigate = useNavigate()
  const selected = targets.find(target => target.id === Number(targetId))
  const activeModuleIds = modules.filter(module => module.kind === 'ACTIVE').map(module => module.id)
  const activeSelected = preset === 'SAFE_ACTIVE' || (preset === 'CUSTOM' && selectedModules.some(id => activeModuleIds.includes(id)))

  useEffect(() => {
    let active = true
    api.scanModules()
      .then(rows => {
        if (!active) return
        setModules(rows)
        setSelectedModules(rows.filter(module => module.default_enabled).map(module => module.id))
      })
      .catch(caught => { if (active) setError(errorMessage(caught)) })
    return () => { active = false }
  }, [])

  useEffect(() => {
    setProfileId('')
    setActiveConfirmation(false)
    setRuntimeValues({})
    if (!targetId) { setProfiles([]); setApiRequests([]); return }
    let active = true
    Promise.all([api.authProfiles(Number(targetId)), api.apiRequests(Number(targetId))])
      .then(([profileRows, requestRows]) => {
        if (!active) return
        setProfiles(profileRows)
        setApiRequests(requestRows)
      })
      .catch(() => { if (active) { setProfiles([]); setApiRequests([]) } })
    return () => { active = false }
  }, [targetId])

  function setRuntimeValue(templateId: number, group: keyof RuntimeValueGroup, name: string, value: string) {
    setRuntimeValues(current => {
      const templateValues = current[templateId] || { path_parameters: {}, query_parameters: {}, header_values: {} }
      return { ...current, [templateId]: { ...templateValues, [group]: { ...templateValues[group], [name]: value } } }
    })
  }

  function runtimePayload(): ApiRequestRuntimeValues[] {
    return Object.entries(runtimeValues).flatMap(([templateId, groups]) => {
      const clean = (values: Record<string, string>) => Object.fromEntries(Object.entries(values).filter(([, value]) => value.length > 0))
      const value = {
        template_id: Number(templateId),
        path_parameters: clean(groups.path_parameters),
        query_parameters: clean(groups.query_parameters),
        header_values: clean(groups.header_values),
      }
      return Object.values(value.path_parameters).length || Object.values(value.query_parameters).length || Object.values(value.header_values).length ? [value] : []
    })
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!selected) return
    if (selected.requires_ownership_verification && selected.ownership_verification_status !== 'VERIFIED') {
      setError('Conclua a verificação de propriedade do domínio antes de iniciar o scan.')
      return
    }
    setBusy(true); setError('')
    let scanId: number | null = null
    try {
      if (selected.is_protected_target) {
        const health = await api.targetHealth(selected.id)
        if (!health.available) throw new Error('Target unavailable')
      }
      const scan = await api.createScan(
        selected.id,
        profileId ? Number(profileId) : undefined,
        experimentLabel.trim() || undefined,
        preset,
        preset === 'CUSTOM' ? selectedModules : undefined,
        activeSelected && activeConfirmation,
      )
      scanId = scan.id
      await api.startScan(scan.id, runtimePayload())
      await refresh()
      navigate(`/scans/${scan.id}`)
    } catch (caught) {
      setError(errorMessage(caught)); await refresh()
      if (scanId) navigate(`/scans/${scanId}`)
    } finally { setBusy(false) }
  }

  return <>
    <PageTitle eyebrow="DAST CONFIGURÁVEL" title="Observe. Analise. Entenda." description="Escolha a profundidade da varredura e acompanhe a execução em segundo plano."/>
    {!targets.length ? <section className="panel"><Empty title="Um alvo é o primeiro passo" text="Cadastre a aplicação local que deseja analisar." action={<Link className="button" to="/targets">Cadastrar alvo</Link>}/></section> : <div className="new-scan-grid">
      <section className="panel form-panel"><div className="step-label">01 / DEFINIR ESCOPO</div><h2>Selecione uma aplicação</h2><form onSubmit={submit}>
        <label>Alvo cadastrado<select required value={targetId} disabled={busy} onChange={event => setTargetId(event.target.value)}><option value="">Selecione um alvo…</option>{targets.map(target => <option key={target.id} value={target.id} disabled={target.requires_ownership_verification && target.ownership_verification_status !== 'VERIFIED'}>{target.name}{target.requires_ownership_verification ? ` · ${target.ownership_verification_status}` : ''}</option>)}</select></label>
        <label>Perfil de acesso<select value={profileId} disabled={busy || !selected} onChange={event => setProfileId(event.target.value)}><option value="">Sem autenticação</option>{profiles.map(profile => <option key={profile.id} value={profile.id} disabled={Boolean(selected?.is_protected_target && profile.last_auth_success !== true)}>{profile.name} · {profile.role_name}{profile.last_auth_success === true ? ' · validado' : ''}</option>)}</select></label>
        <label>Identificador do scan <span>(opcional)</span><input value={experimentLabel} onChange={event => setExperimentLabel(event.target.value)} pattern="[A-Za-z0-9._-]+" maxLength={160} placeholder="release-2026-10"/></label>
        <fieldset className="preset-picker"><legend>Perfil da varredura</legend>{([
          ['DISCOVERY', 'Somente descoberta', 'Mapeia páginas, APIs, formulários e scripts.'],
          ['PASSIVE', 'Análise passiva', 'Executa todos os módulos seguros sobre respostas observadas.'],
          ['SAFE_ACTIVE', 'Safe Active', 'Executa probes controlados por GET/HEAD/OPTIONS, com orçamento e sem seguir redirects.'],
          ['CUSTOM', 'Personalizado', 'Permite escolher exatamente quais análises executar.'],
        ] as [ScanPreset, string, string][]).map(([value, title, description]) => <button type="button" className={preset === value ? 'preset-option selected' : 'preset-option'} key={value} onClick={() => setPreset(value)}><strong>{title}</strong><small>{description}</small></button>)}</fieldset>
        {preset === 'CUSTOM' && <div className="module-picker"><span>Módulos</span>{modules.map(module => <label className="module-option" key={module.id}><input type="checkbox" checked={module.id === 'discovery' || selectedModules.includes(module.id)} disabled={module.id === 'discovery'} onChange={event => setSelectedModules(current => event.target.checked ? [...new Set([...current, module.id])] : current.filter(id => id !== module.id))}/><span><strong>{module.name}</strong><small>{module.description}</small></span></label>)}</div>}
        {activeSelected && <div className="active-confirmation"><label className="check-label"><input type="checkbox" checked={activeConfirmation} onChange={event => setActiveConfirmation(event.target.checked)}/> Confirmo que tenho autorização para executar probes ativos neste alvo.</label><small>Somente GET, HEAD e OPTIONS. Sem envio de formulários, sem métodos mutáveis e sem seguir redirects externos.</small></div>}
        {selected && <div className="selected-target"><span>Escopo autorizado</span><code>{selected.base_url}</code>{selected.api_url && <code>{selected.api_url}</code>}{selected.components.map(component => <code key={`${component.kind}:${component.url}`}>{component.name} · {component.kind} · {component.url}</code>)}{profileId && <small>Sessão isolada: {profiles.find(profile => profile.id === Number(profileId))?.name}</small>}</div>}
        {apiRequests.some(template => ['GET', 'HEAD', 'OPTIONS'].includes(template.method) && (pathParameterNames(template.path).length || template.query_parameters.length || template.header_names.length)) && <section className="runtime-values"><div><strong>Valores temporários da API</strong><small>Usados somente durante este scan. Campos vazios não são enviados nem armazenados.</small></div>{apiRequests.filter(template => ['GET', 'HEAD', 'OPTIONS'].includes(template.method) && (pathParameterNames(template.path).length || template.query_parameters.length || template.header_names.length)).map(template => <fieldset key={template.id}><legend>{template.method} {template.path}</legend>{pathParameterNames(template.path).map(name => <label key={`path-${name}`}>Path · {name}<input value={runtimeValues[template.id]?.path_parameters[name] || ''} maxLength={2048} placeholder="Obrigatório para executar esta rota" onChange={event => setRuntimeValue(template.id, 'path_parameters', name, event.target.value)}/></label>)}{template.query_parameters.map(name => <label key={`query-${name}`}>Query · {name}<input value={runtimeValues[template.id]?.query_parameters[name] || ''} maxLength={2048} placeholder="Vazio usa o marcador dast" onChange={event => setRuntimeValue(template.id, 'query_parameters', name, event.target.value)}/></label>)}{template.header_names.map(name => <label key={`header-${name}`}>Header · {name}<input type="password" autoComplete="off" value={runtimeValues[template.id]?.header_values[name] || ''} maxLength={2048} placeholder="Valor mascarado e efêmero" onChange={event => setRuntimeValue(template.id, 'header_values', name, event.target.value)}/></label>)}</fieldset>)}</section>}
        {selected?.requires_ownership_verification && selected.ownership_verification_status !== 'VERIFIED' && <div className="info-box"><ShieldCheck size={18}/><p>Este domínio ainda não está verificado. Conclua a prova de propriedade na <Link to={`/targets/${selected.id}`}>visão geral do alvo</Link>.</p></div>}
        <ErrorBox message={error}/><button className="button full-width" disabled={busy || !selected || (selected.requires_ownership_verification && selected.ownership_verification_status !== 'VERIFIED') || (activeSelected && !activeConfirmation)}>{busy ? <Radar size={17} className="spin"/> : <Radar size={17}/>} {busy ? 'Agendando varredura…' : 'Iniciar varredura'}</button>
        <p className="form-hint">Perfis de alvos protegidos precisam ser validados. A sessão existe apenas durante o scan e é descartada com o BrowserContext.</p>
      </form></section>
      <section className="panel form-panel"><div className="step-label">02 / CONTROLES DE SEGURANÇA</div><h2>Descoberta segura e análise modular</h2>{['Autenticação controlada opcional', 'Crawler em contexto isolado', 'Valores de API somente em memória', 'Progresso por módulo e cancelamento', 'Relatório de vulnerabilidades no site'].map(title => <div className="check-row" key={title}><Check size={16}/><span>{title}</span><span className="muted">Seguro</span></div>)}<div className="info-box"><ShieldCheck size={20}/><p>Safe Active usa marcadores inofensivos e comparação diferencial para XSS, SQL Injection, Path Traversal, redirects e métodos HTTP. Não envia formulários, não executa POST/PUT/PATCH/DELETE e não segue redirects.</p></div></section>
    </div>}
  </>
}
