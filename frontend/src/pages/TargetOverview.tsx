import { useEffect, useMemo, useState } from 'react'
import { Download, FileJson, HeartPulse, Plus, ShieldCheck, Trash2, Upload } from 'lucide-react'
import { Link, useParams } from 'react-router-dom'
import { api, errorMessage } from '../api'
import { AccessProfileSurfaceView, RoleComparisonView } from '../components/AccessViews'
import { Badge, Empty, ErrorBox, MethodBadge, PageTitle } from '../components/ui'
import type { AccessProfileSurface, AccessSurface, ApiRequestBodyMode, ApiRequestTemplate, AuthorizationCandidate, AuthorizationPreview, AuthProfile, CweCoverage, PrivacyAnalysis, RoleComparison, Scan, ScanComparison, ScanSummary, SensitiveSurface, Target, TargetHealth } from '../types'

const tabs = ['Visão geral', 'OpenAPI', 'Postman', 'API manual', 'Discovery', 'Superfície de acesso', 'Comparação de perfis', 'Comparação de scans', 'Testes de autorização', 'Cobertura CWE', 'Dados sensíveis', 'Resumo do scan'] as const
type Tab = typeof tabs[number]

export function TargetOverview() {
  const id = Number(useParams().id)
  const [tab, setTab] = useState<Tab>('Visão geral')
  const [target, setTarget] = useState<Target | null>(null)
  const [health, setHealth] = useState<TargetHealth | null>(null)
  const [profiles, setProfiles] = useState<AuthProfile[]>([])
  const [scans, setScans] = useState<Scan[]>([])
  const [access, setAccess] = useState<AccessSurface | null>(null)
  const [sensitive, setSensitive] = useState<SensitiveSurface | null>(null)
  const [privacy, setPrivacy] = useState<PrivacyAnalysis | null>(null)
  const [cwe, setCwe] = useState<CweCoverage | null>(null)
  const [profileA, setProfileA] = useState('')
  const [profileB, setProfileB] = useState('')
  const [roleSurface, setRoleSurface] = useState<AccessProfileSurface | null>(null)
  const [comparison, setComparison] = useState<RoleComparison | null>(null)
  const [candidates, setCandidates] = useState<AuthorizationCandidate[]>([])
  const [preview, setPreview] = useState<AuthorizationPreview | null>(null)
  const [summary, setSummary] = useState<ScanSummary | null>(null)
  const [baselineScan, setBaselineScan] = useState('')
  const [currentScan, setCurrentScan] = useState('')
  const [scanComparison, setScanComparison] = useState<ScanComparison | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [openApiFile, setOpenApiFile] = useState<File | null>(null)
  const [postmanFile, setPostmanFile] = useState<File | null>(null)
  const [apiRequests, setApiRequests] = useState<ApiRequestTemplate[]>([])
  const [requestName, setRequestName] = useState('')
  const [requestMethod, setRequestMethod] = useState<ApiRequestTemplate['method']>('GET')
  const [requestPath, setRequestPath] = useState('')
  const [requestQuery, setRequestQuery] = useState('')
  const [requestHeaders, setRequestHeaders] = useState('')
  const [requestBodyMode, setRequestBodyMode] = useState<ApiRequestBodyMode>('NONE')
  const [requestContentType, setRequestContentType] = useState('')
  const [requestAuth, setRequestAuth] = useState(false)

  useEffect(() => {
    let active = true
    Promise.all([api.target(id), api.authProfiles(id), api.scans(), api.accessSurface(id), api.sensitiveSurface(id), api.privacyAnalysis(id), api.cweCoverage(id), api.authorizationCandidates(id), api.apiRequests(id)])
      .then(([targetRow, profileRows, scanRows, accessRows, sensitiveRows, privacyRows, cweRows, candidateRows, requestRows]) => {
        if (!active) return
        setTarget(targetRow); setProfiles(profileRows); setScans(scanRows.filter(scan => scan.target_id === id)); setAccess(accessRows); setSensitive(sensitiveRows); setPrivacy(privacyRows); setCwe(cweRows); setCandidates(candidateRows); setApiRequests(requestRows)
        if (profileRows[0]) setProfileA(String(profileRows[0].id))
        if (profileRows[1]) setProfileB(String(profileRows[1].id))
      }).catch(caught => { if (active) setError(errorMessage(caught)) })
    return () => { active = false }
  }, [id])

  useEffect(() => {
    if (!profileA) { setRoleSurface(null); setPreview(null); return }
    let active = true
    Promise.all([api.accessProfileSurface(Number(profileA)), api.authorizationPreview(id, Number(profileA))])
      .then(([surface, plan]) => { if (active) { setRoleSurface(surface); setPreview(plan) } })
      .catch(caught => { if (active) setError(errorMessage(caught)) })
    return () => { active = false }
  }, [id, profileA])

  useEffect(() => {
    if (!profileA || !profileB || profileA === profileB) { setComparison(null); return }
    let active = true
    api.roleComparison(id, Number(profileA), Number(profileB))
      .then(value => { if (active) setComparison(value) })
      .catch(caught => { if (active) setError(errorMessage(caught)) })
    return () => { active = false }
  }, [id, profileA, profileB])

  const completedScans = useMemo(() => scans.filter(scan => scan.status === 'COMPLETED').sort((a, b) => b.id - a.id), [scans])
  const selectedScan = useMemo(() => completedScans.find(scan => scan.auth_profile_id === Number(profileA)) || completedScans[0] || scans[0], [completedScans, profileA, scans])

  useEffect(() => {
    if (completedScans.length < 2) {
      setBaselineScan(''); setCurrentScan(''); setScanComparison(null); return
    }
    const ids = new Set(completedScans.map(scan => String(scan.id)))
    if (!ids.has(currentScan)) setCurrentScan(String(completedScans[0].id))
    if (!ids.has(baselineScan)) setBaselineScan(String(completedScans[1].id))
  }, [baselineScan, completedScans, currentScan])

  useEffect(() => {
    if (!baselineScan || !currentScan || baselineScan === currentScan) {
      setScanComparison(null); return
    }
    let active = true
    api.scanComparison(id, Number(baselineScan), Number(currentScan))
      .then(value => { if (active) setScanComparison(value) })
      .catch(caught => { if (active) { setScanComparison(null); setError(errorMessage(caught)) } })
    return () => { active = false }
  }, [baselineScan, currentScan, id])

  useEffect(() => {
    if (!selectedScan) { setSummary(null); return }
    let active = true
    api.scanSummary(selectedScan.id).then(value => { if (active) setSummary(value) }).catch(() => { if (active) setSummary(null) })
    return () => { active = false }
  }, [selectedScan])

  async function checkHealth() {
    setBusy(true); setError('')
    try { setHealth(await api.targetHealth(id)) } catch (caught) { setError(errorMessage(caught)) }
    finally { setBusy(false) }
  }

  async function verifyOwnership() {
    setBusy(true); setError('')
    try {
      await api.verifyOwnership(id)
      setTarget(await api.target(id))
    } catch (caught) { setError(errorMessage(caught)) }
    finally { setBusy(false) }
  }

  async function generateCandidates() {
    if (!profileA || !profileB) return
    setBusy(true); setError('')
    try {
      await api.generateAuthorizationCandidates(id, Number(profileA), Number(profileB))
      setCandidates(await api.authorizationCandidates(id))
      setRoleSurface(await api.accessProfileSurface(Number(profileA)))
    } catch (caught) { setError(errorMessage(caught)) }
    finally { setBusy(false) }
  }

  async function importOpenApi() {
    if (!openApiFile) return
    setBusy(true); setError('')
    try {
      if (openApiFile.size > 2_000_000) throw new Error('O arquivo excede o limite de 2 MB.')
      await api.importOpenApi(id, await openApiFile.text(), openApiFile.name)
      setTarget(await api.target(id)); setOpenApiFile(null)
    } catch (caught) { setError(errorMessage(caught)) }
    finally { setBusy(false) }
  }

  async function removeOpenApi() {
    if (!window.confirm('Remover o contrato OpenAPI deste alvo?')) return
    setBusy(true); setError('')
    try { await api.deleteOpenApi(id); setTarget(await api.target(id)) }
    catch (caught) { setError(errorMessage(caught)) }
    finally { setBusy(false) }
  }

  async function importPostman() {
    if (!postmanFile) return
    setBusy(true); setError('')
    try {
      if (postmanFile.size > 2_000_000) throw new Error('O arquivo excede o limite de 2 MB.')
      await api.importPostman(id, await postmanFile.text(), postmanFile.name)
      setTarget(await api.target(id)); setPostmanFile(null)
    } catch (caught) { setError(errorMessage(caught)) }
    finally { setBusy(false) }
  }

  async function removePostman() {
    if (!window.confirm('Remover a coleção Postman deste alvo?')) return
    setBusy(true); setError('')
    try { await api.deletePostman(id); setTarget(await api.target(id)) }
    catch (caught) { setError(errorMessage(caught)) }
    finally { setBusy(false) }
  }

  function parameterNames(value: string) {
    return value.split(',').map(item => item.trim()).filter(Boolean)
  }

  async function createApiRequest() {
    setBusy(true); setError('')
    try {
      await api.createApiRequest(id, { name: requestName, method: requestMethod, path: requestPath, query_parameters: parameterNames(requestQuery), header_names: parameterNames(requestHeaders), body_mode: requestBodyMode, content_type: requestContentType || null, requires_auth: requestAuth })
      setApiRequests(await api.apiRequests(id))
      setRequestName(''); setRequestPath(''); setRequestQuery(''); setRequestHeaders(''); setRequestContentType(''); setRequestBodyMode('NONE'); setRequestAuth(false)
    } catch (caught) { setError(errorMessage(caught)) }
    finally { setBusy(false) }
  }

  async function removeApiRequest(requestId: number) {
    if (!window.confirm('Remover este template de API?')) return
    setBusy(true); setError('')
    try { await api.deleteApiRequest(id, requestId); setApiRequests(await api.apiRequests(id)) }
    catch (caught) { setError(errorMessage(caught)) }
    finally { setBusy(false) }
  }

  function exportSummary() {
    if (!summary) return
    const blob = new Blob([JSON.stringify(summary, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url; anchor.download = `dast-scan-summary-${summary.scan_id}.json`; anchor.click()
    URL.revokeObjectURL(url)
  }

  if (!target) return <><PageTitle eyebrow="TARGET" title="Overview" description="Loading controlled integration…"/><ErrorBox message={error}/></>
  return <>
    <PageTitle eyebrow={target.requires_ownership_verification ? target.ownership_verification_status : target.is_protected_target ? 'PROTECTED TARGET' : target.environment} title={target.name} description="Discovery autenticado, sessões isoladas e evidências sanitizadas." action={(!target.requires_ownership_verification || target.ownership_verification_status === 'VERIFIED') ? <Link className="button" to={`/new-scan?target=${id}`}>Discovery + Passive</Link> : undefined}/>
    <div className="target-tabs">{tabs.map(item => <button className={tab === item ? 'active' : ''} key={item} onClick={() => setTab(item)}>{item}</button>)}</div>
    <ErrorBox message={error}/>

    {tab === 'Visão geral' && <><div className="overview-grid"><section className="panel"><h2><HeartPulse size={18}/> Disponibilidade dos componentes</h2><dl><dt>Frontend / base</dt><dd><Badge value={health?.frontend.status || 'UNKNOWN'}/></dd><dt>API / backend</dt><dd><Badge value={health?.api?.status || 'UNKNOWN'}/></dd><dt>Health code</dt><dd>{health?.code || 'NOT_CHECKED'}</dd><dt>Perfis configurados</dt><dd>{profiles.length}</dd><dt>Safe Scan Mode</dt><dd>{target.safe_scan_mode ? 'ON' : 'OFF'}</dd></dl><button className="button secondary" disabled={busy || (target.requires_ownership_verification && target.ownership_verification_status !== 'VERIFIED')} onClick={() => void checkHealth()}>{busy ? 'Verificando…' : 'Verificar disponibilidade'}</button>{health && !health.available && <div className="auth-test-result">TARGET_UNAVAILABLE</div>}</section><section className="panel"><h2><ShieldCheck size={18}/> Escopo autorizado</h2><code>{target.base_url}</code><br/>{target.api_url && <code>{target.api_url}</code>}<p>Hosts exatos: {target.allowed_hosts.join(', ')}. Redirects e destinos fora dessa lista são bloqueados.</p></section></div>{target.requires_ownership_verification && <section className="panel detail-section"><h2><ShieldCheck size={18}/> Verificação de propriedade</h2><p>Status: <Badge value={target.ownership_verification_status}/></p><p>Publique um arquivo de texto em cada URL abaixo contendo somente o token informado.</p><div className="openapi-summary"><dl><dt>CAMINHO</dt><dd><code>/.well-known/dast-verification.txt</code></dd><dt>TOKEN</dt><dd><code>{target.ownership_verification_token}</code></dd><dt>HOSTS</dt><dd>{target.allowed_hosts.join(', ')}</dd><dt>EXPIRAÇÃO</dt><dd>{target.ownership_verification_expires_at ? new Date(target.ownership_verification_expires_at).toLocaleString('pt-BR') : 'Ainda não verificado'}</dd></dl></div>{[target.base_url, target.api_url].filter(Boolean).map(value => <code key={value!}>{new URL('/.well-known/dast-verification.txt', value!).toString()}</code>)}<div className="form-actions"><button className="button" disabled={busy} onClick={() => void verifyOwnership()}>{busy ? 'Verificando…' : target.ownership_verification_status === 'VERIFIED' ? 'Verificar novamente' : 'Verificar domínio'}</button></div><div className="info-box"><ShieldCheck size={18}/><p>A validação não segue redirects, bloqueia DNS privado/misto e expira em 30 dias.</p></div></section>}</>}

    {tab === 'OpenAPI' && <section className="panel detail-section"><h2><FileJson size={18}/> Contrato OpenAPI / Swagger</h2><p>Importe JSON ou YAML. As rotas entram no inventário do próximo scan, inclusive métodos não navegáveis, mas não são executadas automaticamente.</p>{target.openapi_title ? <div className="openapi-summary"><dl><dt>DOCUMENTO</dt><dd>{target.openapi_title}</dd><dt>VERSÃO</dt><dd>{target.openapi_version}</dd><dt>OPERAÇÕES</dt><dd>{target.openapi_operation_count}</dd><dt>IMPORTADO EM</dt><dd>{target.openapi_imported_at ? new Date(target.openapi_imported_at).toLocaleString('pt-BR') : '—'}</dd></dl><button className="button secondary" disabled={busy} onClick={() => void removeOpenApi()}><Trash2 size={15}/> Remover contrato</button></div> : <Empty title="Nenhum contrato importado" text="O crawler continuará descobrindo a aplicação normalmente."/>}<div className="openapi-upload"><label>Arquivo OpenAPI ou Swagger<input type="file" accept=".json,.yaml,.yml,application/json,application/yaml,text/yaml" onChange={event => setOpenApiFile(event.target.files?.[0] || null)}/></label><button className="button" disabled={busy || !openApiFile} onClick={() => void importOpenApi()}><Upload size={15}/> {busy ? 'Importando…' : 'Importar contrato'}</button></div><div className="info-box"><ShieldCheck size={18}/><p>Servidores externos ao frontend ou à API cadastrada são rejeitados. Exemplos, schemas e extensões não são persistidos.</p></div></section>}

    {tab === 'Postman' && <section className="panel detail-section"><h2><FileJson size={18}/> Coleção Postman</h2><p>Importe uma coleção v2.0 ou v2.1. As requisições entram no inventário do próximo scan; métodos mutáveis não são executados automaticamente.</p>{target.postman_name ? <div className="openapi-summary"><dl><dt>COLEÇÃO</dt><dd>{target.postman_name}</dd><dt>SCHEMA</dt><dd>{target.postman_version}</dd><dt>REQUISIÇÕES</dt><dd>{target.postman_request_count}</dd><dt>IMPORTADA EM</dt><dd>{target.postman_imported_at ? new Date(target.postman_imported_at).toLocaleString('pt-BR') : '—'}</dd></dl><button className="button secondary" disabled={busy} onClick={() => void removePostman()}><Trash2 size={15}/> Remover coleção</button></div> : <Empty title="Nenhuma coleção importada" text="Você pode combinar Postman, OpenAPI e descoberta automática no mesmo alvo."/>}<div className="openapi-upload"><label>Collection JSON<input type="file" accept=".json,application/json" onChange={event => setPostmanFile(event.target.files?.[0] || null)}/></label><button className="button" disabled={busy || !postmanFile} onClick={() => void importPostman()}><Upload size={15}/> {busy ? 'Importando…' : 'Importar coleção'}</button></div><div className="info-box"><ShieldCheck size={18}/><p>Tokens, cookies, valores de headers, corpos, exemplos e scripts são descartados. Somente a estrutura sanitizada das requisições é armazenada.</p></div></section>}

    {tab === 'API manual' && <section className="panel detail-section"><h2><Plus size={18}/> Requisições de API</h2><p>Cadastre endpoints que não aparecem no crawler, OpenAPI ou Postman. Informe somente nomes e templates; valores, credenciais e corpos não são armazenados.</p><div className="manual-api-form"><label>Nome<input value={requestName} maxLength={160} placeholder="Consultar pedido" onChange={event => setRequestName(event.target.value)}/></label><label>Método<select value={requestMethod} onChange={event => setRequestMethod(event.target.value as ApiRequestTemplate['method'])}>{['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'].map(method => <option key={method}>{method}</option>)}</select></label><label className="manual-api-path">Caminho relativo<input value={requestPath} maxLength={2048} placeholder="/api/orders/{id}" onChange={event => setRequestPath(event.target.value)}/></label><label>Parâmetros de query<input value={requestQuery} placeholder="include, page" onChange={event => setRequestQuery(event.target.value)}/></label><label>Nomes de headers<input value={requestHeaders} placeholder="X-Tenant-ID, Accept-Language" onChange={event => setRequestHeaders(event.target.value)}/></label><label>Corpo<select value={requestBodyMode} onChange={event => setRequestBodyMode(event.target.value as ApiRequestBodyMode)}>{['NONE', 'JSON', 'FORM', 'MULTIPART', 'GRAPHQL', 'RAW'].map(mode => <option key={mode}>{mode}</option>)}</select></label><label>Content-Type<input value={requestContentType} placeholder="application/json" onChange={event => setRequestContentType(event.target.value)}/></label><label className="check-row"><input type="checkbox" checked={requestAuth} onChange={event => setRequestAuth(event.target.checked)}/> Requer autenticação</label></div><button className="button" disabled={busy || !requestName.trim()||!requestPath.trim()} onClick={() => void createApiRequest()}><Plus size={15}/> {busy ? 'Salvando…' : 'Adicionar ao inventário'}</button>{apiRequests.length ? <div className="table-scroll manual-api-list"><table><thead><tr><th>Método</th><th>Nome / caminho</th><th>Parâmetros</th><th>Autenticação</th><th></th></tr></thead><tbody>{apiRequests.map(item => <tr key={item.id}><td><MethodBadge method={item.method}/></td><td><strong>{item.name}</strong><small><code>{item.path}</code> · {item.body_mode}</small></td><td>{[...item.query_parameters, ...item.header_names].join(', ') || '—'}</td><td>{item.requires_auth ? 'Obrigatória':'Não informada'}</td><td><button className="icon-link" aria-label={`Remover ${item.name}`} disabled={busy} onClick={() => void removeApiRequest(item.id)}><Trash2 size={16}/></button></td></tr>)}</tbody></table></div> : <Empty title="Nenhum endpoint manual" text="Os endpoints cadastrados aqui serão combinados ao inventário do próximo scan."/>}<div className="info-box"><ShieldCheck size={18}/><p>GET, HEAD e OPTIONS são analisados de forma passiva. Valores para {'{id}'}, queries e headers podem ser informados apenas ao iniciar o scan e são descartados após a execução. Métodos mutáveis permanecem somente no inventário.</p></div></section>}

    {tab === 'Discovery' && <section className="panel"><h2>Discovery autenticado</h2><p>Cada perfil possui um inventário isolado. NOT_OBSERVED significa apenas que o recurso não foi observado, não que o acesso foi negado.</p><div className="table-scroll"><table><thead><tr><th>Endpoint</th>{access?.profiles.map(profile => <th key={profile.profile_id}>{profile.profile_name}<small>{profile.role_name}</small></th>)}</tr></thead><tbody>{access?.rows.map(row => <tr key={`${row.method}:${row.endpoint}`}><td><MethodBadge method={row.method}/> <code>{row.endpoint}</code></td>{access.profiles.map(profile => <td key={profile.profile_id}><Badge value={row.access[String(profile.profile_id)]}/></td>)}</tr>)}</tbody></table></div></section>}

    {tab === 'Superfície de acesso' && <section className="panel"><h2>Superfície do perfil de acesso</h2>{profiles.length ? <><label>Perfil de acesso<select value={profileA} onChange={event => setProfileA(event.target.value)}>{profiles.map(profile => <option key={profile.id} value={profile.id}>{profile.name} · {profile.role_name}</option>)}</select></label><AccessProfileSurfaceView surface={roleSurface}/></> : <Empty title="Nenhum perfil de acesso configurado"/>}</section>}

    {tab === 'Comparação de perfis' && <section className="panel"><h2>Comparação de perfis</h2>{profiles.length >= 2 ? <RoleComparisonView profiles={profiles} profileA={profileA} profileB={profileB} comparison={comparison} candidates={candidates} busy={busy} onProfileA={setProfileA} onProfileB={setProfileB} onGenerate={() => void generateCandidates()}/> : <Empty title="São necessários pelo menos dois perfis de acesso"/>}</section>}

    {tab === 'Comparação de scans' && <section className="panel detail-section"><h2>Comparação de scans</h2><p>Compare duas execuções concluídas do mesmo alvo. Identificadores e parâmetros sensíveis permanecem sanitizados.</p>{completedScans.length >= 2 ? <><div className="manual-api-form"><label>Baseline<select value={baselineScan} onChange={event => setBaselineScan(event.target.value)}>{completedScans.map(scan => <option key={scan.id} value={scan.id}>#{scan.id} · {scan.experiment_label || new Date(scan.finished_at || scan.created_at).toLocaleString('pt-BR')}</option>)}</select></label><label>Scan atual<select value={currentScan} onChange={event => setCurrentScan(event.target.value)}>{completedScans.map(scan => <option key={scan.id} value={scan.id}>#{scan.id} · {scan.experiment_label || new Date(scan.finished_at || scan.created_at).toLocaleString('pt-BR')}</option>)}</select></label></div>{baselineScan === currentScan ? <Empty title="Selecione dois scans diferentes"/> : scanComparison ? <><div className="scan-summary"><div><span>Novos achados</span><strong>{scanComparison.new_findings.length}</strong></div><div><span>Resolvidos</span><strong>{scanComparison.resolved_findings.length}</strong></div><div><span>Persistentes</span><strong>{scanComparison.persistent_findings.length}</strong></div><div><span>Endpoints adicionados</span><strong>{scanComparison.added_endpoints.length}</strong></div><div><span>Endpoints removidos</span><strong>{scanComparison.removed_endpoints.length}</strong></div></div><h3>Alterações em achados</h3>{[...scanComparison.new_findings.map(item => ({ ...item, state: 'NOVO' })), ...scanComparison.resolved_findings.map(item => ({ ...item, state: 'RESOLVIDO' })), ...scanComparison.persistent_findings.map(item => ({ ...item, state: 'PERSISTENTE' }))].length ? <div className="table-scroll"><table><thead><tr><th>Estado</th><th>Achado</th><th>CWE / severidade</th><th>Endpoint</th></tr></thead><tbody>{[...scanComparison.new_findings.map(item => ({ ...item, state: 'NOVO' })), ...scanComparison.resolved_findings.map(item => ({ ...item, state: 'RESOLVIDO' })), ...scanComparison.persistent_findings.map(item => ({ ...item, state: 'PERSISTENTE' }))].map((item, index) => <tr key={`${item.state}:${item.cwe}:${item.endpoint}:${index}`}><td><Badge value={item.state}/></td><td>{item.title}</td><td>{item.cwe} · <Badge value={item.severity}/></td><td><code>{item.endpoint}</code></td></tr>)}</tbody></table></div> : <Empty title="Nenhum achado nos scans selecionados"/>}<h3>Alterações na superfície</h3>{scanComparison.added_endpoints.length || scanComparison.removed_endpoints.length ? <div className="table-scroll"><table><thead><tr><th>Estado</th><th>Método</th><th>Caminho</th><th>Tipo</th></tr></thead><tbody>{[...scanComparison.added_endpoints.map(item => ({ ...item, state: 'ADICIONADO' })), ...scanComparison.removed_endpoints.map(item => ({ ...item, state: 'REMOVIDO' }))].map(item => <tr key={`${item.state}:${item.method}:${item.path}`}><td><Badge value={item.state}/></td><td><MethodBadge method={item.method}/></td><td><code>{item.path}</code></td><td>{item.resource_type}</td></tr>)}</tbody></table></div> : <Empty title="Nenhuma alteração na superfície descoberta"/>}</> : <Empty title="Carregando comparação…"/>}</> : <Empty title="São necessários pelo menos dois scans concluídos"/>}</section>}

    {tab === 'Testes de autorização' && <section className="panel"><h2>Preview dos testes de autorização</h2><p>Sugestões nunca são executadas automaticamente. Revisão humana e regra aprovada continuam obrigatórias.</p>{preview?.items.length ? <div className="table-scroll"><table><thead><tr><th>Proprietário → teste</th><th>Recurso</th><th>Esperado</th><th>Confiança</th><th>Estado</th></tr></thead><tbody>{preview.items.map(item => <tr key={item.scenario_id}><td>{item.owner_profile} → {item.test_profile}</td><td><MethodBadge method={item.method}/> <code>{item.resource}</code></td><td>{item.expected_access}</td><td>{item.confidence}</td><td><Badge value={item.executable ? 'READY' : 'REVIEW'}/></td></tr>)}</tbody></table></div> : <Empty title="Nenhum cenário de autorização revisado"/>}<p className="muted">Requisições mutáveis: 0 · confirmação explícita obrigatória.</p></section>}

    {tab === 'Cobertura CWE' && <section className="panel"><h2>Cobertura CWE</h2><div className="scan-summary"><div><span>CWEs</span><strong>{cwe?.total_cwes || 0}</strong></div><div><span>Mapeadas ao OWASP</span><strong>{cwe?.mapped_to_owasp || 0}</strong></div><div><span>Sem mapeamento direto</span><strong>{cwe?.without_direct_owasp_mapping || 0}</strong></div></div>{cwe?.rows.map(row => <div className="module-row" key={row.cwe}><strong>{row.cwe}</strong><span>{row.occurrences} ocorrência(s) · {row.affected_endpoints} endpoint(s)</span><span>{row.owasp_mappings.join(', ') || 'Sem mapeamento OWASP direto'}</span></div>)}</section>}

    {tab === 'Dados sensíveis' && <section className="panel"><h2>Dados sensíveis</h2><p>Esta visão indica risco técnico e não afirma automaticamente uma violação legal.</p><div className="scan-summary"><div><span>Endpoints sensíveis</span><strong>{privacy?.sensitive_endpoints || 0}</strong></div><div><span>Achados de autorização</span><strong>{privacy?.authorization_findings_affecting_sensitive_data || 0}</strong></div></div><div className="table-scroll"><table><thead><tr><th>Endpoint</th><th>Categorias</th><th>Observado por</th><th>Confiança</th></tr></thead><tbody>{sensitive?.rows.map(row => <tr key={`${row.method}:${row.endpoint}`}><td><MethodBadge method={row.method}/> <code>{row.endpoint}</code></td><td>{row.categories.join(', ')}</td><td>{row.observed_by.join(', ')}</td><td><Badge value={row.confidence}/></td></tr>)}</tbody></table></div></section>}

    {tab === 'Resumo do scan' && <section className="panel"><h2>Resumo do scan</h2>{summary ? <><div className="scan-summary"><div><span>Perfil</span><strong>{summary.scan_profile}</strong></div><div><span>Role</span><strong>{summary.role_name || 'ANONYMOUS'}</strong></div><div><span>Autenticação</span><strong>{summary.authenticated ? 'AUTHENTICATED' : 'ANONYMOUS'}</strong></div><div><span>Identificador</span><strong>{summary.experiment_label || '—'}</strong></div><div><span>Páginas / APIs / Forms</span><strong>{summary.pages_discovered} / {summary.api_endpoints} / {summary.forms}</strong></div><div><span>Achados passivos</span><strong>{summary.passive_findings}</strong></div><div><span>Issues / ocorrências</span><strong>{summary.unique_findings} / {summary.finding_occurrences}</strong></div><div><span>Candidatos de autorização</span><strong>{summary.authorization_candidates}</strong></div><div><span>Probes de autorização</span><strong>{summary.authorization_probes}</strong></div></div><p><strong>Versão:</strong> {summary.dast_version} · <strong>Ambiente:</strong> {summary.environment}</p><p><strong>CWEs:</strong> {summary.cwes.join(', ') || 'Nenhuma'} · <strong>Categorias sensíveis:</strong> {summary.sensitive_categories.join(', ') || 'Nenhuma'}</p><p><strong>Módulos:</strong> {summary.modules_enabled.join(', ')}</p><button className="button secondary" onClick={exportSummary}><Download size={16}/> Exportar JSON sanitizado</button></> : <Empty title="Nenhum scan disponível"/>}</section>}
  </>
}
