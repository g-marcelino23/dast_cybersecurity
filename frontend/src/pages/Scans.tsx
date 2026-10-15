import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  ArrowDown,
  ArrowLeft,
  Download,
  FileInput,
  FileText,
  Globe2,
  KeyRound,
  Layers3,
  Network,
  Play,
  Plus,
  ShieldAlert,
  Square,
} from 'lucide-react'
import { api, errorMessage } from '../api'
import { useData } from '../data'
import {
  Badge,
  date,
  Empty,
  EndpointsTable,
  ErrorBox,
  FindingsTable,
  MethodBadge,
  PageTitle,
  ScansTable,
  SearchField,
} from '../components/ui'
import type {
  DiscoveredEndpoint,
  DiscoverySource,
  DiscoverySummary,
  Finding,
  ResourceType,
  Scan,
  SensitiveDataObservation,
  SensitiveDataSummary,
  AuthorizationSummary,
  FindingCorrelation,
  Target,
} from '../types'

interface ManualApiCoverage {
  imported: number
  eligible: number
  requestsSent: number
  responsesCollected: number
  skippedPathTemplates: number
  skippedWithoutAuth: number
  skippedUnsafeMethods: number
  runtimeValuesSupplied: number
  requestBudget: number
  budgetTruncated: boolean
}

function manualApiCoverage(scan: Scan): ManualApiCoverage | null {
  const raw = scan.configuration_snapshot.manual_api_collection
  const imported = scan.configuration_snapshot.manual_api_requests_imported
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || typeof imported !== 'number') {
    return null
  }
  const collection = raw as Record<string, unknown>
  const numberValue = (key: string) =>
    typeof collection[key] === 'number' ? collection[key] as number : 0
  return {
    imported,
    eligible: numberValue('eligible'),
    requestsSent: numberValue('requests_sent'),
    responsesCollected: numberValue('responses_collected'),
    skippedPathTemplates: numberValue('skipped_path_templates'),
    skippedWithoutAuth: numberValue('skipped_without_auth'),
    skippedUnsafeMethods: numberValue('skipped_unsafe_methods'),
    runtimeValuesSupplied: numberValue('runtime_values_supplied'),
    requestBudget: numberValue('request_budget'),
    budgetTruncated: collection.budget_truncated === true,
  }
}

export async function downloadReport(
  scan: Scan,
  target: Target | undefined,
  findings: Finding[],
) {
  const content = await buildReport(scan, target, findings)
  downloadBlob(JSON.stringify(content, null, 2), 'application/json', `dast-scan-${scan.id}.json`)
}

async function buildReport(scan: Scan, target: Target | undefined, findings: Finding[]) {
  const [endpoints, discovery, sensitiveData, privacySurface, authorizationProbes, authorizationSummary, findingCorrelation] = await Promise.all([
    api.scanEndpoints(scan.id),
    api.discoverySummary(scan.id),
    api.sensitiveData(scan.id),
    api.sensitiveDataSummary(scan.id),
    api.authorizationProbes(scan.id),
    api.authorizationSummary(scan.id),
    api.findingCorrelation(scan.id),
  ])
  const severityDistribution = Object.fromEntries(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(severity => [severity, findings.filter(finding => finding.severity === severity).length]))
  return {
    tool: 'DAST',
    version: scan.dast_version,
    generated_at: new Date().toISOString(),
    scope: 'Authorized web application discovery and passive HTTP security analysis.',
    target,
    scan,
    executive_summary: {
      unique_issues: findingCorrelation.unique_issues,
      occurrences: findingCorrelation.occurrences,
      affected_endpoints: findingCorrelation.affected_endpoints,
      severity_distribution: severityDistribution,
    },
    discovery,
    endpoints,
    privacy_surface: privacySurface,
    sensitive_data_observations: sensitiveData,
    authorization_summary: authorizationSummary,
    authorization_probes: authorizationProbes,
    authorization_findings: findings.filter((finding) => finding.issue_key?.startsWith('authz:')),
    privacy_impact_summary: {
      sensitive_surface: privacySurface,
      authorization_failures: authorizationSummary.privacy_impacting_authorization_failures,
    },
    finding_correlation: findingCorrelation,
    findings,
    limitations: [
      'A ausência de achados não comprova a ausência de vulnerabilidades.',
      'Somente os endpoints alcançados e os módulos habilitados foram analisados.',
      'Achados potenciais e inconclusivos exigem revisão humana.',
    ],
  }
}

function downloadBlob(content: string, type: string, filename: string) {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

function escapeHtml(value: unknown) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character] || character)
}

export async function downloadHtmlReport(scan: Scan, target: Target | undefined, findings: Finding[]) {
  const report = await buildReport(scan, target, findings)
  const rows = findings.map(finding => `<tr><td>${escapeHtml(finding.title)}</td><td>${escapeHtml(finding.finding_type)}</td><td>${escapeHtml(finding.severity)}</td><td>${escapeHtml(finding.status)}</td><td>${escapeHtml(finding.cwe)}</td><td>${escapeHtml(finding.endpoint)}</td></tr>`).join('')
  const summary = report.executive_summary
  const manualCoverage = manualApiCoverage(scan)
  const manualCoverageHtml = manualCoverage && manualCoverage.imported > 0
    ? `<h2>Cobertura da API manual</h2><div class="cards"><div class="card"><strong>${manualCoverage.imported}</strong>templates</div><div class="card"><strong>${manualCoverage.requestsSent}</strong>requisições</div><div class="card"><strong>${manualCoverage.responsesCollected}</strong>respostas</div><div class="card"><strong>${manualCoverage.skippedPathTemplates + manualCoverage.skippedWithoutAuth + manualCoverage.skippedUnsafeMethods}</strong>ignorados com segurança</div></div><p class="meta">Rotas parametrizadas: ${manualCoverage.skippedPathTemplates} · sem autenticação disponível: ${manualCoverage.skippedWithoutAuth} · métodos mutáveis: ${manualCoverage.skippedUnsafeMethods} · orçamento: ${manualCoverage.requestBudget}.</p>`
    : ''
  const html = `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><title>Relatório DAST #${scan.id}</title><style>body{font-family:Arial,sans-serif;margin:40px;color:#17202a}h1{margin-bottom:4px}.meta{color:#52606d}.cards{display:flex;gap:12px;margin:24px 0}.card{border:1px solid #ccd5df;border-radius:8px;padding:14px;min-width:120px}.card strong{display:block;font-size:24px}table{width:100%;border-collapse:collapse;margin-top:24px}th,td{text-align:left;border-bottom:1px solid #dde3ea;padding:10px;font-size:12px}th{background:#f2f5f8}.notice{margin-top:28px;padding:14px;background:#f5f7fa}</style></head><body><h1>Relatório DAST</h1><p class="meta">Scan #${scan.id} · ${escapeHtml(target?.name || `Aplicação #${scan.target_id}`)} · gerado em ${new Date().toLocaleString('pt-BR')}</p><div class="cards"><div class="card"><strong>${summary.unique_issues}</strong>issues únicos</div><div class="card"><strong>${summary.occurrences}</strong>ocorrências</div><div class="card"><strong>${summary.affected_endpoints}</strong>endpoints</div><div class="card"><strong>${summary.severity_distribution.CRITICAL + summary.severity_distribution.HIGH}</strong>alta + crítica</div></div>${manualCoverageHtml}<h2>Vulnerabilidades e achados</h2><table><thead><tr><th>Achado</th><th>Tipo</th><th>Severidade</th><th>Status</th><th>CWE</th><th>Endpoint</th></tr></thead><tbody>${rows || '<tr><td colspan="6">Nenhum achado registrado.</td></tr>'}</tbody></table><div class="notice"><strong>Limitações</strong><ul>${report.limitations.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul></div></body></html>`
  downloadBlob(html, 'text/html;charset=utf-8', `dast-scan-${scan.id}.html`)
}

export function downloadSarifReport(scan: Scan, findings: Finding[]) {
  const rules = Array.from(new Map(findings.map(finding => [finding.cwe, { id: finding.cwe, name: finding.title, shortDescription: { text: finding.description }, help: { text: finding.recommendation } }])).values())
  const sarif = { version: '2.1.0', $schema: 'https://json.schemastore.org/sarif-2.1.0.json', runs: [{ tool: { driver: { name: 'DAST', version: scan.dast_version, rules } }, results: findings.map(finding => ({ ruleId: finding.cwe, level: ['CRITICAL', 'HIGH'].includes(finding.severity) ? 'error' : finding.severity === 'MEDIUM' ? 'warning' : 'note', message: { text: finding.title }, locations: [{ physicalLocation: { artifactLocation: { uri: finding.endpoint } } }], properties: { confidence: finding.confidence, findingType: finding.finding_type, status: finding.status } })) }] }
  downloadBlob(JSON.stringify(sarif, null, 2), 'application/sarif+json', `dast-scan-${scan.id}.sarif`)
}

export function Scans() {
  const { scans, targets } = useData()
  const [search, setSearch] = useState('')
  const filtered = scans.filter((scan) =>
    `${scan.id} ${scan.status} ${targets.find((target) => target.id === scan.target_id)?.name}`
      .toLowerCase()
      .includes(search.toLowerCase()),
  )
  return (
    <>
      <PageTitle
        eyebrow="HISTÓRICO"
        title="Escaneamentos"
        description="Acompanhe discovery, análise passiva e evidências de cada execução."
        action={
          <Link className="button" to="/new-scan">
            <Plus size={16} /> Novo scan
          </Link>
        }
      />
      <div className="toolbar">
        <SearchField
          value={search}
          onChange={setSearch}
          placeholder="Buscar alvo, status ou ID…"
        />
        <span>{filtered.length} scan(s)</span>
      </div>
      <section className="panel">
        <ScansTable scans={filtered} targets={targets} />
      </section>
    </>
  )
}

export function ScanDetail() {
  const { id } = useParams()
  const scanId = Number(id)
  const { scans, targets, findings, refresh } = useData()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [endpoints, setEndpoints] = useState<DiscoveredEndpoint[]>([])
  const [summary, setSummary] = useState<DiscoverySummary | null>(null)
  const [sensitiveData, setSensitiveData] = useState<SensitiveDataObservation[]>([])
  const [privacySurface, setPrivacySurface] = useState<SensitiveDataSummary | null>(null)
  const [authorizationSummary, setAuthorizationSummary] = useState<AuthorizationSummary | null>(null)
  const [findingCorrelation, setFindingCorrelation] = useState<FindingCorrelation | null>(null)
  const [method, setMethod] = useState('')
  const [resourceType, setResourceType] = useState('')
  const [source, setSource] = useState('')
  const scan = scans.find((item) => item.id === scanId)

  useEffect(() => {
    if (!scan || !['PENDING', 'RUNNING'].includes(scan.status)) return
    const timer = window.setInterval(() => void refresh(), 1500)
    return () => window.clearInterval(timer)
  }, [refresh, scan])

  useEffect(() => {
    if (!Number.isInteger(scanId)) return
    let active = true
    Promise.all([api.scanEndpoints(scanId), api.discoverySummary(scanId), api.sensitiveData(scanId), api.sensitiveDataSummary(scanId), api.authorizationSummary(scanId), api.findingCorrelation(scanId)])
      .then(([endpointRows, discovery, sensitiveRows, privacySummary, authzSummary, correlation]) => {
        if (active) {
          setEndpoints(endpointRows)
          setSummary(discovery)
          setSensitiveData(sensitiveRows)
          setPrivacySurface(privacySummary)
          setAuthorizationSummary(authzSummary)
          setFindingCorrelation(correlation)
        }
      })
      .catch((caught: unknown) => {
        if (active) setError(errorMessage(caught))
      })
    return () => {
      active = false
    }
  }, [scanId, scan?.status])

  if (!scan) return <Empty title="Scan não encontrado" />
  const target = targets.find((item) => item.id === scan.target_id)
  const apiCoverage = manualApiCoverage(scan)
  const items = findings.filter((finding) => finding.scan_id === scan.id)
  const filteredEndpoints = endpoints.filter(
    (endpoint) =>
      (!method || endpoint.method === method) &&
      (!resourceType || endpoint.resource_type === resourceType) &&
      (!source || endpoint.source === source),
  )

  async function run() {
    setBusy(true)
    setError('')
    try {
      await api.startScan(scanId)
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      await refresh()
      setBusy(false)
    }
  }

  async function cancel() {
    setBusy(true)
    setError('')
    try {
      await api.cancelScan(scanId)
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      await refresh()
      setBusy(false)
    }
  }

  return (
    <>
      <Link className="back-link" to="/scans">
        <ArrowLeft size={15} /> Escaneamentos
      </Link>
      <PageTitle
        eyebrow={`SCN-${String(scan.id).padStart(4, '0')}`}
        title={target?.name || 'Resultado do scan'}
        description="Superfície descoberta e evidências da análise passiva."
        action={<div className="report-actions"><button className="button secondary" disabled={!['COMPLETED', 'FAILED'].includes(scan.status)} onClick={() => void downloadReport(scan, target, items)}><Download size={16}/> JSON</button><button className="button secondary" disabled={!['COMPLETED', 'FAILED'].includes(scan.status)} onClick={() => void downloadHtmlReport(scan, target, items)}><FileText size={16}/> HTML</button><button className="button secondary" disabled={!['COMPLETED', 'FAILED'].includes(scan.status)} onClick={() => downloadSarifReport(scan, items)}><Download size={16}/> SARIF</button></div>}
      />
      <section className="panel scan-summary">
        <div>
          <span>Status</span>
          <Badge value={busy ? 'RUNNING' : scan.status} />
        </div>
        <div>
          <span>Início</span>
          <strong>{date(scan.started_at)}</strong>
        </div>
        <div>
          <span>Término</span>
          <strong>{date(scan.finished_at)}</strong>
        </div>
        <div>
          <span>Achados</span>
          <strong>{scan.total_findings}</strong>
        </div>
      </section>
      <ErrorBox message={error || scan.error_message || ''} />
      {['PENDING', 'RUNNING'].includes(scan.status) && <section className="panel scan-progress"><div className="scan-progress-heading"><div><span>Fase atual</span><strong>{scan.phase.replaceAll('_', ' ')}</strong></div><strong>{scan.progress_percent}%</strong></div><div className="progress-track" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={scan.progress_percent}><span style={{ width: `${scan.progress_percent}%` }}/></div><button className="button secondary" disabled={busy || scan.cancellation_requested} onClick={() => void cancel()}><Square size={14}/> {scan.cancellation_requested ? 'Cancelamento solicitado' : 'Cancelar scan'}</button></section>}
      <section className="discovery-cards report-severity-cards">
        {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const).map(severity => <article className="stat-card" key={severity}><div className="stat-top"><span>{severity}</span><span className={`severity-dot dot-${severity.toLowerCase()}`}/></div><strong>{items.filter(item => item.severity === severity).length.toString().padStart(2, '0')}</strong><small>Ocorrências</small></article>)}
      </section>
      {authorizationSummary && <section className="panel scan-summary"><div><span>Authorization probes</span><strong>{authorizationSummary.total_probes}</strong></div><div><span>Denied correctly</span><strong>{authorizationSummary.denied_correctly}</strong></div><div><span>Confirmed bypass</span><strong>{authorizationSummary.confirmed_bypass}</strong></div><div><span>Privacy-impacting</span><strong>{authorizationSummary.privacy_impacting_authorization_failures}</strong></div></section>}
      {findingCorrelation && <div className="info-box"><Layers3 size={18}/><p><strong>Unique issues: {findingCorrelation.unique_issues}</strong> · Occurrences: {findingCorrelation.occurrences} · Affected endpoints: {findingCorrelation.affected_endpoints}. Evidências por endpoint permanecem disponíveis.</p></div>}
      {scan.status === 'PENDING' && (
        <button className="button run-pending" disabled={busy} onClick={() => void run()}>
          <Play size={16} />
          {busy ? 'Agendando…' : 'Iniciar scan pendente'}
        </button>
      )}
      {scan.status === 'RUNNING' && (
        <div className="info-box">
          Varredura em execução. Esta página atualiza automaticamente.
        </div>
      )}
      {scan.status === 'CANCELLED' && <div className="info-box">A varredura foi cancelada com segurança.</div>}
      {scan.observations.length > 0 && (
        <section className="panel observations">
          <h2>Respostas diretas observadas</h2>
          {scan.observations.map((observation, index) => (
            <div key={index}>
              <code>{observation.endpoint}</code>
              <span className="subtle-tag">HTTP {observation.status_code}</span>
              {observation.status_code >= 300 && observation.status_code < 400 && (
                <small>Redirecionamento não seguido pelo coletor passivo</small>
              )}
            </div>
          ))}
        </section>
      )}
      {apiCoverage && apiCoverage.imported > 0 && (
        <section className="manual-api-coverage">
          <div className="section-heading">
            <div>
              <div className="eyebrow">COBERTURA DE API</div>
              <h2>Endpoints manuais</h2>
              <p>O que entrou no inventário e o que foi realmente coletado neste scan.</p>
            </div>
            <span className="subtle-tag">LIMITE {apiCoverage.requestBudget} REQUESTS</span>
          </div>
          <div className="discovery-cards">
            {[
              { label: 'Templates', value: apiCoverage.imported, detail: 'Cadastrados no inventário' },
              { label: 'Elegíveis', value: apiCoverage.eligible, detail: 'GET, HEAD ou OPTIONS' },
              { label: 'Executados', value: apiCoverage.requestsSent, detail: 'Requisições enviadas' },
              { label: 'Analisados', value: apiCoverage.responsesCollected, detail: 'Respostas recebidas' },
            ].map(item => (
              <article className="stat-card" key={item.label}>
                <div className="stat-top"><span>{item.label}</span><Network size={17}/></div>
                <strong>{item.value.toString().padStart(2, '0')}</strong>
                <small>{item.detail}</small>
              </article>
            ))}
          </div>
          <div className="info-box">
            <ShieldAlert size={18}/>
            <p>
              <strong>Ignorados com segurança:</strong> {apiCoverage.skippedUnsafeMethods} método(s)
              mutável(is), {apiCoverage.skippedPathTemplates} rota(s) sem valor de path e{' '}
              {apiCoverage.skippedWithoutAuth} endpoint(s) sem autenticação disponível.
              {' '}{apiCoverage.runtimeValuesSupplied} endpoint(s) usaram valores temporários.
              {apiCoverage.budgetTruncated && ' O orçamento de requisições foi atingido.'}
            </p>
          </div>
        </section>
      )}
      <section className="discovery-section">
        <div className="section-heading">
          <div>
            <div className="eyebrow">SUPERFÍCIE DE ATAQUE</div>
            <h2>Endpoints descobertos</h2>
            <p>Páginas renderizadas, tráfego natural da aplicação e formulários observados.</p>
          </div>
          <span className="subtle-tag">
            {summary?.requests_observed ?? scan.discovery_requests_observed} REQUESTS
          </span>
        </div>
        <div className="discovery-cards">
          {[
            { label: 'Páginas', value: summary?.pages ?? 0, icon: Globe2, color: 'teal' },
            { label: 'APIs', value: summary?.api_endpoints ?? 0, icon: Network, color: 'blue' },
            { label: 'Formulários', value: summary?.forms ?? 0, icon: FileInput, color: 'amber' },
            {
              label: 'Endpoints únicos',
              value: summary?.unique_endpoints ?? 0,
              icon: Layers3,
              color: 'purple',
            },
          ].map(({ label, value, icon: Icon, color }) => (
            <article className="stat-card" key={label}>
              <div className="stat-top">
                <span>{label}</span>
                <span className={`stat-icon ${color}`}>
                  <Icon size={18} />
                </span>
              </div>
              <strong>{value.toString().padStart(2, '0')}</strong>
              <small>Inventário deste scan</small>
            </article>
          ))}
        </div>
        <div className="surface-flow panel" aria-label="Fluxo da superfície descoberta">
          <div>
            <Globe2 size={20} />
            <span>Frontend</span>
            <code>{target?.base_url}</code>
          </div>
          <ArrowDown size={18} />
          <div>
            <Network size={20} />
            <span>API Backend</span>
            <code>{target?.api_url || 'Detectada pelo tráfego'}</code>
          </div>
          <ArrowDown size={18} />
          <div>
            <Layers3 size={20} />
            <span>Endpoints</span>
            <code>{summary?.unique_endpoints ?? 0} rotas/métodos únicos</code>
          </div>
        </div>
        <div className="toolbar endpoint-filters">
          <select aria-label="Filtrar método" value={method} onChange={(event) => setMethod(event.target.value)}>
            <option value="">Todos os métodos</option>
            {summary?.methods.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
          <select aria-label="Filtrar tipo" value={resourceType} onChange={(event) => setResourceType(event.target.value)}>
            <option value="">Todos os tipos</option>
            {(['PAGE', 'API', 'FORM', 'SCRIPT', 'OTHER'] as ResourceType[]).map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
          <select aria-label="Filtrar origem" value={source} onChange={(event) => setSource(event.target.value)}>
            <option value="">Todas as origens</option>
            {(['OPENAPI', 'POSTMAN', 'MANUAL_API', 'CRAWLER', 'NETWORK', 'HTML', 'FORM', 'JAVASCRIPT'] as DiscoverySource[]).map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
          <span>{filteredEndpoints.length} registro(s)</span>
        </div>
        <section className="panel">
          <EndpointsTable endpoints={filteredEndpoints} />
        </section>
      </section>
      <section className="privacy-surface">
        <div className="section-heading">
          <div><div className="eyebrow">PRIVACY SURFACE</div><h2>Dados sensíveis observados</h2><p>Classificação estrutural em memória. Estas observações não significam exposição indevida.</p></div>
          <span className="subtle-tag">{privacySurface?.observations ?? 0} OBSERVAÇÕES</span>
        </div>
        <div className="discovery-cards privacy-cards">
          {[{ label: 'Endpoints com dados', value: privacySurface?.endpoints_with_sensitive_data ?? 0, icon: ShieldAlert, color: 'amber' }, { label: 'Categorias', value: privacySurface?.categories_detected ?? 0, icon: Layers3, color: 'purple' }, { label: 'Dados de saúde', value: privacySurface?.health_endpoints ?? 0, icon: ShieldAlert, color: 'teal' }, { label: 'Endpoints autenticados', value: privacySurface?.authenticated_endpoints ?? 0, icon: KeyRound, color: 'blue' }].map(({ label, value, icon: Icon, color }) => <article className="stat-card" key={label}><div className="stat-top"><span>{label}</span><span className={`stat-icon ${color}`}><Icon size={18}/></span></div><strong>{value.toString().padStart(2, '0')}</strong><small>Superfície observada</small></article>)}
        </div>
        {privacySurface && privacySurface.categories.length > 0 && <div className="category-strip">{privacySurface.categories.map(item => <span key={item.category}><Badge value={item.category}/><strong>{item.count}</strong></span>)}</div>}
        <section className="panel"><div className="table-scroll"><table><thead><tr><th>Categoria</th><th>Endpoint</th><th>Campo</th><th>Confidence</th><th>Ocorrências</th></tr></thead><tbody>{sensitiveData.map(item => { const endpoint = endpoints.find(row => row.id === item.endpoint_id); return <tr key={item.id}><td><Badge value={item.category}/></td><td><span className="method-path"><MethodBadge method={endpoint?.method || 'GET'}/><code>{endpoint?.path || `#${item.endpoint_id}`}</code></span></td><td><code>{item.field_path}</code></td><td><Badge value={item.confidence}/></td><td>{item.count}</td></tr> })}</tbody></table></div>{!sensitiveData.length && <Empty title="Nenhum dado sensível observado" text="O detector não encontrou evidência estrutural nas respostas analisadas."/>}</section>
      </section>
      <section className="panel findings-section">
        <div className="panel-heading">
          <div>
            <h2>Vulnerabilidades e achados</h2>
            <p>Issues agrupados, com severidade, confiança, CWE e estado de tratamento.</p>
          </div>
          <span className="subtle-tag">{items.length} ACHADOS</span>
        </div>
        <FindingsTable findings={items} />
      </section>
      <div className="privacy-note">
        O inventário nunca inclui valores de campos, tokens de autorização ou conteúdo das
        respostas. NONE significa que nenhum impacto em privacidade foi inferido pelo módulo.
      </div>
    </>
  )
}

export function EndpointDetail() {
  const { scanId, endpointId } = useParams()
  const numericScanId = Number(scanId)
  const numericEndpointId = Number(endpointId)
  const [endpoint, setEndpoint] = useState<DiscoveredEndpoint | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    api
      .endpoint(numericScanId, numericEndpointId)
      .then((value) => {
        if (active) setEndpoint(value)
      })
      .catch((caught: unknown) => {
        if (active) setError(errorMessage(caught))
      })
    return () => {
      active = false
    }
  }, [numericEndpointId, numericScanId])

  if (error) return <ErrorBox message={error} />
  if (!endpoint) return <div className="loading"><Network className="spin" /> Carregando endpoint…</div>
  return (
    <>
      <Link className="back-link" to={`/scans/${endpoint.scan_id}`}>
        <ArrowLeft size={15} /> Voltar ao scan #{endpoint.scan_id}
      </Link>
      <PageTitle
        eyebrow={`ENDPOINT #${endpoint.id}`}
        title={`${endpoint.method} ${endpoint.path}`}
        description={endpoint.url}
      />
      <div className="finding-detail-grid">
        <div>
          <section className="panel detail-section">
            <h2>Descoberta</h2>
            <p>
              Este endpoint foi observado via <strong>{endpoint.source}</strong> e classificado
              como <strong>{endpoint.resource_type}</strong>. Nenhum corpo de resposta foi
              armazenado.
            </p>
          </section>
          <section className="panel detail-section">
            <h2>Parâmetros sanitizados</h2>
            <pre>{endpoint.parameters ? JSON.stringify(endpoint.parameters, null, 2) : 'Nenhum parâmetro observado.'}</pre>
          </section>
          <section className="panel detail-section">
            <h2>Metadados técnicos</h2>
            <pre>{endpoint.metadata ? JSON.stringify(endpoint.metadata, null, 2) : 'Nenhum metadado adicional.'}</pre>
          </section>
        </div>
        <aside className="panel classification">
          <h2>Inventário</h2>
          <dl>
            <dt>Método</dt>
            <dd><MethodBadge method={endpoint.method} /></dd>
            <dt>Tipo</dt>
            <dd><Badge value={endpoint.resource_type} /></dd>
            <dt>Descoberto via</dt>
            <dd>{endpoint.source}</dd>
            <dt>Status HTTP</dt>
            <dd>{endpoint.status_code ?? 'Não observado'}</dd>
            <dt>Content-Type</dt>
            <dd>{endpoint.content_type || 'Não observado'}</dd>
            <dt>Possível autenticação</dt>
            <dd>{endpoint.requires_auth === true ? ([401, 403].includes(endpoint.status_code || 0) ? 'Resposta 401/403 observada' : 'Observado em sessão autenticada') : 'Não determinado'}</dd>
            <dt>Scan</dt>
            <dd><Link className="text-link" to={`/scans/${endpoint.scan_id}`}>#{endpoint.scan_id}</Link></dd>
          </dl>
        </aside>
      </div>
    </>
  )
}
