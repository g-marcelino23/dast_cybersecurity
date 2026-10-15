import type { ReactNode } from 'react'
import { ArrowUpRight, Crosshair, Search } from 'lucide-react'
import { Link } from 'react-router-dom'
import type { DiscoveredEndpoint, Finding, Scan, Target } from '../types'
export const labels: Record<string, string> = { INFO: 'Informativa', LOW: 'Baixa', MEDIUM: 'Média', HIGH: 'Alta', CRITICAL: 'Crítica', NONE: 'Não inferido', PENDING: 'Pendente', RUNNING: 'Em execução', COMPLETED: 'Concluído', FAILED: 'Falhou', CANCELLED: 'Cancelado', OPEN: 'Aberta', CONFIRMED: 'Confirmada', IN_REVIEW: 'Em análise', IN_PROGRESS: 'Em correção', RESOLVED: 'Resolvida', ACCEPTED_RISK: 'Risco aceito', FALSE_POSITIVE: 'Falso positivo', REOPENED: 'Reaberta', CONFIRMED_VULNERABILITY: 'Vulnerabilidade confirmada', POTENTIAL_VULNERABILITY: 'Possível vulnerabilidade', MISCONFIGURATION: 'Configuração insegura', INFORMATION: 'Informação', INCONCLUSIVE: 'Inconclusivo', BEARER_LOGIN: 'Login + Bearer', COOKIE_LOGIN: 'Login + Cookie', FORM_LOGIN: 'Login por formulário', BASIC: 'Basic Auth', BEARER_TOKEN: 'Bearer Token', API_KEY: 'API Key', CUSTOM_HEADERS: 'Headers personalizados', OAUTH2_CLIENT_CREDENTIALS: 'OAuth 2.0 / OIDC', PERSONAL_IDENTIFIER: 'Identificador pessoal', CONTACT_INFORMATION: 'Contato', AUTHENTICATION_DATA: 'Dado de autenticação', HEALTH_INFORMATION: 'Informação de saúde', MEDICAL_RECORD: 'Registro de saúde', PRESCRIPTION: 'Prescrição', MEDICATION: 'Medicamento', EXAM_RESULT: 'Resultado de exame', DIAGNOSIS: 'Diagnóstico', APPOINTMENT_INFORMATION: 'Agendamento', FINANCIAL_INFORMATION: 'Financeiro', OTHER_SENSITIVE: 'Outro dado sensível' }
export const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const
export function Badge({ value }: { value: string }) { return <span className={`badge badge-${value.toLowerCase()}`}><i/>{labels[value] || value}</span> }
export function MethodBadge({ method }: { method: string }) { return <span className={`method method-${method.toLowerCase()}`}>{method}</span> }
export function date(value: string | null) { return value ? new Date(/Z$|[+-]\d{2}:\d{2}$/.test(value) ? value : `${value}Z`).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' }) : '—' }
export function PageTitle({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) { return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>{action}</div> }
export function Empty({ title = 'Nenhum registro por aqui', text = 'Os resultados aparecerão depois da primeira varredura.', action }: { title?: string; text?: string; action?: ReactNode }) { return <div className="empty"><Crosshair size={30}/><h3>{title}</h3><p>{text}</p>{action}</div> }
export function ErrorBox({ message }: { message: string }) { return message ? <div className="error-box" role="alert">{message}</div> : null }
export function SearchField({ value, onChange, placeholder }: { value: string; onChange: (value: string) => void; placeholder: string }) { return <label className="search"><Search size={16}/><input aria-label={placeholder} placeholder={placeholder} value={value} onChange={e => onChange(e.target.value)}/></label> }
export function FindingsTable({ findings }: { findings: Finding[] }) {
  if (!findings.length) return <Empty title="Nenhum achado neste recorte" text="A ausência de achados não garante a segurança da aplicação."/>
  const groups = Array.from(findings.reduce((map, finding) => {
    const key = finding.issue_key || `${finding.title}:${finding.cwe}`
    const current = map.get(key)
    if (current) {
      current.occurrences += 1
      current.endpoints.add(finding.endpoint)
    } else {
      map.set(key, { finding, occurrences: 1, endpoints: new Set([finding.endpoint]) })
    }
    return map
  }, new Map<string, { finding: Finding; occurrences: number; endpoints: Set<string> }>()).values())
  return <div className="table-scroll"><table><thead><tr><th>Achado</th><th>Tipo</th><th>Severidade</th><th>Status</th><th>CWE</th><th>Ocorrências</th><th>Endpoints</th></tr></thead><tbody>{groups.map(({ finding: f, occurrences, endpoints }) => <tr key={f.issue_key || f.id}><td><Link className="finding-link" to={`/findings/${f.id}`}>{f.title}<ArrowUpRight size={14}/></Link><small className="table-subtitle">{f.owasp_category || 'Sem associação OWASP'}</small></td><td><Badge value={f.finding_type}/></td><td><Badge value={f.severity}/></td><td><Badge value={f.status}/></td><td className="mono">{f.cwe}</td><td className="mono">{occurrences}</td><td className="mono">{endpoints.size}</td></tr>)}</tbody></table></div>
}
export function EndpointsTable({ endpoints }: { endpoints: DiscoveredEndpoint[] }) {
  if (!endpoints.length) return <Empty title="Nenhum endpoint neste recorte" text="Ajuste os filtros ou execute um scan de discovery."/>
  return <div className="table-scroll"><table><thead><tr><th>Método</th><th>Endpoint</th><th>Tipo</th><th>Origem</th><th>Status</th><th>Content-Type</th><th aria-label="Detalhes"/></tr></thead><tbody>{endpoints.map(endpoint => <tr key={endpoint.id}><td><MethodBadge method={endpoint.method}/></td><td><Link className="finding-link mono" to={`/scans/${endpoint.scan_id}/endpoints/${endpoint.id}`}>{endpoint.path}<ArrowUpRight size={14}/></Link></td><td><Badge value={endpoint.resource_type}/></td><td><span className="source-tag">{endpoint.source}</span></td><td className="mono">{endpoint.status_code ?? '—'}</td><td><span className="endpoint" title={endpoint.content_type || undefined}>{endpoint.content_type || '—'}</span></td><td><Link aria-label={`Abrir endpoint ${endpoint.id}`} className="icon-link" to={`/scans/${endpoint.scan_id}/endpoints/${endpoint.id}`}><ArrowUpRight size={18}/></Link></td></tr>)}</tbody></table></div>
}
export function ScansTable({ scans, targets }: { scans: Scan[]; targets: Target[] }) {
  if (!scans.length) return <Empty title="Seu primeiro scan começa aqui" text="Cadastre uma aplicação local e observe sua configuração de segurança." action={<Link to="/targets" className="button secondary">Cadastrar alvo <ArrowUpRight size={15}/></Link>}/>
  return <div className="table-scroll"><table><thead><tr><th>Scan / alvo</th><th>Status</th><th>Início</th><th>Achados</th><th aria-label="Detalhes"/></tr></thead><tbody>{scans.map(scan => <tr key={scan.id}><td><Link className="scan-target" to={`/scans/${scan.id}`}><span className="scan-icon"><Crosshair size={17}/></span><span>{targets.find(t => t.id === scan.target_id)?.name || `Alvo #${scan.target_id}`}<small>SCN-{String(scan.id).padStart(4, '0')}</small></span></Link></td><td><Badge value={scan.status}/></td><td className="muted">{date(scan.started_at)}</td><td className="mono">{scan.total_findings.toString().padStart(2, '0')}</td><td><Link aria-label={`Abrir scan ${scan.id}`} className="icon-link" to={`/scans/${scan.id}`}><ArrowUpRight size={18}/></Link></td></tr>)}</tbody></table></div>
}
