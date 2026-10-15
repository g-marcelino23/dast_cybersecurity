import { Link } from 'react-router-dom'
import type { AccessProfileSurface, AuthorizationCandidate, AuthProfile, RoleComparison } from '../types'
import { Badge, Empty, MethodBadge } from './ui'

export function AccessProfileSurfaceView({ surface }: { surface: AccessProfileSurface | null }) {
  if (!surface) return <Empty title="Selecione um perfil"/>
  if (!surface.last_scan_id) return <Empty title="Nenhum scan autenticado foi executado para este perfil" text={`Estado da autenticação: ${surface.authentication_status}`}/>
  return <>
    <div className="scan-summary">
      <div><span>Autenticação</span><strong>{surface.authentication_status}</strong></div>
      <div><span>Páginas</span><strong>{surface.pages_discovered}</strong></div>
      <div><span>APIs</span><strong>{surface.api_endpoints}</strong></div>
      <div><span>Formulários</span><strong>{surface.forms}</strong></div>
      <div><span>Endpoints sensíveis</span><strong>{surface.sensitive_endpoints}</strong></div>
      <div><span>Achados passivos</span><strong>{surface.passive_findings}</strong></div>
      <div><span>Issues únicos</span><strong>{surface.unique_issues}</strong></div>
      <div><span>Candidatos de autorização</span><strong>{surface.authorization_candidates}</strong></div>
    </div>
    <div className="module-row"><strong>Métodos</strong><span>{surface.methods.join(', ') || 'Nenhum'}</span><span>scan #{surface.last_scan_id}</span></div>
    <div className="module-row"><strong>Dados sensíveis</strong><span>{surface.sensitive_categories.join(', ') || 'Nenhuma categoria observada'}</span><span>somente metadados</span></div>
    <div className="module-row"><strong>Cobertura CWE</strong><span>{surface.cwes.join(', ') || 'Nenhuma CWE observada'}</span><span>{surface.authorization_rules_related} regra(s) relacionada(s)</span></div>
  </>
}

interface ComparisonProps {
  profiles: AuthProfile[]
  profileA: string
  profileB: string
  comparison: RoleComparison | null
  candidates: AuthorizationCandidate[]
  busy: boolean
  onProfileA: (value: string) => void
  onProfileB: (value: string) => void
  onGenerate: () => void
}

export function RoleComparisonView(props: ComparisonProps) {
  const profileNames = new Map(props.profiles.map(profile => [profile.id, profile.name]))
  return <>
    <p className="muted">Diferenças entre superfícies observadas não comprovam uma vulnerabilidade de autorização.</p>
    <div className="form-grid">
      <label>Perfil A<select value={props.profileA} onChange={event => props.onProfileA(event.target.value)}>{props.profiles.map(profile => <option key={profile.id} value={profile.id}>{profile.name} · {profile.role_name}</option>)}</select></label>
      <label>Perfil B<select value={props.profileB} onChange={event => props.onProfileB(event.target.value)}>{props.profiles.map(profile => <option key={profile.id} value={profile.id} disabled={String(profile.id) === props.profileA}>{profile.name} · {profile.role_name}</option>)}</select></label>
    </div>
    {props.comparison ? <>
      <p>{props.comparison.message}</p>
      <div className="table-scroll"><table><thead><tr><th>Recurso</th><th>Tipo</th><th>Categorias sensíveis</th><th>Estado</th></tr></thead><tbody>{props.comparison.rows.map(row => <tr key={`${row.method}:${row.endpoint}:${row.resource_type}`}><td><MethodBadge method={row.method}/> <code>{row.endpoint}</code></td><td>{row.resource_type}</td><td>{row.sensitive_categories.join(', ') || '—'}</td><td><Badge value={row.state}/></td></tr>)}</tbody></table></div>
      <button className="button secondary" disabled={props.busy || !props.comparison.profile_a_scan_id || !props.comparison.profile_b_scan_id} onClick={props.onGenerate}>{props.busy ? 'Gerando…' : 'Gerar candidatos de autorização'}</button>
    </> : <Empty title="Selecione dois perfis diferentes"/>}
    <h3>Candidatos de autorização</h3>
    {props.candidates.length ? <div className="table-scroll"><table><thead><tr><th>Proprietário → teste</th><th>Recurso</th><th>Motivo</th><th>Confiança</th><th>Estado</th></tr></thead><tbody>{props.candidates.map(candidate => <tr key={candidate.id}><td>{profileNames.get(candidate.owner_profile_id)} → {profileNames.get(candidate.test_profile_id)}</td><td><MethodBadge method={candidate.method}/> <code>{candidate.resource_pattern}</code><small>{candidate.sensitive_categories.join(', ')}</small></td><td>{candidate.reason}</td><td>{candidate.confidence}</td><td><Badge value={candidate.status}/></td></tr>)}</tbody></table></div> : <Empty title="Nenhum candidato de autorização" text="Candidatos exigem dois scans autenticados concluídos e permanecem como sugestões."/>}
    <p><Link className="text-link" to="/authorization">Revisar regras de autorização</Link></p>
  </>
}
