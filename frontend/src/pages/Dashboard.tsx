import { Activity, ArrowRight, ArrowUpRight, Bug, Crosshair, Plus, ShieldCheck, Target } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useData } from '../data'
import { labels, PageTitle, ScansTable, severities } from '../components/ui'
export function Dashboard() {
  const { scans, targets, findings } = useData()
  const completed = scans.filter(s => s.status === 'COMPLETED').length
  const distribution = severities.map(severity => ({ severity, count: findings.filter(f => f.severity === severity).length }))
  const total = findings.length
  const segments = distribution.reduce<{ colors: string[]; offset: number }>((acc, d) => {
    const end = acc.offset + (total ? d.count / total * 100 : 0)
    acc.colors.push(`var(--${d.severity.toLowerCase()}) ${acc.offset}% ${end}%`)
    return { colors: acc.colors, offset: end }
  }, { colors: [], offset: 0 })
  return <>
    <PageTitle eyebrow="VISÃO GERAL" title="Segurança em perspectiva." description="Acompanhe a superfície e os riscos das suas aplicações web e APIs." action={<Link className="button" to="/new-scan"><Plus size={17}/> Novo scan</Link>}/>
    <section className="overview-banner"><div className="banner-orbit"><ShieldCheck size={32}/></div><div><span className="tiny-tag">DYNAMIC APPLICATION SECURITY</span><h2>Da descoberta à correção.</h2><p>Encontre, explique e acompanhe vulnerabilidades com evidências e classificação CWE.</p></div><Link to="/targets" className="banner-link">Gerenciar aplicações <ArrowUpRight size={17}/></Link></section>
    <section className="stats-grid" aria-label="Métricas do workspace">{[
      { title: 'Total de scans', value: scans.length, icon: Activity, caption: `${completed} concluídos`, color: 'teal' },
      { title: 'Aplicações', value: targets.length, icon: Target, caption: 'Alvos autorizados no workspace', color: 'blue' },
      { title: 'Ocorrências', value: total, icon: Bug, caption: `${new Set(findings.map(f => f.issue_key || `${f.title}:${f.cwe}`)).size} issues únicos`, color: 'amber' },
      { title: 'Alta + crítica', value: findings.filter(f => ['HIGH', 'CRITICAL'].includes(f.severity)).length, icon: Crosshair, caption: 'Prioridade de investigação', color: 'purple' },
    ].map(({ title, value, icon: Icon, caption, color }) => <article className="stat-card" key={title}><div className="stat-top"><span>{title}</span><span className={`stat-icon ${color}`}><Icon size={18}/></span></div><strong>{value.toString().padStart(2, '0')}</strong><small>{caption}</small></article>)}</section>
    <div className="dashboard-middle"><section className="panel severity-panel"><div className="panel-heading"><div><h2>Distribuição por severidade</h2><p>Achados observados em todas as varreduras</p></div><span className="subtle-tag">CWE FIRST</span></div><div className="severity-content"><div className="donut" role="img" aria-label={`${total} achados: ${distribution.map(d => `${labels[d.severity]} ${d.count}`).join(', ')}`} style={{ background: total ? `conic-gradient(${segments.colors.join(',')})` : 'conic-gradient(#243142 0% 100%)' }}><div><strong>{total}</strong><span>achados</span></div></div><div className="severity-legend">{distribution.map(d => <div className="legend-row" key={d.severity}><span className={`severity-dot dot-${d.severity.toLowerCase()}`}/><span>{labels[d.severity]}</span><div className="bar-track"><i style={{ width: `${total ? d.count / total * 100 : 0}%`, background: `var(--${d.severity.toLowerCase()})` }}/></div><strong>{d.count}</strong></div>)}</div></div></section>
    <section className="panel coverage-panel"><div className="panel-heading"><div><h2>O que estamos analisando</h2><p>Oito módulos passivos. Evidências observáveis.</p></div></div>{[['01', 'Security headers', 'Políticas de proteção HTTP'], ['02', 'Server disclosure', 'Identificadores de tecnologia'], ['03', 'Cookies', 'Atributos de possíveis sessões'], ['04', 'CORS', 'Origens e credenciais'], ['05', 'Sensitive data', 'Metadados potencialmente sensíveis'], ['06', 'Content Security Policy', 'Diretivas potencialmente permissivas'], ['07', 'Cache control', 'Cache público de possíveis sessões'], ['08', 'Error disclosure', 'Stack traces e erros técnicos']].map(([n, title, sub]) => <div className="module-row" key={n}><span className="module-number">{n}</span><div><strong>{title}</strong><small>{sub}</small></div><span className="module-active"/></div>)}</section></div>
    <section className="panel"><div className="panel-heading"><div><h2>CWE Coverage</h2><p>Encontradas independentemente de mapeamento direto ao OWASP Top 10.</p></div><span className="subtle-tag">OWASP OPTIONAL</span></div>{Array.from(new Set(findings.map(item => item.cwe))).map(cwe => <div className="module-row" key={cwe}><strong>{cwe}</strong><span>{findings.filter(item => item.cwe === cwe).length} occurrence(s)</span><span>{findings.some(item => item.cwe === cwe && item.owasp_category) ? 'Mapped to OWASP Top 10' : 'Without direct OWASP Top 10 mapping'}</span></div>)}</section>
    <section className="panel"><div className="panel-heading"><div><h2>Escaneamentos recentes</h2><p>Da execução às evidências da análise</p></div><Link className="text-link" to="/scans">Ver todos <ArrowRight size={15}/></Link></div><ScansTable scans={scans.slice(0, 5)} targets={targets}/></section>
    <div className="privacy-note"><ShieldCheck size={17}/><p>Achados indicam configurações observadas, não exploração confirmada. Dados sensíveis observados permanecem separados de vulnerabilidades.</p></div>
  </>
}
