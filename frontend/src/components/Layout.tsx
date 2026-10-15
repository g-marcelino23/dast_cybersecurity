import { Activity, ArrowUpRight, Bug, ChevronRight, FileChartColumn, KeyRound, LayoutDashboard, Menu, Plus, Radar, Settings2, ShieldAlert, ShieldCheck, Target, X } from 'lucide-react'
import { useState } from 'react'
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom'
import { useData } from '../data'
const navigation = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard }, { to: '/targets', label: 'Alvos', icon: Target },
  { to: '/auth-profiles', label: 'Perfis de Acesso', icon: KeyRound },
  { to: '/authorization', label: 'Testes de Autorização', icon: ShieldAlert },
  { to: '/new-scan', label: 'Novo Scan', icon: Radar }, { to: '/scans', label: 'Escaneamentos', icon: Activity },
  { to: '/findings', label: 'Vulnerabilidades', icon: Bug }, { to: '/reports', label: 'Relatórios', icon: FileChartColumn },
  { to: '/settings', label: 'Configurações', icon: Settings2 },
]
export function Layout() {
  const [menu, setMenu] = useState(false)
  const { loading, error, refresh } = useData()
  const location = useLocation()
  const current = navigation.find(n => n.to === location.pathname)?.label || 'Detalhes da análise'
  return <div className="app-shell">
    <aside className={`sidebar ${menu ? 'open' : ''}`}><Link className="brand" to="/"><span className="brand-symbol"><ShieldCheck size={26}/></span><span><span className="brand-accent">DAST</span><small>DYNAMIC APPLICATION SECURITY</small></span></Link>
      <div className="workspace"><span className="workspace-avatar">D</span><div>Security Workspace<small>Aplicações web e APIs</small></div><span className="workspace-dot"/></div>
      <div className="nav-label">PLATAFORMA</div><nav>{navigation.map(({ to, label, icon: Icon }) => <NavLink key={to} to={to} end={to === '/'} onClick={() => setMenu(false)} className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}><Icon size={18}/><span>{label}</span>{to === '/new-scan' && <Plus size={13} className="nav-plus"/>}</NavLink>)}</nav>
      <div className="sidebar-bottom"><div className="scope-card"><ShieldCheck size={19}/><strong>Escopo autorizado</strong><p>Local, privado ou domínio verificado.<br/>Sessões isoladas por scan.</p><Link to="/settings">Ver política de segurança <ArrowUpRight size={13}/></Link></div><div className="version"><span>DAST v0.22.0</span><span>SAFE</span></div></div>
    </aside>
    {menu && <button className="menu-overlay" aria-label="Fechar menu" onClick={() => setMenu(false)}/>}
    <div className="main-shell"><header className="topbar"><div className="breadcrumb"><button className="mobile-menu" aria-label="Alternar menu" onClick={() => setMenu(!menu)}>{menu ? <X size={20}/> : <Menu size={20}/>}</button><span>Workspace</span><ChevronRight size={14}/><strong>{current}</strong></div><div className="topbar-right"><span className={`connection ${error ? 'offline' : ''}`}><i/>{loading ? 'Conectando' : error ? 'API indisponível' : 'API conectada'}</span><span className="local-tag">LOCAL</span><span className="profile">CD</span></div></header>
    <main>{error && <div role="alert" className="global-error">{error}<button onClick={() => void refresh()}>Tentar novamente</button></div>}{loading ? <div className="loading"><Radar className="spin"/> Carregando workspace…</div> : <Outlet/>}</main>
    <footer><span><ShieldCheck size={13}/> Segurança de aplicações com evidências sanitizadas.</span><span>Discovery · análise passiva · autorização controlada</span></footer></div>
  </div>
}
