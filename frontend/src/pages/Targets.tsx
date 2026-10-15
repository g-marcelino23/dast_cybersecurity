import { useState } from 'react'
import type { FormEvent } from 'react'
import { Crosshair, KeyRound, Plus, ShieldCheck } from 'lucide-react'
import { Link } from 'react-router-dom'
import { api, errorMessage } from '../api'
import { useData } from '../data'
import { Empty, ErrorBox, PageTitle, SearchField } from '../components/ui'

export function Targets() {
  const { targets, refresh } = useData()
  const [form, setForm] = useState(false)
  const [search, setSearch] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [protectedTarget, setProtectedTarget] = useState(false)
  const [safeMode, setSafeMode] = useState(true)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError('')
    const fields = new FormData(event.currentTarget)
    try {
      const created = await api.createTarget({
        name: String(fields.get('name')).trim(),
        base_url: String(fields.get('base_url')).trim(),
        api_url: String(fields.get('api_url')).trim() || null,
        description: String(fields.get('description')).trim() || null,
        environment: fields.get('environment') === 'FIXTURE' ? 'FIXTURE' : 'LOCAL',
        is_protected_target: protectedTarget,
        safe_scan_mode: protectedTarget || safeMode,
      })
      await refresh(); setForm(false)
      if (created.requires_ownership_verification) {
        setError('Aplicação salva. Publique o desafio e conclua a verificação na visão geral.')
      }
    } catch (caught) { setError(errorMessage(caught)) }
    finally { setBusy(false) }
  }

  const filtered = targets.filter(target => `${target.name} ${target.base_url}`.toLowerCase().includes(search.toLowerCase()))
  return <>
    <PageTitle eyebrow="SUPERFÍCIE DE ANÁLISE" title="Aplicações" description="Organize sites, frontends e APIs que você está autorizado a analisar." action={<button className="button" onClick={() => setForm(!form)}><Plus size={17}/> Cadastrar aplicação</button>}/>
    {form && <section className="panel form-panel"><h2>Cadastrar aplicação</h2><p className="muted">Alvos locais são liberados diretamente. Domínios públicos exigem HTTPS e prova de propriedade antes de qualquer scan.</p><form onSubmit={submit}><div className="form-grid">
      <label>Nome da aplicação<input name="name" required maxLength={120} placeholder="Portal de Clientes"/></label>
      <label>URL base<input name="base_url" required type="url" maxLength={2048} placeholder="http://localhost:5173"/></label>
      <label>URL da API <span>(opcional)</span><input name="api_url" type="url" maxLength={2048} placeholder="http://localhost:3001"/></label>
      <label>Descrição <span>(opcional)</span><input name="description" maxLength={4000} placeholder="Frontend e API do portal em homologação"/></label>
      <label>Ambiente<select name="environment" defaultValue="LOCAL" disabled={protectedTarget}><option value="LOCAL">LOCAL / PRIVADO</option><option value="FIXTURE">LABORATÓRIO / FIXTURE</option></select></label>
      <label className="check-label"><input name="protected_target" type="checkbox" checked={protectedTarget} onChange={event => { setProtectedTarget(event.target.checked); if (event.target.checked) setSafeMode(true) }}/> Exigir validação dos perfis</label>
      <label className="check-label"><input name="safe_scan_mode" type="checkbox" checked={protectedTarget || safeMode} disabled={protectedTarget} onChange={event => setSafeMode(event.target.checked)}/> Safe Scan Mode {protectedTarget && '(obrigatório)'}</label>
    </div><ErrorBox message={error}/><div className="form-actions"><button type="button" className="button secondary" disabled={busy} onClick={() => setForm(false)}>Cancelar</button><button className="button" disabled={busy}>{busy ? 'Validando alvo…' : 'Salvar alvo'}</button></div></form></section>}
    <div className="toolbar"><SearchField value={search} onChange={setSearch} placeholder="Buscar por nome ou URL…"/><span>{filtered.length} alvo(s)</span></div>
    <div className="target-grid">{filtered.map(target => <article className="panel target-card" key={target.id}><div className="target-card-top"><span className="target-symbol"><Crosshair size={23}/></span><span className="subtle-tag">{target.requires_ownership_verification ? target.ownership_verification_status : target.is_protected_target ? 'PROTECTED TARGET' : target.environment}</span></div><h2>{target.name}</h2><p>{target.description || 'Nenhuma descrição adicionada.'}</p><dl><dt>FRONTEND / BASE</dt><dd className="mono">{target.base_url}</dd>{target.api_url && <><dt>API / BACKEND</dt><dd className="mono">{target.api_url}</dd></>}<dt>OPENAPI</dt><dd>{target.openapi_title ? `${target.openapi_title} · ${target.openapi_operation_count} operações` : 'Não importado'}</dd><dt>SEGURANÇA</dt><dd>{target.safe_scan_mode ? 'Safe Scan Mode ON' : 'Modo personalizado'}</dd></dl><div className="target-bottom"><Link className="text-link" to={`/targets/${target.id}`}>Visão geral</Link><Link className="text-link" to="/auth-profiles"><KeyRound size={13}/> Perfis</Link>{(!target.requires_ownership_verification || target.ownership_verification_status === 'VERIFIED') && <Link className="text-link" to={`/new-scan?target=${target.id}`}>Novo scan <Plus size={14}/></Link>}</div></article>)}</div>
    {!filtered.length && <section className="panel"><Empty title={search ? 'Nenhum alvo encontrado' : 'Adicione sua primeira aplicação'} text="Cadastre uma aplicação local, privada ou um domínio público autorizado."/></section>}
    <div className="privacy-note"><ShieldCheck size={17}/><p>Domínios públicos só entram no escopo após verificação. A allowlist usa hosts exatos, bloqueia DNS misto/rebinding e nunca segue redirects automaticamente.</p></div>
  </>
}
