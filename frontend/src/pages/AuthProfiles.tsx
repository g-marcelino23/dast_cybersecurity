import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { CheckCircle2, KeyRound, Pencil, Plus, ShieldCheck, Trash2 } from 'lucide-react'
import { api, errorMessage } from '../api'
import { useData } from '../data'
import { Badge, Empty, ErrorBox, PageTitle } from '../components/ui'
import type { AuthProfile, AuthProfileInput, AuthType, LoginSuggestion } from '../types'

export function AuthProfiles() {
  const { targets } = useData()
  const [targetId, setTargetId] = useState('')
  const [profiles, setProfiles] = useState<AuthProfile[]>([])
  const [editing, setEditing] = useState<AuthProfile | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [authType, setAuthType] = useState<AuthType>('BEARER_LOGIN')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [testResult, setTestResult] = useState<Record<number, string>>({})
  const [mfaCodes, setMfaCodes] = useState<Record<number, string>>({})
  const [authPasswords, setAuthPasswords] = useState<Record<number, string>>({})
  const [authSecrets, setAuthSecrets] = useState<Record<number, string>>({})
  const [loginSuggestion, setLoginSuggestion] = useState<LoginSuggestion | null>(null)

  useEffect(() => {
    if (!targetId && targets[0]) setTargetId(String(targets[0].id))
  }, [targetId, targets])

  useEffect(() => {
    if (!targetId) return
    let active = true
    api.authProfiles(Number(targetId))
      .then(rows => { if (active) setProfiles(rows) })
      .catch(caught => { if (active) setError(errorMessage(caught)) })
    return () => { active = false }
  }, [targetId])

  async function reload() {
    if (targetId) setProfiles(await api.authProfiles(Number(targetId)))
  }

  function startCreate() {
    setEditing(null); setAuthType('BEARER_LOGIN'); setShowForm(true); setError('')
  }

  function startEdit(profile: AuthProfile) {
    setEditing(profile); setAuthType(profile.auth_type); setShowForm(true); setError('')
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError('')
    const fields = new FormData(event.currentTarget)
    const usernameField = String(fields.get('username_field') || '').trim()
    const passwordField = String(fields.get('password_field') || '').trim()
    const username = String(fields.get('username') || '')
    const loginType = ['BEARER_LOGIN', 'COOKIE_LOGIN', 'FORM_LOGIN'].includes(authType)
    const directType = ['BASIC', 'BEARER_TOKEN', 'API_KEY', 'CUSTOM_HEADERS'].includes(authType)
    const oauthType = authType === 'OAUTH2_CLIENT_CREDENTIALS'
    let headerTemplate: Record<string, string> | null = null
    if (authType === 'BEARER_TOKEN') headerTemplate = { Authorization: 'Bearer {{secret}}' }
    if (authType === 'API_KEY') {
      const headerName = String(fields.get('api_key_header') || 'X-API-Key').trim()
      const prefix = String(fields.get('api_key_prefix') || '')
      headerTemplate = { [headerName]: `${prefix}{{secret}}` }
    }
    if (authType === 'CUSTOM_HEADERS') {
      try {
        const parsed: unknown = JSON.parse(String(fields.get('header_template') || '{}'))
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error()
        headerTemplate = Object.fromEntries(Object.entries(parsed).map(([name, value]) => [name, String(value)]))
      } catch {
        setError('O template de headers precisa ser um objeto JSON válido.'); setBusy(false); return
      }
    }
    const payload: AuthProfileInput = {
      name: String(fields.get('name')).trim(),
      role_name: String(fields.get('role_name')).trim(),
      auth_type: authType,
      login_url: loginType || oauthType ? String(fields.get('login_url') || '').trim() || null : null,
      validation_url: authType === 'NONE' ? null : String(fields.get('validation_url')).trim() || null,
      http_method: 'POST',
      body_encoding: authType === 'FORM_LOGIN' || oauthType ? 'FORM' : 'JSON',
      body_template: loginType ? {
        [usernameField]: '{{username}}', [passwordField]: '{{password}}',
      } : null,
      header_template: directType ? headerTemplate : null,
      username_field: loginType ? usernameField || null : null,
      password_field: loginType ? passwordField || null : null,
      token_json_path: authType === 'BEARER_LOGIN' || oauthType ? String(fields.get('token_json_path')).trim() : null,
      token_header_name: authType === 'BEARER_LOGIN' || oauthType ? String(fields.get('token_header_name')).trim() : null,
      token_prefix: authType === 'BEARER_LOGIN' || oauthType ? String(fields.get('token_prefix')).trim() : null,
      mfa_url: loginType ? String(fields.get('mfa_url') || '').trim() || null : null,
      mfa_challenge_json_path: loginType ? String(fields.get('mfa_challenge_json_path') || '').trim() || null : null,
      mfa_challenge_field: loginType ? String(fields.get('mfa_challenge_field') || '').trim() || null : null,
      mfa_code_field: loginType ? String(fields.get('mfa_code_field') || '').trim() || null : null,
      role_json_path: authType === 'NONE' ? null : String(fields.get('role_json_path') || '').trim() || null,
      oidc_discovery_url: oauthType ? String(fields.get('oidc_discovery_url') || '').trim() || null : null,
      oauth_scopes: oauthType ? String(fields.get('oauth_scopes') || '').split(/[\s,]+/).filter(Boolean) : [],
      oauth_audience: oauthType ? String(fields.get('oauth_audience') || '').trim() || null : null,
      ...((loginType || authType === 'BASIC' || oauthType) && username ? { username } : {}),
    }
    try {
      if (editing) await api.updateAuthProfile(editing.id, payload)
      else await api.createAuthProfile(Number(targetId), payload)
      await reload(); setShowForm(false); setEditing(null)
    } catch (caught) { setError(errorMessage(caught)) }
    finally { setBusy(false) }
  }

  async function testProfile(profile: AuthProfile) {
    setTestResult(current => ({ ...current, [profile.id]: 'Testando…' }))
    try {
      const result = await api.validateAuthProfile(profile.id, { password: authPasswords[profile.id] || undefined, mfaCode: mfaCodes[profile.id]?.trim() || undefined, secret: authSecrets[profile.id] || undefined }, true)
      setAuthPasswords(current => ({ ...current, [profile.id]: '' }))
      setMfaCodes(current => ({ ...current, [profile.id]: '' }))
      setAuthSecrets(current => ({ ...current, [profile.id]: '' }))
      setTestResult(current => ({ ...current, [profile.id]: result.success ? `Authentication successful · Role configured: ${result.role_name} · Sessão temporária pronta para o próximo scan` : result.requires_mfa ? 'MFA code required · informe um código temporário e teste novamente' : `${result.message}${result.status_code ? ` · HTTP ${result.status_code}` : ''}` }))
      await reload()
    } catch (caught) {
      setTestResult(current => ({ ...current, [profile.id]: errorMessage(caught) }))
    }
  }

  async function detectLogin() {
    if (!targetId) return
    setBusy(true); setError('')
    try {
      const suggestions = await api.loginSuggestions(Number(targetId))
      setLoginSuggestion(suggestions[0] || null)
      if (!suggestions.length) setError('Nenhum formulário de login foi sugerido pelo discovery passivo.')
    } catch (caught) { setError(errorMessage(caught)) }
    finally { setBusy(false) }
  }

  async function remove(profile: AuthProfile) {
    if (!window.confirm(`Excluir o perfil ${profile.name}?`)) return
    try { await api.deleteAuthProfile(profile.id); await reload() }
    catch (caught) { setError(errorMessage(caught)) }
  }

  return <>
    <PageTitle eyebrow="SESSÕES ISOLADAS" title="Perfis de Acesso" description="Configure autenticação controlada para aplicações locais autorizadas." action={<button className="button" disabled={!targetId} onClick={startCreate}><Plus size={16}/> Novo perfil</button>}/>
    {!targets.length ? <section className="panel"><Empty title="Cadastre um alvo primeiro" text="Perfis sempre pertencem a um alvo local ou privado."/></section> : <>
      <div className="toolbar auth-target"><label>Alvo<select value={targetId} onChange={event => { setTargetId(event.target.value); setShowForm(false) }}>{targets.map(target => <option key={target.id} value={target.id}>{target.name}</option>)}</select></label><span>{profiles.length} perfil(is)</span></div>
      {showForm && <section className="panel form-panel auth-form"><h2><KeyRound size={17}/>{editing ? `Editar ${editing.name}` : 'Novo perfil de acesso'}</h2><p>Credenciais, tokens e API Keys são fornecidos somente ao validar e permanecem apenas na sessão temporária.</p>{['BEARER_LOGIN', 'COOKIE_LOGIN', 'FORM_LOGIN'].includes(authType) && <button type="button" className="button secondary" onClick={() => void detectLogin()}>Detectar configuração</button>}{loginSuggestion && ['BEARER_LOGIN', 'COOKIE_LOGIN', 'FORM_LOGIN'].includes(authType) && <div className="info-box"><ShieldCheck size={18}/><p><strong>SUGGESTED · revisão obrigatória</strong><br/>{loginSuggestion.method} {loginSuggestion.login_url}<br/>Campos: {loginSuggestion.username_field || 'não identificado'} / {loginSuggestion.password_field || 'não identificado'} · {loginSuggestion.confidence}</p></div>}<form key={editing?.id || 'new'} onSubmit={submit}>
        <div className="form-grid">
          <label>Nome do perfil<input name="name" required maxLength={120} defaultValue={editing?.name} placeholder="Usuário de teste A"/></label>
          <label>Role<input name="role_name" required maxLength={120} defaultValue={editing?.role_name} placeholder="VIEWER"/></label>
          <label>Tipo<select value={authType} onChange={event => setAuthType(event.target.value as AuthType)}><option value="BEARER_LOGIN">Login JSON + Bearer</option><option value="COOKIE_LOGIN">Login JSON + Cookie</option><option value="FORM_LOGIN">Login por formulário</option><option value="OAUTH2_CLIENT_CREDENTIALS">OAuth 2.0 / OIDC Client Credentials</option><option value="BASIC">Basic Auth</option><option value="BEARER_TOKEN">Bearer Token manual</option><option value="API_KEY">API Key</option><option value="CUSTOM_HEADERS">Headers personalizados</option><option value="NONE">Sem autenticação</option></select></label>
          {authType !== 'NONE' && <label>URL de validação<input name="validation_url" type="url" defaultValue={editing?.validation_url || ''} placeholder="http://localhost:3001/auth/me"/></label>}
          {['BEARER_LOGIN', 'COOKIE_LOGIN', 'FORM_LOGIN'].includes(authType) && <><label>URL de login<input name="login_url" required type="url" defaultValue={editing?.login_url || ''} placeholder="http://localhost:3001/auth/login"/></label><label>Username<input name="username" required={!editing} autoComplete="off" placeholder={editing ? 'Deixe vazio para preservar' : 'Usuário sintético'}/></label><label>Campo username<input name="username_field" required defaultValue={editing?.username_field || 'email'}/></label><label>Campo password<input name="password_field" required defaultValue={editing?.password_field || 'password'}/></label></>}
          {authType === 'BASIC' && <label>Username<input name="username" required={!editing} autoComplete="off" placeholder={editing ? 'Deixe vazio para preservar' : 'Usuário do Basic Auth'}/></label>}
          {authType === 'OAUTH2_CLIENT_CREDENTIALS' && <><label>Token endpoint <span>(opcional com discovery)</span><input name="login_url" type="url" defaultValue={editing?.login_url || ''} placeholder="http://localhost:8080/oauth/token"/></label><label>OIDC discovery URL <span>(opcional)</span><input name="oidc_discovery_url" type="url" defaultValue={editing?.oidc_discovery_url || ''} placeholder="http://localhost:8080/.well-known/openid-configuration"/></label><label>Client ID<input name="username" required={!editing} autoComplete="off" placeholder={editing ? 'Deixe vazio para preservar' : 'dast-scanner'}/></label><label>Scopes<input name="oauth_scopes" defaultValue={editing?.oauth_scopes.join(' ') || ''} placeholder="openid api.read"/><span>Separe por espaço ou vírgula.</span></label><label>Audience <span>(opcional)</span><input name="oauth_audience" defaultValue={editing?.oauth_audience || ''} placeholder="https://api.local"/></label></>}
          {authType === 'API_KEY' && <><label>Nome do header<input name="api_key_header" required defaultValue={Object.keys(editing?.header_template || {})[0] || 'X-API-Key'}/></label><label>Prefixo opcional<input name="api_key_prefix" defaultValue="" placeholder="Token "/></label></>}
          {authType === 'CUSTOM_HEADERS' && <label className="full-grid">Template JSON de headers<textarea name="header_template" required rows={6} defaultValue={JSON.stringify(editing?.header_template || { 'X-Custom-Header': 'valor', Authorization: 'Bearer {{secret}}' }, null, 2)}/><span>Use {'{{secret}}'} para valores sensíveis. Headers não sensíveis podem ter valores fixos.</span></label>}
          {(authType === 'BEARER_LOGIN' || authType === 'OAUTH2_CLIENT_CREDENTIALS') && <><label>Caminho JSON do token<input name="token_json_path" required defaultValue={editing?.token_json_path || (authType === 'OAUTH2_CLIENT_CREDENTIALS' ? 'access_token' : 'token')} placeholder="session.access_token"/></label><label>Header<input name="token_header_name" required defaultValue={editing?.token_header_name || 'Authorization'}/></label><label>Prefixo<input name="token_prefix" defaultValue={editing?.token_prefix || 'Bearer'}/></label></>}
          {['BEARER_LOGIN', 'COOKIE_LOGIN', 'FORM_LOGIN'].includes(authType) && <><label>URL MFA opcional<input name="mfa_url" type="url" defaultValue={editing?.mfa_url || ''} placeholder="http://localhost:3001/auth/mfa/verify"/></label><label>Path JSON do challenge<input name="mfa_challenge_json_path" defaultValue={editing?.mfa_challenge_json_path || ''} placeholder="challenge_id"/></label><label>Campo do challenge<input name="mfa_challenge_field" defaultValue={editing?.mfa_challenge_field || ''} placeholder="challenge_id"/></label><label>Campo do código MFA<input name="mfa_code_field" defaultValue={editing?.mfa_code_field || ''} placeholder="codigo"/></label></>}
          {authType !== 'NONE' && <label>Path JSON do role <span>(opcional)</span><input name="role_json_path" defaultValue={editing?.role_json_path || ''} placeholder="usuario.perfil"/></label>}
        </div><ErrorBox message={error}/><div className="form-actions"><button type="button" className="button secondary" onClick={() => setShowForm(false)}>Cancelar</button><button className="button" disabled={busy}>{busy ? 'Protegendo credencial…' : 'Salvar perfil'}</button></div>
      </form></section>}
      <div className="auth-profile-grid">{profiles.map(profile => <article className="panel auth-profile-card" key={profile.id}><div className="auth-profile-title"><span className="target-symbol"><KeyRound size={20}/></span><Badge value={profile.auth_type}/></div><h2>{profile.name}</h2><p className="role-label">{profile.role_name}</p><div className="credential-state"><CheckCircle2 size={15}/> {profile.credentials_configured ? 'Configuração pronta' : 'Configuração pendente'} · {profile.last_auth_success === true ? 'VALIDATED' : profile.last_auth_success === false ? 'FAILED' : 'NOT TESTED'}</div><dl><dt>LOGIN</dt><dd>{profile.login_url || profile.oidc_discovery_url || 'Autenticação direta'}</dd><dt>VALIDAÇÃO</dt><dd>{profile.validation_url || 'URL principal do alvo'}</dd></dl>{['BEARER_LOGIN', 'COOKIE_LOGIN', 'FORM_LOGIN', 'BASIC'].includes(profile.auth_type) && <label>Senha temporária<input type="password" autoComplete="current-password" value={authPasswords[profile.id] || ''} onChange={event => setAuthPasswords(current => ({ ...current, [profile.id]: event.target.value }))} placeholder="Não será armazenada"/></label>}{['BEARER_TOKEN', 'API_KEY', 'CUSTOM_HEADERS', 'OAUTH2_CLIENT_CREDENTIALS'].includes(profile.auth_type) && <label>{profile.auth_type === 'OAUTH2_CLIENT_CREDENTIALS' ? 'Client secret temporário' : 'Token / segredo temporário'}<input type="password" autoComplete="off" value={authSecrets[profile.id] || ''} onChange={event => setAuthSecrets(current => ({ ...current, [profile.id]: event.target.value }))} placeholder="Não será armazenado"/></label>}{profile.mfa_url && <label>Código MFA temporário<input type="password" inputMode="numeric" autoComplete="one-time-code" value={mfaCodes[profile.id] || ''} onChange={event => setMfaCodes(current => ({ ...current, [profile.id]: event.target.value }))} placeholder="Não será armazenado"/></label>}{testResult[profile.id] && <div className="auth-test-result">{testResult[profile.id]}</div>}<div className="profile-actions"><button className="button secondary" onClick={() => void testProfile(profile)}>Validar e preparar sessão</button><button className="icon-button" aria-label={`Editar ${profile.name}`} onClick={() => startEdit(profile)}><Pencil size={15}/></button><button className="icon-button danger" aria-label={`Excluir ${profile.name}`} onClick={() => void remove(profile)}><Trash2 size={15}/></button></div></article>)}</div>
      {profiles.length > 0 && <section className="panel"><h2>Validation and authenticated scans</h2><div className="table-scroll"><table><thead><tr><th>Profile</th><th>Target</th><th>Status</th><th>Last validation</th><th>Session initialized</th><th>Last authenticated scan</th></tr></thead><tbody>{profiles.map(profile => <tr key={profile.id}><td>{profile.name}<small>{profile.role_name}</small></td><td>{targets.find(target => target.id === profile.target_id)?.name || `#${profile.target_id}`}</td><td><Badge value={profile.last_auth_success === true ? 'VALIDATED' : profile.last_auth_success === false ? 'FAILED' : 'NOT_TESTED'}/></td><td>{profile.last_auth_tested_at ? new Date(profile.last_auth_tested_at).toLocaleString('pt-BR') : 'Never'}</td><td>{profile.last_auth_success === true ? 'YES' : 'NO'}</td><td>{profile.last_authenticated_scan_id ? `#${profile.last_authenticated_scan_id}` : 'No authenticated scan'}</td></tr>)}</tbody></table></div></section>}
      {!profiles.length && !showForm && <section className="panel"><Empty title="Nenhum perfil configurado" text="Crie perfis configuráveis para executar scans em sessões isoladas."/></section>}
      <div className="privacy-note"><ShieldCheck size={17}/><p>Senhas, códigos MFA, tokens e cookies não são persistidos nem retornados pela API. Cada scan recebe um BrowserContext novo e descarta a sessão ao concluir.</p></div>
    </>}
  </>
}
