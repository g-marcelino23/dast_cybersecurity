import { useEffect, useState } from 'react'
import { Eye, Play, Plus, ShieldCheck } from 'lucide-react'
import { api, errorMessage } from '../api'
import { Badge, Empty, ErrorBox, MethodBadge, PageTitle } from '../components/ui'
import { useData } from '../data'
import type {
  AuthorizationProbe,
  AuthorizationRule,
  AuthorizationScenario,
  AuthorizationTestPlan,
  AuthProfile,
  ExpectedAccess,
} from '../types'

const resultBadge = (result: AuthorizationProbe['result']) => {
  if (result === 'ALLOWED_AS_EXPECTED' || result === 'DENIED_AS_EXPECTED') return 'PASS'
  if (result === 'CONFIRMED_BYPASS' || result === 'POSSIBLE_BYPASS') return 'FAIL'
  if (result === 'SKIPPED') return 'SKIPPED'
  return 'INCONCLUSIVE'
}

export function AuthorizationTesting() {
  const { targets } = useData()
  const [targetId, setTargetId] = useState(targets[0]?.id || 0)
  const [profiles, setProfiles] = useState<AuthProfile[]>([])
  const [rules, setRules] = useState<AuthorizationRule[]>([])
  const [scenarios, setScenarios] = useState<AuthorizationScenario[]>([])
  const [selectedScenario, setSelectedScenario] = useState(0)
  const [plan, setPlan] = useState<AuthorizationTestPlan | null>(null)
  const [probes, setProbes] = useState<AuthorizationProbe[]>([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [confirmed, setConfirmed] = useState(false)
  const [rule, setRule] = useState({ name: '', source_role: '', resource_pattern: '', http_method: 'GET', expected_access: 'DENY' as ExpectedAccess, description: '' })
  const [scenario, setScenario] = useState({ name: '', owner_profile_id: 0, test_profile_id: 0, authorization_rule_id: 0 })
  const selectedScenarioRow = scenarios.find((item) => item.id === selectedScenario)
  const scenarioRunning = selectedScenarioRow?.execution_status === 'RUNNING'
  const scenarioNeedsRerun = selectedScenarioRow != null && ['COMPLETED', 'FAILED', 'INTERRUPTED'].includes(selectedScenarioRow.execution_status)

  useEffect(() => {
    if (!targetId) return
    setError('')
    Promise.all([api.authProfiles(targetId), api.authorizationRules(targetId), api.authorizationScenarios(targetId)])
      .then(([profileRows, ruleRows, scenarioRows]) => {
        setProfiles(profileRows)
        setRules(ruleRows)
        setScenarios(scenarioRows)
        setSelectedScenario(scenarioRows[0]?.id || 0)
        setPlan(null)
        setProbes([])
      })
      .catch((caught: unknown) => setError(errorMessage(caught)))
  }, [targetId])

  async function createRule(event: React.FormEvent) {
    event.preventDefault()
    setError('')
    try {
      const created = await api.createAuthorizationRule(targetId, { ...rule, description: rule.description || null, enabled: true })
      setRules((current) => [...current, created])
      setScenario((current) => ({ ...current, authorization_rule_id: created.id }))
    } catch (caught) { setError(errorMessage(caught)) }
  }

  async function createScenario(event: React.FormEvent) {
    event.preventDefault()
    setError('')
    if (scenario.owner_profile_id === scenario.test_profile_id) {
      setError('Os perfis proprietário e de teste devem ser diferentes.')
      return
    }
    try {
      const created = await api.createAuthorizationScenario(targetId, { ...scenario, enabled: true })
      setScenarios((current) => [...current, created])
      setSelectedScenario(created.id)
      setPlan(null)
    } catch (caught) { setError(errorMessage(caught)) }
  }

  async function preview() {
    setBusy(true); setError('')
    try { setPlan(await api.authorizationPlan(selectedScenario)) }
    catch (caught) { setError(errorMessage(caught)) }
    finally { setBusy(false) }
  }

  async function run(rerun: boolean) {
    setBusy(true); setError('')
    try {
      setProbes(await api.runAuthorizationScenario(selectedScenario, rerun))
      setScenarios(await api.authorizationScenarios(targetId))
      setConfirmed(false)
    }
    catch (caught) { setError(errorMessage(caught)) }
    finally {
      setScenarios(await api.authorizationScenarios(targetId).catch(() => scenarios))
      setBusy(false)
    }
  }

  async function suggestRules() {
    setBusy(true); setError('')
    try {
      const suggested = await api.suggestAuthorizationRules(targetId)
      setRules((current) => [...current, ...suggested])
    }
    catch (caught) { setError(errorMessage(caught)) }
    finally { setBusy(false) }
  }

  async function reviewRule(item: AuthorizationRule, status: 'APPROVED' | 'REJECTED') {
    try {
      const updated = await api.setAuthorizationRuleStatus(item.id, status)
      setRules(current => current.map(ruleRow => ruleRow.id === updated.id ? updated : ruleRow))
    } catch (caught) { setError(errorMessage(caught)) }
  }

  return <>
    <PageTitle eyebrow="CONTROLE DE ACESSO" title="Testes de Autorização" description="Compare um baseline legítimo com o mesmo recurso acessado por outro perfil, sem enumerar identificadores."/>
    <div className="info-box"><ShieldCheck size={18}/><p>Somente endpoints locais/autorizados já observados. Apenas GET e HEAD são executados; métodos mutáveis ficam como <strong>NOT_TESTED_MUTATING_METHOD</strong>. HTTP 200 isoladamente não confirma falha.</p></div>
    <ErrorBox message={error}/>
    <section className="panel form-panel auth-target"><label>Alvo<select value={targetId} onChange={(event) => setTargetId(Number(event.target.value))}>{targets.map((target) => <option key={target.id} value={target.id}>{target.name}</option>)}</select></label><button className="button secondary" disabled={busy || !targetId} onClick={() => void suggestRules()}>Sugerir regras</button></section>
    <div className="authz-grid">
      <section className="panel form-panel"><h2><Plus size={17}/> Nova regra de autorização</h2><form onSubmit={(event) => void createRule(event)}><div className="form-grid">
        <label>Nome<input required value={rule.name} onChange={(event) => setRule({...rule, name: event.target.value})}/></label>
        <label>Role<input required value={rule.source_role} onChange={(event) => setRule({...rule, source_role: event.target.value})} placeholder="VIEWER"/></label>
        <label>Método<select value={rule.http_method} onChange={(event) => setRule({...rule, http_method: event.target.value})}>{['GET','HEAD','POST','PUT','PATCH','DELETE'].map((method) => <option key={method}>{method}</option>)}</select></label>
        <label>Expected Access<select value={rule.expected_access} onChange={(event) => setRule({...rule, expected_access: event.target.value as ExpectedAccess})}>{['ALLOW','DENY','CONDITIONAL','UNKNOWN'].map((value) => <option key={value}>{value}</option>)}</select></label>
        <label className="authz-wide">Resource Pattern<input required value={rule.resource_pattern} onChange={(event) => setRule({...rule, resource_pattern: event.target.value})} placeholder="/api/accounts/{id}/settings"/></label>
        <label className="authz-wide">Descrição<textarea value={rule.description} onChange={(event) => setRule({...rule, description: event.target.value})}/></label>
      </div><div className="form-actions"><button className="button" disabled={!targetId}>Salvar regra</button></div></form></section>
      <section className="panel form-panel"><h2><Plus size={17}/> Novo cenário</h2><form onSubmit={(event) => void createScenario(event)}><div className="form-grid">
        <label className="authz-wide">Nome<input required value={scenario.name} onChange={(event) => setScenario({...scenario, name: event.target.value})}/></label>
        <label>Perfil proprietário<select required value={scenario.owner_profile_id} onChange={(event) => setScenario({...scenario, owner_profile_id: Number(event.target.value)})}><option value={0}>Selecione</option>{profiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.name}</option>)}</select></label>
        <label>Perfil de teste<select required value={scenario.test_profile_id} onChange={(event) => setScenario({...scenario, test_profile_id: Number(event.target.value)})}><option value={0}>Selecione</option>{profiles.filter((profile) => profile.id !== scenario.owner_profile_id).map((profile) => <option key={profile.id} value={profile.id}>{profile.name}</option>)}</select></label>
        <label className="authz-wide">Regra APPROVED<select required value={scenario.authorization_rule_id} onChange={(event) => setScenario({...scenario, authorization_rule_id: Number(event.target.value)})}><option value={0}>Selecione</option>{rules.filter(item => item.status === 'APPROVED').map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
      </div><div className="form-actions"><button className="button" disabled={!rules.length || profiles.length < 2}>Salvar cenário</button></div></form></section>
    </div>
    <section className="panel"><h2>Review de regras</h2>{rules.map(item => <div className="module-row" key={item.id}><div><strong>{item.name}</strong><small>{item.suggestion_reason || `${item.http_method} ${item.resource_pattern}`}</small></div><Badge value={item.status}/><div>{item.status === 'SUGGESTED' && <><button className="button secondary" onClick={() => void reviewRule(item, 'APPROVED')}>Approve</button><button className="button secondary" onClick={() => void reviewRule(item, 'REJECTED')}>Reject</button></>}</div></div>)}</section>
    <section className="panel authz-execution"><h2>Authorization Test Plan</h2>{!scenarios.length ? <Empty title="Nenhum cenário configurado" text="Crie uma regra e associe dois perfis diferentes."/> : <>
      <div className="authz-actions"><select value={selectedScenario} onChange={(event) => { setSelectedScenario(Number(event.target.value)); setPlan(null); setConfirmed(false) }}>{scenarios.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select>{selectedScenarioRow && <Badge value={selectedScenarioRow.execution_status}/>}<button className="button secondary" disabled={busy || scenarioRunning} onClick={() => void preview()}><Eye size={16}/> Preview</button><button className="button" disabled={busy || scenarioRunning || !plan || !confirmed} onClick={() => void run(Boolean(scenarioNeedsRerun))}><Play size={16}/> {scenarioNeedsRerun ? 'Executar novamente' : scenarioRunning ? 'Executando…' : 'Executar testes de autorização'}</button></div>
      {plan && <><div className="scan-summary"><div><span>Target</span><strong>{plan.target_name}</strong></div><div><span>Rules approved</span><strong>{plan.rules_approved}</strong></div><div><span>Probes</span><strong>{plan.total_requests}</strong></div><div><span>Methods</span><strong>{plan.methods.join(', ')}</strong></div><div><span>Mutating requests</span><strong>{plan.mutating_requests}</strong></div><div><span>Sensitive endpoints</span><strong>{plan.sensitive_endpoints}</strong></div></div><div className="info-box"><ShieldCheck size={18}/><p><strong>Target: localhost/private</strong><br/>{plan.request_urls.map(url => <code key={url}>{url}<br/></code>)}</p></div><label className="check-label"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)}/> Confirmo a execução explícita dos probes read-only exibidos acima.</label></>}
    </>}</section>
    {probes.length > 0 && <section className="panel"><div className="table-scroll"><table><thead><tr><th>Resultado</th><th>Perfis</th><th>Recurso</th><th>Esperado</th><th>HTTP</th><th>Confidence</th></tr></thead><tbody>{probes.map((probe) => <tr key={probe.id}><td><Badge value={resultBadge(probe.result)}/><small className="authz-result">{probe.result}</small></td><td>{profiles.find((item) => item.id === probe.owner_profile_id)?.name} → {profiles.find((item) => item.id === probe.test_profile_id)?.name}</td><td><MethodBadge method={probe.method}/> <code>{probe.endpoint}</code></td><td>{probe.expected_access}</td><td>{probe.status_code ?? '—'}</td><td>{probe.confidence}</td></tr>)}</tbody></table></div></section>}
  </>
}
