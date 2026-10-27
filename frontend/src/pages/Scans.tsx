import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  ArrowDown,
  ArrowLeft,
  CheckCircle2,
  ChevronRight,
  Circle,
  Download,
  FileInput,
  FileText,
  Globe2,
  KeyRound,
  Layers3,
  LoaderCircle,
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
  labels,
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

const scanStages = [
  { label: 'Preparação', detail: 'Valida o alvo e prepara o ambiente isolado.', at: 5 },
  { label: 'Descoberta', detail: 'Mapeia páginas, APIs e endpoints acessíveis.', at: 20 },
  { label: 'Análise', detail: 'Verifica respostas, headers e configurações.', at: 55 },
  { label: 'Testes seguros', detail: 'Executa probes controlados sem ações destrutivas.', at: 65 },
  { label: 'Relatório', detail: 'Organiza achados, evidências e recomendações.', at: 82 },
]

function phaseLabel(phase: string) {
  if (phase.startsWith('ACTIVE_')) return 'Executando testes seguros'
  return ({
    PENDING: 'Aguardando início',
    PREPARING: 'Preparando o scan',
    AUTHENTICATING: 'Validando a sessão',
    DISCOVERING: 'Descobrindo a aplicação',
    IMPORTING_API_SPEC: 'Importando a especificação da API',
    IMPORTING_API_COLLECTION: 'Importando a coleção da API',
    IMPORTING_MANUAL_API: 'Preparando endpoints manuais',
    COLLECTING_MANUAL_API: 'Coletando endpoints manuais',
    ANALYZING: 'Analisando respostas',
    ACTIVE_TESTING: 'Executando testes seguros',
    PERSISTING: 'Salvando resultados',
    CANCELLING: 'Cancelando com segurança',
    CANCELLED: 'Scan cancelado',
    FAILED: 'Falha no scan',
    COMPLETED: 'Scan concluído',
  } as Record<string, string>)[phase] || phase.replaceAll('_', ' ')
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

export async function buildHtmlReport(scan: Scan, target: Target | undefined, findings: Finding[]) {
  const report = await buildReport(scan, target, findings)
  const summary = report.executive_summary
  const manualCoverage = manualApiCoverage(scan)
  const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const
  const severityNames: Record<string, string> = {
    CRITICAL: 'Crítica', HIGH: 'Alta', MEDIUM: 'Média', LOW: 'Baixa', INFO: 'Informativa',
  }
  const sortedFindings = [...findings].sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity))
  const highRisk = summary.severity_distribution.CRITICAL + summary.severity_distribution.HIGH
  const riskLabel = summary.severity_distribution.CRITICAL > 0 ? 'Crítico' : summary.severity_distribution.HIGH > 0 ? 'Alto' : summary.severity_distribution.MEDIUM > 0 ? 'Moderado' : 'Baixo'
  const targetName = target?.name || `Aplicação #${scan.target_id}`
  const targetUrl = target?.base_url || 'URL não informada'
  const generatedAt = new Date().toLocaleString('pt-BR')
  const totalSeverity = Math.max(findings.length, 1)
  const severityRows = severityOrder.map(severity => {
    const value = summary.severity_distribution[severity]
    const width = Math.max(value ? 3 : 0, Math.round((value / totalSeverity) * 100))
    return `<div class="severity-row"><span class="severity-name"><i class="dot ${severity.toLowerCase()}"></i>${severityNames[severity]}</span><div class="severity-track"><i class="${severity.toLowerCase()}" style="width:${width}%"></i></div><strong>${value}</strong></div>`
  }).join('')
  const findingIndexRows = sortedFindings.map((finding, index) => `<tr><td>${String(index + 1).padStart(2, '0')}</td><td><a href="#finding-${finding.id}">${escapeHtml(finding.title)}</a><small>${escapeHtml(finding.endpoint)}</small></td><td><span class="severity-pill ${finding.severity.toLowerCase()}">${severityNames[finding.severity]}</span></td><td>${escapeHtml(finding.cwe)}</td><td>${escapeHtml(labels[finding.status] || finding.status)}</td></tr>`).join('')
  const findingDetails = sortedFindings.map((finding, index) => `<article class="finding-detail" id="finding-${finding.id}">
    <div class="finding-title-row"><span class="finding-number">${String(index + 1).padStart(2, '0')}</span><div><span class="severity-pill ${finding.severity.toLowerCase()}">${severityNames[finding.severity]}</span><h3>${escapeHtml(finding.title)}</h3></div><span class="finding-cwe">${escapeHtml(finding.cwe)}</span></div>
    <dl class="finding-meta"><div><dt>Tipo</dt><dd>${escapeHtml(labels[finding.finding_type] || finding.finding_type)}</dd></div><div><dt>Confiança</dt><dd>${escapeHtml(labels[finding.confidence] || finding.confidence)}</dd></div><div><dt>Status</dt><dd>${escapeHtml(labels[finding.status] || finding.status)}</dd></div><div><dt>OWASP</dt><dd>${escapeHtml(finding.owasp_category || 'Sem associação direta')}</dd></div></dl>
    <div class="finding-block"><h4>Descrição</h4><p>${escapeHtml(finding.description)}</p></div>
    <div class="finding-block"><h4>Endpoint afetado</h4><code>${escapeHtml(finding.endpoint)}</code></div>
    <div class="finding-columns"><div class="finding-block evidence"><h4>Evidência sanitizada</h4><pre>${escapeHtml(finding.evidence || 'Nenhuma evidência textual registrada.')}</pre></div><div class="finding-block recommendation"><h4>Recomendação</h4><p>${escapeHtml(finding.recommendation)}</p></div></div>
  </article>`).join('')
  const manualCoverageHtml = manualCoverage && manualCoverage.imported > 0
    ? `<section class="report-section"><div class="section-heading"><span>05</span><div><h2>Cobertura da API manual</h2><p>Resumo dos templates importados e das requisições efetivamente coletadas.</p></div></div><div class="metric-grid compact"><div class="metric"><span>Templates</span><strong>${manualCoverage.imported}</strong></div><div class="metric"><span>Elegíveis</span><strong>${manualCoverage.eligible}</strong></div><div class="metric"><span>Executados</span><strong>${manualCoverage.requestsSent}</strong></div><div class="metric"><span>Respostas</span><strong>${manualCoverage.responsesCollected}</strong></div></div><p class="note">A DAST ignorou com segurança ${manualCoverage.skippedUnsafeMethods} método(s) mutável(is), ${manualCoverage.skippedPathTemplates} rota(s) sem valores de path e ${manualCoverage.skippedWithoutAuth} endpoint(s) sem autenticação disponível. Orçamento: ${manualCoverage.requestBudget} requisições.</p></section>`
    : ''
  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Relatório DAST #${scan.id} - ${escapeHtml(targetName)}</title><style>
  :root{--ink:#101828;--text:#344054;--muted:#667085;--line:#e4e7ec;--soft:#f8fafc;--blue:#2563eb;--green:#079455;--critical:#c11574;--high:#d92d20;--medium:#dc6803;--low:#175cd3;--info:#087e8b;font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#344054;background:#eef2f6;font-synthesis:none}
  *{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:#eef2f6;color:var(--text);font-size:13px;line-height:1.55}.print-toolbar{position:sticky;top:0;z-index:10;display:flex;justify-content:flex-end;padding:12px max(20px,calc((100vw - 1080px)/2));background:#101828}.print-toolbar button{border:0;border-radius:7px;background:#fff;color:#101828;padding:10px 15px;font-weight:700;cursor:pointer}.report{width:min(1080px,calc(100% - 32px));margin:28px auto;background:#fff;box-shadow:0 18px 50px rgba(16,24,40,.12)}
  .report-header{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:24px 34px;border-bottom:1px solid var(--line)}.brand{display:flex;align-items:center;gap:12px}.brand-mark{width:38px;height:38px;border-radius:10px;display:grid;place-items:center;background:#eff6ff;color:var(--blue);font-weight:800}.brand strong{display:block;color:var(--ink);font-size:17px}.brand small{display:block;color:var(--muted);font-size:9px;letter-spacing:.9px}.report-id{text-align:right}.report-id strong{display:block;color:var(--ink)}.report-id span{font-size:11px;color:var(--muted)}
  .cover{padding:48px 34px 38px;background:linear-gradient(135deg,#f8fbff 0%,#fff 58%);border-bottom:1px solid var(--line)}.cover-kicker{color:var(--blue);font-size:10px;font-weight:800;letter-spacing:1.8px}.cover h1{max-width:760px;margin:12px 0 10px;color:var(--ink);font-size:37px;line-height:1.12;letter-spacing:-1.4px}.cover>p{max-width:760px;margin:0;color:var(--muted);font-size:15px}.cover-meta{display:grid;grid-template-columns:2fr 1fr 1fr;gap:18px;margin-top:34px;padding-top:24px;border-top:1px solid var(--line)}.cover-meta span{display:block;color:var(--muted);font-size:9px;text-transform:uppercase;letter-spacing:.8px}.cover-meta strong,.cover-meta code{display:block;margin-top:6px;color:var(--ink);font-size:12px;overflow-wrap:anywhere}
  .report-body{padding:10px 34px 38px}.report-section{padding:30px 0;border-bottom:1px solid var(--line)}.section-heading{display:flex;align-items:flex-start;gap:14px;margin-bottom:20px}.section-heading>span{display:grid;place-items:center;width:28px;height:28px;border-radius:7px;background:#eff6ff;color:var(--blue);font-size:10px;font-weight:800}.section-heading h2{margin:0;color:var(--ink);font-size:20px;letter-spacing:-.4px}.section-heading p{margin:4px 0 0;color:var(--muted);font-size:11px}
  .risk-banner{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:18px 20px;border:1px solid #dbeafe;border-radius:10px;background:#f5f9ff;margin-bottom:18px}.risk-banner span{color:var(--muted);font-size:10px}.risk-banner strong{display:block;margin-top:3px;color:var(--ink);font-size:21px}.risk-level{padding:7px 12px;border-radius:999px;background:#fff;border:1px solid #bfdbfe;color:#1d4ed8!important;font-size:11px!important}
  .metric-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.metric{padding:16px;border:1px solid var(--line);border-radius:9px;background:#fff}.metric span{display:block;color:var(--muted);font-size:10px}.metric strong{display:block;margin-top:7px;color:var(--ink);font-size:25px}.metric-grid.compact .metric strong{font-size:20px}
  .summary-columns{display:grid;grid-template-columns:1fr 1fr;gap:28px}.severity-row{display:grid;grid-template-columns:100px minmax(80px,1fr) 24px;gap:10px;align-items:center;margin:13px 0}.severity-name{display:flex;align-items:center;gap:7px;font-size:11px}.dot{width:8px;height:8px;border-radius:50%}.severity-track{height:7px;border-radius:9px;background:#eef1f5;overflow:hidden}.severity-track i{display:block;height:100%;border-radius:9px}.critical{background:var(--critical)}.high{background:var(--high)}.medium{background:var(--medium)}.low{background:var(--low)}.info{background:var(--info)}.severity-row strong{font-size:11px;color:var(--ink);text-align:right}.scope-list{margin:0;padding:0;list-style:none}.scope-list li{display:flex;justify-content:space-between;gap:16px;padding:10px 0;border-bottom:1px solid #eef1f5}.scope-list li:last-child{border-bottom:0}.scope-list span{color:var(--muted);font-size:10px}.scope-list strong{color:var(--ink);font-size:11px;text-align:right}
  table{width:100%;border-collapse:collapse}th{padding:10px 12px;background:var(--soft);border:1px solid var(--line);color:var(--muted);font-size:9px;text-align:left;text-transform:uppercase;letter-spacing:.5px}td{padding:12px;border:1px solid var(--line);vertical-align:top;font-size:10px}td:first-child{width:34px;color:var(--muted)}td a{color:var(--ink);font-weight:700;text-decoration:none}td small{display:block;margin-top:4px;max-width:380px;color:var(--muted);overflow-wrap:anywhere}.severity-pill{display:inline-flex;border-radius:999px;padding:4px 8px;color:#fff;font-size:9px;font-weight:700}.severity-pill.critical{background:var(--critical)}.severity-pill.high{background:var(--high)}.severity-pill.medium{background:var(--medium)}.severity-pill.low{background:var(--low)}.severity-pill.info{background:var(--info)}
  .finding-detail{padding:22px 0;border-bottom:1px solid var(--line);page-break-inside:avoid}.finding-detail:last-child{border-bottom:0}.finding-title-row{display:grid;grid-template-columns:36px minmax(0,1fr) auto;gap:13px;align-items:start}.finding-number{display:grid;place-items:center;width:32px;height:32px;border-radius:8px;background:#f2f4f7;color:#475467;font-weight:800}.finding-title-row h3{margin:7px 0 0;color:var(--ink);font-size:17px}.finding-cwe{color:#475467;background:#f2f4f7;border-radius:6px;padding:5px 8px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:10px}.finding-meta{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:18px 0}.finding-meta>div{padding:10px 12px;border:1px solid var(--line);border-radius:7px}.finding-meta dt{color:var(--muted);font-size:8px;text-transform:uppercase;letter-spacing:.6px}.finding-meta dd{margin:4px 0 0;color:var(--ink);font-size:10px}.finding-block{margin-top:14px}.finding-block h4{margin:0 0 7px;color:var(--ink);font-size:10px;text-transform:uppercase;letter-spacing:.5px}.finding-block p{margin:0;color:#475467}.finding-block code,.finding-block pre{display:block;margin:0;padding:12px;border:1px solid var(--line);border-radius:7px;background:var(--soft);color:#344054;font:10px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}.finding-columns{display:grid;grid-template-columns:1fr 1fr;gap:14px}.recommendation{padding:13px;border-radius:8px;background:#f0fdf4;border:1px solid #bbf7d0}.recommendation h4{color:#067647}.note{padding:14px 16px;border-left:3px solid var(--blue);background:#f8fafc;color:#475467;font-size:11px}.methodology{display:grid;grid-template-columns:1fr 1fr;gap:22px}.methodology ul{margin:0;padding-left:18px}.methodology li{margin:7px 0;color:#475467}.limitations{background:#fffaeb;border:1px solid #fedf89;border-radius:9px;padding:16px}.limitations strong{color:#93370d}.limitations ul{margin:9px 0 0;padding-left:18px}.report-footer{display:flex;justify-content:space-between;gap:16px;padding:20px 34px;background:#101828;color:#d0d5dd;font-size:9px}.report-footer strong{color:#fff}
  @media(max-width:760px){.report{width:100%;margin:0;box-shadow:none}.print-toolbar{position:static}.cover,.report-body,.report-header{padding-left:20px;padding-right:20px}.cover h1{font-size:30px}.cover-meta,.metric-grid,.summary-columns,.finding-meta,.finding-columns,.methodology{grid-template-columns:1fr}.report-header{align-items:flex-start}.report-id{display:none}.severity-row{grid-template-columns:90px 1fr 22px}.finding-title-row{grid-template-columns:34px 1fr}.finding-cwe{grid-column:2}}
  @page{size:A4;margin:14mm}@media print{body{background:#fff;font-size:10px}.print-toolbar{display:none}.report{width:100%;margin:0;box-shadow:none}.report-header{padding-top:0}.cover{padding-top:28px}.report-section{page-break-inside:auto}.finding-detail{page-break-inside:avoid}.report-footer{background:#fff;color:#667085;border-top:1px solid var(--line)}.report-footer strong{color:#101828}a{color:inherit!important;text-decoration:none!important}}
  </style></head><body><div class="print-toolbar"><button onclick="window.print()">Imprimir ou salvar em PDF</button></div><main class="report">
  <header class="report-header"><div class="brand"><span class="brand-mark">D</span><div><strong>DAST</strong><small>DYNAMIC APPLICATION SECURITY TESTING</small></div></div><div class="report-id"><strong>Relatório de segurança</strong><span>SCN-${String(scan.id).padStart(4, '0')}</span></div></header>
  <section class="cover"><span class="cover-kicker">RELATÓRIO TÉCNICO</span><h1>Análise dinâmica de segurança</h1><p>Resultados do escaneamento da aplicação, com evidências sanitizadas e recomendações para tratamento dos achados.</p><div class="cover-meta"><div><span>Aplicação analisada</span><strong>${escapeHtml(targetName)}</strong><code>${escapeHtml(targetUrl)}</code></div><div><span>Scan</span><strong>#${scan.id}</strong><code>${escapeHtml(scan.preset || 'SAFE_ACTIVE')}</code></div><div><span>Gerado em</span><strong>${escapeHtml(generatedAt)}</strong><code>DAST v${escapeHtml(scan.dast_version)}</code></div></div></section>
  <div class="report-body">
    <section class="report-section"><div class="section-heading"><span>01</span><div><h2>Resumo executivo</h2><p>Visão geral da superfície analisada e da criticidade dos resultados.</p></div></div><div class="risk-banner"><div><span>Classificação geral</span><strong>Risco ${riskLabel.toLowerCase()}</strong></div><span class="risk-level">${riskLabel}</span></div><div class="metric-grid"><div class="metric"><span>Issues únicos</span><strong>${summary.unique_issues}</strong></div><div class="metric"><span>Ocorrências</span><strong>${summary.occurrences}</strong></div><div class="metric"><span>Endpoints afetados</span><strong>${summary.affected_endpoints}</strong></div><div class="metric"><span>Alta e crítica</span><strong>${highRisk}</strong></div></div></section>
    <section class="report-section"><div class="section-heading"><span>02</span><div><h2>Distribuição e cobertura</h2><p>Severidades identificadas e alcance observado durante a execução.</p></div></div><div class="summary-columns"><div>${severityRows}</div><ul class="scope-list"><li><span>Páginas</span><strong>${report.discovery.pages}</strong></li><li><span>Endpoints de API</span><strong>${report.discovery.api_endpoints}</strong></li><li><span>Formulários</span><strong>${report.discovery.forms}</strong></li><li><span>Requisições observadas</span><strong>${report.discovery.requests_observed}</strong></li><li><span>Perfil do scan</span><strong>${escapeHtml(scan.preset)}</strong></li><li><span>Status</span><strong>${escapeHtml(labels[scan.status] || scan.status)}</strong></li></ul></div></section>
    <section class="report-section"><div class="section-heading"><span>03</span><div><h2>Índice de achados</h2><p>Lista priorizada para triagem e acompanhamento da correção.</p></div></div>${sortedFindings.length ? `<table><thead><tr><th>#</th><th>Achado</th><th>Severidade</th><th>CWE</th><th>Status</th></tr></thead><tbody>${findingIndexRows}</tbody></table>` : '<p class="note">Nenhum achado foi registrado neste scan. A ausência de achados não comprova a ausência de vulnerabilidades.</p>'}</section>
    ${sortedFindings.length ? `<section class="report-section"><div class="section-heading"><span>04</span><div><h2>Detalhamento técnico</h2><p>Evidências sanitizadas e orientações de correção por achado.</p></div></div>${findingDetails}</section>` : ''}
    ${manualCoverageHtml}
    <section class="report-section"><div class="section-heading"><span>${manualCoverage && manualCoverage.imported > 0 ? '06' : '05'}</span><div><h2>Metodologia e limitações</h2><p>Premissas usadas para interpretar os resultados deste documento.</p></div></div><div class="methodology"><div><h3>Metodologia</h3><ul><li>Descoberta da superfície autorizada.</li><li>Análise passiva de respostas e configurações.</li><li>Safe Active limitado a GET, HEAD e OPTIONS.</li><li>Evidências sanitizadas antes da persistência.</li></ul></div><div class="limitations"><strong>Limitações da análise</strong><ul>${report.limitations.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul></div></div></section>
  </div><footer class="report-footer"><span><strong>DAST</strong> · Relatório técnico de segurança</span><span>SCN-${String(scan.id).padStart(4, '0')} · ${escapeHtml(generatedAt)}</span></footer></main></body></html>`
}

export async function downloadHtmlReport(scan: Scan, target: Target | undefined, findings: Finding[]) {
  const html = await buildHtmlReport(scan, target, findings)
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
  const [selectedFindingId, setSelectedFindingId] = useState<number | null>(null)
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

  useEffect(() => {
    const scanFindings = findings.filter((finding) => finding.scan_id === scanId)
    if (!scanFindings.length) {
      if (selectedFindingId !== null) setSelectedFindingId(null)
      return
    }
    if (!scanFindings.some((finding) => finding.id === selectedFindingId)) {
      setSelectedFindingId(scanFindings[0].id)
    }
  }, [findings, scanId, selectedFindingId])

  if (!scan) return <Empty title="Scan não encontrado" />
  const target = targets.find((item) => item.id === scan.target_id)
  const apiCoverage = manualApiCoverage(scan)
  const items = findings.filter((finding) => finding.scan_id === scan.id)
  const selectedFinding = items.find((finding) => finding.id === selectedFindingId) || items[0]
  const progress = scan.status === 'COMPLETED' ? 100 : Math.max(0, Math.min(100, scan.progress_percent))
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
        description="Acompanhe o progresso, os achados e as evidências em tempo real."
        action={<div className="report-actions"><button className="button secondary" disabled={!['COMPLETED', 'FAILED'].includes(scan.status)} onClick={() => void downloadReport(scan, target, items)}><Download size={16}/> JSON</button><button className="button secondary" disabled={!['COMPLETED', 'FAILED'].includes(scan.status)} onClick={() => void downloadHtmlReport(scan, target, items)}><FileText size={16}/> Relatório</button><button className="button secondary" disabled={!['COMPLETED', 'FAILED'].includes(scan.status)} onClick={() => downloadSarifReport(scan, items)}><Download size={16}/> SARIF</button></div>}
      />
      <ErrorBox message={error || scan.error_message || ''} />
      <section className="scan-workbench">
        <article className="panel scan-workbench-progress">
          <div className="workbench-heading">
            <div>
              <span>PROGRESSO DO SCAN</span>
              <h2>{phaseLabel(scan.phase)}</h2>
            </div>
            <Badge value={busy ? 'RUNNING' : scan.status}/>
          </div>
          <div className="workbench-progress-summary">
            <strong>{progress}%</strong>
            <div className="progress-track" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={progress}>
              <span style={{ width: `${progress}%` }}/>
            </div>
          </div>
          <div className="scan-stage-list">
            {scanStages.map((stage, index) => {
              const next = scanStages[index + 1]
              const complete = scan.status === 'COMPLETED' || (next ? progress >= next.at : progress >= 100)
              const active = !complete && progress >= stage.at
              return <div className={`scan-stage ${complete ? 'complete' : active ? 'active' : ''}`} key={stage.label}>
                <span className="scan-stage-icon">
                  {complete ? <CheckCircle2 size={19}/> : active ? <LoaderCircle className="spin" size={19}/> : <Circle size={19}/>}
                </span>
                <div><strong>{stage.label}</strong><small>{stage.detail}</small></div>
                <span>{complete ? 'Concluído' : active ? 'Em andamento' : 'Aguardando'}</span>
              </div>
            })}
          </div>
          <div className="workbench-meta">
            <span>Início <strong>{date(scan.started_at)}</strong></span>
            <span>Endpoints <strong>{summary?.unique_endpoints ?? endpoints.length}</strong></span>
            <span>Achados <strong>{items.length}</strong></span>
          </div>
          {['PENDING', 'RUNNING'].includes(scan.status) && <button className="button secondary workbench-cancel" disabled={busy || scan.cancellation_requested} onClick={() => void cancel()}><Square size={14}/> {scan.cancellation_requested ? 'Cancelamento solicitado' : 'Cancelar scan'}</button>}
        </article>

        <article className="panel scan-workbench-findings">
          <div className="workbench-heading">
            <div><span>ACHADOS</span><h2>{items.length} encontrados</h2></div>
            <a className="text-link" href="#scan-findings">Ver todos</a>
          </div>
          <div className="live-findings-list">
            {items.slice(0, 6).map((finding) => <button
              type="button"
              className={finding.id === selectedFinding?.id ? 'live-finding selected' : 'live-finding'}
              key={finding.id}
              aria-pressed={finding.id === selectedFinding?.id}
              onClick={() => setSelectedFindingId(finding.id)}
            >
              <Badge value={finding.severity}/>
              <span><strong>{finding.title}</strong><code>{finding.endpoint}</code></span>
              <ChevronRight size={17}/>
            </button>)}
            {!items.length && <div className="live-findings-empty"><LoaderCircle className={scan.status === 'RUNNING' ? 'spin' : ''} size={22}/><strong>Nenhum achado até agora</strong><small>{scan.status === 'RUNNING' ? 'Os resultados aparecerão aqui durante a análise.' : 'Este scan não registrou vulnerabilidades.'}</small></div>}
          </div>
        </article>

        <article className="panel scan-workbench-evidence">
          <div className="workbench-heading">
            <div><span>EVIDÊNCIA DO ACHADO</span><h2>{selectedFinding?.title || 'Selecione um achado'}</h2></div>
            {selectedFinding && <Link className="button secondary" to={`/findings/${selectedFinding.id}`}>Abrir detalhes <ChevronRight size={15}/></Link>}
          </div>
          {selectedFinding ? <div className="evidence-grid">
            <section>
              <div className="evidence-label"><span>Evidência coletada</span><Badge value={selectedFinding.severity}/></div>
              <code className="evidence-endpoint">{selectedFinding.endpoint}</code>
              <pre>{selectedFinding.evidence || selectedFinding.description}</pre>
            </section>
            <section>
              <div className="evidence-label"><span>Como corrigir</span><span className="subtle-tag">{selectedFinding.cwe}</span></div>
              <p>{selectedFinding.recommendation}</p>
            </section>
          </div> : <div className="evidence-placeholder"><ShieldAlert size={25}/><p>Quando a DAST identificar um achado, a evidência sanitizada e a recomendação aparecerão aqui.</p></div>}
        </article>
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
      <section className="panel findings-section" id="scan-findings">
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
