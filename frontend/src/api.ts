import type { AccessProfileSurface, AccessSurface, ApiRequestRuntimeValues, ApiRequestTemplate, ApiRequestTemplateInput, AuthenticationTestResult, AuthenticationValidationResult, AuthorizationCandidate, AuthorizationPreview, AuthorizationProbe, AuthorizationRule, AuthorizationRuleStatus, AuthorizationScenario, AuthorizationSummary, AuthorizationTestPlan, AuthProfile, AuthProfileInput, CweCoverage, DiscoveredEndpoint, DiscoverySummary, ExpectedAccess, Finding, FindingCorrelation, FindingStatus, LoginSuggestion, OpenApiImport, OwnershipVerification, PostmanImport, PrivacyAnalysis, ResourceType, RoleComparison, RoleSurfaceSnapshot, Scan, ScanComparison, ScanModule, ScanPreset, ScanSummary, SensitiveDataObservation, SensitiveDataSummary, SensitiveSurface, Target, TargetHealth, TargetInput } from './types'
export const API_URL = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/$/, '')
async function request<T>(path: string, body?: unknown, method?: string): Promise<T> {
  const resolvedMethod = method || (body === undefined ? 'GET' : 'POST')
  const response = await fetch(`${API_URL}${path}`, {
    method: resolvedMethod,
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!response.ok) {
    const data = await response.json().catch(() => ({}))
    const detail = typeof data.detail === 'string'
      ? data.detail
      : typeof data.detail?.message === 'string'
        ? data.detail.message
        : `A solicitação falhou (HTTP ${response.status}). Verifique os campos.`
    throw new Error(detail)
  }
  return response.status === 204 ? undefined as T : response.json() as Promise<T>
}
async function all<T>(path: string): Promise<T[]> {
  const rows: T[] = []
  for (let offset = 0; ; offset += 1000) {
    const page = await request<T[]>(`${path}?limit=1000&offset=${offset}`)
    rows.push(...page)
    if (page.length < 1000) return rows
  }
}
export const api = {
  targets: () => all<Target>('/targets'), scans: () => all<Scan>('/scans'),
  findings: () => all<Finding>('/findings'),
  updateFindingStatus: (id: number, status: FindingStatus) => request<Finding>(`/findings/${id}/status`, { status }, 'PATCH'),
  targetFindings: (id: number) => request<Finding[]>(`/targets/${id}/findings`),
  createTarget: (target: TargetInput) => request<Target>('/targets', target),
  target: (id: number) => request<Target>(`/targets/${id}`),
  ownershipVerification: (id: number) => request<OwnershipVerification>(`/targets/${id}/ownership-verification`),
  verifyOwnership: (id: number) => request<OwnershipVerification>(`/targets/${id}/ownership-verification`, {}),
  importOpenApi: (id: number, content: string, filename?: string) => request<OpenApiImport>(`/targets/${id}/openapi`, { content, filename: filename || null }, 'PUT'),
  deleteOpenApi: (id: number) => request<void>(`/targets/${id}/openapi`, undefined, 'DELETE'),
  importPostman: (id: number, content: string, filename?: string) => request<PostmanImport>(`/targets/${id}/postman`, { content, filename: filename || null }, 'PUT'),
  deletePostman: (id: number) => request<void>(`/targets/${id}/postman`, undefined, 'DELETE'),
  apiRequests: (id: number) => request<ApiRequestTemplate[]>(`/targets/${id}/api-requests`),
  createApiRequest: (id: number, input: ApiRequestTemplateInput) => request<ApiRequestTemplate>(`/targets/${id}/api-requests`, input),
  deleteApiRequest: (targetId: number, requestId: number) => request<void>(`/targets/${targetId}/api-requests/${requestId}`, undefined, 'DELETE'),
  targetHealth: (id: number) => request<TargetHealth>(`/targets/${id}/health`),
  accessSurface: (id: number) => request<AccessSurface>(`/targets/${id}/access-surface`),
  roleComparison: (targetId: number, profileAId: number, profileBId: number) => request<RoleComparison>(`/targets/${targetId}/role-comparison?profile_a_id=${profileAId}&profile_b_id=${profileBId}`),
  authorizationCandidates: (targetId: number) => request<AuthorizationCandidate[]>(`/targets/${targetId}/authorization-candidates`),
  generateAuthorizationCandidates: (targetId: number, profileAId: number, profileBId: number) => request<AuthorizationCandidate[]>(`/targets/${targetId}/authorization-candidates/generate`, { profile_a_id: profileAId, profile_b_id: profileBId }),
  sensitiveSurface: (id: number) => request<SensitiveSurface>(`/targets/${id}/sensitive-surface`),
  cweCoverage: (id: number) => request<CweCoverage>(`/targets/${id}/cwe-coverage`),
  privacyAnalysis: (id: number) => request<PrivacyAnalysis>(`/targets/${id}/privacy-analysis`),
  loginSuggestions: (id: number) => request<LoginSuggestion[]>(`/targets/${id}/login-suggestions`),
  scanModules: () => request<ScanModule[]>('/scanner/modules'),
  createScan: (targetId: number, authProfileId?: number, experimentLabel?: string, preset: ScanPreset = 'PASSIVE', modules?: string[], activeConfirmation = false) => request<Scan>('/scans', { target_id: targetId, auth_profile_id: authProfileId || null, mode: 'DISCOVERY_PASSIVE', experiment_label: experimentLabel || null, preset, modules: modules || null, active_confirmation: activeConfirmation }),
  startScan: (id: number, manualApiValues: ApiRequestRuntimeValues[] = []) => request<Scan>(`/scans/${id}/start`, { manual_api_values: manualApiValues }),
  cancelScan: (id: number) => request<Scan>(`/scans/${id}/cancel`, {}),
  runScan: (id: number, manualApiValues: ApiRequestRuntimeValues[] = []) => request<Scan>(`/scans/${id}/run`, { manual_api_values: manualApiValues }),
  scanEndpoints: (id: number, filters: { method?: string; resourceType?: ResourceType; source?: string } = {}) => {
    const query = new URLSearchParams({ limit: '1000' })
    if (filters.method) query.set('method', filters.method)
    if (filters.resourceType) query.set('resource_type', filters.resourceType)
    if (filters.source) query.set('source', filters.source)
    return request<DiscoveredEndpoint[]>(`/scans/${id}/endpoints?${query}`)
  },
  endpoint: (scanId: number, endpointId: number) => request<DiscoveredEndpoint>(`/scans/${scanId}/endpoints/${endpointId}`),
  discoverySummary: (id: number) => request<DiscoverySummary>(`/scans/${id}/discovery-summary`),
  authProfiles: (targetId: number) => request<AuthProfile[]>(`/targets/${targetId}/auth-profiles`),
  createAuthProfile: (targetId: number, profile: AuthProfileInput) => request<AuthProfile>(`/targets/${targetId}/auth-profiles`, profile),
  updateAuthProfile: (id: number, profile: Partial<AuthProfileInput>) => request<AuthProfile>(`/auth-profiles/${id}`, profile, 'PUT'),
  deleteAuthProfile: (id: number) => request<void>(`/auth-profiles/${id}`, undefined, 'DELETE'),
  testAuthProfile: (id: number) => request<AuthenticationTestResult>(`/auth-profiles/${id}/test`, {}),
  validateAuthProfile: (id: number, credentials: { password?: string; mfaCode?: string; secret?: string }, retainSession = false) => request<AuthenticationValidationResult>(`/auth-profiles/${id}/validation`, { ...(credentials.password ? { password: credentials.password } : {}), ...(credentials.mfaCode ? { mfa_code: credentials.mfaCode } : {}), ...(credentials.secret ? { secret: credentials.secret } : {}), retain_session: retainSession }),
  accessProfileSurface: (id: number) => request<AccessProfileSurface>(`/auth-profiles/${id}/access-profile-surface`),
  roleSurfaceSnapshots: (id: number) => request<RoleSurfaceSnapshot[]>(`/auth-profiles/${id}/role-surface-snapshots`),
  authorizationPreview: (targetId: number, profileId: number) => request<AuthorizationPreview>(`/targets/${targetId}/authorization-preview/${profileId}`),
  scanSummary: (scanId: number) => request<ScanSummary>(`/scans/${scanId}/summary`),
  scanComparison: (targetId: number, baselineScanId: number, currentScanId: number, responseSizeTolerancePercent = 10) => request<ScanComparison>(`/targets/${targetId}/scan-comparison?baseline_scan_id=${baselineScanId}&current_scan_id=${currentScanId}&response_size_tolerance_percent=${responseSizeTolerancePercent}`),
  sensitiveData: (id: number) => request<SensitiveDataObservation[]>(`/scans/${id}/sensitive-data`),
  sensitiveDataSummary: (id: number) => request<SensitiveDataSummary>(`/scans/${id}/sensitive-data-summary`),
  authorizationRules: (targetId: number) => request<AuthorizationRule[]>(`/targets/${targetId}/authorization-rules`),
  createAuthorizationRule: (targetId: number, rule: { name: string; source_role: string; resource_pattern: string; http_method: string; expected_access: ExpectedAccess; description: string | null; enabled: boolean }) => request<AuthorizationRule>(`/targets/${targetId}/authorization-rules`, rule),
  suggestAuthorizationRules: (targetId: number) => request<AuthorizationRule[]>(`/targets/${targetId}/authorization-rule-suggestions`, {}),
  setAuthorizationRuleStatus: (id: number, status: AuthorizationRuleStatus) => request<AuthorizationRule>(`/authorization-rules/${id}/status`, { status }, 'PUT'),
  authorizationScenarios: (targetId: number) => request<AuthorizationScenario[]>(`/targets/${targetId}/authorization-scenarios`),
  createAuthorizationScenario: (targetId: number, scenario: { name: string; owner_profile_id: number; test_profile_id: number; authorization_rule_id: number; enabled: boolean }) => request<AuthorizationScenario>(`/targets/${targetId}/authorization-scenarios`, scenario),
  authorizationPlan: (scenarioId: number) => request<AuthorizationTestPlan>(`/authorization/scenarios/${scenarioId}/plan`),
  runAuthorizationScenario: (scenarioId: number, rerun = false) => request<AuthorizationProbe[]>(`/authorization/scenarios/${scenarioId}/run`, { confirmed: true, rerun }),
  authorizationProbes: (scanId: number) => request<AuthorizationProbe[]>(`/scans/${scanId}/authorization-probes`),
  authorizationSummary: (scanId: number) => request<AuthorizationSummary>(`/scans/${scanId}/authorization-summary`),
  findingCorrelation: (scanId: number) => request<FindingCorrelation>(`/scans/${scanId}/finding-correlation`),
}
export function errorMessage(error: unknown): string {
  return error instanceof TypeError ? 'Não foi possível conectar à API. Verifique o backend e o banco de dados.' : error instanceof Error ? error.message : 'Ocorreu um erro inesperado.'
}
