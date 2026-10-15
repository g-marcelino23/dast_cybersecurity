import { afterEach, describe, expect, it, vi } from 'vitest'

import { api } from './api'
import { downloadHtmlReport, downloadReport, downloadSarifReport } from './pages/Scans'
import type { Finding, Scan, Target } from './types'

const scan = {
  id: 59,
  target_id: 6,
  status: 'COMPLETED',
  dast_version: '0.22.0',
  configuration_snapshot: {},
} as Scan

const target = { id: 6, name: 'Laboratório <seguro>' } as Target
const findings = [{
  id: 1,
  scan_id: 59,
  title: 'Entrada <refletida>',
  description: 'Descrição sintética',
  endpoint: 'http://127.0.0.1:8775/reflect',
  severity: 'HIGH',
  confidence: 'HIGH',
  cwe: 'CWE-79',
  recommendation: 'Aplicar escaping.',
  finding_type: 'CONFIRMED_VULNERABILITY',
  status: 'OPEN',
} as Finding]

describe('report exports', () => {
  afterEach(() => vi.restoreAllMocks())

  it('gera JSON, HTML e SARIF com nomes e MIME types corretos', async () => {
    vi.spyOn(api, 'scanEndpoints').mockResolvedValue([])
    vi.spyOn(api, 'discoverySummary').mockResolvedValue({
      scan_id: 59,
      pages: 1,
      api_endpoints: 2,
      forms: 0,
      requests_observed: 3,
      unique_endpoints: 3,
      methods: ['GET'],
    })
    vi.spyOn(api, 'sensitiveData').mockResolvedValue([])
    vi.spyOn(api, 'sensitiveDataSummary').mockResolvedValue({
      scan_id: 59,
      observations: 0,
      endpoints_with_sensitive_data: 0,
      categories_detected: 0,
      health_endpoints: 0,
      authenticated_endpoints: 0,
      categories: [],
    })
    vi.spyOn(api, 'authorizationProbes').mockResolvedValue([])
    vi.spyOn(api, 'authorizationSummary').mockResolvedValue({
      total_probes: 0,
      denied_correctly: 0,
      allowed_correctly: 0,
      confirmed_bypass: 0,
      possible_bypass: 0,
      inconclusive: 0,
      skipped: 0,
      errors: 0,
      privacy_impacting_authorization_failures: 0,
    })
    vi.spyOn(api, 'findingCorrelation').mockResolvedValue({
      unique_issues: 1,
      occurrences: 1,
      affected_endpoints: 1,
    })

    const blobs: Blob[] = []
    vi.stubGlobal('URL', {
      createObjectURL: vi.fn((blob: Blob) => { blobs.push(blob); return 'blob:report' }),
      revokeObjectURL: vi.fn(),
    })
    const downloads: string[] = []
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      downloads.push(this.download)
    })

    await downloadReport(scan, target, findings)
    await downloadHtmlReport(scan, target, findings)
    downloadSarifReport(scan, findings)

    expect(downloads).toEqual([
      'dast-scan-59.json',
      'dast-scan-59.html',
      'dast-scan-59.sarif',
    ])
    expect(blobs.map(blob => blob.type)).toEqual([
      'application/json',
      'text/html;charset=utf-8',
      'application/sarif+json',
    ])
    expect(blobs.every(blob => blob.size > 0)).toBe(true)
  })
})
