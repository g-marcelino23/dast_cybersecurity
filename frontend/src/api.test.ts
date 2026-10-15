import { afterEach, describe, expect, it, vi } from 'vitest'

import { api } from './api'

function jsonResponse(data: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => data,
  } as Response
}

describe('API client', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('pagina coleções até receber uma página incompleta', async () => {
    const firstPage = Array.from({ length: 1000 }, (_, id) => ({ id: id + 1 }))
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(firstPage))
      .mockResolvedValueOnce(jsonResponse([{ id: 1001 }]))
    vi.stubGlobal('fetch', fetchMock)

    await expect(api.targets()).resolves.toHaveLength(1001)
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'http://localhost:8000/targets?limit=1000&offset=0',
      expect.any(Object),
    )
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'http://localhost:8000/targets?limit=1000&offset=1000',
      expect.any(Object),
    )
  })

  it('envia os controles de segurança ao criar um Safe Active scan', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ id: 9 }))
    vi.stubGlobal('fetch', fetchMock)

    await api.createScan(4, undefined, 'validação', 'SAFE_ACTIVE', ['open_redirect'], true)

    expect(fetchMock).toHaveBeenCalledWith(
      'http://localhost:8000/scans',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          target_id: 4,
          auth_profile_id: null,
          mode: 'DISCOVERY_PASSIVE',
          experiment_label: 'validação',
          preset: 'SAFE_ACTIVE',
          modules: ['open_redirect'],
          active_confirmation: true,
        }),
      }),
    )
  })

  it('propaga uma mensagem de erro sanitizada da API', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(jsonResponse({ detail: { message: 'Alvo fora do escopo.' } }, 422)),
    )

    await expect(api.createTarget({
      name: 'x',
      base_url: 'https://example.test',
      api_url: null,
      description: null,
      environment: 'LOCAL',
      is_protected_target: false,
      safe_scan_mode: true,
    }))
      .rejects.toThrow('Alvo fora do escopo.')
  })
})
