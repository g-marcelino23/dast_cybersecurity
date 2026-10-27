import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api } from './api'
import { Layout } from './components/Layout'
import { DataProvider } from './data'
import { NewScan } from './pages/NewScan'
import { Targets } from './pages/Targets'
import type { Scan, Target } from './types'

function jsonResponse(data: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => data,
  } as Response
}

function renderHome() {
  return render(
    <MemoryRouter>
      <DataProvider>
        <Routes>
          <Route element={<Layout/>}>
            <Route index element={<NewScan/>}/>
          </Route>
        </Routes>
      </DataProvider>
    </MemoryRouter>,
  )
}

const localTarget = {
  id: 1,
  name: 'Portal local',
  base_url: 'http://localhost:5173',
  api_url: 'http://localhost:8001',
  components: [],
  description: 'Alvo autorizado',
  environment: 'LOCAL',
  is_protected_target: false,
  safe_scan_mode: true,
  allowed_hosts: ['localhost'],
  requires_ownership_verification: false,
  ownership_verification_token: null,
  ownership_verified_at: null,
  ownership_verification_expires_at: null,
  ownership_verification_status: 'NOT_REQUIRED',
  openapi_title: null,
  openapi_version: null,
  openapi_operation_count: 0,
  openapi_imported_at: null,
  postman_name: null,
  postman_version: null,
  postman_request_count: 0,
  postman_imported_at: null,
  created_at: '2026-10-20T12:00:00Z',
} as Target

function mockWorkspace(targets: Target[] = []) {
  vi.spyOn(api, 'targets').mockResolvedValue(targets)
  vi.spyOn(api, 'scans').mockResolvedValue([])
  vi.spyOn(api, 'findings').mockResolvedValue([])
}

function renderPage(path: string, element: React.ReactNode) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <DataProvider>
        <Routes>
          <Route element={<Layout/>}>
            <Route path={path.split('?')[0].replace(/^\//, '')} element={element}/>
          </Route>
        </Routes>
      </DataProvider>
    </MemoryRouter>,
  )
}

describe('workspace shell', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('carrega o dashboard quando a API responde', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse([])))
    renderHome()

    expect(screen.getByText('Carregando workspace…')).toBeInTheDocument()
    expect(await screen.findByText('Escaneie uma aplicação pela URL.')).toBeInTheDocument()
    expect(screen.getByText('API conectada')).toBeInTheDocument()
    expect(fetch).toHaveBeenCalledTimes(3)
  })

  it('mostra um erro acionável quando a API está indisponível', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('connection refused')))
    renderHome()

    expect(await screen.findByRole('alert')).toHaveTextContent('Não foi possível conectar à API')
    expect(screen.getByRole('button', { name: 'Tentar novamente' })).toBeInTheDocument()
  })

  it('cadastra a URL e inicia um Safe Active scan em um clique', async () => {
    mockWorkspace()
    const createTarget = vi.spyOn(api, 'createTarget').mockResolvedValue(localTarget)
    const createScan = vi.spyOn(api, 'createScan').mockResolvedValue({ id: 42 } as Scan)
    const startScan = vi.spyOn(api, 'startScan').mockResolvedValue({ id: 42 } as Scan)
    const user = userEvent.setup()

    renderPage('/new-scan', <NewScan/>)

    await user.type(await screen.findByLabelText('URL do site ou aplicação'), 'http://localhost:5173')
    await user.click(screen.getByRole('button', { name: 'Escanear agora' }))

    await waitFor(() => expect(startScan).toHaveBeenCalledWith(42))
    expect(createTarget).toHaveBeenCalledWith(expect.objectContaining({
      name: 'localhost:5173',
      base_url: 'http://localhost:5173',
      safe_scan_mode: true,
    }))
    expect(createScan).toHaveBeenCalledWith(1, undefined, undefined, 'SAFE_ACTIVE', undefined, true)
  })

  it('envia os dados sanitizados ao cadastrar um alvo local', async () => {
    mockWorkspace()
    const createTarget = vi.spyOn(api, 'createTarget').mockResolvedValue(localTarget)
    const user = userEvent.setup()

    renderPage('/targets', <Targets/>)

    await user.click(await screen.findByRole('button', { name: 'Cadastrar aplicação' }))
    await user.type(screen.getByLabelText('Nome da aplicação'), '  Portal local  ')
    await user.type(screen.getByLabelText('URL base'), 'http://localhost:5173')
    await user.type(screen.getByLabelText('Descrição (opcional)'), '  Alvo autorizado  ')
    await user.click(screen.getByRole('button', { name: 'Salvar alvo' }))

    expect(createTarget).toHaveBeenCalledWith(expect.objectContaining({
      name: 'Portal local',
      base_url: 'http://localhost:5173',
      description: 'Alvo autorizado',
      environment: 'LOCAL',
      safe_scan_mode: true,
    }))
  })
})
