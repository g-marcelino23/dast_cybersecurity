import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { Layout } from './components/Layout'
import { DataProvider } from './data'
import { Dashboard } from './pages/Dashboard'

function jsonResponse(data: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => data,
  } as Response
}

function renderDashboard() {
  return render(
    <MemoryRouter>
      <DataProvider>
        <Routes>
          <Route element={<Layout/>}>
            <Route index element={<Dashboard/>}/>
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
    renderDashboard()

    expect(screen.getByText('Carregando workspace…')).toBeInTheDocument()
    expect(await screen.findByText('Segurança em perspectiva.')).toBeInTheDocument()
    expect(screen.getByText('API conectada')).toBeInTheDocument()
    expect(fetch).toHaveBeenCalledTimes(3)
  })

  it('mostra um erro acionável quando a API está indisponível', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('connection refused')))
    renderDashboard()

    expect(await screen.findByRole('alert')).toHaveTextContent('Não foi possível conectar à API')
    expect(screen.getByRole('button', { name: 'Tentar novamente' })).toBeInTheDocument()
  })
})
