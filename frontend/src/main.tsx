import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { DataProvider } from './data'
import { Layout } from './components/Layout'
import { Empty } from './components/ui'
import { Dashboard } from './pages/Dashboard'
import { Targets } from './pages/Targets'
import { NewScan } from './pages/NewScan'
import { EndpointDetail, Scans, ScanDetail } from './pages/Scans'
import { Findings, FindingDetail } from './pages/Findings'
import { Reports, Settings } from './pages/Support'
import { AuthProfiles } from './pages/AuthProfiles'
import { AuthorizationTesting } from './pages/AuthorizationTesting'
import { TargetOverview } from './pages/TargetOverview'
import './styles.css'
ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode><BrowserRouter><DataProvider><Routes><Route element={<Layout/>}>
    <Route index element={<Dashboard/>}/><Route path="targets" element={<Targets/>}/><Route path="targets/:id" element={<TargetOverview/>}/><Route path="auth-profiles" element={<AuthProfiles/>}/><Route path="authorization" element={<AuthorizationTesting/>}/><Route path="new-scan" element={<NewScan/>}/><Route path="scans" element={<Scans/>}/><Route path="scans/:id" element={<ScanDetail/>}/><Route path="scans/:scanId/endpoints/:endpointId" element={<EndpointDetail/>}/><Route path="findings" element={<Findings/>}/><Route path="findings/:id" element={<FindingDetail/>}/><Route path="reports" element={<Reports/>}/><Route path="settings" element={<Settings/>}/><Route path="*" element={<Empty title="Página não encontrada"/>}/>
  </Route></Routes></DataProvider></BrowserRouter></React.StrictMode>,
)
