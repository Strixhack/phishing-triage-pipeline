import { Routes, Route, NavLink } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import CaseList from './pages/CaseList'
import CaseDetail from './pages/CaseDetail'
import Upload from './pages/Upload'
import NIS2Dashboard from './pages/NIS2Dashboard'
import Campaigns from './pages/Campaigns'

const nav = [
  { to: '/',          label: '▣  Dashboard' },
  { to: '/cases',     label: '⊟  Cases' },
  { to: '/upload',    label: '↑  Upload' },
  { to: '/nis2',      label: '⧖  NIS2' },
  { to: '/campaigns', label: '⬡  Campaigns' },
]

export default function App() {
  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>
      <nav style={{
        width: 180,
        background: 'var(--surface)',
        borderRight: '1px solid var(--border)',
        padding: '20px 0',
        flexShrink: 0,
        display: 'flex',
        flexDirection: 'column',
        gap: 4,
      }}>
        <div style={{ padding: '0 16px 20px', borderBottom: '1px solid var(--border)', marginBottom: 8 }}>
          <div style={{ color: 'var(--accent)', fontWeight: 700, fontSize: 13 }}>⬡ PHISH-TRIAGE</div>
          <div style={{ color: 'var(--muted)', fontSize: 10, marginTop: 2 }}>SOC Analysis Platform v2</div>
        </div>
        {nav.map(({ to, label }) => (
          <NavLink key={to} to={to} end={to === '/'}
            style={({ isActive }) => ({
              display: 'block',
              padding: '7px 16px',
              color: isActive ? 'var(--accent)' : 'var(--muted)',
              borderLeft: isActive ? '2px solid var(--accent)' : '2px solid transparent',
              fontSize: 12,
              transition: 'color 0.15s',
              textDecoration: 'none',
            })}>
            {label}
          </NavLink>
        ))}
      </nav>
      <main style={{ flex: 1, padding: 24, overflow: 'auto' }}>
        <Routes>
          <Route path="/"             element={<Dashboard />} />
          <Route path="/cases"        element={<CaseList />} />
          <Route path="/cases/:id"    element={<CaseDetail />} />
          <Route path="/upload"       element={<Upload />} />
          <Route path="/nis2"         element={<NIS2Dashboard />} />
          <Route path="/campaigns"    element={<Campaigns />} />
        </Routes>
      </main>
    </div>
  )
}
