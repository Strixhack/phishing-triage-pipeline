import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'
import { api } from '../api/client'

const COLORS = { malicious: '#f85149', suspicious: '#e3b341', benign: '#3fb950', pending: '#58a6ff' }

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [cases, setCases] = useState([])
  const [nis2, setNis2] = useState(null)
  const navigate = useNavigate()

  useEffect(() => {
    api.stats().then(setStats).catch(() => {})
    api.listCases({ limit: 8 }).then(r => setCases(r.items)).catch(() => {})
    api.nis2().then(setNis2).catch(() => {})
  }, [])

  const pieData = stats ? [
    { name: 'Malicious',  value: stats.malicious  },
    { name: 'Suspicious', value: stats.suspicious },
    { name: 'Benign',     value: stats.benign     },
    { name: 'Pending',    value: stats.pending    },
  ].filter(d => d.value > 0) : []

  const overdue = nis2?.significant_cases?.filter(c => c.status === 'overdue').length || 0

  return (
    <div>
      <h1 style={{ fontSize: 16, fontWeight: 700, marginBottom: 20, color: 'var(--text)' }}>
        SOC Dashboard
      </h1>

      {/* Stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12, marginBottom: 24 }}>
        {[
          { label: 'Total Cases',  value: stats?.total      ?? '—', color: 'var(--text)' },
          { label: 'Malicious',    value: stats?.malicious  ?? '—', color: '#f85149' },
          { label: 'Suspicious',   value: stats?.suspicious ?? '—', color: '#e3b341' },
          { label: 'NIS2 Overdue', value: overdue,                  color: overdue > 0 ? '#f85149' : 'var(--green)' },
        ].map(({ label, value, color }) => (
          <div key={label} className="card" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 28, fontWeight: 700, color }}>{value}</div>
            <div style={{ color: 'var(--muted)', fontSize: 11, marginTop: 4 }}>{label}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* Verdict chart */}
        <div className="card">
          <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 12, color: 'var(--muted)' }}>
            VERDICT DISTRIBUTION
          </div>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={80}
                     dataKey="value" paddingAngle={3}>
                  {pieData.map((entry) => (
                    <Cell key={entry.name} fill={COLORS[entry.name.toLowerCase()]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', fontSize: 12 }}
                  labelStyle={{ color: 'var(--text)' }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ color: 'var(--muted)', textAlign: 'center', padding: 40 }}>No cases yet</div>
          )}
        </div>

        {/* Recent cases */}
        <div className="card">
          <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 12, color: 'var(--muted)' }}>
            RECENT CASES
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {cases.length === 0 && (
              <div style={{ color: 'var(--muted)' }}>No cases yet. Upload a .eml file.</div>
            )}
            {cases.map(c => (
              <div key={c.id}
                onClick={() => navigate(`/cases/${c.id}`)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  padding: '6px 0', borderBottom: '1px solid var(--border)',
                  cursor: 'pointer',
                }}
              >
                <span className={`badge ${c.verdict}`}>{c.verdict}</span>
                <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 12 }}>
                  {c.subject || '(no subject)'}
                </span>
                <span style={{ color: 'var(--muted)', fontSize: 11, flexShrink: 0 }}>
                  {c.risk_score.toFixed(0)}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
