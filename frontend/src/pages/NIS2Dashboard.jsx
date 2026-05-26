import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'

const STATUS_META = {
  overdue:           { label: 'OVERDUE',          color: 'var(--red)'    },
  early_warning_due: { label: '24H DUE',           color: 'var(--orange)' },
  approaching:       { label: 'APPROACHING 72H',   color: 'var(--orange)' },
  on_track:          { label: 'ON TRACK',           color: 'var(--green)'  },
  notified:          { label: 'NOTIFIED',           color: 'var(--muted)'  },
}

export default function NIS2Dashboard() {
  const [data, setData] = useState(null)
  const navigate = useNavigate()

  useEffect(() => {
    api.nis2().then(setData).catch(() => {})
    const t = setInterval(() => api.nis2().then(setData).catch(() => {}), 30_000)
    return () => clearInterval(t)
  }, [])

  const cases = data?.significant_cases || []
  const overdue = cases.filter(c => c.status === 'overdue').length

  return (
    <div>
      <h1 style={{ fontSize: 16, fontWeight: 700, marginBottom: 4 }}>NIS2 Compliance</h1>
      <p style={{ color: 'var(--muted)', fontSize: 12, marginBottom: 20 }}>
        Article 23 — Early warning: 24h · Incident notification: 72h · Refreshes every 30s
      </p>

      {/* Summary */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12, marginBottom: 24 }}>
        {[
          { label: 'Significant Cases', value: cases.length, color: 'var(--text)' },
          { label: 'Overdue',           value: overdue,      color: overdue > 0 ? 'var(--red)' : 'var(--green)' },
          { label: 'Notified',          value: cases.filter(c => c.notified).length, color: 'var(--green)' },
        ].map(({ label, value, color }) => (
          <div key={label} className="card" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 28, fontWeight: 700, color }}>{value}</div>
            <div style={{ color: 'var(--muted)', fontSize: 11, marginTop: 4 }}>{label}</div>
          </div>
        ))}
      </div>

      {/* NIS2 explanation */}
      <div className="card" style={{ marginBottom: 20, borderColor: 'var(--border)' }}>
        <div style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 600, marginBottom: 8 }}>
          WHAT COUNTS AS A SIGNIFICANT INCIDENT?
        </div>
        <p style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.7 }}>
          Under NIS2 (EU 2022/2555), a significant incident must be reported if it causes
          severe disruption to services or financial loss, or affects other organisations.
          In this pipeline, any case with verdict <span style={{ color: 'var(--red)' }}>MALICIOUS</span> or
          risk score ≥ 55 triggers NIS2 timers automatically.
        </p>
      </div>

      {/* Cases table */}
      <div className="card">
        <div style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 600, marginBottom: 12 }}>
          SIGNIFICANT CASES — sorted by urgency
        </div>
        {cases.length === 0 ? (
          <div style={{ color: 'var(--muted)' }}>No significant incidents. Good news.</div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>
                {['Ref','Score','Verdict','NIS2 Status','72h Deadline','Hours Left','Notified'].map(h => (
                  <th key={h} style={{ padding: '5px 8px', textAlign: 'left', fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {cases.map(c => {
                const meta = STATUS_META[c.status] || STATUS_META.on_track
                return (
                  <tr key={c.case_id}
                    onClick={() => navigate(`/cases/${c.case_id}`)}
                    style={{ borderBottom: '1px solid var(--border)', cursor: 'pointer' }}
                    onMouseEnter={e => e.currentTarget.style.background = 'var(--surface)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                  >
                    <td style={{ padding: '6px 8px', color: 'var(--accent)', fontWeight: 600 }}>{c.reference}</td>
                    <td style={{ padding: '6px 8px' }}>{c.risk_score.toFixed(0)}</td>
                    <td style={{ padding: '6px 8px' }}>
                      <span className={`badge ${c.verdict}`}>{c.verdict}</span>
                    </td>
                    <td style={{ padding: '6px 8px', color: meta.color, fontWeight: 600 }}>{meta.label}</td>
                    <td style={{ padding: '6px 8px', color: 'var(--muted)' }}>
                      {new Date(c.notification_due).toLocaleString()}
                    </td>
                    <td style={{ padding: '6px 8px', color: meta.color }}>
                      {c.hours_until_notification.toFixed(1)}h
                    </td>
                    <td style={{ padding: '6px 8px', color: c.notified ? 'var(--green)' : 'var(--muted)' }}>
                      {c.notified ? '✓' : '—'}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
