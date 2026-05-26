import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'

const VERDICTS = ['', 'malicious', 'suspicious', 'benign', 'pending']

export default function CaseList() {
  const [cases, setCases] = useState([])
  const [total, setTotal] = useState(0)
  const [verdict, setVerdict] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  useEffect(() => {
    setLoading(true)
    const params = {}
    if (verdict) params.verdict = verdict
    api.listCases(params)
      .then(r => { setCases(r.items); setTotal(r.total) })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [verdict])

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 20 }}>
        <h1 style={{ fontSize: 16, fontWeight: 700 }}>Cases ({total})</h1>
        <select value={verdict} onChange={e => setVerdict(e.target.value)}>
          {VERDICTS.map(v => (
            <option key={v} value={v}>{v || 'All verdicts'}</option>
          ))}
        </select>
      </div>

      {loading && <div style={{ color: 'var(--muted)' }}>Loading…</div>}

      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border)', color: 'var(--muted)', textAlign: 'left' }}>
            {['Ref', 'Subject', 'Sender', 'SPF/DKIM/DMARC', 'Score', 'Verdict', 'Escalation', 'Detected'].map(h => (
              <th key={h} style={{ padding: '6px 8px', fontWeight: 600 }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {cases.length === 0 && !loading && (
            <tr>
              <td colSpan={8} style={{ color: 'var(--muted)', padding: 24, textAlign: 'center' }}>
                No cases found. Upload a .eml file to get started.
              </td>
            </tr>
          )}
          {cases.map(c => (
            <tr key={c.id}
              onClick={() => navigate(`/cases/${c.id}`)}
              style={{
                borderBottom: '1px solid var(--border)',
                cursor: 'pointer',
                transition: 'background 0.1s',
              }}
              onMouseEnter={e => e.currentTarget.style.background = 'var(--surface)'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
            >
              <td style={{ padding: '7px 8px', color: 'var(--accent)', fontWeight: 600 }}>{c.reference}</td>
              <td style={{ padding: '7px 8px', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {c.subject || '(no subject)'}
              </td>
              <td style={{ padding: '7px 8px', color: 'var(--muted)', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {c.sender}
              </td>
              <td style={{ padding: '7px 8px' }}>
                <AuthPill val={c.spf} /> <AuthPill val={c.dkim} /> <AuthPill val={c.dmarc} />
              </td>
              <td style={{ padding: '7px 8px' }}>
                <ScoreBar score={c.risk_score} />
              </td>
              <td style={{ padding: '7px 8px' }}>
                <span className={`badge ${c.verdict}`}>{c.verdict}</span>
              </td>
              <td style={{ padding: '7px 8px', color: 'var(--muted)' }}>{c.escalation}</td>
              <td style={{ padding: '7px 8px', color: 'var(--muted)', whiteSpace: 'nowrap' }}>
                {new Date(c.detected_at).toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function AuthPill({ val }) {
  const color = val === 'pass' ? 'var(--green)' : val === 'fail' ? 'var(--red)' : 'var(--muted)'
  return <span style={{ color, fontSize: 10, fontWeight: 700 }}>{(val || 'N/A').toUpperCase()}</span>
}

function ScoreBar({ score }) {
  const color = score >= 60 ? 'var(--red)' : score >= 30 ? 'var(--orange)' : 'var(--green)'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <div className="score-bar" style={{ width: 60 }}>
        <div className="score-bar-fill" style={{ width: `${score}%`, background: color }} />
      </div>
      <span style={{ color, fontSize: 11 }}>{score.toFixed(0)}</span>
    </div>
  )
}
