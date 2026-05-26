import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { api } from '../api/client'

export default function CaseDetail() {
  const { id } = useParams()
  const [c, setCase] = useState(null)
  const [note, setNote] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)

  const load = () => api.getCase(id).then(data => { setCase(data); setNote(data.analyst_note || '') })
  useEffect(() => { load() }, [id])

  async function act(updates) {
    setSaving(true)
    setError(null)
    try {
      await api.updateCase(id, { ...updates, actor: 'analyst' })
      await load()
    } catch (e) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  if (!c) return <div style={{ color: 'var(--muted)' }}>Loading…</div>

  const { nis2 } = c
  const nis2Color = {
    overdue: 'var(--red)',
    early_warning_due: 'var(--orange)',
    approaching: 'var(--orange)',
    on_track: 'var(--green)',
    notified: 'var(--green)',
    not_applicable: 'var(--muted)',
  }[nis2?.status] || 'var(--muted)'

  return (
    <div style={{ maxWidth: 900 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 20 }}>
        <h1 style={{ fontSize: 16, fontWeight: 700 }}>{c.reference}</h1>
        <span className={`badge ${c.verdict}`}>{c.verdict}</span>
        <span style={{ color: 'var(--muted)', fontSize: 12 }}>Escalation: {c.escalation}</span>
        {c.thehive_case_id && (
          <span style={{ color: 'var(--accent)', fontSize: 11 }}>TheHive: {c.thehive_case_id}</span>
        )}
      </div>

      {error && <div style={{ color: 'var(--red)', marginBottom: 12 }}>✗ {error}</div>}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
        {/* Email metadata */}
        <div className="card">
          <div style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 600, marginBottom: 10 }}>EMAIL METADATA</div>
          <MetaRow label="Subject" value={c.subject} />
          <MetaRow label="From"    value={c.sender} />
          <MetaRow label="To"      value={c.recipient} />
          <MetaRow label="SPF"     value={c.spf}  color={authColor(c.spf)} />
          <MetaRow label="DKIM"    value={c.dkim} color={authColor(c.dkim)} />
          <MetaRow label="DMARC"   value={c.dmarc} color={authColor(c.dmarc)} />
          <MetaRow label="Risk Score" value={`${c.risk_score}/100`} />
        </div>

        {/* NIS2 status */}
        <div className="card" style={{ borderColor: nis2?.is_significant ? nis2Color : 'var(--border)' }}>
          <div style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 600, marginBottom: 10 }}>NIS2 STATUS</div>
          <MetaRow label="Significant"     value={nis2?.is_significant ? 'YES' : 'No'} color={nis2?.is_significant ? 'var(--orange)' : undefined} />
          <MetaRow label="Status"          value={nis2?.status?.replace(/_/g,' ').toUpperCase()} color={nis2Color} />
          <MetaRow label="24h deadline"    value={fmt(nis2?.early_warning_due)} />
          <MetaRow label="72h deadline"    value={fmt(nis2?.notification_due)} />
          <MetaRow label="Hours remaining" value={`${nis2?.hours_until_notification}h`} color={nis2Color} />
          {nis2?.is_significant && !c.notified_at && (
            <button style={{ marginTop: 12 }} onClick={() => act({ mark_notified: true })} disabled={saving}>
              ✓ Mark as Notified
            </button>
          )}
          {c.notified_at && (
            <div style={{ color: 'var(--green)', marginTop: 10, fontSize: 12 }}>
              ✓ Notified at {new Date(c.notified_at).toLocaleString()}
            </div>
          )}
        </div>
      </div>

      {/* Analyst actions */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 600, marginBottom: 12 }}>ANALYST ACTIONS</div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
          {['benign','suspicious','malicious'].map(v => (
            <button key={v} onClick={() => act({ verdict: v })} disabled={saving}
              style={{ borderColor: c.verdict === v ? 'var(--accent)' : undefined }}>
              {v}
            </button>
          ))}
          <div style={{ width: 1, background: 'var(--border)' }} />
          {['L1','L2','CISO','closed'].map(e => (
            <button key={e} onClick={() => act({ escalation: e })} disabled={saving}
              style={{ borderColor: c.escalation === e ? 'var(--accent)' : undefined }}>
              {e}
            </button>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <textarea
            value={note}
            onChange={e => setNote(e.target.value)}
            placeholder="Analyst note…"
            rows={2}
            style={{ flex: 1, resize: 'vertical' }}
          />
          <button className="primary" onClick={() => act({ analyst_note: note })} disabled={saving}>
            Save
          </button>
        </div>
      </div>

      {/* IOCs */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 600, marginBottom: 10 }}>
          IOCs ({c.iocs?.length || 0})
        </div>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)', color: 'var(--muted)' }}>
              {['Type','Value','VT','AbuseIPDB','MISP','Risk'].map(h => (
                <th key={h} style={{ padding: '4px 8px', textAlign: 'left', fontWeight: 600 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {(c.iocs || []).map(ioc => (
              <tr key={ioc.id} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '4px 8px', color: 'var(--accent)' }}>{ioc.type}</td>
                <td style={{ padding: '4px 8px', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {ioc.value}
                </td>
                <td style={{ padding: '4px 8px', color: scoreColor(ioc.vt_score != null ? ioc.vt_score * 100 : null) }}>
                  {ioc.vt_score != null ? `${(ioc.vt_score * 100).toFixed(0)}%` : '—'}
                </td>
                <td style={{ padding: '4px 8px', color: scoreColor(ioc.abuseipdb_score) }}>
                  {ioc.abuseipdb_score != null ? ioc.abuseipdb_score.toFixed(0) : '—'}
                </td>
                <td style={{ padding: '4px 8px', color: ioc.misp_hits > 0 ? 'var(--red)' : 'var(--muted)' }}>
                  {ioc.misp_hits}
                </td>
                <td style={{ padding: '4px 8px', color: scoreColor(ioc.risk_score) }}>
                  {ioc.risk_score.toFixed(0)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Audit log */}
      <div className="card">
        <div style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 600, marginBottom: 10 }}>AUDIT LOG</div>
        {(c.audit_log || []).map(a => (
          <div key={a.id} style={{ display: 'flex', gap: 12, padding: '5px 0', borderBottom: '1px solid var(--border)', fontSize: 11 }}>
            <span style={{ color: 'var(--muted)', whiteSpace: 'nowrap' }}>{new Date(a.timestamp).toLocaleString()}</span>
            <span style={{ color: 'var(--accent)' }}>{a.actor}</span>
            <span style={{ color: 'var(--text)' }}>{a.action}</span>
            <span style={{ color: 'var(--muted)', flex: 1 }}>{a.detail}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function MetaRow({ label, value, color }) {
  return (
    <div style={{ display: 'flex', gap: 8, padding: '3px 0', fontSize: 12 }}>
      <span style={{ color: 'var(--muted)', width: 100, flexShrink: 0 }}>{label}</span>
      <span style={{ color: color || 'var(--text)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {value || '—'}
      </span>
    </div>
  )
}

function authColor(val) {
  return val === 'pass' ? 'var(--green)' : val === 'fail' ? 'var(--red)' : undefined
}

function scoreColor(score) {
  if (score == null) return 'var(--muted)'
  return score >= 60 ? 'var(--red)' : score >= 30 ? 'var(--orange)' : 'var(--green)'
}

function fmt(iso) {
  return iso ? new Date(iso).toLocaleString() : '—'
}
