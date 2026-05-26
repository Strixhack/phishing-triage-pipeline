import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'

export default function Campaigns() {
  const [data, setData] = useState(null)
  const navigate = useNavigate()

  useEffect(() => {
    fetch('/api/campaigns/')
      .then(r => r.json())
      .then(setData)
      .catch(() => {})
  }, [])

  const campaigns = data?.campaigns || []

  return (
    <div>
      <h1 style={{ fontSize: 16, fontWeight: 700, marginBottom: 4 }}>Campaign Detection</h1>
      <p style={{ color: 'var(--muted)', fontSize: 12, marginBottom: 20 }}>
        Clusters similar phishing emails by sender domain, subject template, and URL overlap
      </p>

      {campaigns.length === 0 ? (
        <div className="card" style={{ color: 'var(--muted)' }}>
          No campaigns detected yet. Upload multiple phishing emails to identify patterns.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {campaigns.map(camp => (
            <div key={camp.campaign_id} className="card"
              style={{ borderColor: camp.verdict === 'malicious' ? 'var(--red)' : 'var(--orange)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10 }}>
                <span style={{ color: 'var(--accent)', fontWeight: 700, fontFamily: 'monospace' }}>
                  {camp.campaign_id}
                </span>
                <span className={`badge ${camp.verdict}`}>{camp.verdict}</span>
                <span style={{ color: 'var(--muted)', fontSize: 11 }}>
                  {camp.case_count} cases · similarity {(camp.similarity_score * 100).toFixed(0)}%
                </span>
                <span style={{ color: 'var(--muted)', fontSize: 11, marginLeft: 'auto' }}>
                  {new Date(camp.first_seen).toLocaleDateString()} → {new Date(camp.last_seen).toLocaleDateString()}
                </span>
              </div>

              <div style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 6 }}>SHARED INDICATORS</div>
                {camp.shared_indicators.map((ind, i) => (
                  <div key={i} style={{ fontSize: 11, color: 'var(--orange)', marginBottom: 3 }}>
                    ▸ {ind}
                  </div>
                ))}
              </div>

              <div>
                <div style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 6 }}>CASES IN CAMPAIGN</div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  {camp.case_ids.map(id => (
                    <button key={id} onClick={() => navigate(`/cases/${id}`)}>
                      Case #{id}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
