import { useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'

const SEVERITY_COLOR = { critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)', low: 'var(--muted)', none: 'var(--muted)' }
const CONFIDENCE_COLOR = { high: 'var(--green)', medium: 'var(--orange)', low: 'var(--muted)' }

export default function Upload() {
  const [dragging, setDragging] = useState(false)
  const [loading, setLoading]   = useState(false)
  const [result, setResult]     = useState(null)
  const [error, setError]       = useState(null)
  const fileRef = useRef()
  const navigate = useNavigate()

  async function handleFile(file) {
    if (!file?.name.endsWith('.eml')) { setError('Only .eml files accepted'); return }
    setLoading(true); setError(null); setResult(null)
    try {
      const data = await api.uploadEmail(file)
      setResult(data)
    } catch (e) { setError(e.message) }
    finally { setLoading(false) }
  }

  const verdictColor = { malicious: 'var(--red)', suspicious: 'var(--orange)', benign: 'var(--green)', pending: 'var(--accent)' }

  return (
    <div style={{ maxWidth: 680 }}>
      <h1 style={{ fontSize: 16, fontWeight: 700, marginBottom: 20 }}>Upload Email</h1>

      <div className="card"
        onDragOver={e => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={e => { e.preventDefault(); setDragging(false); handleFile(e.dataTransfer.files[0]) }}
        onClick={() => fileRef.current.click()}
        style={{ border: `2px dashed ${dragging ? 'var(--accent)' : 'var(--border)'}`, textAlign: 'center', padding: 48, cursor: 'pointer', marginBottom: 16 }}>
        <input ref={fileRef} type="file" accept=".eml" style={{ display: 'none' }} onChange={e => handleFile(e.target.files[0])} />
        {loading
          ? <div style={{ color: 'var(--accent)' }}>⟳ Analysing — YARA scan · IOC enrichment · MITRE mapping…</div>
          : <><div style={{ fontSize: 32, marginBottom: 12 }}>✉</div>
             <div style={{ color: 'var(--muted)' }}>Drop a <code>.eml</code> file here or click to browse</div></>
        }
      </div>

      {error && <div className="card" style={{ borderColor: 'var(--red)', color: 'var(--red)', marginBottom: 16 }}>✗ {error}</div>}

      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {/* Summary */}
          <div className="card" style={{ borderColor: verdictColor[result.verdict] }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: verdictColor[result.verdict], marginBottom: 12 }}>
              ✓ Triage complete — {result.verdict.toUpperCase()}
            </div>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <tbody>
                {[
                  ['Reference',    result.reference],
                  ['Risk Score',   `${result.risk_score}/100`],
                  ['IOCs Found',   result.ioc_count],
                  ['TheHive ID',   result.thehive_case_id || 'N/A'],
                  ['YARA Matches', result.yara?.matches || 0],
                  ['MITRE Techniques', result.mitre?.total || 0],
                  ['NIS2 Significant', result.nis2?.is_significant ? '⚠ YES — timers started' : 'No'],
                ].map(([k, v]) => (
                  <tr key={k} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ color: 'var(--muted)', padding: '5px 0', width: '40%' }}>{k}</td>
                    <td style={{ padding: '5px 0' }}>{String(v)}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            {/* Score breakdown */}
            <div style={{ marginTop: 16 }}>
              <div style={{ color: 'var(--muted)', fontSize: 11, marginBottom: 8 }}>SCORE BREAKDOWN</div>
              {Object.entries(result.score_breakdown || {}).map(([k, v]) => (
                <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 5 }}>
                  <span style={{ width: 90, color: 'var(--muted)', fontSize: 11 }}>{k}</span>
                  <div className="score-bar" style={{ flex: 1 }}>
                    <div className="score-bar-fill"
                      style={{ width: `${v}%`, background: v > 60 ? 'var(--red)' : v > 30 ? 'var(--orange)' : 'var(--green)' }} />
                  </div>
                  <span style={{ width: 28, textAlign: 'right', fontSize: 11 }}>{v}</span>
                </div>
              ))}
            </div>
            <button className="primary" style={{ marginTop: 16 }} onClick={() => navigate(`/cases/${result.case_id}`)}>
              View Full Case →
            </button>
          </div>

          {/* YARA results */}
          {result.yara?.matches > 0 && (
            <div className="card" style={{ borderColor: 'var(--red)' }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--red)', marginBottom: 10 }}>
                ⚠ YARA — {result.yara.matches} rule{result.yara.matches > 1 ? 's' : ''} matched
              </div>
              {result.yara.rules_triggered.map(rule => (
                <div key={rule} style={{ fontSize: 11, color: 'var(--orange)', marginBottom: 3 }}>
                  ▸ {rule}
                </div>
              ))}
            </div>
          )}

          {/* MITRE ATT&CK */}
          {result.mitre?.techniques?.length > 0 && (
            <div className="card" style={{ borderColor: 'var(--purple)' }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--purple)', marginBottom: 10 }}>
                MITRE ATT&CK — {result.mitre.total} technique{result.mitre.total > 1 ? 's' : ''} mapped
              </div>
              {result.mitre.techniques.map(t => (
                <div key={t.technique_id} style={{ display: 'flex', gap: 8, marginBottom: 6, alignItems: 'flex-start' }}>
                  <span style={{ color: 'var(--accent)', fontFamily: 'monospace', fontSize: 11, flexShrink: 0 }}>
                    {t.technique_id}
                  </span>
                  <span style={{ color: 'var(--text)', fontSize: 11 }}>{t.name}</span>
                  <span style={{ color: 'var(--muted)', fontSize: 10, marginLeft: 'auto', flexShrink: 0 }}>
                    {t.tactic}
                  </span>
                  <span style={{ color: CONFIDENCE_COLOR[t.confidence], fontSize: 10, flexShrink: 0 }}>
                    {t.confidence}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* Cortex */}
          {result.cortex?.length > 0 && (
            <div className="card" style={{ borderColor: 'var(--green)' }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--green)', marginBottom: 10 }}>
                Cortex Analysis — {result.cortex.length} IOC{result.cortex.length > 1 ? 's' : ''} analysed
              </div>
              {result.cortex.map((cr, i) => (
                <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 4, fontSize: 11 }}>
                  <span style={{ color: 'var(--accent)', fontFamily: 'monospace', flexShrink: 0 }}>{cr.type}</span>
                  <span style={{ color: 'var(--muted)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cr.ioc}</span>
                  <span style={{ color: cr.highest_level === 'malicious' ? 'var(--red)' : cr.highest_level === 'suspicious' ? 'var(--orange)' : 'var(--green)', flexShrink: 0 }}>
                    {cr.highest_level}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
