const BASE = '/api'

async function req(path, opts = {}) {
  const res = await fetch(`${BASE}${path}`, opts)
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `HTTP ${res.status}`)
  }
  return res.json()
}

export const api = {
  health:      ()                   => req('/health'),
  stats:       ()                   => req('/cases/stats/summary'),
  listCases:   (params = {})        => req('/cases/?' + new URLSearchParams(params)),
  getCase:     (id)                 => req(`/cases/${id}`),
  updateCase:  (id, body)           => req(`/cases/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }),
  listIOCs:    (params = {})        => req('/iocs/?' + new URLSearchParams(params)),
  nis2:        ()                   => req('/nis2/dashboard'),

  uploadEmail: (file) => {
    const form = new FormData()
    form.append('file', file)
    return req('/emails/upload', { method: 'POST', body: form })
  },
}
