import type { AdminControls, AlertRule, Asset, AssetRisk, AuditEntry, FeedStatus, GraphAnomaly, GraphBaseline, GraphData, ProbePolicy, ProbeStatus, SiemDestination, SiteSummary } from './types'

async function request<T>(path: string, apiKey: string): Promise<T> {
  const response = await fetch(path, {
    headers: authHeaders(apiKey),
    signal: AbortSignal.timeout(15_000),
  })
  if (response.status === 401 || response.status === 403) {
    throw new Error('The API key is invalid or lacks permission.')
  }
  if (!response.ok) throw new Error(`Request failed (${response.status})`)
  return response.json() as Promise<T>
}

export const api = {
  assets: (key: string) => request<Asset[]>('/api/v1/assets?limit=500', key),
  asset: (key: string, id: string) => request<Asset>(`/api/v1/assets/${id}`, key),
  graph: (key: string) => request<GraphData>('/api/v1/assets/graph/communications', key),
  sites: (key: string) => request<SiteSummary[]>('/api/v1/assets/sites/summary', key),
  risk: (key: string) => request<AssetRisk[]>('/api/v1/assets/risk/summary', key),
  anomalies: (key: string) => request<GraphAnomaly[]>('/api/v1/anomalies', key),
  acknowledgeAnomaly: (key: string, id: string) =>
    requestWithBody<GraphAnomaly>(`/api/v1/anomalies/${id}/acknowledge`, key, 'POST', {}),
  feedStatus: (key: string) => request<FeedStatus>('/api/v1/admin/feeds/status', key),
  audit: (key: string) => request<AuditEntry[]>('/api/v1/admin/audit?limit=100', key),
  adminControls: async (key: string): Promise<AdminControls> => {
    const [alertRules, siemDestinations, probeStatus, baselines] = await Promise.all([
      request<AlertRule[]>('/api/v1/admin/alerts/rules', key),
      request<SiemDestination[]>('/api/v1/admin/siem/destinations', key),
      request<ProbeStatus>('/api/v1/admin/probing/status', key),
      request<GraphBaseline[]>('/api/v1/anomalies/baselines', key),
    ])
    return { alertRules, siemDestinations, probeStatus, baselines }
  },
  createAlertRule: (key: string, body: { name: string; event_type: string; site_id: string | null; webhook_url: string }) => requestWithBody<AlertRule>('/api/v1/admin/alerts/rules', key, 'POST', body),
  deleteAlertRule: (key: string, id: string) => requestNoContent(`/api/v1/admin/alerts/rules/${id}`, key, 'DELETE'),
  createSiemDestination: (key: string, body: { name: string; host: string; port: number; minimum_severity: string }) => requestWithBody<SiemDestination>('/api/v1/admin/siem/destinations', key, 'POST', body),
  setSiemEnabled: (key: string, id: string, enabled: boolean) => requestWithBody<SiemDestination>(`/api/v1/admin/siem/destinations/${id}/${enabled ? 'enable' : 'disable'}`, key, 'POST', {}),
  captureBaseline: (key: string, site_id: string, confirmation: string) => requestWithBody<GraphBaseline>('/api/v1/anomalies/baselines', key, 'POST', { site_id, confirmation }),
  createProbePolicy: (key: string, body: Record<string, unknown>) => requestWithBody<ProbePolicy>('/api/v1/admin/probing/policies', key, 'POST', body),
  approveProbePolicy: (key: string, id: string, confirmation: string, approval_hours: number) => requestWithBody<ProbePolicy>(`/api/v1/admin/probing/policies/${id}/approve`, key, 'POST', { confirmation, approval_hours }),
  disableProbePolicy: (key: string, id: string) => requestWithBody<ProbePolicy>(`/api/v1/admin/probing/policies/${id}/disable`, key, 'POST', {}),
  setFirmwareBaseline: (key: string, id: string) =>
    requestWithBody<{ firmware_drift: boolean }>(
      `/api/v1/admin/assets/${id}/firmware-baseline`, key, 'PUT', { version: null },
    ),
  exportCsv: (key: string) => download('/api/v1/exports/assets.csv', key, 'ot-sentinel-assets.csv'),
  exportCycloneDx: (key: string) =>
    download('/api/v1/exports/cyclonedx', key, 'ot-sentinel.cdx.json'),
}

async function requestWithBody<T>(path: string, apiKey: string, method: string, body: unknown): Promise<T> {
  const response = await fetch(path, {
    method,
    headers: { ...authHeaders(apiKey), 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  })
  if (!response.ok) throw new Error(`Request failed (${response.status})`)
  return response.json() as Promise<T>
}

async function requestNoContent(path: string, apiKey: string, method: string): Promise<void> {
  const response = await fetch(path, { method, headers: authHeaders(apiKey), signal: AbortSignal.timeout(15_000) })
  if (!response.ok) throw new Error(`Request failed (${response.status})`)
}

async function download(path: string, apiKey: string, filename: string) {
  const response = await fetch(path, {
    headers: authHeaders(apiKey),
    signal: AbortSignal.timeout(30_000),
  })
  if (!response.ok) throw new Error(`Export failed (${response.status})`)
  const url = URL.createObjectURL(await response.blob())
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 0)
}

export function authHeaders(credential: string): HeadersInit {
  const looksLikeJwt = credential.split('.').length === 3
  return looksLikeJwt
    ? { Authorization: `Bearer ${credential}` }
    : { 'X-API-Key': credential }
}
