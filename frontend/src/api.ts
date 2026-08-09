import type { Asset, AssetRisk, AuditEntry, FeedStatus, GraphAnomaly, GraphData, SiteSummary } from './types'

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
