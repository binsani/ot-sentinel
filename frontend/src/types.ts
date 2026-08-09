export type Vulnerability = {
  cve_id: string
  status: 'candidate' | 'confirmed' | 'rejected'
  confidence: number
  cvss_score: number | null
  severity: string | null
  known_exploited: boolean | null
  patch_available: boolean | null
  advisory: { description?: string }
}

export type Asset = {
  id: string
  site_id: string
  ip_address: string
  mac_address: string | null
  hostname: string | null
  vendor: string | null
  model: string | null
  firmware_version: string | null
  firmware_baseline: string | null
  firmware_baseline_set_at: string | null
  firmware_baseline_set_by: string | null
  firmware_drift_detected_at: string | null
  firmware_drift: boolean
  protocols: string[]
  fingerprint: Record<string, unknown>
  criticality: number
  first_seen: string
  last_seen: string
  vulnerabilities?: Vulnerability[]
}

export type GraphData = {
  nodes: Array<{ id: string; label: string }>
  edges: Array<{
    id: string
    source: string
    target: string
    protocol: string
    packet_count: number
    byte_count: number
    last_seen: string
  }>
}

export type FeedStatus = {
  sources: Array<{
    source: string
    status: 'healthy' | 'failed'
    occurred_at: string
    details: Record<string, unknown>
  }>
}

export type SiteSummary = {
  site_id: string
  asset_count: number
  last_seen: string
  firmware_drift_count: number
  vulnerability_matches: number
  vulnerable_assets: number
}

export type AuditEntry = {
  id: number
  occurred_at: string
  actor_subject: string | null
  action: string
  object_type: string
  object_id: string | null
  details: Record<string, unknown>
  entry_hash: string
  previous_hash: string | null
}
