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

export type AssetRisk = {
  asset_id: string
  site_id: string
  ip_address: string
  vendor: string | null
  model: string | null
  score: number
  band: 'low' | 'medium' | 'high' | 'critical'
  components: {
    vulnerability: number
    network_exposure: number
    criticality: number
  }
  evidence: {
    max_cvss: number | null
    known_exploited: boolean
    observed_peer_count: number
    asset_criticality: number
  }
}

export type GraphAnomaly = {
  id: string
  baseline_id: string
  site_id: string
  source_ip: string
  destination_ip: string
  protocol: string
  status: 'open' | 'acknowledged'
  first_seen: string
  last_seen: string
  observation_count: number
  acknowledged_at: string | null
  acknowledged_by: string | null
}

export type AlertRule = {
  id: string
  name: string
  event_type: 'firmware_drift' | 'vulnerability_match' | 'communication_anomaly'
  site_id: string | null
  webhook_url: string
  enabled: boolean
  created_by: string
  created_at: string
}

export type SiemDestination = {
  id: string
  name: string
  host: string
  port: number
  transport: 'tcp_tls'
  minimum_severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  enabled: boolean
  created_by: string
  created_at: string
}

export type ProbePolicy = {
  id: string
  name: string
  site_id: string
  enabled: boolean
  allowed_cidrs: string[]
  protocols: Array<'icmp_echo' | 'tcp_connect'>
  max_targets: number
  rate_per_minute: number
  maintenance_start_hour: number
  maintenance_end_hour: number
  approved_by: string | null
  approval_expires_at: string | null
}

export type ProbeStatus = {
  global_enabled: boolean
  executor_available: false
  transmission_capable: false
  policies: ProbePolicy[]
}

export type GraphBaseline = {
  id: string
  site_id: string
  active: boolean
  captured_at: string
  captured_by: string
  edge_count: number
}

export type AdminControls = {
  alertRules: AlertRule[]
  siemDestinations: SiemDestination[]
  probeStatus: ProbeStatus
  baselines: GraphBaseline[]
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
