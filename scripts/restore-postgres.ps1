[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DatabaseUrl,
    [Parameter(Mandatory = $true)]
    [string]$BackupFile,
    [Parameter(Mandatory = $true)]
    [string]$ManifestFile,
    [Parameter(Mandatory = $true)]
    [string]$Confirmation
)

$ErrorActionPreference = 'Stop'
$postgresUrl = $DatabaseUrl -replace '^postgresql\+psycopg://', 'postgresql://'
if ($Confirmation -ne 'RESTORE INTO VERIFIED EMPTY DATABASE') {
    throw 'Exact restore confirmation is required.'
}
$backupPath = [System.IO.Path]::GetFullPath($BackupFile)
$manifestPath = [System.IO.Path]::GetFullPath($ManifestFile)
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schema -ne 'ot-sentinel-backup-manifest/v1') { throw 'Unsupported manifest schema.' }
$actualChecksum = (Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualChecksum -ne $manifest.sha256) { throw 'Backup SHA-256 does not match the manifest.' }

$userTableCount = & psql $postgresUrl --no-psqlrc --tuples-only --no-align --command @'
SELECT count(*) FROM pg_catalog.pg_tables
WHERE schemaname = 'public' AND tablename <> 'spatial_ref_sys';
'@
if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect restore target.' }
if ([int]$userTableCount.Trim() -ne 0) {
    throw 'Restore target is not empty. Refusing to overwrite an existing database.'
}

& pg_restore --exit-on-error --no-owner --dbname=$postgresUrl $backupPath
if ($LASTEXITCODE -ne 0) { throw "pg_restore failed with exit code $LASTEXITCODE" }

$restoredJson = & psql $postgresUrl --no-psqlrc --tuples-only --no-align --command @'
SELECT json_build_object(
  'audit_head', (SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1),
  'audit_entries', (SELECT count(*) FROM audit_log),
  'assets', (SELECT count(*) FROM assets),
  'observations', (SELECT count(*) FROM observations),
  'protocol_events', (SELECT count(*) FROM protocol_events),
  'cve_matches', (SELECT count(*) FROM cve_matches)
)::text;
'@
if ($LASTEXITCODE -ne 0) { throw 'Restore verification query failed.' }
$restored = $restoredJson.Trim() | ConvertFrom-Json
foreach ($field in @('audit_head', 'audit_entries', 'assets', 'observations', 'protocol_events', 'cve_matches')) {
    if ([string]$restored.$field -ne [string]$manifest.evidence.$field) {
        throw "Restore evidence mismatch for $field."
    }
}

[ordered]@{
    verified = $true
    restored_at = [DateTime]::UtcNow.ToString('o')
    sha256 = $actualChecksum
    evidence = $restored
} | ConvertTo-Json -Depth 5
