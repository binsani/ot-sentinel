[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DatabaseUrl,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [ValidateRange(0, 3650)]
    [int]$RetentionDays = 0
)

$ErrorActionPreference = 'Stop'
$postgresUrl = $DatabaseUrl -replace '^postgresql\+psycopg://', 'postgresql://'
$outputPath = [System.IO.Path]::GetFullPath($OutputDirectory)
[System.IO.Directory]::CreateDirectory($outputPath) | Out-Null
$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$baseName = "ot-sentinel-$stamp"
$temporaryDump = Join-Path $outputPath "$baseName.dump.partial"
$finalDump = Join-Path $outputPath "$baseName.dump"
$temporaryManifest = Join-Path $outputPath "$baseName.manifest.json.partial"
$finalManifest = Join-Path $outputPath "$baseName.manifest.json"

try {
    & pg_dump --format=custom --compress=9 --no-owner --file=$temporaryDump $postgresUrl
    if ($LASTEXITCODE -ne 0) { throw "pg_dump failed with exit code $LASTEXITCODE" }
    $evidenceJson = & psql $postgresUrl --no-psqlrc --tuples-only --no-align --command @'
SELECT json_build_object(
  'audit_head', (SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1),
  'audit_entries', (SELECT count(*) FROM audit_log),
  'assets', (SELECT count(*) FROM assets),
  'observations', (SELECT count(*) FROM observations),
  'protocol_events', (SELECT count(*) FROM protocol_events),
  'cve_matches', (SELECT count(*) FROM cve_matches)
)::text;
'@
    if ($LASTEXITCODE -ne 0) { throw "backup evidence query failed" }
    $evidence = $evidenceJson.Trim() | ConvertFrom-Json
    $checksum = (Get-FileHash -LiteralPath $temporaryDump -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest = [ordered]@{
        schema = 'ot-sentinel-backup-manifest/v1'
        created_at = [DateTime]::UtcNow.ToString('o')
        dump_file = [System.IO.Path]::GetFileName($finalDump)
        sha256 = $checksum
        evidence = $evidence
    }
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $temporaryManifest -Encoding utf8
    Move-Item -LiteralPath $temporaryDump -Destination $finalDump
    Move-Item -LiteralPath $temporaryManifest -Destination $finalManifest
} finally {
    Remove-Item -LiteralPath $temporaryDump -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $temporaryManifest -Force -ErrorAction SilentlyContinue
}

if ($RetentionDays -gt 0) {
    $cutoff = [DateTime]::UtcNow.AddDays(-$RetentionDays)
    Get-ChildItem -LiteralPath $outputPath -File | Where-Object {
        $_.LastWriteTimeUtc -lt $cutoff -and
        ($_.Name -match '^ot-sentinel-\d{8}T\d{6}Z\.(dump|manifest\.json)$')
    } | Remove-Item -Force
}

Write-Output $finalManifest
