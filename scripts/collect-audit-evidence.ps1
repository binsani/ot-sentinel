[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [switch]$AllowDirty
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$outputPath = [System.IO.Path]::GetFullPath($OutputDirectory)
[System.IO.Directory]::CreateDirectory($outputPath) | Out-Null
$safeRepositoryRoot = $repositoryRoot.Replace('\', '/')

$commit = (& git -c "safe.directory=$safeRepositoryRoot" -C $repositoryRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to resolve the repository commit.'
}
$statusLines = @(
    & git -c "safe.directory=$safeRepositoryRoot" -C $repositoryRoot status --porcelain --untracked-files=no
)
if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect repository state.' }
$dirty = $statusLines.Count -gt 0
if ($dirty -and -not $AllowDirty) {
    throw 'Refusing to collect release evidence from a modified worktree. Use -AllowDirty only for rehearsal.'
}

$evidenceFiles = @(
    'backend/uv.lock',
    'frontend/package-lock.json',
    'sensor/uv.lock',
    'docker-compose.yml',
    'deploy/kubernetes/base/kustomization.yaml',
    '.github/workflows/ci.yml',
    '.github/workflows/codeql.yml',
    '.github/workflows/release.yml',
    'RELEASE_NOTES.md',
    'docs/release-checklist.md',
    'docs/architecture.md',
    'docs/authentication.md',
    'docs/backup-restore.md',
    'docs/field-acceptance.md',
    'docs/threat-model.md',
    'SECURITY.md',
    'scripts/verify-passive-release.py',
    'scripts/verify-release-version.py'
)
$hashes = foreach ($relativePath in $evidenceFiles) {
    $absolutePath = Join-Path $repositoryRoot $relativePath
    if (-not (Test-Path -LiteralPath $absolutePath -PathType Leaf)) {
        throw "Required evidence file is missing: $relativePath"
    }
    [ordered]@{
        path = $relativePath
        sha256 = (Get-FileHash -LiteralPath $absolutePath -Algorithm SHA256).Hash.ToLowerInvariant()
        bytes = (Get-Item -LiteralPath $absolutePath).Length
    }
}

$manifest = [ordered]@{
    schema = 'ot-sentinel-audit-evidence/v1'
    generated_at = [DateTime]::UtcNow.ToString('o')
    commit = $commit
    worktree_dirty = $dirty
    repository = 'https://github.com/binsani/ot-sentinel'
    files = $hashes
    assertions = [ordered]@{
        contains_secrets = $false
        field_acceptance_completed = $false
        external_assessment_completed = $false
    }
}
$manifestPath = Join-Path $outputPath "ot-sentinel-audit-evidence-$($commit.Substring(0, 12)).json"
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding utf8
Write-Output $manifestPath
