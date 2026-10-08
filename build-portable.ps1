param(
    [string]$DotNet = 'dotnet',
    [string]$OutputDirectory = 'artifacts\SDA-win-x64'
)

$ErrorActionPreference = 'Stop'
$sdaRoot = $PSScriptRoot
$sdaOutput = [IO.Path]::GetFullPath($OutputDirectory, $sdaRoot)
if (Test-Path -LiteralPath $sdaOutput) {
    throw 'Le dossier de sortie existe deja. Conservez ses eventuels maFiles et choisissez une copie propre du depot pour reconstruire.'
}

$env:DOTNET_CLI_HOME = Join-Path $sdaRoot '.build\cli'
$env:NUGET_PACKAGES = Join-Path $sdaRoot '.build\packages'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'

function Invoke-SdaDotNet {
    & $DotNet @args
    if ($LASTEXITCODE -ne 0) { throw "Echec de dotnet (code $LASTEXITCODE)." }
}

Push-Location $sdaRoot
try {
    New-Item -ItemType Directory -Force -Path 'artifacts' | Out-Null
    Invoke-SdaDotNet restore 'verification/OfflineChecks.csproj' --locked-mode --force --no-http-cache
    Invoke-SdaDotNet run --project 'verification/OfflineChecks.csproj' --configuration Release --no-restore

    $sdaAuditText = Invoke-SdaDotNet package list --project 'SteamDesktopAuthenticator.sln' --vulnerable --include-transitive --no-restore --format json
    $sdaAudit = ($sdaAuditText -join [Environment]::NewLine) | ConvertFrom-Json
    if ($sdaAudit.problems -or @($sdaAudit.projects).Count -ne 2) { throw 'Audit NuGet incomplet.' }
    foreach ($sdaProject in $sdaAudit.projects) {
        foreach ($sdaFramework in $sdaProject.frameworks) {
            foreach ($sdaPackage in @($sdaFramework.topLevelPackages) + @($sdaFramework.transitivePackages)) {
                if ($sdaPackage.vulnerabilities) { throw "Vulnerabilite detectee : $($sdaPackage.id)" }
            }
        }
    }
    $sdaAuditText | Set-Content -LiteralPath 'artifacts/audit-nuget.json' -Encoding utf8

    Invoke-SdaDotNet publish 'Steam Desktop Authenticator/Steam Desktop Authenticator.csproj' --configuration Release --no-restore --output $sdaOutput
    Copy-Item -LiteralPath 'LICENSE' -Destination $sdaOutput
    Copy-Item -LiteralPath 'USAGE-PONCTUEL.md' -Destination $sdaOutput

    # Une reconstruction ne doit jamais incorporer les secrets d'une utilisation precedente.
    if (Get-ChildItem -LiteralPath $sdaOutput -Recurse -Force | Where-Object { $_.Name -eq 'maFiles' -or $_.Name -like '*.maFile*' }) {
        throw 'Des fichiers de compte sont presents dans la sortie.'
    }
    Write-Output "Dossier autonome : $sdaOutput"
}
finally {
    Pop-Location
}
