[CmdletBinding()]
param(
    [string]$Version = "dev",
    [string[]]$Targets = @(
        "windows/amd64",
        "windows/386",
        "windows/arm64",
        "linux/amd64",
        "linux/386",
        "linux/arm64",
        "darwin/amd64",
        "darwin/arm64"
    )
)

$ErrorActionPreference = "Stop"

# $PSScriptRoot is the directory holding this script, which is already the
# repository root. Taking its parent pointed one level too high, so every
# path below (main.go, vuln_db.json) resolved outside the repo.
$root = $PSScriptRoot
$dist = Join-Path $root "dist"
$staging = Join-Path $dist ".staging"

if (Test-Path $dist) {
    Remove-Item $dist -Recurse -Force
}
New-Item -ItemType Directory -Path $staging | Out-Null

$commit = "unknown"
try {
    $commit = (git -C $root rev-parse --short HEAD 2>$null)
    if (-not $commit) {
        $commit = "unknown"
    }
} catch {
    $commit = "unknown"
}

# The correlation database is loaded by relative path at runtime, so a release
# without it is a binary that silently reports nothing. Fail here instead.
$db = Join-Path $root "vuln_db.json"
if (-not (Test-Path $db)) {
    throw "vuln_db.json not found. Regenerate it first: go run ./tools/convertor.go"
}

foreach ($target in $Targets) {
    $parts = $target.Split("/")
    if ($parts.Count -ne 2) {
        throw "Invalid target '$target'. Use GOOS/GOARCH, for example windows/amd64."
    }

    $goos = $parts[0]
    $goarch = $parts[1]
    $extension = ""
    if ($goos -eq "windows") {
        $extension = ".exe"
    }

    $name = "fenrir-$Version-$goos-$goarch"
    $stage = Join-Path $staging $name
    New-Item -ItemType Directory -Path $stage | Out-Null

    $env:GOOS = $goos
    $env:GOARCH = $goarch
    $env:CGO_ENABLED = "0"

    $ldflags = "-s -w -X github.com/leviathan-offsec/FenrirLVX/cmd.Version=$Version -X github.com/leviathan-offsec/FenrirLVX/cmd.Commit=$commit"
    go build -trimpath -ldflags $ldflags -o (Join-Path $stage ("fenrir" + $extension)) (Join-Path $root "main.go")

    Copy-Item (Join-Path $root "vuln_db.json") $stage
    Copy-Item (Join-Path $root "README.md") $stage

    $archive = Join-Path $dist ($name + ".zip")
    Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $archive
}

$env:GOOS = $null
$env:GOARCH = $null
$env:CGO_ENABLED = $null

Get-ChildItem $dist -Filter "*.zip" | Get-FileHash -Algorithm SHA256 |
    ForEach-Object { "$($_.Hash)  $($_.Path | Split-Path -Leaf)" } |
    Set-Content (Join-Path $dist "SHA256SUMS")

Remove-Item $staging -Recurse -Force
Write-Host "Release artifacts written to $dist"
