# Fenrir v0.1.0

<p align="center">
  <img src="/TUI.gif" alt="Fenrir TUI demo" width="900">
</p>

**WordPress reconnaissance and auto-triage from the Leviathan stack.**

Fenrir is a focused Go CLI for authorized security testing. It fingerprints
WordPress targets, enumerates plugins and themes, correlates detected versions
with a local vulnerability database, and presents concise triage results.

> Use Fenrir only on systems you own or are explicitly authorized to assess.
> Mass scanning must follow the target owner's rules and the relevant
> bug-bounty program policy.

## What it does

- Single-target WordPress fingerprinting without Shodan
- Plugin and theme enumeration
- Local CVE and Wordfence-style vulnerability correlation
- Confidence scoring using version evidence and changelog context
- Optional Shodan host discovery for authorized research
- Concurrent mass triage with honeypot filtering
- Windows, Linux, and macOS builds for amd64, 386, and arm64

Fenrir is a triage tool, not proof that a target is secure. Findings should be
manually verified and reported through the target's approved channel.

## Install

### Run from source

Requires Go 1.27 or newer:

```powershell
git clone https://github.com/leviathan-offsec/FenrirLVX.git
Set-Location .\Fenrir
go run . --help
go run . version
```

### One-line install

```powershell
go install github.com/leviathan-offsec/FenrirLVX@latest
fenrir --help
fenrir version
```

On Windows, the Go bin directory must be on `PATH`. If `fenrir` is not
recognized, run:

```powershell
& "$(go env GOPATH)\bin\fenrir.exe" --help
```

## Quick start

### Scan one authorized target

```powershell
go run . scan -t https://staging.example.com
```

The scan reports whether WordPress is detected, the discovered plugins and
themes, matching local vulnerability records, response metadata, and a
confidence score when findings exist.

### WordPress workflow with optional Shodan context

```powershell
$env:SHODAN_API_KEY = "replace-with-a-rotated-key"
go run . wordpress -t staging.example.com -k $env:SHODAN_API_KEY
```

The Shodan key is optional for the `wordpress` command. Never commit a key or
paste one into a public issue, screenshot, shell history, or README.

### Mass triage through Shodan

```powershell
$env:SHODAN_API_KEY = "replace-with-a-rotated-key"
go run . mass -k $env:SHODAN_API_KEY -p 1 -d 5
```

Useful flags:

| Flag | Command | Purpose |
| --- | --- | --- |
| `-t` | `scan`, `wordpress` | Target URL or domain |
| `-k` | `wordpress`, `mass` | Shodan API key |
| `-q` | `mass` | Shodan query |
| `-p` | `mass` | Number of result pages |
| `-d` | `mass` | Delay between Shodan pages |
| `-P` | `mass` | Exact version matching |

## Reading the console

Fenrir uses a small operator-console vocabulary:

```text
[+] Clean       no local vulnerability match was produced
[!]             lower-confidence or medium-severity signal
[!!]            high-severity signal
[!!!]           high-confidence signal
[SKIP]          honeypot or canary-like response was not triaged
```

`Clean` means that the current local database did not match the detected
versions. It does **not** mean the target is safe.

### Example

```text
[*] Querying Shodan: http.component:"WordPress" http.status:200
[*] Pages: 1 (~100 targets), delay: 5s
[+] Scanning 100 targets...

[!!] staging.example.com (203.0.113.10)  confidence=75/100  changelog=0
    plugins  elementor 4.2.1, contact-form-7 6.0.5
    server   cloudflare [200]
    findings
      !!  9.8  CVE-2026-32475  Elementor Pro arbitrary file upload
      ... +2 more (elementor-pro)

[+] Clean: docs.example.com (203.0.113.11)
```

The default command is intentionally a normal terminal workflow rather than a
full-screen TUI, so it works in PowerShell, CI logs, SSH sessions, and bug
bounty notes without special terminal support.

## Build releases

The included PowerShell script creates a tidy `dist\` directory with versioned
archives and checksums:

```powershell
.\tools\build.ps1 -Version v1.0.0
```

By default it builds:

- Windows: `amd64`, `386`, `arm64`
- Linux: `amd64`, `386`, `arm64`
- macOS: `amd64`, `arm64`

To build only selected targets:

```powershell
.\tools\build.ps1 -Version v1.0.0 -Targets windows/amd64,linux/amd64
```

Each archive contains:

```text
fenrir/
  fenrir(.exe)
  vuln_db.json
  wordfence_production.json
  README.md
```

## Project layout

```text
cmd/          Cobra commands and CLI wiring
pkg/banner/   Leviathan/Fenrir console identity
pkg/engine/   fingerprinting, enumeration, triage, reporting
pkg/shodan/   optional Shodan discovery and host lookups
tools/        reproducible release helpers
vuln_db.json  local vulnerability correlation data
```

## Development

```powershell
go test ./...
go vet ./...
go run . scan -t https://staging.example.com
```

Keep generated release files under `dist\`; they are ignored by Git.

## License

This project is licensed under the MIT License.

```text
MIT License
@cyeezy08 - Leviathan X
Copyright (c) 2025 Fenrir contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
