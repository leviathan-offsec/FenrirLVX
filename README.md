# FenrirLVX

<p align="center">
  <img src="/TUI.gif" alt="Fenrir TUI demo" width="900">
</p>

**High-speed Go CLI for WordPress attack surface mapping, plugin fingerprinting, and offline CVE correlation.**

FenrirLVX is a focused, low-footprint Go security utility built for authorized offensive security operations, bug bounty triage, and perimeter auditing. It fingerprints WordPress targets, enumerates plugins and themes, correlates detected versions against a local vulnerability database (`vuln_db.json`), and outputs deterministic triage findings without external API dependencies.

> [!IMPORTANT]
> Use FenrirLVX only against assets you own or have explicit written authorization to assess.

---

## Capabilities

- **Direct Fingerprinting:** Single-target WordPress and component detection with zero external API dependencies.
- **Component Enumeration:** Plugin and theme version discovery via static asset inspection and header telemetry.
- **Offline Vulnerability Correlation:** Local mapping against CVE and Wordfence vulnerability data (`vuln_db.json`).
- **Confidence Scoring:** Version signal validation factoring in changelogs, cache signatures, and response headers.
- **Shodan Query Support:** Optional passive host discovery for scoped enterprise ranges.
- **Concurrent Mass Triage:** Multi-target worker pool with honeypot and canary edge filtering.
- **Cross-Platform:** Native single-binary builds for Linux, macOS, and Windows (`amd64`, `arm64`).

---

## Installation

### Via `go install` (Recommended)

Requires Go 1.22+:

```bash
go install -v github.com/leviathan-offsec/FenrirLVX@latest
```

Ensure `$GOPATH/bin` is in your `PATH`:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
FenrirLVX --help
```

### From Source

```bash
git clone https://github.com/leviathan-offsec/FenrirLVX.git
cd FenrirLVX
go build -o fenrir .
./fenrir --help
```

---

## Usage

### Single-Target Scan

Scan an authorized target URL directly without third-party services:

```bash
fenrir scan -t https://staging.example.com
```

The scan outputs detected CMS technologies, active plugins, detected themes, and correlations against local vulnerability definitions with confidence scoring.

### Target Recon with Shodan Enrichment

```bash
export SHODAN_API_KEY="your-api-key"
fenrir wordpress -t staging.example.com -k $SHODAN_API_KEY
```

*The Shodan key is optional; direct scanning functions entirely offline.*

### Mass Triage via Shodan Query

```bash
fenrir mass -k $SHODAN_API_KEY -q 'http.component:"WordPress" org:"TargetOrg"' -p 1 -d 5
```

### Key CLI Flags

| Flag | Supported Commands | Description |
| :--- | :--- | :--- |
| `-t` | `scan`, `wordpress` | Target URL or domain |
| `-k` | `wordpress`, `mass` | Shodan API key (optional) |
| `-q` | `mass` | Shodan search query filter |
| `-p` | `mass` | Total result pages to fetch (default: 1) |
| `-d` | `mass` | Polling delay in seconds between queries (default: 5) |
| `-P` | `mass` | Enable strict/precision version matching |

---

## Triage Console Taxonomy

FenrirLVX utilizes deterministic severity signaling in its terminal output:

```text
[+] Clean       No matching vulnerability signature in local database
[!]             Low or medium-severity signal / unverified version match
[!!]            High-severity vulnerability signature detected
[!!!]           Critical CVSS / exploit-confirmed vulnerability signature
[SKIP]          Honeypot, WAF canary, or synthetic response filtered
```

> [!NOTE]
> `Clean` indicates no local signatures matched the detected component versions. Manual verification of non-standard endpoints is always advised.

---

## Project Structure

```text
cmd/          Cobra command wiring and CLI interface
pkg/banner/   Console branding and output telemetry
pkg/engine/   Fingerprinting, asset enumeration, and CVE correlation
pkg/shodan/   Shodan host discovery client
tools/        Cross-compilation and release automation scripts
vuln_db.json  Local vulnerability definitions and signatures
```

---

## License

MIT License. Developed by `@cyeezy08` for [Leviathan OffSec](https://leviathan.ac).
