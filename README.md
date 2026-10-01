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
- **Database Coverage Reporting:** Every result states how much of the target the database could actually speak to, so a clean verdict is distinguishable from a stale one.
- **Per-Match Evidence:** Each finding carries the detected version, the advisory range it fell in, and whether that range was unbounded.
- **Confidence Scoring:** Version signal validation factoring in changelogs, cache signatures, and response headers.
- **Shodan Query Support:** Optional passive host discovery for scoped enterprise ranges.
- **Concurrent Mass Triage:** Multi-target worker pool with honeypot and canary edge filtering.
- **Cross-Platform:** Native single-binary builds for Linux, macOS, and Windows (`amd64`, `arm64`, `386`).

---

## Installation

### From Release

Download the archive for your platform from
[releases](https://github.com/leviathan-offsec/FenrirLVX/releases). Each archive
contains the binary, `vuln_db.json`, and a `SHA256SUMS` file. Verify it:

```bash
sha256sum -c SHA256SUMS --ignore-missing
./fenrir-v0.1.0-linux-amd64 --help
```

**Run it from the directory containing `vuln_db.json`.** The database is looked
up by relative path, so the binary and the JSON file need to sit together.

### From Source

```bash
git clone https://github.com/leviathan-offsec/FenrirLVX.git
cd FenrirLVX
go build -o fenrir .
./fenrir --help
```

`vuln_db.json` is committed, so a source build is fully offline-capable with no
extra setup. Requires Go 1.27 or newer.

### Regenerating the Database

`vuln_db.json` is generated from a Wordfence export, which is not committed
because of its size. To rebuild it from your own feed:

```bash
# needs the Wordfence API key and an export
cp wordfence_production.json .
go run ./tools/convertor.go
```

The convertor parses the feed and rewrites `vuln_db.json` in place. It is a
maintenance tool, not part of a normal build.

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

A clean verdict also reports database coverage:

```text
[+] staging.example.com Clean
    database coverage  3/7 plugins matched  4 with no advisory data
```

> [!IMPORTANT]
> `Clean` means no local signature matched, not that the target is free of
> known issues. Four plugins had no advisory data in this database, and that
> gap is stated rather than hidden. An offline scanner cannot prove absence.
> It can only report what its data covers.

> [!NOTE]
> Plugins with an unbounded advisory (a `*` on either version bound) will
> match any detected version. Those matches are flagged so you can discount
> them.

---

## Project Structure

```text
cmd/          Cobra command wiring and CLI interface
pkg/banner/   Console branding and output telemetry
pkg/engine/   Fingerprinting, asset enumeration, and CVE correlation
pkg/shodan/   Shodan host discovery client
tools/        Database convertor and release build script
build.ps1     Cross-platform release build (Windows)
vuln_db.json  Local vulnerability definitions and signatures
```

## Development

```bash
go build ./...
go test ./...
go vet ./...
```

The `pkg/engine` tests cover range-boundary handling, version parsing,
coverage accounting and the clean-path disclosure. They are the regression net
for the two failure modes that matter here: a plugin silently missing from the
database, and a match firing on an advisory with no upper bound.

---

## License

MIT License. Developed by `@cyeezy08` for [Leviathan OffSec](https://leviathan.ac).
