<div align="center">

# 🔒 cpv

**Check Pip Vulnerabilities — a fast, zero-false-positive security scanner for Python environments**

[![CI](https://github.com/michaelcolletti/cpv/actions/workflows/ci.yml/badge.svg)](https://github.com/michaelcolletti/cpv/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/cpv)](https://crates.io/crates/cpv)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust 1.75+](https://img.shields.io/badge/Rust-1.75%2B-orange)](https://www.rust-lang.org/)

A single-binary Rust tool that validates every package in your `pip list` against the **[OSV.dev](https://osv.dev)** vulnerability database — the same source powering GitHub's Dependabot and Google's supply-chain security tooling.
Finds CVEs, backdoors, and supply-chain compromises like the [XZ Utils attack](https://www.xda-developers.com/popular-python-library-backdoor-machine/) **before** they reach production.

</div>

---

## Why cpv?

| Pain point | How cpv addresses it |
|---|---|
| `pip audit` misses some OSV entries | Queries OSV batch API directly — same data, no middleware |
| Slow Python tooling | Single compiled Rust binary, concurrent HTTP, scans 200+ packages in ~3 seconds |
| "Vulnerable" with no fix guidance | Computes the **minimum safe upgrade version** from OSV range data |
| Transitive risk is invisible | Built-in dependency graph highlights packages pulled in by others |
| No CI integration | `--fail-on-vuln` returns exit code 2; plug straight into any pipeline |
| No audit trail | `--report` writes a Markdown report with CVEs, CVSS scores, and pip commands |

---

## Demo

```
$ cpv --input pip_list.txt --quiet --remediate

Checking 216 packages against OSV.dev...

  ✗ aiohttp@3.9.3  (12 vulns)
    GHSA-5m98-qgg9-wh84 (CVE-2024-30251)
    aiohttp vulnerable to Denial of Service when trying to parse malformed POST requests
    Severity: CVSS_V3  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
    Ref: https://nvd.nist.gov/vuln/detail/CVE-2024-30251

  ✗ urllib3@2.2.0  (6 vulns)
  ...
  ✗ tornado@6.4   (6 vulns)
  ...

→ 216 packages checked — 29 vulnerable

─── Remediation Plan ────────────────────────────────────────
  Package            Current    Safe Version          Dependents in env
  ─────────────────────────────────────────────────────────────────────
  aiohttp            3.9.3      upgrade → 3.13.3      langchain-community, fsspec
  urllib3            2.2.0      upgrade → 2.6.3       requests, selenium, httpcore
  tornado            6.4        upgrade → 6.5.5       jupyter_server, ipykernel
  setuptools         65.5.0     upgrade → 78.1.1      pip, build
  Pygments           2.17.2     NO FIX AVAILABLE      rich, nbconvert, ipykernel
  ...

  Quick fix (run this):
  pip install --upgrade aiohttp==3.13.3 urllib3==2.6.3 tornado==6.5.5 ...

  ⚠ Packages with no upstream fix: Pygments
  Consider removing or replacing these packages.
```

---

## Installation

### Pre-built binary (recommended)

Download the latest binary for your platform from the [Releases](https://github.com/michaelcolletti/cpv/releases) page:

```bash
# macOS (Apple Silicon)
curl -Lo cpv https://github.com/michaelcolletti/cpv/releases/latest/download/cpv-macos-aarch64
chmod +x cpv && sudo mv cpv /usr/local/bin/

# macOS (Intel)
curl -Lo cpv https://github.com/michaelcolletti/cpv/releases/latest/download/cpv-macos-x86_64
chmod +x cpv && sudo mv cpv /usr/local/bin/

# Linux (x86_64)
curl -Lo cpv https://github.com/michaelcolletti/cpv/releases/latest/download/cpv-linux-x86_64
chmod +x cpv && sudo mv cpv /usr/local/bin/
```

### From source

```bash
cargo install --git https://github.com/michaelcolletti/cpv
```

Or clone and build:
```bash
git clone https://github.com/michaelcolletti/cpv
cd cpv
cargo build --release
# binary at: ./target/release/cpv
```

**Requirements:** Rust 1.75+ (install via [rustup.rs](https://rustup.rs))

---

## Usage

```
cpv [OPTIONS]

Options:
  -i, --input <FILE>                  Path to pip list output. If omitted, reads from stdin
  -q, --quiet                         Suppress clean package lines; show only vulnerable
      --json                          Output results as JSON (includes safe_version + dependents)
      --fail-on-vuln                  Exit code 2 if any vulnerabilities found (CI use)
  -r, --remediate                     Show fix versions and downstream dependents
      --output-requirements <FILE>    Write safe pinned requirements.txt
      --report <FILE>                 Write detailed Markdown remediation report
  -h, --help                          Print help
  -V, --version                       Print version
```

### Scan a pip list file

```bash
cpv --input pip_list.txt
```

### Pipe directly from pip

```bash
pip list | cpv
# or with pip freeze output
pip freeze | cpv
```

### Full remediation workflow

```bash
# 1. Scan + generate both artifacts
cpv --input pip_list.txt \
    --quiet \
    --remediate \
    --output-requirements safe_requirements.txt \
    --report remediation.md

# 2. Apply the safe requirements
pip install -r safe_requirements.txt

# 3. Review packages with no fix
grep "NO FIX" safe_requirements.txt
```

### CI pipeline (GitHub Actions)

```yaml
- name: Scan Python environment for CVEs
  run: |
    pip list | cpv --fail-on-vuln --quiet
```

Or with a report artifact:
```yaml
- name: Security scan
  run: |
    pip list | cpv --quiet --report security-report.md
- name: Upload security report
  uses: actions/upload-artifact@v4
  with:
    name: security-report
    path: security-report.md
```

### JSON output (for tooling integration)

```bash
cpv --input pip_list.txt --json | jq '.[] | select(.vulnerable) | {package, version, safe_version}'
```

```json
{
  "package": "urllib3",
  "version": "2.2.0",
  "safe_version": "2.6.3"
}
```

---

## How it works

```
pip list output
      │
      ▼
┌─────────────┐      ┌──────────────────────────────────┐
│   parser    │─────▶│  POST /v1/querybatch (≤1000/req) │
│  (name +    │      │  OSV.dev batch API               │
│  version)   │      └──────────────┬───────────────────┘
└─────────────┘                     │ vuln IDs (id + modified)
                                    ▼
                     ┌──────────────────────────────────┐
                     │  GET /v1/vulns/{id} ×N           │
                     │  concurrent via tokio JoinSet    │
                     └──────────────┬───────────────────┘
                                    │ full affected[] ranges
                                    ▼
                     ┌──────────────────────────────────┐
                     │  remediate::compute_safe_version │
                     │  • filter ECOSYSTEM ranges       │
                     │  • collect all fixed[] events    │
                     │  • take max across all vulns     │
                     └──────────────┬───────────────────┘
                                    │ SafeVersion::FixedIn(v)
                                    ▼
                          reporter (terminal / JSON /
                          requirements.txt / Markdown)
```

**Why two API calls?**
The OSV batch endpoint (`/v1/querybatch`) returns only `id + modified` per vuln — the full `affected` ranges with fix versions require a second call to `/v1/vulns/{id}`. `cpv` fans these out concurrently so total latency is roughly one network round-trip.

---

## Output modes

| Mode | Flag | Use case |
|------|------|----------|
| Terminal (default) | — | Human review; color-coded, per-CVE summaries |
| Quiet terminal | `--quiet` | Show only vulnerable packages |
| JSON | `--json` | Pipe to `jq`, SIEM, or dashboards |
| Requirements file | `--output-requirements` | Drop-in replacement pinned to safe versions |
| Markdown report | `--report` | Audit trail, PR comments, Confluence/Notion |
| Remediation plan | `--remediate` | Upgrade table with one-liner pip command |

---

## Remediation report structure

The `--report` Markdown output contains:

1. **Executive Summary** — package counts, total CVE records, packages with no fix
2. **Remediation Plan** — table mapping every vulnerable package to its safe version and downstream dependents
3. **Dependency Chain Analysis** — highlights transitive risk (e.g., `requests` is used by `langchain`, `selenium`, `google-auth`, `huggingface-hub`)
4. **Vulnerability Details** — per-package section with GHSA/CVE IDs, CVSS scores, published dates, advisory links
5. **Quick Fix Commands** — copy-paste pip upgrade block

---

## Security posture of cpv itself

`cpv` is regularly self-audited:

```bash
cargo audit    # scans all 196 transitive dependencies against RustSec advisory DB
cargo clippy -- -D warnings   # zero warnings policy
```

**Last audit result: 0 vulnerabilities in 196 crate dependencies.**

Dependencies are intentionally minimal:

| Crate | Purpose |
|-------|---------|
| `reqwest` | Async HTTP client (rustls or native-tls) |
| `tokio` | Async runtime |
| `serde` / `serde_json` | JSON serialization |
| `clap` | CLI argument parsing |
| `colored` | Terminal color output |
| `anyhow` | Error handling |

---

## Real-world scan example

Scanning a typical data-science / LLM environment (216 packages):

| Category | Count |
|---|---|
| Packages scanned | 216 |
| Vulnerable packages | 29 |
| Total CVE records | 87 |
| Packages with known fix | 28 |
| Packages with **no upstream fix** | 1 (`Pygments`) |

Notable findings from a real `pip list`:
- **`setuptools@65.5.0`** — 5 vulns including command injection via package URL (CVE-2024-6345) and path traversal (CVE-2025-47273). Safe version: `78.1.1`
- **`aiohttp@3.9.3`** — 12 vulns including DoS, request smuggling, zip-bomb amplification. Safe version: `3.13.3`
- **`langchain@0.1.6`** — 5 vulns including SQL injection and RCE via directory traversal. Safe version: `0.3.0`
- **`urllib3@2.2.0`** — 6 vulns including proxy credential leak and decompression bomb bypass. Safe version: `2.6.3`
- **`pip@24.0`** — 2 vulns including symlink path traversal. Safe version: `26.0`

---

## CI/CD integration

The repository ships with a [GitHub Actions workflow](.github/workflows/ci.yml) that:

1. **Check** — `rustfmt`, `clippy -D warnings`, `cargo audit` on every push/PR
2. **Test** — full test suite on Ubuntu, macOS, and Windows
3. **Release** — triggered by `v*.*.*` tags; cross-compiles binaries for:
   - Linux x86_64 and aarch64
   - macOS x86_64 and Apple Silicon
   - Windows x86_64
4. **Publish** — creates a GitHub Release with all binaries attached

To cut a release:
```bash
git tag v0.2.0 -m "feat: add SARIF output"
git push origin v0.2.0
```

---

## Contributing

```bash
git clone https://github.com/michaelcolletti/cpv
cd cpv
cargo test        # run unit tests
cargo clippy -- -D warnings   # must pass clean
cargo audit       # must pass clean
```

PRs welcome. Please keep the dependency count low and include tests for any new parser or version-comparison logic.

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">
Built with Rust 🦀 · Powered by <a href="https://osv.dev">OSV.dev</a> · Inspired by real-world supply-chain attacks
</div>
