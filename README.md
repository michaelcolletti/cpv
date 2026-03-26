<div align="center">

# 🔒 cpv — Check Pip Vulnerabilities

**A fast, accurate security scanner for Python environments — powered by OSV.dev**

[![CI](https://github.com/michaelcolletti/cpv/actions/workflows/ci.yml/badge.svg)](https://github.com/michaelcolletti/cpv/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust 1.75+](https://img.shields.io/badge/Rust-1.75%2B-orange)](https://www.rust-lang.org/)

A single-binary Rust tool that validates every package in your `pip list` against the **[OSV.dev](https://osv.dev)** vulnerability database — the same source powering GitHub Dependabot and Google's supply-chain security tooling.

Finds CVEs, backdoors, and supply-chain compromises like the [XZ Utils attack](https://www.xda-developers.com/popular-python-library-backdoor-machine/) **before** they reach production.

</div>

---

## Why cpv?

| Problem | What cpv does |
|---|---|
| `pip-audit` requires a separate install and virtual environment | `cpv` is a single compiled binary — drop it anywhere, no Python needed |
| Slow scanning on large environments | Concurrent HTTP fan-out; scans 200+ packages in ~3 seconds |
| Scan results with no fix guidance | Computes the **minimum safe upgrade version** directly from OSV range data |
| Transitive risk is invisible | Built-in dependency map flags packages pulled in by others |
| No CI gate | `--fail-on-vuln` returns exit code `2`; plugs into any pipeline |
| No audit trail | `--report` writes a full Markdown report with CVEs, CVSS scores, and pip commands |

> **Note:** `pip audit` is not a valid command — pip has no built-in security subcommand.
> The standalone [`pip-audit`](https://github.com/pypa/pip-audit) tool (`pip install pip-audit`) is the closest equivalent, but requires Python, a virtualenv, and a separate install step. `cpv` needs none of that.

---

## Demo

```
$ cpv --input pip_list.txt --quiet --remediate

Checking 216 packages against OSV.dev...

  ✗ aiohttp@3.9.3  (12 vulns)
    GHSA-5m98-qgg9-wh84 (CVE-2024-30251)
    aiohttp vulnerable to Denial of Service when trying to parse malformed POST requests
    Severity: CVSS_V3  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

  ✗ urllib3@2.2.0  (6 vulns)  ...
  ✗ tornado@6.4   (6 vulns)  ...
  ✗ setuptools@65.5.0  (5 vulns)  ...

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
# macOS — Apple Silicon
curl -Lo cpv https://github.com/michaelcolletti/cpv/releases/latest/download/cpv-macos-aarch64
chmod +x cpv && sudo mv cpv /usr/local/bin/

# macOS — Intel
curl -Lo cpv https://github.com/michaelcolletti/cpv/releases/latest/download/cpv-macos-x86_64
chmod +x cpv && sudo mv cpv /usr/local/bin/

# Linux — x86_64
curl -Lo cpv https://github.com/michaelcolletti/cpv/releases/latest/download/cpv-linux-x86_64
chmod +x cpv && sudo mv cpv /usr/local/bin/

# Linux — aarch64 (Graviton, Ampere, Raspberry Pi)
curl -Lo cpv https://github.com/michaelcolletti/cpv/releases/latest/download/cpv-linux-aarch64
chmod +x cpv && sudo mv cpv /usr/local/bin/
```

### From source

**Requirements:** Rust 1.75+ (install via [rustup.rs](https://rustup.rs))

```bash
# Install directly
cargo install --git https://github.com/michaelcolletti/cpv

# Or clone and build
git clone https://github.com/michaelcolletti/cpv
cd cpv
cargo build --release
./target/release/cpv --help
```

---

## Usage

```
cpv [OPTIONS]

Options:
  -i, --input <FILE>                  Path to `pip list` output file.
                                      Omit to read from stdin.
  -q, --quiet                         Suppress clean package lines; show only vulnerable
      --json                          Output results as JSON
                                      (includes safe_version and dependents fields)
      --fail-on-vuln                  Exit with code 2 if any vulnerabilities found
                                      (for CI pipeline gates)
  -r, --remediate                     Show fix versions and downstream dependents
      --output-requirements <FILE>    Write a safe pinned requirements.txt
      --report <FILE>                 Write a detailed Markdown remediation report
  -h, --help                          Print help
  -V, --version                       Print version
```

### Scan a saved pip list

```bash
pip list > pip_list.txt
cpv --input pip_list.txt
```

### Pipe directly from pip

```bash
# From a running environment
pip list | cpv

# Works with pip freeze output too
pip freeze | cpv
```

### Full remediation workflow

```bash
# 1. Scan and generate both output artifacts
cpv --input pip_list.txt \
    --quiet \
    --remediate \
    --output-requirements safe_requirements.txt \
    --report remediation.md

# 2. Review the plan
cat remediation.md

# 3. Apply safe versions
pip install -r safe_requirements.txt

# 4. Check what has no upstream fix yet
grep "NO FIX" safe_requirements.txt
```

### Gate a CI pipeline

```yaml
- name: Scan Python environment for CVEs
  run: pip list | cpv --fail-on-vuln --quiet
```

With a report artifact:

```yaml
- name: Security scan
  run: pip list | cpv --quiet --report security-report.md

- name: Upload security report
  uses: actions/upload-artifact@v4
  with:
    name: security-report
    path: security-report.md
```

### JSON output for tooling integration

```bash
cpv --input pip_list.txt --json \
  | jq '.[] | select(.vulnerable) | {package, version, safe_version}'
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
┌─────────────┐      ┌──────────────────────────────────────┐
│   parser    │─────▶│  POST /v1/querybatch  (≤1000/req)    │
│  (name +    │      │  OSV.dev batch API                   │
│  version)   │      └──────────────┬───────────────────────┘
└─────────────┘                     │  vuln IDs only (id + modified)
                                    ▼
                     ┌──────────────────────────────────────┐
                     │  GET /v1/vulns/{id}  ×N              │
                     │  concurrent via tokio::task::JoinSet │
                     └──────────────┬───────────────────────┘
                                    │  full affected[] ranges
                                    ▼
                     ┌──────────────────────────────────────┐
                     │  remediate::compute_safe_version     │
                     │  • filter ECOSYSTEM ranges only      │
                     │  • collect all fixed[] events        │
                     │  • take max across all vulns         │
                     └──────────────┬───────────────────────┘
                                    │  SafeVersion::FixedIn(v)
                                    ▼
                          reporter  (terminal · JSON ·
                          requirements.txt · Markdown)
```

**Why two API calls?**
The OSV batch endpoint returns only `id + modified` per vuln — the full `affected` ranges with fix versions require a second call to `/v1/vulns/{id}`. `cpv` fans these out concurrently so total latency is roughly one network round-trip regardless of how many vulnerabilities are found.

---

## Output modes

| Mode | Flag | Best for |
|------|------|----------|
| Terminal (default) | *(none)* | Human review; color-coded, per-CVE summaries |
| Quiet terminal | `--quiet` | Show only the vulnerable packages |
| JSON | `--json` | Pipe to `jq`, SIEMs, or dashboards |
| Requirements file | `--output-requirements` | Drop-in pip install with safe pinned versions |
| Markdown report | `--report` | Audit trail, PR comments, Confluence/Notion |
| Remediation plan | `--remediate` | Upgrade table + one-liner pip command |

---

## Remediation report contents

The `--report` Markdown output contains:

1. **Executive Summary** — total packages, CVE count, packages with no upstream fix
2. **Remediation Plan** — table mapping every vulnerable package to its safe version and downstream dependents
3. **Dependency Chain Analysis** — transitive risk highlights (e.g. `urllib3` is pulled in by `requests`, `selenium`, `httpcore`, `botocore`)
4. **Vulnerability Details** — per-package sections with GHSA/CVE IDs, CVSS scores, published dates, and advisory links
5. **Quick Fix Commands** — copy-paste `pip install --upgrade` block with exact safe versions

---

## Security posture of cpv itself

`cpv` runs `cargo audit` against its own dependency tree on every CI run:

```bash
cargo audit        # scans all transitive deps against the RustSec advisory DB
cargo clippy -- -D warnings   # zero-warnings policy enforced in CI
cargo fmt -- --check          # formatting enforced in CI
```

**Current audit result: 0 vulnerabilities in 162 transitive crate dependencies.**

Dependencies are intentionally minimal — no macros, no proc-macro heavy stacks:

| Crate | Purpose |
|-------|---------|
| `reqwest` | Async HTTP client (rustls — no OpenSSL dependency) |
| `tokio` | Async runtime |
| `serde` / `serde_json` | JSON serialization |
| `clap` | CLI argument parsing |
| `colored` | Terminal color output |
| `anyhow` | Ergonomic error propagation |

Using `rustls` (pure-Rust TLS) instead of OpenSSL means `cpv` cross-compiles cleanly to all targets with zero system library dependencies.

---

## Real-world scan results

Scanning a representative data-science / LLM environment (216 packages):

| Metric | Result |
|---|---|
| Packages scanned | 216 |
| Vulnerable packages | **29** (13%) |
| Total CVE/GHSA records | **87** |
| Packages with a known fix | 28 |
| Packages with **no upstream fix** | 1 (`Pygments`) |
| Scan time | ~3 seconds |

Notable findings from a real environment:

| Package | Version | Vulns | Worst issue | Safe version |
|---------|---------|-------|-------------|--------------|
| `aiohttp` | 3.9.3 | 12 | DoS, request smuggling, zip-bomb amplification | `3.13.3` |
| `setuptools` | 65.5.0 | 5 | Command injection via package URL (CVE-2024-6345) | `78.1.1` |
| `langchain` | 0.1.6 | 5 | SQL injection, RCE via directory traversal | `0.3.0` |
| `urllib3` | 2.2.0 | 6 | Proxy credential leak, decompression bomb bypass | `2.6.3` |
| `tornado` | 6.4 | 6 | HTTP smuggling, cookie parser DoS, CRLF injection | `6.5.5` |
| `pip` | 24.0 | 2 | Symlink path traversal during tar extraction | `26.0` |
| `Pygments` | 2.17.2 | 1 | ReDoS via GUID regex | **no fix yet** |

---

## CI/CD integration

The repository ships with a [GitHub Actions workflow](.github/workflows/ci.yml) with four jobs:

| Job | Trigger | What it does |
|-----|---------|--------------|
| **Check** | every push / PR | `rustfmt`, `clippy -D warnings`, `cargo audit` |
| **Test** | after Check passes | full test suite on Ubuntu, macOS, Windows |
| **Release** | `v*.*.*` tag | cross-compiles 5 platform binaries |
| **Publish** | after Release | creates GitHub Release with all binaries attached |

### Cutting a release

```bash
# Bump the version in Cargo.toml first, then:
git tag v0.2.0 -m "feat: add SARIF output"
git push origin v0.2.0
# CI builds and publishes the release automatically
```

Platform targets built on every release tag:

| Binary | Platform |
|--------|----------|
| `cpv-linux-x86_64` | Linux x86\_64 |
| `cpv-linux-aarch64` | Linux arm64 (Graviton, etc.) |
| `cpv-macos-x86_64` | macOS Intel |
| `cpv-macos-aarch64` | macOS Apple Silicon |
| `cpv-windows-x86_64.exe` | Windows x86\_64 |

---

## Contributing

```bash
git clone https://github.com/michaelcolletti/cpv
cd cpv
cargo test                    # run unit tests (8 tests)
cargo clippy -- -D warnings   # must pass with zero warnings
cargo fmt --all -- --check    # must pass clean
cargo audit                   # must report 0 vulnerabilities
```

PRs welcome. Please keep the dependency count low and include tests for any new parser or version-comparison logic. See the existing tests in `src/remediate.rs` and `src/parser.rs` for the expected style.

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">
Built with Rust 🦀 · Powered by <a href="https://osv.dev">OSV.dev</a> · Inspired by real supply-chain attacks
</div>
