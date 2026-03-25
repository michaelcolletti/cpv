/// The computed safe upgrade version for a package.
#[derive(Debug, Clone, PartialEq)]
pub enum SafeVersion {
    /// Upgrade to this version or higher.
    FixedIn(String),
    /// OSV has no fix event for this vulnerability — no known safe version.
    NoFixAvailable,
    /// The vulnerability record contained no usable ECOSYSTEM range data.
    Unknown,
}

use crate::osv::OsvVuln;

/// Compute the minimum safe version across all vulns for a package.
///
/// Strategy:
/// - For each vuln, scan all ECOSYSTEM ranges for `fixed` events.
/// - Collect all fixed versions; take the maximum (you need to be >= the highest fix).
/// - If any vuln has ranges but no `fixed` event, it is `NoFixAvailable`.
/// - If no ECOSYSTEM ranges exist at all, it is `Unknown`.
/// - Across all vulns for a package, take the maximum fixed version.
///   If any single vuln is `NoFixAvailable`, the whole package is `NoFixAvailable`.
pub fn compute_safe_version(vulns: &[OsvVuln]) -> SafeVersion {
    if vulns.is_empty() {
        return SafeVersion::Unknown;
    }

    let mut overall_max: Option<String> = None;
    let mut any_no_fix = false;

    for vuln in vulns {
        let ecosystem_ranges: Vec<_> = vuln
            .affected
            .iter()
            .flat_map(|a| a.ranges.iter())
            .filter(|r| r.range_type == "ECOSYSTEM")
            .collect();

        if ecosystem_ranges.is_empty() {
            // No ECOSYSTEM range — treat as unknown for this vuln; don't block overall.
            continue;
        }

        let fixed_versions: Vec<&str> = ecosystem_ranges
            .iter()
            .flat_map(|r| r.events.iter())
            .filter_map(|e| e.fixed.as_deref())
            .collect();

        let has_last_affected = ecosystem_ranges
            .iter()
            .flat_map(|r| r.events.iter())
            .any(|e| e.last_affected.is_some());

        if fixed_versions.is_empty() {
            if has_last_affected {
                any_no_fix = true;
            }
            // If neither fixed nor last_affected, OSV just hasn't filled in the range yet.
            // Treat as unknown — don't block the overall result.
            continue;
        }

        // Take the maximum fixed version across all ranges for this vuln.
        let vuln_max = fixed_versions
            .into_iter()
            .reduce(|a, b| version_max_str(a, b))
            .unwrap();

        overall_max = Some(match overall_max {
            None => vuln_max.to_string(),
            Some(prev) => version_max_str(&prev, vuln_max).to_string(),
        });
    }

    if any_no_fix {
        return SafeVersion::NoFixAvailable;
    }

    match overall_max {
        Some(v) => SafeVersion::FixedIn(v),
        None => SafeVersion::Unknown,
    }
}

// ── Version comparison ─────────────────────────────────────────────────────────

/// Returns true if `a` is strictly greater than `b`.
///
/// Handles Python-style versions including pre-release suffixes:
///   "3.10.0" > "3.9.99", "6.4.2" > "6.4", "0.43" > "0.43b0"
pub fn version_gt(a: &str, b: &str) -> bool {
    let parts_a: Vec<&str> = a.split('.').collect();
    let parts_b: Vec<&str> = b.split('.').collect();
    let len = parts_a.len().max(parts_b.len());

    for i in 0..len {
        let seg_a = parts_a.get(i).copied().unwrap_or("0");
        let seg_b = parts_b.get(i).copied().unwrap_or("0");
        let (num_a, suf_a) = parse_version_segment(seg_a);
        let (num_b, suf_b) = parse_version_segment(seg_b);

        match num_a.cmp(&num_b) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => {
                // Empty suffix = release. Any suffix = pre-release.
                // Release beats pre-release: "" > "b0", "" > "rc1"
                match (suf_a.is_empty(), suf_b.is_empty()) {
                    (true, false) => return true,
                    (false, true) => return false,
                    _ => match suf_a.cmp(suf_b) {
                        std::cmp::Ordering::Greater => return true,
                        std::cmp::Ordering::Less => return false,
                        std::cmp::Ordering::Equal => continue,
                    },
                }
            }
        }
    }
    false // equal is not greater
}

fn parse_version_segment(s: &str) -> (u64, &str) {
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let num: u64 = s[..split].parse().unwrap_or(0);
    (num, &s[split..])
}

fn version_max_str<'a>(a: &'a str, b: &'a str) -> &'a str {
    if version_gt(a, b) {
        a
    } else {
        b
    }
}

// ── Known dependency relationships ─────────────────────────────────────────────

/// Returns a list of packages in the user's environment that depend on `pkg_name`.
/// This is a curated static map based on well-known PyPI package relationships.
pub fn known_dependents(pkg_name: &str) -> &'static [&'static str] {
    match pkg_name.to_lowercase().as_str() {
        "urllib3" => &["requests", "selenium", "httpcore", "botocore"],
        "requests" => &[
            "langchain",
            "langchain-community",
            "langsmith",
            "google-auth",
            "selenium",
            "huggingface-hub",
        ],
        "certifi" => &["requests", "httpcore"],
        "idna" => &["requests", "httpx", "email-validator"],
        "h11" => &["httpcore", "uvicorn"],
        "httpcore" => &["httpx"],
        "starlette" => &["fastapi", "langserve"],
        "jinja2" => &[
            "jupyter_server",
            "langchain-core",
            "nbconvert",
            "jupyterlab",
        ],
        "tornado" => &["jupyter_server", "ipykernel"],
        "aiohttp" => &["langchain-community", "fsspec"],
        "langchain-core" => &["langchain", "langchain-community", "langserve"],
        "langchain" => &["langchain-community", "langserve"],
        "orjson" => &["chromadb"],
        "protobuf" => &["grpcio", "googleapis-common-protos", "opentelemetry-proto"],
        "pyasn1" => &["pyasn1-modules", "rsa"],
        "setuptools" => &["pip", "build", "many packages at install time"],
        "pillow" => &["fpdf2", "matplotlib"],
        "pygments" => &["rich", "nbconvert", "jupyterlab", "ipykernel"],
        "filelock" => &["huggingface-hub", "fsspec", "tokenizers"],
        "tqdm" => &["huggingface-hub", "langchain"],
        "zipp" => &["importlib-metadata", "importlib-resources"],
        "marshmallow" => &["dataclasses-json", "langchain-community"],
        "fonttools" => &["pillow"],
        "black" => &["langchain-cli"],
        "jupyter_server" => &["jupyterlab", "notebook_shim"],
        "nbconvert" => &["jupyterlab", "jupyter_server"],
        "pyarrow" => &["pandas", "langchain-community"],
        "orjson_" => &["chromadb"],
        _ => &[],
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_version_comparison() {
        assert!(version_gt("3.10.0", "3.9.99"));
        assert!(version_gt("6.4.2", "6.4"));
        assert!(version_gt("1.0.0", "0.99.99"));
        assert!(!version_gt("1.0.0", "1.0.0"));
        assert!(!version_gt("2.0", "3.0"));
    }

    #[test]
    fn prerelease_comparison() {
        assert!(version_gt("0.43", "0.43b0"));
        assert!(version_gt("1.0", "1.0rc1"));
        assert!(!version_gt("1.0b1", "1.0"));
        assert!(!version_gt("0.43b0", "0.43"));
    }

    #[test]
    fn version_zero_sentinel() {
        assert!(version_gt("3.9.4", "0"));
        assert!(!version_gt("0", "3.9.4"));
    }

    #[test]
    fn compute_safe_version_no_vulns() {
        assert_eq!(compute_safe_version(&[]), SafeVersion::Unknown);
    }

    #[test]
    fn compute_safe_version_takes_max_across_vulns() {
        use crate::osv::{OsvAffected, OsvEvent, OsvRange, OsvVuln};

        let make_vuln = |fixed: &str| OsvVuln {
            id: "GHSA-test".into(),
            summary: None,
            details: None,
            severity: vec![],
            aliases: vec![],
            published: None,
            modified: None,
            references: vec![],
            affected: vec![OsvAffected {
                package: None,
                ranges: vec![OsvRange {
                    range_type: "ECOSYSTEM".into(),
                    events: vec![
                        OsvEvent {
                            introduced: Some("0".into()),
                            fixed: None,
                            last_affected: None,
                        },
                        OsvEvent {
                            introduced: None,
                            fixed: Some(fixed.into()),
                            last_affected: None,
                        },
                    ],
                }],
            }],
        };

        let vulns = vec![make_vuln("3.9.4"), make_vuln("3.10.0"), make_vuln("3.9.8")];
        assert_eq!(
            compute_safe_version(&vulns),
            SafeVersion::FixedIn("3.10.0".into())
        );
    }
}
