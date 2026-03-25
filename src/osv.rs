use std::collections::HashMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::parser::Package;

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL: &str = "https://api.osv.dev/v1/vulns";
/// OSV limits batch queries to 1000 per request
const BATCH_CHUNK_SIZE: usize = 1000;

// ── Request types ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct OsvQuery {
    version: String,
    package: OsvPackageRef,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OsvPackageRef {
    pub name: String,
    pub ecosystem: String,
}

#[derive(Serialize)]
struct OsvBatchRequest {
    queries: Vec<OsvQuery>,
}

// ── Response types ─────────────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct OsvBatchResponse {
    pub results: Vec<OsvQueryResult>,
}

#[derive(Deserialize, Debug, Default)]
pub struct OsvQueryResult {
    #[serde(default)]
    pub vulns: Vec<OsvVuln>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OsvVuln {
    pub id: String,
    pub summary: Option<String>,
    // Kept for JSON completeness / future use
    #[allow(dead_code)]
    pub details: Option<String>,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub published: Option<String>,
    // Kept for JSON completeness / future use
    #[allow(dead_code)]
    pub modified: Option<String>,
    #[serde(default)]
    pub references: Vec<OsvReference>,
    /// Version ranges showing which versions are affected and what fixes them.
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OsvAffected {
    // Kept for potential future package-filtering logic
    #[allow(dead_code)]
    pub package: Option<OsvPackageRef>,
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OsvRange {
    /// "ECOSYSTEM", "SEMVER", or "GIT"
    #[serde(rename = "type")]
    pub range_type: String,
    #[serde(default)]
    pub events: Vec<OsvEvent>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct OsvEvent {
    /// Version at which the vulnerability was introduced (used for context, not fix logic).
    #[allow(dead_code)]
    pub introduced: Option<String>,
    /// Version at which the vulnerability was fixed (exclusive lower bound for safety).
    pub fixed: Option<String>,
    /// Last affected version (no fix released).
    pub last_affected: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub severity_type: String,
    pub score: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OsvReference {
    #[serde(rename = "type")]
    pub ref_type: Option<String>,
    pub url: String,
}

// ── Result bundle returned to reporter ────────────────────────────────────────

#[derive(Debug)]
pub struct PackageResult {
    pub package: Package,
    pub vulns: Vec<OsvVuln>,
}

// ── Client ─────────────────────────────────────────────────────────────────────

pub struct OsvClient {
    client: reqwest::Client,
}

impl OsvClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    /// Query OSV for all packages, chunking into batches of BATCH_CHUNK_SIZE.
    /// Then fetches full vuln details (including `affected` ranges) for all
    /// unique vuln IDs found, so fix versions are available.
    pub async fn query_batch(&self, packages: &[Package]) -> Result<Vec<PackageResult>> {
        let mut results: Vec<PackageResult> = Vec::with_capacity(packages.len());

        for chunk in packages.chunks(BATCH_CHUNK_SIZE) {
            let queries: Vec<OsvQuery> = chunk
                .iter()
                .map(|p| OsvQuery {
                    version: p.version.clone(),
                    package: OsvPackageRef {
                        name: p.name.clone(),
                        ecosystem: "PyPI".to_string(),
                    },
                })
                .collect();

            let body = OsvBatchRequest { queries };
            let resp: OsvBatchResponse = self
                .client
                .post(OSV_BATCH_URL)
                .json(&body)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            for (pkg, result) in chunk.iter().zip(resp.results.into_iter()) {
                results.push(PackageResult {
                    package: pkg.clone(),
                    vulns: result.vulns,
                });
            }
        }

        // Collect unique vuln IDs from vulnerable packages
        let ids: Vec<String> = {
            let mut seen = std::collections::HashSet::new();
            results
                .iter()
                .flat_map(|r| r.vulns.iter().map(|v| v.id.clone()))
                .filter(|id| seen.insert(id.clone()))
                .collect()
        };

        if !ids.is_empty() {
            let details = self.fetch_vuln_details(ids).await?;
            // Replace stub vulns with full detail vulns
            for r in &mut results {
                for v in &mut r.vulns {
                    if let Some(full) = details.get(&v.id) {
                        *v = full.clone();
                    }
                }
            }
        }

        Ok(results)
    }

    /// Fetch full vuln details for a list of IDs concurrently.
    async fn fetch_vuln_details(&self, ids: Vec<String>) -> Result<HashMap<String, OsvVuln>> {
        let mut set = tokio::task::JoinSet::new();

        for id in ids {
            let client = self.client.clone();
            let url = format!("{}/{}", OSV_VULN_URL, id);
            set.spawn(async move {
                let result: Result<OsvVuln, _> = client
                    .get(&url)
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await;
                result.map(|v| (id, v))
            });
        }

        let mut map = HashMap::new();
        while let Some(res) = set.join_next().await {
            match res {
                Ok(Ok((id, vuln))) => {
                    map.insert(id, vuln);
                }
                Ok(Err(e)) => eprintln!("Warning: failed to fetch vuln details: {e}"),
                Err(e) => eprintln!("Warning: task error: {e}"),
            }
        }

        Ok(map)
    }
}
