use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::parser::Package;

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
/// OSV limits batch queries to 1000 per request
const BATCH_CHUNK_SIZE: usize = 1000;

// ── Request types ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct OsvQuery {
    version: String,
    package: OsvPackageRef,
}

#[derive(Serialize)]
struct OsvPackageRef {
    name: String,
    ecosystem: String,
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
    pub details: Option<String>,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub published: Option<String>,
    pub modified: Option<String>,
    #[serde(default)]
    pub references: Vec<OsvReference>,
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

        Ok(results)
    }
}
