use colored::Colorize;
use std::io::Write as IoWrite;
use std::path::Path;

use crate::osv::PackageResult;
use crate::remediate::{compute_safe_version, known_dependents, SafeVersion};

pub struct ReportOptions<'a> {
    pub quiet: bool,
    pub as_json: bool,
    pub remediate: bool,
    pub output_requirements: Option<&'a Path>,
    pub report_file: Option<&'a Path>,
}

/// Print results to stdout. Returns the count of vulnerable packages.
pub fn report(results: &[PackageResult], opts: &ReportOptions) -> usize {
    if opts.as_json {
        return report_json(results);
    }

    let vuln_count = report_human(results, opts.quiet);

    if opts.remediate {
        print_remediation(results);
    }

    if let Some(path) = opts.output_requirements {
        if let Err(e) = write_requirements(results, path) {
            eprintln!("Warning: could not write requirements file: {e}");
        } else {
            eprintln!("Wrote safe requirements to {}", path.display());
        }
    }

    if let Some(path) = opts.report_file {
        if let Err(e) = write_markdown_report(results, path) {
            eprintln!("Warning: could not write report: {e}");
        } else {
            eprintln!("Wrote remediation report to {}", path.display());
        }
    }

    vuln_count
}

// ── Human-readable scan output ─────────────────────────────────────────────────

fn report_human(results: &[PackageResult], quiet: bool) -> usize {
    let total = results.len();
    let vulnerable: Vec<&PackageResult> = results.iter().filter(|r| !r.vulns.is_empty()).collect();
    let vuln_count = vulnerable.len();

    if !quiet {
        for r in results {
            if r.vulns.is_empty() {
                println!(
                    "  {} {}@{}",
                    "✓".green(),
                    r.package.name.bold(),
                    r.package.version
                );
            }
        }
    }

    for r in &vulnerable {
        println!(
            "\n  {} {}@{}  ({} vuln{})",
            "✗".red().bold(),
            r.package.name.bold().red(),
            r.package.version,
            r.vulns.len(),
            if r.vulns.len() == 1 { "" } else { "s" }
        );
        for v in &r.vulns {
            let cve_aliases: Vec<&str> = v
                .aliases
                .iter()
                .filter(|a| a.starts_with("CVE-"))
                .map(String::as_str)
                .collect();

            let id_line = if cve_aliases.is_empty() {
                v.id.yellow().to_string()
            } else {
                format!("{} ({})", v.id.yellow(), cve_aliases.join(", ").yellow())
            };

            println!("    {}", id_line);

            if let Some(summary) = &v.summary {
                println!("    {}", summary);
            }

            if let Some(sev) = v.severity.first() {
                println!("    Severity: {} {}", sev.severity_type, sev.score.red());
            }

            let best_ref = v
                .references
                .iter()
                .find(|r| r.ref_type.as_deref() == Some("ADVISORY"))
                .or_else(|| v.references.first());
            if let Some(r) = best_ref {
                println!("    Ref: {}", r.url.dimmed());
            }
        }
    }

    println!(
        "\n{} {} package{} checked — {} vulnerable",
        "→".cyan(),
        total,
        if total == 1 { "" } else { "s" },
        if vuln_count == 0 {
            "0".green().to_string()
        } else {
            vuln_count.to_string().red().bold().to_string()
        }
    );

    vuln_count
}

// ── Remediation table ──────────────────────────────────────────────────────────

fn print_remediation(results: &[PackageResult]) {
    let vulnerable: Vec<&PackageResult> = results.iter().filter(|r| !r.vulns.is_empty()).collect();
    if vulnerable.is_empty() {
        return;
    }

    println!(
        "\n{}",
        "─── Remediation Plan ───────────────────────────────────────".cyan()
    );
    println!(
        "  {:<35} {:<15} {:<20} {}",
        "Package".bold(),
        "Current".bold(),
        "Safe Version".bold(),
        "Dependents in env".bold()
    );
    println!("  {}", "─".repeat(90).dimmed());

    for r in &vulnerable {
        let safe = compute_safe_version(&r.vulns);
        let safe_str = match &safe {
            SafeVersion::FixedIn(v) => format!("upgrade → {}", v).green().to_string(),
            SafeVersion::NoFixAvailable => "NO FIX AVAILABLE".red().bold().to_string(),
            SafeVersion::Unknown => "unknown".yellow().to_string(),
        };

        let deps = known_dependents(&r.package.name);
        let dep_str = if deps.is_empty() {
            "—".dimmed().to_string()
        } else {
            deps.join(", ").yellow().to_string()
        };

        println!(
            "  {:<35} {:<15} {:<20} {}",
            r.package.name.bold(),
            r.package.version,
            safe_str,
            dep_str
        );
    }

    // Generate the pip upgrade command for packages that have a fix
    let upgrades: Vec<String> = vulnerable
        .iter()
        .filter_map(|r| {
            if let SafeVersion::FixedIn(v) = compute_safe_version(&r.vulns) {
                Some(format!("{}=={}", r.package.name, v))
            } else {
                None
            }
        })
        .collect();

    if !upgrades.is_empty() {
        println!("\n{}", "  Quick fix (run this):".cyan().bold());
        println!("  pip install --upgrade {}", upgrades.join(" \\\n    "));
    }

    let no_fix: Vec<&str> = vulnerable
        .iter()
        .filter(|r| compute_safe_version(&r.vulns) == SafeVersion::NoFixAvailable)
        .map(|r| r.package.name.as_str())
        .collect();

    if !no_fix.is_empty() {
        println!(
            "\n  {} Packages with no upstream fix: {}",
            "⚠".yellow().bold(),
            no_fix.join(", ").red()
        );
        println!("  Consider removing or replacing these packages.");
    }
}

// ── Requirements file writer ───────────────────────────────────────────────────

/// Write a pip requirements file with safe pinned versions.
/// - Vulnerable packages with a known fix: pinned to the fix version.
/// - Vulnerable packages with no fix: commented out with a warning.
/// - Clean packages: pinned to their current version.
fn write_requirements(results: &[PackageResult], path: &Path) -> anyhow::Result<()> {
    let mut file = std::fs::File::create(path)?;

    writeln!(file, "# Generated by cpv — safe pinned requirements")?;
    writeln!(file, "# Run: pip install -r {}", path.display())?;
    writeln!(
        file,
        "# Packages with NO FIX are commented out — review manually\n"
    )?;

    for r in results {
        if r.vulns.is_empty() {
            writeln!(file, "{}=={}", r.package.name, r.package.version)?;
        } else {
            let safe = compute_safe_version(&r.vulns);
            match safe {
                SafeVersion::FixedIn(v) => {
                    let ids: Vec<&str> = r.vulns.iter().map(|v| v.id.as_str()).collect();
                    writeln!(
                        file,
                        "{}=={}  # upgraded from {} — fixes: {}",
                        r.package.name,
                        v,
                        r.package.version,
                        ids.join(", ")
                    )?;
                }
                SafeVersion::NoFixAvailable => {
                    let ids: Vec<&str> = r.vulns.iter().map(|v| v.id.as_str()).collect();
                    writeln!(
                        file,
                        "# NO FIX: {}=={}  # vulns: {} — REMOVE OR REPLACE",
                        r.package.name,
                        r.package.version,
                        ids.join(", ")
                    )?;
                }
                SafeVersion::Unknown => {
                    let ids: Vec<&str> = r.vulns.iter().map(|v| v.id.as_str()).collect();
                    writeln!(
                        file,
                        "# REVIEW: {}=={}  # vulns: {} — fix version unknown",
                        r.package.name,
                        r.package.version,
                        ids.join(", ")
                    )?;
                }
            }
        }
    }

    Ok(())
}

// ── Markdown report writer ─────────────────────────────────────────────────────

fn write_markdown_report(results: &[PackageResult], path: &Path) -> anyhow::Result<()> {
    let mut f = std::fs::File::create(path)?;

    let vulnerable: Vec<&PackageResult> = results.iter().filter(|r| !r.vulns.is_empty()).collect();
    let total_vulns: usize = vulnerable.iter().map(|r| r.vulns.len()).sum();
    let no_fix_count = vulnerable
        .iter()
        .filter(|r| compute_safe_version(&r.vulns) == SafeVersion::NoFixAvailable)
        .count();

    writeln!(f, "# cpv Security Remediation Report\n")?;
    writeln!(
        f,
        "> Generated by [cpv](https://github.com/michaelcolletti/cpv)\n"
    )?;

    // Executive summary
    writeln!(f, "## Executive Summary\n")?;
    writeln!(f, "| Metric | Value |")?;
    writeln!(f, "|--------|-------|")?;
    writeln!(f, "| Total packages scanned | {} |", results.len())?;
    writeln!(f, "| Vulnerable packages | {} |", vulnerable.len())?;
    writeln!(f, "| Total vulnerability records | {} |", total_vulns)?;
    writeln!(f, "| Packages with no known fix | {} |", no_fix_count)?;
    writeln!(
        f,
        "| Clean packages | {} |\n",
        results.len() - vulnerable.len()
    )?;

    // Remediation summary table
    writeln!(f, "## Remediation Plan\n")?;
    writeln!(
        f,
        "| Package | Current Version | Safe Version | Action | Downstream Dependents |"
    )?;
    writeln!(
        f,
        "|---------|----------------|-------------|--------|----------------------|"
    )?;

    for r in &vulnerable {
        let safe = compute_safe_version(&r.vulns);
        let (safe_str, action) = match &safe {
            SafeVersion::FixedIn(v) => (format!("`{}`", v), "Upgrade"),
            SafeVersion::NoFixAvailable => ("**None**".into(), "Remove / Replace"),
            SafeVersion::Unknown => ("Unknown".into(), "Monitor"),
        };
        let deps = known_dependents(&r.package.name);
        let dep_str = if deps.is_empty() {
            "—".into()
        } else {
            deps.iter()
                .map(|d| format!("`{}`", d))
                .collect::<Vec<_>>()
                .join(", ")
        };
        writeln!(
            f,
            "| `{}` | `{}` | {} | {} | {} |",
            r.package.name, r.package.version, safe_str, action, dep_str
        )?;
    }

    writeln!(f)?;

    // Dependency chain analysis
    writeln!(f, "## Dependency Chain Analysis\n")?;
    writeln!(
        f,
        "Vulnerable packages that are depended on by other packages in this environment \
         represent **transitive risk** — fixing the leaf package may not be sufficient \
         if the dependent also pins an older version.\n"
    )?;

    let transitive: Vec<(&PackageResult, Vec<&str>)> = vulnerable
        .iter()
        .filter_map(|r| {
            let deps = known_dependents(&r.package.name);
            if deps.is_empty() {
                None
            } else {
                Some((*r, deps.to_vec()))
            }
        })
        .collect();

    if transitive.is_empty() {
        writeln!(f, "_No transitive dependency issues detected._\n")?;
    } else {
        for (r, deps) in &transitive {
            let safe = compute_safe_version(&r.vulns);
            let safe_note = match &safe {
                SafeVersion::FixedIn(v) => format!("Fixed in `{}`", v),
                SafeVersion::NoFixAvailable => "**No upstream fix available**".into(),
                SafeVersion::Unknown => "Fix version unknown".into(),
            };

            writeln!(f, "### `{}` ({})", r.package.name, r.package.version)?;
            writeln!(f, "- **Status:** {}", safe_note)?;
            writeln!(
                f,
                "- **Used by:** {}",
                deps.iter()
                    .map(|d| format!("`{}`", d))
                    .collect::<Vec<_>>()
                    .join(", ")
            )?;
            writeln!(
                f,
                "- **Action:** Upgrade `{}`, then verify dependents still resolve correctly.",
                r.package.name
            )?;
            writeln!(f)?;
        }
    }

    // Per-package vulnerability detail
    writeln!(f, "## Vulnerability Details\n")?;

    for r in &vulnerable {
        let safe = compute_safe_version(&r.vulns);
        let safe_badge = match &safe {
            SafeVersion::FixedIn(v) => format!("Fix: upgrade to `{}`", v),
            SafeVersion::NoFixAvailable => "**NO FIX — remove or replace**".into(),
            SafeVersion::Unknown => "_Fix version unknown — monitor upstream_".into(),
        };

        writeln!(f, "### `{}` @ `{}`\n", r.package.name, r.package.version)?;
        writeln!(f, "**{}**\n", safe_badge)?;

        for v in &r.vulns {
            let cves: Vec<&str> = v
                .aliases
                .iter()
                .filter(|a| a.starts_with("CVE-"))
                .map(String::as_str)
                .collect();

            let title = if cves.is_empty() {
                format!("#### {}", v.id)
            } else {
                format!("#### {} ({})", v.id, cves.join(", "))
            };
            writeln!(f, "{}\n", title)?;

            if let Some(summary) = &v.summary {
                writeln!(f, "{}\n", summary)?;
            }

            if let Some(sev) = v.severity.first() {
                writeln!(
                    f,
                    "- **Severity:** `{}` score `{}`",
                    sev.severity_type, sev.score
                )?;
            }

            if let Some(published) = &v.published {
                let date = published.split('T').next().unwrap_or(published);
                writeln!(f, "- **Published:** {}", date)?;
            }

            if !v.aliases.is_empty() {
                writeln!(f, "- **Aliases:** {}", v.aliases.join(", "))?;
            }

            let advisory_refs: Vec<&str> = v
                .references
                .iter()
                .filter(|r| r.ref_type.as_deref() == Some("ADVISORY"))
                .map(|r| r.url.as_str())
                .collect();
            if !advisory_refs.is_empty() {
                writeln!(f, "- **Advisories:**")?;
                for url in advisory_refs {
                    writeln!(f, "  - <{}>", url)?;
                }
            }

            let web_refs: Vec<&str> = v
                .references
                .iter()
                .filter(|r| r.ref_type.as_deref() != Some("ADVISORY"))
                .map(|r| r.url.as_str())
                .take(3)
                .collect();
            if !web_refs.is_empty() {
                writeln!(f, "- **References:**")?;
                for url in web_refs {
                    writeln!(f, "  - <{}>", url)?;
                }
            }

            writeln!(f)?;
        }

        writeln!(f, "---\n")?;
    }

    // pip upgrade snippet
    let upgrades: Vec<String> = vulnerable
        .iter()
        .filter_map(|r| {
            if let SafeVersion::FixedIn(v) = compute_safe_version(&r.vulns) {
                Some(format!("{}=={}", r.package.name, v))
            } else {
                None
            }
        })
        .collect();

    if !upgrades.is_empty() {
        writeln!(f, "## Quick Fix Commands\n")?;
        writeln!(f, "```bash")?;
        writeln!(f, "pip install --upgrade \\")?;
        for (i, pkg) in upgrades.iter().enumerate() {
            if i < upgrades.len() - 1 {
                writeln!(f, "  {} \\", pkg)?;
            } else {
                writeln!(f, "  {}", pkg)?;
            }
        }
        writeln!(f, "```\n")?;
    }

    Ok(())
}

// ── JSON output ────────────────────────────────────────────────────────────────

fn report_json(results: &[PackageResult]) -> usize {
    let output: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            let safe = compute_safe_version(&r.vulns);
            let safe_version = match &safe {
                SafeVersion::FixedIn(v) => serde_json::json!(v),
                SafeVersion::NoFixAvailable => serde_json::json!("no_fix"),
                SafeVersion::Unknown => serde_json::json!(null),
            };
            serde_json::json!({
                "package": r.package.name,
                "version": r.package.version,
                "vulnerable": !r.vulns.is_empty(),
                "safe_version": safe_version,
                "dependents": known_dependents(&r.package.name),
                "vulnerabilities": r.vulns.iter().map(|v| {
                    serde_json::json!({
                        "id": v.id,
                        "aliases": v.aliases,
                        "summary": v.summary,
                        "severity": v.severity.iter().map(|s| {
                            serde_json::json!({"type": s.severity_type, "score": s.score})
                        }).collect::<Vec<_>>(),
                        "published": v.published,
                        "references": v.references.iter().map(|r| r.url.clone()).collect::<Vec<_>>(),
                    })
                }).collect::<Vec<_>>(),
            })
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&output).unwrap());

    results.iter().filter(|r| !r.vulns.is_empty()).count()
}
