use colored::Colorize;
use serde_json;

use crate::osv::PackageResult;

/// Print results to stdout. Returns the count of vulnerable packages.
pub fn report(results: &[PackageResult], quiet: bool, as_json: bool) -> usize {
    if as_json {
        return report_json(results);
    }
    report_human(results, quiet)
}

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
                format!(
                    "{} ({})",
                    v.id.yellow(),
                    cve_aliases.join(", ").yellow()
                )
            };

            println!("    {}", id_line);

            if let Some(summary) = &v.summary {
                println!("    {}", summary);
            }

            // Show CVSS score if available
            if let Some(sev) = v.severity.first() {
                println!("    Severity: {} {}", sev.severity_type, sev.score.red());
            }

            // Show the most useful reference (advisory > article > web)
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

fn report_json(results: &[PackageResult]) -> usize {
    let output: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            serde_json::json!({
                "package": r.package.name,
                "version": r.package.version,
                "vulnerable": !r.vulns.is_empty(),
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
