mod osv;
mod parser;
mod remediate;
mod reporter;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

/// cpv — Check pip packages for known security vulnerabilities via OSV.dev
#[derive(Parser, Debug)]
#[command(
    name = "cpv",
    version,
    about = "Validates pip packages against the OSV vulnerability database",
    long_about = "Parses `pip list` output and queries https://osv.dev for known CVEs,\n\
                  backdoors, and supply-chain compromises affecting your Python environment.\n\n\
                  Examples:\n\
                    cpv --input pip_list.txt\n\
                    pip list | cpv\n\
                    cpv --input pip_list.txt --remediate\n\
                    cpv --input pip_list.txt --remediate --output-requirements safe_reqs.txt --report remediation.md"
)]
struct Cli {
    /// Path to a file containing `pip list` output.
    /// If omitted, reads from stdin (pipe `pip list` directly).
    #[arg(short, long, value_name = "FILE")]
    input: Option<PathBuf>,

    /// Show only vulnerable packages (suppress clean package lines)
    #[arg(short, long)]
    quiet: bool,

    /// Output results as JSON (includes safe_version and dependents fields)
    #[arg(long)]
    json: bool,

    /// Exit with non-zero status code 2 if any vulnerabilities are found (for CI pipelines)
    #[arg(long)]
    fail_on_vuln: bool,

    /// Show remediation plan: compute safe upgrade versions and list downstream dependents
    #[arg(short, long)]
    remediate: bool,

    /// Write a pip requirements file with safe pinned versions.
    /// Vulnerable packages are upgraded to their fix version; unfixable packages are commented out.
    #[arg(long, value_name = "FILE")]
    output_requirements: Option<PathBuf>,

    /// Write a detailed Markdown remediation report documenting all vulnerabilities,
    /// fix versions, CVSS scores, dependency chains, and pip upgrade commands.
    #[arg(long, value_name = "FILE")]
    report: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Read pip list content from file or stdin
    let content = match &cli.input {
        Some(path) => std::fs::read_to_string(path)?,
        None => {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf
        }
    };

    let packages = parser::parse_pip_list(&content);

    if packages.is_empty() {
        eprintln!("No packages found. Provide `pip list` output via --input or stdin.");
        std::process::exit(1);
    }

    eprintln!("Checking {} packages against OSV.dev...", packages.len());

    let client = osv::OsvClient::new();
    let results = client.query_batch(&packages).await?;

    let opts = reporter::ReportOptions {
        quiet: cli.quiet,
        as_json: cli.json,
        remediate: cli.remediate,
        output_requirements: cli.output_requirements.as_deref(),
        report_file: cli.report.as_deref(),
    };

    let vuln_count = reporter::report(&results, &opts);

    if cli.fail_on_vuln && vuln_count > 0 {
        std::process::exit(2);
    }

    Ok(())
}
