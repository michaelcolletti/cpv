mod osv;
mod parser;
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
                  backdoors, and supply-chain compromises affecting your Python environment."
)]
struct Cli {
    /// Path to a file containing `pip list` output.
    /// If omitted, reads from stdin (pipe `pip list` directly).
    #[arg(short, long, value_name = "FILE")]
    input: Option<PathBuf>,

    /// Show only vulnerable packages (suppress clean ones)
    #[arg(short, long)]
    quiet: bool,

    /// Output results as JSON
    #[arg(long)]
    json: bool,

    /// Exit with non-zero status if any vulnerabilities are found (useful in CI)
    #[arg(long)]
    fail_on_vuln: bool,
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

    let vuln_count = reporter::report(&results, cli.quiet, cli.json);

    if cli.fail_on_vuln && vuln_count > 0 {
        std::process::exit(2);
    }

    Ok(())
}
