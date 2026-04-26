use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use vc_inspector_core::{inspect_json_str, inspect_json_str_with_did_document, InspectionReport};

#[derive(Debug, Parser)]
#[command(
    name = "vc-inspect",
    about = "Inspect trust-relevant structure in W3C Verifiable Credentials"
)]
struct Args {
    /// Path to a Verifiable Credential JSON file.
    credential: PathBuf,

    /// Optional DID Document JSON for the credential issuer.
    #[arg(long)]
    did_doc: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let input = fs::read_to_string(&args.credential)
        .with_context(|| format!("failed to read {}", args.credential.display()))?;
    let report = if let Some(did_doc_path) = &args.did_doc {
        let did_document = fs::read_to_string(did_doc_path)
            .with_context(|| format!("failed to read {}", did_doc_path.display()))?;
        inspect_json_str_with_did_document(&input, &did_document)?
    } else {
        inspect_json_str(&input)?
    };

    print_report(&report);

    Ok(())
}

fn print_report(report: &InspectionReport) {
    println!("VC INSPECTION REPORT");
    println!();
    println!("Format: {}", report.format);
    println!("Issuer: {}", report.issuer.as_deref().unwrap_or("missing"));
    println!(
        "Subject: {}",
        report.subject.as_deref().unwrap_or("missing")
    );
    println!(
        "Credential Types: {}",
        if report.credential_types.is_empty() {
            "missing".to_string()
        } else {
            report.credential_types.join(", ")
        }
    );
    println!("Overall Status: {}", report.overall_status.label());
    println!();
    println!("Checks:");

    for check in &report.checks {
        println!("[{}] {}", check.status.label(), check.message);
    }

    println!();
    println!("Trust Flow:");
    println!("issuer -> holder -> verifier");
}
