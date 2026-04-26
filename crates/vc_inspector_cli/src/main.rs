use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use vc_inspector_core::{
    inspect_json_str, inspect_json_str_with_did_document, CheckStatus, InspectionReport,
};

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

    /// Print the inspection report as machine-readable JSON.
    #[arg(long)]
    json: bool,

    /// Write a human-readable Markdown report to this path.
    #[arg(long, value_name = "PATH")]
    markdown_report: Option<PathBuf>,
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

    if args.json {
        print_json_report(&report)?;
    } else {
        print_text_report(&report);
    }

    if let Some(markdown_report_path) = &args.markdown_report {
        fs::write(markdown_report_path, render_markdown_report(&report))
            .with_context(|| format!("failed to write {}", markdown_report_path.display()))?;
    }

    Ok(())
}

fn print_json_report(report: &InspectionReport) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}

fn print_text_report(report: &InspectionReport) {
    println!("VC INSPECTION REPORT");
    println!();
    println!("Schema Version: {}", report.schema_version);
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
        println!(
            "[{}] {} ({})",
            check.status.label(),
            check.message,
            check.id
        );
    }

    println!();
    println!("Trust Flow:");
    println!("issuer -> holder -> verifier");
}

fn render_markdown_report(report: &InspectionReport) -> String {
    let mut output = String::new();

    output.push_str("# VC Inspection Report\n\n");
    output.push_str(&format!("- Schema Version: {}\n", report.schema_version));
    output.push_str(&format!("- Format: {}\n", report.format));
    output.push_str(&format!(
        "- Issuer: {}\n",
        report.issuer.as_deref().unwrap_or("missing")
    ));
    output.push_str(&format!(
        "- Subject: {}\n",
        report.subject.as_deref().unwrap_or("missing")
    ));
    output.push_str(&format!(
        "- Credential Types: {}\n",
        if report.credential_types.is_empty() {
            "missing".to_string()
        } else {
            report.credential_types.join(", ")
        }
    ));
    output.push_str(&format!(
        "- Overall Status: {}\n\n",
        report.overall_status.label()
    ));

    output.push_str("## Summary\n\n");
    output.push_str(summary_for(report));
    output.push_str("\n\n");

    output.push_str("## Checks\n\n");
    output.push_str("| ID | Category | Status | Result | Why It Matters |\n");
    output.push_str("|---|---|---|---|---|\n");
    for check in &report.checks {
        output.push_str(&format!(
            "| `{}` | `{}` | {} | {} | {} |\n",
            check.id,
            check.category.label(),
            check.status.label(),
            escape_markdown_table_cell(&check.message),
            escape_markdown_table_cell(check.why_it_matters)
        ));
    }

    output.push_str("\n## Trust Flow\n\n");
    output.push_str("```text\nissuer -> holder -> verifier\n```\n");

    output
}

fn summary_for(report: &InspectionReport) -> &'static str {
    if report
        .checks
        .iter()
        .any(|check| matches!(check.status, CheckStatus::Fail))
    {
        "This credential failed one or more pre-verification checks. Review failed checks before attempting deeper cryptographic verification."
    } else if report
        .checks
        .iter()
        .any(|check| matches!(check.status, CheckStatus::Warn))
    {
        "This credential passed required pre-verification checks but still has warnings. Warnings may reflect missing optional metadata or checks that are intentionally out of scope."
    } else {
        "This credential passed all configured pre-verification checks."
    }
}

fn escape_markdown_table_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}
