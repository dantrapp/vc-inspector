use chrono::Utc;
use serde_json::Value;
use thiserror::Error;

use crate::model::{Credential, DidControlResult, DidDocument};
use crate::report::{CheckResult, InspectionReport};

#[derive(Debug, Error)]
pub enum InspectionError {
    #[error("credential JSON could not be parsed or mapped to supported credential fields: {0}")]
    InvalidCredentialJson(serde_json::Error),
    #[error("DID Document JSON could not be parsed or mapped to supported DID fields: {0}")]
    InvalidDidDocumentJson(serde_json::Error),
}

pub fn inspect_json_str(input: &str) -> Result<InspectionReport, InspectionError> {
    let value: Value =
        serde_json::from_str(input).map_err(InspectionError::InvalidCredentialJson)?;
    inspect_value(value)
}

pub fn inspect_json_str_with_did_document(
    input: &str,
    did_document: &str,
) -> Result<InspectionReport, InspectionError> {
    let value: Value =
        serde_json::from_str(input).map_err(InspectionError::InvalidCredentialJson)?;
    let did_document: DidDocument =
        serde_json::from_str(did_document).map_err(InspectionError::InvalidDidDocumentJson)?;
    inspect_value_with_did_document(value, Some(&did_document))
}

pub fn inspect_value(value: Value) -> Result<InspectionReport, InspectionError> {
    inspect_value_with_did_document(value, None)
}

pub fn inspect_value_with_did_document(
    value: Value,
    did_document: Option<&DidDocument>,
) -> Result<InspectionReport, InspectionError> {
    let credential: Credential =
        serde_json::from_value(value).map_err(InspectionError::InvalidCredentialJson)?;

    let issuer = credential.issuer_id().map(ToString::to_string);
    let subject = credential.subject_id().map(ToString::to_string);
    let credential_types = credential.types();

    let mut checks = Vec::new();

    validate_required_fields(&credential, &credential_types, &mut checks);
    validate_issuer(issuer.as_deref(), &mut checks);
    validate_dates(&credential, &mut checks);
    validate_proof(&credential, &mut checks);
    validate_did_document(&credential, issuer.as_deref(), did_document, &mut checks);
    validate_credential_status(&credential, &mut checks);

    checks.push(CheckResult::warn(
        "Signature bytes were not verified; this tool checks DID control and proof wiring, not cryptographic proof validity",
    ));

    Ok(InspectionReport::new(
        issuer,
        subject,
        credential_types,
        checks,
    ))
}

fn validate_required_fields(
    credential: &Credential,
    credential_types: &[String],
    checks: &mut Vec<CheckResult>,
) {
    if credential.context.is_some()
        && credential.issuer.is_some()
        && credential.credential_subject.is_some()
        && credential.valid_from.is_some()
        && credential_types
            .iter()
            .any(|credential_type| credential_type == "VerifiableCredential")
    {
        checks.push(CheckResult::pass(
            "Required Verifiable Credential fields present",
        ));
    } else {
        checks.push(CheckResult::fail(
            "Missing one or more required fields: @context, type=VerifiableCredential, issuer, validFrom/issuanceDate, credentialSubject",
        ));
    }
}

fn validate_issuer(issuer: Option<&str>, checks: &mut Vec<CheckResult>) {
    match issuer {
        Some(id) if id.starts_with("did:") => {
            checks.push(CheckResult::pass("Issuer is DID-like"));
        }
        Some(_) => {
            checks.push(CheckResult::warn(
                "Issuer is present but does not look like a DID",
            ));
        }
        None => {
            checks.push(CheckResult::fail("Issuer is missing"));
        }
    }
}

fn validate_dates(credential: &Credential, checks: &mut Vec<CheckResult>) {
    if credential.valid_from.is_some() {
        checks.push(CheckResult::pass("Issuance date is present and parseable"));
    } else {
        checks.push(CheckResult::fail(
            "Issuance date is missing or not parseable",
        ));
    }

    match credential.valid_until {
        Some(valid_until) if valid_until < Utc::now() => {
            checks.push(CheckResult::fail("Credential is expired"));
        }
        Some(_) => {
            checks.push(CheckResult::pass("Credential has not expired"));
        }
        None => {
            checks.push(CheckResult::warn(
                "No expiration date present; verifier must rely on issuer policy",
            ));
        }
    }
}

fn validate_proof(credential: &Credential, checks: &mut Vec<CheckResult>) {
    match &credential.proof {
        Some(proof) if proof.proof_type.is_some() && proof.verification_method.is_some() => {
            checks.push(CheckResult::pass("Proof metadata present"));
        }
        Some(_) => {
            checks.push(CheckResult::warn(
                "Proof object present but missing type or verificationMethod",
            ));
        }
        None => {
            checks.push(CheckResult::fail("Proof metadata missing"));
        }
    }
}

fn validate_did_document(
    credential: &Credential,
    issuer: Option<&str>,
    did_document: Option<&DidDocument>,
    checks: &mut Vec<CheckResult>,
) {
    let Some(proof) = &credential.proof else {
        checks.push(CheckResult::warn(
            "DID control could not be checked because proof metadata is missing",
        ));
        return;
    };

    let Some(verification_method) = proof.verification_method.as_deref() else {
        checks.push(CheckResult::warn(
            "DID control could not be checked because proof.verificationMethod is missing",
        ));
        return;
    };

    let Some(did_document) = did_document else {
        checks.push(CheckResult::warn(
            "No DID Document supplied; issuer key control was not checked",
        ));
        return;
    };

    let Some(issuer) = issuer else {
        checks.push(CheckResult::fail(
            "DID Document supplied but credential issuer is missing",
        ));
        return;
    };

    match did_document.validate_assertion_method_control(issuer, verification_method) {
        DidControlResult::Controlled => {
            checks.push(CheckResult::pass("DID Document id matches issuer"));
            checks.push(CheckResult::pass(
                "Proof verificationMethod is controlled by issuer and authorized for assertionMethod",
            ));
        }
        DidControlResult::IssuerMismatch {
            document_id,
            issuer,
        } => checks.push(CheckResult::fail(format!(
            "DID Document id {document_id} does not match issuer {issuer}"
        ))),
        DidControlResult::MethodNotDeclared {
            verification_method,
        } => checks.push(CheckResult::fail(format!(
            "Proof verificationMethod {verification_method} is not declared in issuer DID Document"
        ))),
        DidControlResult::ControllerMismatch {
            verification_method,
            controller,
            issuer,
        } => {
            let controller = controller.unwrap_or_else(|| "missing".to_string());
            checks.push(CheckResult::fail(format!(
                "Proof verificationMethod {verification_method} is controlled by {controller}, not issuer {issuer}"
            )));
        }
        DidControlResult::MethodNotAuthorizedForAssertion {
            verification_method,
        } => checks.push(CheckResult::fail(format!(
            "Proof verificationMethod {verification_method} is not authorized for assertionMethod"
        ))),
    }
}

fn validate_credential_status(credential: &Credential, checks: &mut Vec<CheckResult>) {
    if credential.credential_status.is_some() {
        checks.push(CheckResult::pass("Credential status metadata present"));
    } else {
        checks.push(CheckResult::warn(
            "No credentialStatus field; revocation cannot be checked from this credential",
        ));
    }
}

#[cfg(test)]
mod tests {
    use crate::report::{CheckStatus, OverallStatus};

    use super::{inspect_json_str, inspect_json_str_with_did_document};

    fn fixture(name: &str) -> String {
        let path = format!("../../examples/{name}");
        std::fs::read_to_string(path).expect("fixture should be readable")
    }

    fn did_fixture(name: &str) -> String {
        let path = format!("../../examples/did-docs/{name}");
        std::fs::read_to_string(path).expect("DID fixture should be readable")
    }

    #[test]
    fn valid_degree_passes_did_control_with_cryptographic_scope_warning() {
        let report = inspect_json_str_with_did_document(
            &fixture("valid-degree.json"),
            &did_fixture("university.json"),
        )
        .unwrap();

        assert_eq!(report.issuer.as_deref(), Some("did:example:university"));
        assert_eq!(report.subject.as_deref(), Some("did:example:student123"));
        assert_eq!(report.overall_status, OverallStatus::Warning);
        assert!(report
            .checks
            .iter()
            .any(|check| check.message.contains("DID Document id matches issuer")));
        assert!(report
            .checks
            .iter()
            .any(|check| check.message.contains("Signature bytes")));
    }

    #[test]
    fn missing_did_document_warns() {
        let report = inspect_json_str(&fixture("valid-degree.json")).unwrap();

        assert!(report
            .checks
            .iter()
            .any(|check| check.status == CheckStatus::Warn
                && check.message.contains("No DID Document supplied")));
    }

    #[test]
    fn mismatched_did_document_fails() {
        let report = inspect_json_str_with_did_document(
            &fixture("valid-degree.json"),
            &did_fixture("wrong-controller.json"),
        )
        .unwrap();

        assert_eq!(report.overall_status, OverallStatus::Fail);
        assert!(report
            .checks
            .iter()
            .any(|check| check.status == CheckStatus::Fail
                && check.message.contains("does not match issuer")));
    }

    #[test]
    fn undeclared_verification_method_fails() {
        let report = inspect_json_str_with_did_document(
            &fixture("valid-degree.json"),
            &did_fixture("missing-method.json"),
        )
        .unwrap();

        assert_eq!(report.overall_status, OverallStatus::Fail);
        assert!(report.checks.iter().any(|check| {
            check.status == CheckStatus::Fail && check.message.contains("not declared")
        }));
    }

    #[test]
    fn wrong_method_controller_fails() {
        let report = inspect_json_str_with_did_document(
            &fixture("valid-degree.json"),
            &did_fixture("wrong-method-controller.json"),
        )
        .unwrap();

        assert_eq!(report.overall_status, OverallStatus::Fail);
        assert!(report.checks.iter().any(|check| {
            check.status == CheckStatus::Fail && check.message.contains("not issuer")
        }));
    }

    #[test]
    fn method_without_assertion_authorization_fails() {
        let report = inspect_json_str_with_did_document(
            &fixture("valid-degree.json"),
            &did_fixture("not-assertion-authorized.json"),
        )
        .unwrap();

        assert_eq!(report.overall_status, OverallStatus::Fail);
        assert!(report.checks.iter().any(|check| {
            check.status == CheckStatus::Fail
                && check.message.contains("not authorized for assertionMethod")
        }));
    }

    #[test]
    fn expired_license_fails() {
        let report = inspect_json_str(&fixture("expired-license.json")).unwrap();

        assert_eq!(report.overall_status, OverallStatus::Fail);
        assert!(report
            .checks
            .iter()
            .any(|check| check.status == CheckStatus::Fail && check.message.contains("expired")));
    }

    #[test]
    fn missing_proof_fails() {
        let report = inspect_json_str(&fixture("missing-proof.json")).unwrap();

        assert_eq!(report.overall_status, OverallStatus::Fail);
        assert!(report
            .checks
            .iter()
            .any(|check| check.status == CheckStatus::Fail && check.message.contains("Proof")));
    }

    #[test]
    fn missing_status_warns() {
        let report = inspect_json_str(&fixture("missing-status.json")).unwrap();

        assert!(report
            .checks
            .iter()
            .any(|check| check.status == CheckStatus::Warn
                && check.message.contains("credentialStatus")));
    }
}
