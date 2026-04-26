use chrono::Utc;
use serde_json::Value;
use thiserror::Error;

use crate::model::{Credential, DidControlResult, DidDocument};
use crate::report::{CheckCategory, CheckResult, InspectionReport};

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
        "cryptographic.signature_not_verified",
        CheckCategory::CryptographicScope,
        "Signature bytes were not verified; this tool checks DID control and proof wiring, not cryptographic proof validity",
        "DID key control is not the same as proving that the credential payload was signed and unmodified.",
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
            "structure.required_fields",
            CheckCategory::Structure,
            "Required Verifiable Credential fields present",
            "A verifier needs the standard VC fields before it can interpret the credential.",
        ));
    } else {
        checks.push(CheckResult::fail(
            "structure.required_fields",
            CheckCategory::Structure,
            "Missing one or more required fields: @context, type=VerifiableCredential, issuer, validFrom/issuanceDate, credentialSubject",
            "Missing required fields can make the credential ambiguous or impossible to verify correctly.",
        ));
    }
}

fn validate_issuer(issuer: Option<&str>, checks: &mut Vec<CheckResult>) {
    match issuer {
        Some(id) if id.starts_with("did:") => {
            checks.push(CheckResult::pass(
                "structure.issuer_did",
                CheckCategory::Structure,
                "Issuer is DID-like",
                "The issuer identifier is the anchor used to locate issuer-controlled verification material.",
            ));
        }
        Some(_) => {
            checks.push(CheckResult::warn(
                "structure.issuer_did",
                CheckCategory::Structure,
                "Issuer is present but does not look like a DID",
                "A non-DID issuer may require a different trust or verification mechanism.",
            ));
        }
        None => {
            checks.push(CheckResult::fail(
                "structure.issuer_did",
                CheckCategory::Structure,
                "Issuer is missing",
                "Without an issuer, a verifier cannot determine who is making the credential claim.",
            ));
        }
    }
}

fn validate_dates(credential: &Credential, checks: &mut Vec<CheckResult>) {
    if credential.valid_from.is_some() {
        checks.push(CheckResult::pass(
            "validity.issued_at",
            CheckCategory::Validity,
            "Issuance date is present and parseable",
            "A verifier needs a valid issuance time to evaluate credential freshness and policy.",
        ));
    } else {
        checks.push(CheckResult::fail(
            "validity.issued_at",
            CheckCategory::Validity,
            "Issuance date is missing or not parseable",
            "A missing or invalid issuance date prevents reliable validity-window checks.",
        ));
    }

    match credential.valid_until {
        Some(valid_until) if valid_until < Utc::now() => {
            checks.push(CheckResult::fail(
                "validity.expiration",
                CheckCategory::Validity,
                "Credential is expired",
                "Expired credentials should not be accepted without an explicit policy exception.",
            ));
        }
        Some(_) => {
            checks.push(CheckResult::pass(
                "validity.expiration",
                CheckCategory::Validity,
                "Credential has not expired",
                "The credential is still inside its declared validity window.",
            ));
        }
        None => {
            checks.push(CheckResult::warn(
                "validity.expiration",
                CheckCategory::Validity,
                "No expiration date present; verifier must rely on issuer policy",
                "Without an expiration date, acceptance depends on external issuer or verifier policy.",
            ));
        }
    }
}

fn validate_proof(credential: &Credential, checks: &mut Vec<CheckResult>) {
    match &credential.proof {
        Some(proof) if proof.proof_type.is_some() && proof.verification_method.is_some() => {
            checks.push(CheckResult::pass(
                "structure.proof_metadata",
                CheckCategory::Structure,
                "Proof metadata present",
                "Proof metadata tells a verifier what verification method and proof format the credential references.",
            ));
        }
        Some(_) => {
            checks.push(CheckResult::warn(
                "structure.proof_metadata",
                CheckCategory::Structure,
                "Proof object present but missing type or verificationMethod",
                "Incomplete proof metadata makes the next verification step ambiguous.",
            ));
        }
        None => {
            checks.push(CheckResult::fail(
                "structure.proof_metadata",
                CheckCategory::Structure,
                "Proof metadata missing",
                "Without proof metadata, the credential cannot point to a verification method.",
            ));
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
            "did_control.check_skipped",
            CheckCategory::DidControl,
            "DID control could not be checked because proof metadata is missing",
            "DID control requires proof metadata that references a verification method.",
        ));
        return;
    };

    let Some(verification_method) = proof.verification_method.as_deref() else {
        checks.push(CheckResult::warn(
            "did_control.check_skipped",
            CheckCategory::DidControl,
            "DID control could not be checked because proof.verificationMethod is missing",
            "DID control requires a proof verificationMethod to compare against the DID Document.",
        ));
        return;
    };

    let Some(did_document) = did_document else {
        checks.push(CheckResult::warn(
            "did_control.document_supplied",
            CheckCategory::DidControl,
            "No DID Document supplied; issuer key control was not checked",
            "Without the issuer DID Document, this tool cannot check whether the referenced key belongs to the issuer.",
        ));
        return;
    };

    let Some(issuer) = issuer else {
        checks.push(CheckResult::fail(
            "did_control.issuer_match",
            CheckCategory::DidControl,
            "DID Document supplied but credential issuer is missing",
            "A DID Document cannot be safely matched when the credential issuer is absent.",
        ));
        return;
    };

    match did_document.validate_assertion_method_control(issuer, verification_method) {
        DidControlResult::Controlled => {
            checks.push(CheckResult::pass(
                "did_control.issuer_match",
                CheckCategory::DidControl,
                "DID Document id matches issuer",
                "The supplied DID Document must represent the credential issuer.",
            ));
            checks.push(CheckResult::pass(
                "did_control.assertion_method",
                CheckCategory::DidControl,
                "Proof verificationMethod is controlled by issuer and authorized for assertionMethod",
                "The proof should reference a key the issuer controls and authorizes for making claims.",
            ));
        }
        DidControlResult::IssuerMismatch {
            document_id,
            issuer,
        } => checks.push(CheckResult::fail(
            "did_control.issuer_match",
            CheckCategory::DidControl,
            format!("DID Document id {document_id} does not match issuer {issuer}"),
            "Using a DID Document for a different issuer can bind the credential to the wrong trust anchor.",
        )),
        DidControlResult::MethodNotDeclared {
            verification_method,
        } => checks.push(CheckResult::fail(
            "did_control.method_declared",
            CheckCategory::DidControl,
            format!(
                "Proof verificationMethod {verification_method} is not declared in issuer DID Document"
            ),
            "A verifier should not accept proof wiring to a key the issuer DID Document does not declare.",
        )),
        DidControlResult::ControllerMismatch {
            verification_method,
            controller,
            issuer,
        } => {
            let controller = controller.unwrap_or_else(|| "missing".to_string());
            checks.push(CheckResult::fail(
                "did_control.method_controller",
                CheckCategory::DidControl,
                format!(
                    "Proof verificationMethod {verification_method} is controlled by {controller}, not issuer {issuer}"
                ),
                "The verification method controller must match the issuer to support issuer key control.",
            ));
        }
        DidControlResult::MethodNotAuthorizedForAssertion {
            verification_method,
        } => checks.push(CheckResult::fail(
            "did_control.assertion_method",
            CheckCategory::DidControl,
            format!(
                "Proof verificationMethod {verification_method} is not authorized for assertionMethod"
            ),
            "A DID key can exist without being authorized for credential assertions.",
        )),
    }
}

fn validate_credential_status(credential: &Credential, checks: &mut Vec<CheckResult>) {
    if credential.credential_status.is_some() {
        checks.push(CheckResult::pass(
            "revocation.status_metadata",
            CheckCategory::Revocation,
            "Credential status metadata present",
            "Credential status metadata gives verifiers a way to perform revocation or suspension checks.",
        ));
    } else {
        checks.push(CheckResult::warn(
            "revocation.status_metadata",
            CheckCategory::Revocation,
            "No credentialStatus field; revocation cannot be checked from this credential",
            "Without credential status metadata, this tool cannot identify where revocation should be checked.",
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
    fn report_serializes_with_stable_check_ids() {
        let report = inspect_json_str_with_did_document(
            &fixture("valid-degree.json"),
            &did_fixture("university.json"),
        )
        .unwrap();
        let json = serde_json::to_value(&report).unwrap();

        assert_eq!(json["schema_version"], "1.0");
        assert_eq!(json["overall_status"], "warning");
        assert!(json["checks"].as_array().unwrap().iter().any(|check| {
            check["id"] == "did_control.assertion_method"
                && check["category"] == "did_control"
                && check["status"] == "pass"
                && check["why_it_matters"].is_string()
        }));
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
