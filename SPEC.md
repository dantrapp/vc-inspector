# VC Inspector Spec

## Purpose

VC Inspector is a small Rust developer tool for inspecting the structure, DID proof wiring, and trust-relevant fields of W3C Verifiable Credentials.

It is intentionally scoped as a small, standards-aware verifier skeleton:

- Show typed backend literacy in Rust.
- Show standards-aware thinking around digital credentials.
- Show disciplined security boundaries by checking DID key control without pretending to perform full cryptographic verification.
- Produce output that is easy to understand and audit.

## Target User

Primary user: an engineer learning why a credential passes or fails basic structural checks.

Secondary audience: a technical reviewer who wants clear evidence of trust-boundary handling and implementation constraints.

## Non-Goals

- Do not perform cryptographic signature-byte verification.
- Do not resolve DID documents over the network.
- Do not check live revocation registries.
- Do not claim production readiness.
- Do not build a full web application in the first version.

## Core Workflow

1. User runs the CLI with a credential JSON file.
2. The tool parses the credential into typed Rust structs.
3. The tool extracts issuer, subject, credential type, validity dates, proof metadata, and credential status metadata.
4. If supplied, the tool parses the issuer DID Document into typed Rust structs.
5. The validator runs deterministic checks.
6. The CLI prints a concise report with pass, warning, or fail results.

## Validation Rules

Required first version:

- Credential is valid JSON.
- `@context` is present.
- `type` includes `VerifiableCredential`.
- `issuer` is present and DID-like.
- `credentialSubject` is present.
- Issuance date is present and parseable.
- Expiration date, when present, has not passed.
- Proof metadata is present.
- Optional DID Document `id` matches the credential issuer.
- Optional DID Document declares the proof `verificationMethod`.
- Optional DID Document verification method is controlled by the issuer.
- Optional DID Document authorizes the method for `assertionMethod`.
- Credential status metadata is present, otherwise warn that revocation cannot be checked.
- Signature bytes are not verified, otherwise warn that proof validity remains out of scope.

Each check includes:

- Stable ID, such as `did_control.assertion_method`.
- Category, such as `did_control` or `revocation`.
- Status: `pass`, `warn`, or `fail`.
- Human-readable message.
- Short explanation of why the check matters.

## Output Shape

The text output should be understandable without knowing Rust:

```text
VC INSPECTION REPORT

Format: JSON-LD Verifiable Credential
Issuer: did:example:dmv
Subject: did:example:person123
Credential Types: VerifiableCredential, MobileDriverLicenseCredential
Overall Status: WARNING

Checks:
[PASS] Required fields present
[PASS] Issuer is DID-like
[PASS] Credential has not expired
[PASS] DID Document id matches issuer
[PASS] Proof verificationMethod is controlled by issuer and authorized for assertionMethod
[WARN] No credentialStatus field; revocation cannot be checked
[WARN] Signature bytes were not verified

Trust Flow:
issuer -> holder -> verifier
```

The JSON output should be stable enough for automation:

```json
{
  "schema_version": "1.0",
  "format": "JSON-LD Verifiable Credential",
  "issuer": "did:example:dmv",
  "subject": "did:example:person123",
  "credential_types": ["VerifiableCredential", "MobileDriverLicenseCredential"],
  "overall_status": "warning",
  "checks": [
    {
      "id": "revocation.status_metadata",
      "category": "revocation",
      "status": "warn",
      "message": "No credentialStatus field; revocation cannot be checked from this credential",
      "why_it_matters": "Without credential status metadata, this tool cannot identify where revocation should be checked."
    }
  ]
}
```

## Example Credentials

- `valid-degree.json`: clean credential with proof and credential status.
- `expired-license.json`: expired credential.
- `missing-proof.json`: structurally recognizable but missing proof metadata.
- `missing-status.json`: valid enough to inspect but no credential status metadata.
- `did-docs/university.json`: DID Document that controls and authorizes `did:example:university#key-1`.
- `did-docs/wrong-controller.json`: DID Document id mismatch failure.
- `did-docs/missing-method.json`: undeclared verification method failure.
- `did-docs/wrong-method-controller.json`: declared method controlled by another DID failure.
- `did-docs/not-assertion-authorized.json`: declared method not authorized for assertion failure.

## Success Criteria

- `cargo test` passes.
- CLI works against all example credentials.
- CLI supports `--did-doc` to check issuer DID proof wiring.
- CLI supports `--json` for machine-readable output.
- CLI supports `--markdown-report` for reviewable report artifacts.
- README explains what the tool does, what it does not do, and why that boundary matters.
- The project can be explained as: "It checks whether a digital credential has the pieces a verifier would care about, including whether the claimed issuer document controls the key referenced by the proof, before deeper cryptographic verification."
