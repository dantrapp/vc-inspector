# VC Inspection Report

- Schema Version: 1.0
- Format: JSON-LD Verifiable Credential
- Issuer: did:example:university
- Subject: did:example:student123
- Credential Types: VerifiableCredential, UniversityDegreeCredential
- Overall Status: WARNING

## Summary

This credential passed required pre-verification checks but still has warnings. Warnings may reflect missing optional metadata or checks that are intentionally out of scope.

## Checks

| ID | Category | Status | Result | Why It Matters |
|---|---|---|---|---|
| `structure.required_fields` | `structure` | PASS | Required Verifiable Credential fields present | A verifier needs the standard VC fields before it can interpret the credential. |
| `structure.issuer_did` | `structure` | PASS | Issuer is DID-like | The issuer identifier is the anchor used to locate issuer-controlled verification material. |
| `validity.issued_at` | `validity` | PASS | Issuance date is present and parseable | A verifier needs a valid issuance time to evaluate credential freshness and policy. |
| `validity.expiration` | `validity` | PASS | Credential has not expired | The credential is still inside its declared validity window. |
| `structure.proof_metadata` | `structure` | PASS | Proof metadata present | Proof metadata tells a verifier what verification method and proof format the credential references. |
| `did_control.issuer_match` | `did_control` | PASS | DID Document id matches issuer | The supplied DID Document must represent the credential issuer. |
| `did_control.assertion_method` | `did_control` | PASS | Proof verificationMethod is controlled by issuer and authorized for assertionMethod | The proof should reference a key the issuer controls and authorizes for making claims. |
| `revocation.status_metadata` | `revocation` | PASS | Credential status metadata present | Credential status metadata gives verifiers a way to perform revocation or suspension checks. |
| `cryptographic.signature_not_verified` | `cryptographic_scope` | WARN | Signature bytes were not verified; this tool checks DID control and proof wiring, not cryptographic proof validity | DID key control is not the same as proving that the credential payload was signed and unmodified. |

## Trust Flow

```text
issuer -> holder -> verifier
```
