# VC Inspector

A small Rust tool for inspecting W3C Verifiable Credentials and DID proof wiring.

VC Inspector parses a credential JSON file, optionally checks it against an issuer DID Document, and prints a pass/warn/fail report for trust-relevant structure: issuer, subject, claims, dates, proof metadata, DID assertion-method control, and credential status.

VC Inspector is a credential trust-boundary inspector for reviewing Verifiable Credential structure, DID proof wiring, and verification readiness before full cryptographic validation.

## Why I Built This

I built this to better understand the trust model behind standards-based digital identity systems: how credentials move from issuer to holder to verifier, where verification can fail, and why scoped, explicit validation matters before relying on a credential in a real system.

## Why This Exists

Digital credential systems depend on precise trust boundaries. This project is intentionally boring: typed parsing, explicit validation, clear warnings, and no unsafe claims.

The goal is to understand the identity flow:

```text
issuer -> holder -> verifier
```

In plain English: someone issues a credential, a person or wallet holds it, and a verifier checks whether it should be trusted.

## What It Checks

- Is the credential valid JSON?
- Does it look like a W3C Verifiable Credential?
- Who issued it?
- Who is it about?
- What credential types does it declare?
- Has it expired?
- Does it include proof metadata?
- If a DID Document is supplied, does its `id` match the credential issuer?
- Does the DID Document declare the proof's `verificationMethod`?
- Is that method controlled by the issuer?
- Is that method authorized for `assertionMethod`?
- Does it include credential status metadata for revocation checks?

## Security Boundary

VC Inspector does not perform cryptographic signature-byte verification.

That is deliberate. Real verification requires resolving the issuer's DID Document through a trusted resolver, retrieving verification material, checking proof suites, canonicalizing the signed data, and using a standards-aware identity library such as SpruceID's open-source `ssi`.

This tool validates credential structure, offline DID proof wiring, and trust-relevant metadata before deeper verification.

## Use Case

VC Inspector is a credential trust-boundary inspector. It is useful when integrating credential issuance or verification flows and you need to answer basic questions before deeper cryptographic verification:

- Is the credential malformed?
- Is required metadata missing?
- Is the credential expired?
- Does the proof point to a key controlled by the issuer DID Document?
- Is credential status metadata present for later revocation checks?

The JSON output is intended for automation, CI checks, or a future UI. The Markdown output is intended for review notes, demos, and debugging handoffs.

## Run It

```sh
cargo run -p vc_inspector_cli -- examples/valid-degree.json
```

Run it with an issuer DID Document:

```sh
cargo run -p vc_inspector_cli -- examples/valid-degree.json --did-doc examples/did-docs/university.json
```

Print machine-readable JSON:

```sh
cargo run -p vc_inspector_cli -- examples/valid-degree.json --did-doc examples/did-docs/university.json --json
```

Write a Markdown report:

```sh
cargo run -p vc_inspector_cli -- examples/valid-degree.json --did-doc examples/did-docs/university.json --markdown-report examples/reports/valid-degree.md
```

Try the warning and failure examples:

```sh
cargo run -p vc_inspector_cli -- examples/expired-license.json
cargo run -p vc_inspector_cli -- examples/missing-proof.json
cargo run -p vc_inspector_cli -- examples/missing-status.json
cargo run -p vc_inspector_cli -- examples/valid-degree.json --did-doc examples/did-docs/wrong-controller.json
```

## Test It

```sh
cargo test
```

## Example Output

```text
VC INSPECTION REPORT

Format: JSON-LD Verifiable Credential
Issuer: did:example:university
Subject: did:example:student123
Credential Types: VerifiableCredential, UniversityDegreeCredential
Overall Status: WARNING

Checks:
[PASS] Required Verifiable Credential fields present
[PASS] Issuer is DID-like
[PASS] Issuance date is present and parseable
[PASS] Credential has not expired
[PASS] Proof metadata present
[PASS] DID Document id matches issuer
[PASS] Proof verificationMethod is controlled by issuer and authorized for assertionMethod
[PASS] Credential status metadata present
[WARN] Signature bytes were not verified

Trust Flow:
issuer -> holder -> verifier
```

## JSON Output

The JSON report uses a stable schema version and explicit check IDs:

```json
{
  "schema_version": "1.0",
  "overall_status": "warning",
  "checks": [
    {
      "id": "did_control.assertion_method",
      "category": "did_control",
      "status": "pass",
      "message": "Proof verificationMethod is controlled by issuer and authorized for assertionMethod",
      "why_it_matters": "The proof should reference a key the issuer controls and authorizes for making claims."
    }
  ]
}
```

## ELI5

Think of a digital credential like an ID card.

This tool checks whether the card has the important parts: who issued it, who it is for, whether it expired, and what key was supposed to sign it. If you give it the issuer's DID Document, it also checks whether that key actually belongs to the issuer.

It does not fully prove the ID is real yet. It checks whether the ID is structured correctly before deeper cryptographic verification.
