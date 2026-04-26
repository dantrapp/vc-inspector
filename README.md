# VC Inspector

A small Rust tool for inspecting W3C Verifiable Credentials and DID proof wiring.

VC Inspector parses a credential JSON file, optionally checks it against an issuer DID Document, and prints a pass/warn/fail report for trust-relevant structure: issuer, subject, claims, dates, proof metadata, DID assertion-method control, and credential status.

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

## What It Does Not Do

VC Inspector does not perform cryptographic signature-byte verification.

That is deliberate. Real verification requires resolving the issuer's DID Document through a trusted resolver, retrieving verification material, checking proof suites, canonicalizing the signed data, and using standards-aware identity libraries.

This tool validates credential structure, offline DID proof wiring, and trust-relevant metadata before deeper verification.

## Run It

```sh
cargo run -p vc_inspector_cli -- examples/valid-degree.json
```

Run it with an issuer DID Document:

```sh
cargo run -p vc_inspector_cli -- examples/valid-degree.json --did-doc examples/did-docs/university.json
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

## How To Explain This To A Non-Engineer

This tool checks whether a digital credential has the basic pieces a verifier would need before trusting it. When given a DID Document, it also checks whether the issuer controls and authorizes the key referenced by the proof. It does not prove the credential is authentic by itself; it shows where trust-relevant information is present, missing, expired, mismatched, or outside the tool's scope.

That boundary is the point.
