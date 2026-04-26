mod credential;
mod did;

pub use credential::{Credential, CredentialSubject, Issuer, OneOrMany, Proof};
pub use did::{DidControlResult, DidDocument};
