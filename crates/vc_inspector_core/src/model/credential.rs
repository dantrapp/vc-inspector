use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    pub fn iter(&self) -> Box<dyn Iterator<Item = &T> + '_> {
        match self {
            OneOrMany::One(value) => Box::new(std::iter::once(value)),
            OneOrMany::Many(values) => Box::new(values.iter()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Issuer {
    Id(String),
    Object { id: String },
}

impl Issuer {
    pub fn id(&self) -> &str {
        match self {
            Issuer::Id(id) => id,
            Issuer::Object { id } => id,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    #[serde(rename = "@context")]
    pub context: Option<OneOrMany<Value>>,
    #[serde(rename = "type")]
    pub credential_type: Option<OneOrMany<String>>,
    pub issuer: Option<Issuer>,
    #[serde(alias = "issuanceDate")]
    pub valid_from: Option<DateTime<Utc>>,
    #[serde(alias = "expirationDate")]
    pub valid_until: Option<DateTime<Utc>>,
    pub credential_subject: Option<CredentialSubject>,
    pub credential_status: Option<Value>,
    pub proof: Option<Proof>,
}

impl Credential {
    pub fn issuer_id(&self) -> Option<&str> {
        self.issuer.as_ref().map(Issuer::id)
    }

    pub fn subject_id(&self) -> Option<&str> {
        self.credential_subject
            .as_ref()
            .and_then(CredentialSubject::primary_id)
    }

    pub fn types(&self) -> Vec<String> {
        self.credential_type
            .as_ref()
            .map(|types| types.iter().cloned().collect())
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum CredentialSubject {
    One(Value),
    Many(Vec<Value>),
}

impl CredentialSubject {
    pub fn primary_id(&self) -> Option<&str> {
        match self {
            CredentialSubject::One(value) => value.get("id").and_then(Value::as_str),
            CredentialSubject::Many(values) => values
                .iter()
                .find_map(|value| value.get("id").and_then(Value::as_str)),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    #[serde(rename = "type")]
    pub proof_type: Option<String>,
    pub created: Option<DateTime<Utc>>,
    pub proof_purpose: Option<String>,
    pub verification_method: Option<String>,
}
