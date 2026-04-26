use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    pub id: String,
    #[serde(default)]
    pub verification_method: Vec<DidVerificationMethod>,
    #[serde(default)]
    pub assertion_method: Vec<DidMethodReference>,
}

impl DidDocument {
    pub fn validate_assertion_method_control(
        &self,
        issuer: &str,
        verification_method: &str,
    ) -> DidControlResult {
        if self.id != issuer {
            return DidControlResult::IssuerMismatch {
                document_id: self.id.clone(),
                issuer: issuer.to_string(),
            };
        }

        let Some(method) = self
            .verification_method
            .iter()
            .find(|method| method.id == verification_method)
        else {
            return DidControlResult::MethodNotDeclared {
                verification_method: verification_method.to_string(),
            };
        };

        if method.controller.as_deref() != Some(issuer) {
            return DidControlResult::ControllerMismatch {
                verification_method: verification_method.to_string(),
                controller: method.controller.clone(),
                issuer: issuer.to_string(),
            };
        }

        if !self
            .assertion_method
            .iter()
            .any(|method| method.references(verification_method))
        {
            return DidControlResult::MethodNotAuthorizedForAssertion {
                verification_method: verification_method.to_string(),
            };
        }

        DidControlResult::Controlled
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DidVerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: Option<String>,
    pub controller: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum DidMethodReference {
    Id(String),
    Object(DidVerificationMethod),
}

impl DidMethodReference {
    pub fn references(&self, verification_method: &str) -> bool {
        match self {
            DidMethodReference::Id(id) => id == verification_method,
            DidMethodReference::Object(method) => method.id == verification_method,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DidControlResult {
    Controlled,
    IssuerMismatch {
        document_id: String,
        issuer: String,
    },
    MethodNotDeclared {
        verification_method: String,
    },
    ControllerMismatch {
        verification_method: String,
        controller: Option<String>,
        issuer: String,
    },
    MethodNotAuthorizedForAssertion {
        verification_method: String,
    },
}
