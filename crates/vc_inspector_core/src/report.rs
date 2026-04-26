use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckCategory {
    Structure,
    Validity,
    DidControl,
    Revocation,
    CryptographicScope,
}

impl CheckCategory {
    pub fn label(self) -> &'static str {
        match self {
            CheckCategory::Structure => "structure",
            CheckCategory::Validity => "validity",
            CheckCategory::DidControl => "did_control",
            CheckCategory::Revocation => "revocation",
            CheckCategory::CryptographicScope => "cryptographic_scope",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

impl CheckStatus {
    pub fn label(self) -> &'static str {
        match self {
            CheckStatus::Pass => "PASS",
            CheckStatus::Warn => "WARN",
            CheckStatus::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckResult {
    pub id: &'static str,
    pub category: CheckCategory,
    pub status: CheckStatus,
    pub message: String,
    pub why_it_matters: &'static str,
}

impl CheckResult {
    pub fn pass(
        id: &'static str,
        category: CheckCategory,
        message: impl Into<String>,
        why_it_matters: &'static str,
    ) -> Self {
        Self {
            id,
            category,
            status: CheckStatus::Pass,
            message: message.into(),
            why_it_matters,
        }
    }

    pub fn warn(
        id: &'static str,
        category: CheckCategory,
        message: impl Into<String>,
        why_it_matters: &'static str,
    ) -> Self {
        Self {
            id,
            category,
            status: CheckStatus::Warn,
            message: message.into(),
            why_it_matters,
        }
    }

    pub fn fail(
        id: &'static str,
        category: CheckCategory,
        message: impl Into<String>,
        why_it_matters: &'static str,
    ) -> Self {
        Self {
            id,
            category,
            status: CheckStatus::Fail,
            message: message.into(),
            why_it_matters,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OverallStatus {
    Pass,
    Warning,
    Fail,
}

impl OverallStatus {
    pub fn label(self) -> &'static str {
        match self {
            OverallStatus::Pass => "PASS",
            OverallStatus::Warning => "WARNING",
            OverallStatus::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InspectionReport {
    pub schema_version: &'static str,
    pub format: String,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub credential_types: Vec<String>,
    pub overall_status: OverallStatus,
    pub checks: Vec<CheckResult>,
}

impl InspectionReport {
    pub fn new(
        issuer: Option<String>,
        subject: Option<String>,
        credential_types: Vec<String>,
        checks: Vec<CheckResult>,
    ) -> Self {
        let overall_status = if checks
            .iter()
            .any(|check| matches!(check.status, CheckStatus::Fail))
        {
            OverallStatus::Fail
        } else if checks
            .iter()
            .any(|check| matches!(check.status, CheckStatus::Warn))
        {
            OverallStatus::Warning
        } else {
            OverallStatus::Pass
        };

        Self {
            schema_version: "1.0",
            format: "JSON-LD Verifiable Credential".to_string(),
            issuer,
            subject,
            credential_types,
            overall_status,
            checks,
        }
    }
}
