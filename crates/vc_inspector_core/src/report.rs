#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub status: CheckStatus,
    pub message: String,
}

impl CheckResult {
    pub fn pass(message: impl Into<String>) -> Self {
        Self {
            status: CheckStatus::Pass,
            message: message.into(),
        }
    }

    pub fn warn(message: impl Into<String>) -> Self {
        Self {
            status: CheckStatus::Warn,
            message: message.into(),
        }
    }

    pub fn fail(message: impl Into<String>) -> Self {
        Self {
            status: CheckStatus::Fail,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectionReport {
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
            format: "JSON-LD Verifiable Credential".to_string(),
            issuer,
            subject,
            credential_types,
            overall_status,
            checks,
        }
    }
}
