//! GitLab Dependency Scanning report
//! See: https://docs.gitlab.com/ee/user/application_security/dependency_scanning/
//! See: https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/blob/master/dist/dependency-scanning-report-format.json

use serde::Serialize;

#[derive(Serialize, Debug, Default)]
pub struct Report {
    pub version: String,
    pub vulnerabilities: Vec<Vulnerability>,
    // pub remediations: Option<Vec<Remediation>>,
    pub dependency_files: Vec<DependencyFile>,
}

#[derive(Serialize, Debug, Default)]
pub struct Vulnerability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub cve: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solution: Option<String>,
    pub scanner: Scanner,
    pub identifiers: Vec<Identifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<Link>>,
    //pub details: ???,
    //pub tracking: ???,
    pub location: Location,
}

#[allow(dead_code)]
#[derive(Serialize, Debug)]
pub enum Severity {
    Info,
    Unknown,
    Low,
    Medium,
    High,
    Critical,   
}

impl Default for Severity {
    fn default() -> Self {
        Self::Unknown
    }
}

#[allow(dead_code)]
#[derive(Serialize, Debug)]
pub enum Confidence {
    Ignore,
    Unknown,
    Experimental,
    Low,
    Medium,
    High,
    Confirmed,
}

#[derive(Serialize, Debug, Default)]
pub struct Scanner {
    pub id: String,
    pub name: String,
}

#[derive(Serialize, Debug, Default)]
pub struct Identifier {
    pub r#type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub value: String,
}

#[derive(Serialize, Debug, Default)]
pub struct Link {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub url: String,
}

#[derive(Serialize, Debug, Default)]
pub struct Location {
    pub file: String,
    pub dependency: Dependency,
}

#[derive(Serialize, Debug, Default)]
pub struct Dependency {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<Package>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iid: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependency_path: Option<Vec<IID>>
}

#[derive(Serialize, Debug, Default)]
pub struct IID {
    pub iid: usize,
}

#[derive(Serialize, Debug, Default)]
pub struct Package {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Serialize, Debug, Default)]
pub struct DependencyFile {
    pub path: String,
    pub package_manager: String,
    pub dependencies: Vec<Dependency>
}
