//! GitLab Dependency Scanning report
//! See: https://docs.gitlab.com/ee/user/application_security/dependency_scanning/
//! See: https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/blob/master/dist/dependency-scanning-report-format.json

use serde::Serialize;

#[derive(Serialize, Debug, Default)]
pub struct Report {
    pub version: String,
    pub vulnerabilities: Vec<Vulnerability>,
    pub scan: Scan,
    pub dependency_files: Vec<DependencyFile>,
}

#[derive(Serialize, Debug, Default)]
pub struct Scan {
    //#[serde(skip_serializing_if = "Vec::is_empty")]
    //#[serde(default)]
    //pub messages: Vec<Message>,
    //pub options: Vec<Option>,
    //pub primary_identifiers: Vec<PrimaryIdentifier>,
    pub analyzer: Analyzer,
    pub scanner: Scanner,
    pub start_time: String,
    pub end_time: String,
    pub status: ScanStatus,
    pub r#type: ScanType,
}

#[allow(dead_code)]
#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Success,
    Failure,
}

impl Default for ScanStatus {
    fn default() -> Self {
        ScanStatus::Success
    }
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ScanType {
    DependencyScanning,
}

impl Default for ScanType {
    fn default() -> Self {
        ScanType::DependencyScanning
    }
}

#[derive(Serialize, Debug, Default)]
pub struct Analyzer {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub vendor: Vendor,
    pub version: String,
}

#[derive(Serialize, Debug, Default)]
pub struct Scanner {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub vendor: Vendor,
    pub version: String,
}

#[derive(Serialize, Debug, Default)]
pub struct Vendor {
    pub name: String,
}

#[derive(Serialize, Debug, Default)]
pub struct Vulnerability {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solution: Option<String>,
    pub identifiers: Vec<Identifier>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub cvss_vectors: Vec<CvssVector>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub links: Vec<Link>,
    //pub details: ???,
    //pub tracking: ???,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub flags: Vec<Flag>,
    pub location: Location,
}

#[derive(Serialize, Debug, Default)]
pub struct CvssVector {
    pub vendor: String,
    pub vector: String,
}

#[derive(Serialize, Debug, Default)]
pub struct Flag {
    pub r#type: FlagType,
    pub origin: String,
    pub description: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum FlagType {
    FlaggedAsLikelyFalsePositive
}

impl Default for FlagType {
    fn default() -> FlagType {
        FlagType::FlaggedAsLikelyFalsePositive
    }
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
