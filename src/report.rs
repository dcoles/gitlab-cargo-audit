//! GitLab Dependency Scanning report
//! See: https://docs.gitlab.com/ee/user/application_security/dependency_scanning/

use serde::Serialize;

#[derive(Serialize, Default)]
pub struct Report {
    pub version: String,
    pub vulnerabilities: Vec<Vulnerability>,
    // pub remediations: Option<Vec<Remediation>>,
    pub dependency_files: Vec<DependencyFile>,
}

#[derive(Serialize, Default)]
pub struct Vulnerability {
    pub id: Option<String>,
    pub category: String,
    pub name: Option<String>,
    pub message: Option<String>,
    pub description: Option<String>,
    pub cve: String,
    pub severity: Option<Severity>,
    pub confidence: Option<Confidence>,
    pub solution: Option<String>,
    pub scanner: Scanner,
    pub identifiers: Vec<Identifier>,
    pub links: Option<Vec<Link>>,
    //pub details: ???,
    //pub tracking: ???,
    pub location: Location,
}

#[derive(Serialize)]
pub enum Severity {
    Info,
    Unknown,
    Low,
    Medium,
    High,
    Critical,   
}

#[derive(Serialize)]
pub enum Confidence {
    Ignore,
    Unknown,
    Experimental,
    Low,
    Medium,
    High,
    Confirmed,
}

#[derive(Serialize, Default)]
pub struct Scanner {
    pub id: String,
    pub name: String,
}

#[derive(Serialize, Default)]
pub struct Identifier {
    pub r#type: String,
    pub name: String,
    pub url: Option<String>,
    pub value: String,
}

#[derive(Serialize, Default)]
pub struct Link {
    pub name: Option<String>,
    pub url: String,
}

#[derive(Serialize, Default)]
pub struct Location {
    pub file: String,
    pub dependency: Dependency,
}

#[derive(Serialize, Default)]
pub struct Dependency {
    pub package: Option<Package>,
    pub version: Option<String>,
    pub iid: Option<u64>,
    pub direct: Option<bool>,
    pub dependency_path: Option<Vec<IID>>
}

#[derive(Serialize, Default)]
pub struct Package {
    pub name: Option<String>,
}

#[derive(Serialize, Default)]
pub struct IID {
    pub iid: u64,
}

#[derive(Serialize, Default)]
pub struct DependencyFile {
    pub path: String,
    pub package_manager: String,
    pub dependencies: Vec<Dependency>
}
