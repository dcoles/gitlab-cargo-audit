//! cargo-audit report
//! See: https://crates.io/crates/cargo-audit

use serde::Deserialize;

#[derive(Deserialize)]
pub struct Report {
    //pub database: Database,
    //pub lockfile: Lockfile,
    pub vulnerabilities: Vulnerabilities,
    //pub warnings: Warnings,
}

#[derive(Deserialize)]
pub struct Vulnerabilities {
    pub count: u64,
    pub found: bool,
    pub list: Vec<Vulnerability>,
}

#[derive(Deserialize)]
pub struct Vulnerability {
    pub advisory: Advisory,
    pub package: Package,
}

#[derive(Deserialize)]
pub struct Advisory {
    pub affected_arch: Option<String>,
    pub affected_os: Option<String>,
    pub aliases: Vec<String>,
    pub date: String,
    pub description: String,
    pub id: String,
    pub keywords: Vec<String>,
    pub package: String,
    pub patched_versions: Option<Vec<String>>,
    pub references: Vec<String>,
    pub title: String,
    pub unaffected_versions: Option<Vec<String>>,
    pub url: Option<String>,
}

#[derive(Deserialize)]
pub struct Package {
    //pub dependencies: Option<Dependency>,
    pub name: String,
    pub source: String,
    pub version: String,
}
