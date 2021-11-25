mod report;

use std::{io, vec};

use anyhow::Context;
use rustsec::{Database, Vulnerability};
use rustsec::lockfile::Lockfile;
use serde_json;

const LOCKFILE: &str = "Cargo.lock";
const PACKAGE_MANAGER: &str = "cargo";
const REPORT_VERSION: &str = "2.0";
const SCANNER_ID: &str = "cargo_audit";
const SCANNER_NAME: &str = "cargo-audit";

fn main() -> anyhow::Result<()> {
    let lockfile = Lockfile::load(LOCKFILE).context("failed to load lockfile")?;
    let database = Database::fetch().context("failed to fetch advisory-db")?;
    let vulnerabilities = database.vulnerabilities(&lockfile);

    let report = report::Report {
        version: REPORT_VERSION.to_string(),
        vulnerabilities: report_vulnerabilities(&vulnerabilities),
        dependency_files: vec![
            report::DependencyFile {
                path: LOCKFILE.to_string(),
                package_manager: PACKAGE_MANAGER.to_string(),
                dependencies: Vec::new(),
            }
        ],
    };

    let stdout = io::stdout();
    let stdout = stdout.lock();

    serde_json::to_writer_pretty(stdout, &report)?;

    Ok(())
}

/// Build list of [`report::Vulnerability`] from list of [`Vulnerability`]s.
fn report_vulnerabilities(vulnerabilities: &[Vulnerability]) -> Vec<report::Vulnerability> {
    vulnerabilities.iter().map(|vuln| {
        report::Vulnerability {
            id: Some(vuln.advisory.id.to_string()),  // FIXME: Should be a UUID
            category: String::from("dependency_scanning"),
            message: Some(format!("[{}] {}", vuln.advisory.package, vuln.advisory.title)),
            description: Some(vuln.advisory.description.clone()),
            cve: vuln.advisory.id.to_string(),
            severity: Some(report::Severity::High),
            identifiers: vec![
                report::Identifier {
                    r#type: String::from("rustsec"),
                    name: vuln.advisory.id.to_string(),
                    value: vuln.advisory.id.to_string(),
                    url: Some(format!("https://rustsec.org/advisories/{}", vuln.advisory.id))
                }
                // TODO: Add aliases
            ],
            links: if let Some(url) = &vuln.advisory.url {
                Some(vec![
                    report::Link {
                        url: url.to_string(),
                        .. Default::default()
                    }
                ])
            } else {
                None
            },
            location: report::Location {
                file: String::from(LOCKFILE),
                dependency: report::Dependency {
                    package: Some(report::Package {
                        name: Some(vuln.package.name.to_string()),
                    }),
                    version: Some(vuln.package.version.to_string()),
                    .. Default::default()
                },
            },
            scanner: report::Scanner {
                id: String::from(SCANNER_ID),
                name: String::from(SCANNER_NAME),
            },
            ..Default::default()
        }
    }).collect()
}
