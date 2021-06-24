mod cargo_audit;
mod report;

use std::io;

use serde_json;

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let stdin = stdin.lock();
    let audit: cargo_audit::Report = serde_json::from_reader(stdin)?;

    let report = report_from_audit(&audit)?;

    let stdout = io::stdout();
    let stdout = stdout.lock();

    serde_json::to_writer_pretty(stdout, &report)?;

    Ok(())
}

fn report_from_audit(audit: &cargo_audit::Report) -> serde_json::Result<report::Report> {
    let mut vulnerabilities = Vec::new();
    for vuln in &audit.vulnerabilities.list {
        vulnerabilities.push(report::Vulnerability {
            id: Some(vuln.advisory.id.clone()),  // FIXME: Should be a UUID
            category: String::from("dependency_scanning"),
            message: Some(format!("[{}] {}", vuln.advisory.package, vuln.advisory.title)),
            description: Some(vuln.advisory.description.clone()),
            cve: vuln.advisory.id.clone(),
            severity: Some(report::Severity::High),
            identifiers: vec![
                report::Identifier {
                    r#type: String::from("rustsec"),
                    name: vuln.advisory.id.clone(),
                    value: vuln.advisory.id.clone(),
                    url: Some(format!("https://rustsec.org/advisories/{}", vuln.advisory.id))
                }
                // TODO: Add aliases
            ],
            links: if let Some(url) = &vuln.advisory.url {
                Some(vec![
                    report::Link {
                        url: url.clone(),
                        .. Default::default()
                    }
                ])
            } else {
                None
            },
            location: report::Location {
                file: String::from("Cargo.lock"),
                dependency: report::Dependency {
                    package: Some(report::Package {
                        name: Some(vuln.package.name.clone()),
                    }),
                    version: Some(vuln.package.version.clone()),
                    .. Default::default()
                },
            },
            scanner: report::Scanner {
                id: String::from("cargo_audit"),
                name: String::from("cargo-audit"),
            },
            .. Default::default()
        });
    }
    
    let report = report::Report {
        version: String::from("2.0"),
        vulnerabilities,
        dependency_files: vec![],
    };

    Ok(report)
}
