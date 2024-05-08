mod report;

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context;
use argh::FromArgs;
use petgraph::graph::NodeIndex;
use petgraph::visit::Bfs;
use petgraph::{Direction, Graph};
use rustsec::advisory::Severity;
use rustsec::cargo_lock::dependency::Tree;
use rustsec::cargo_lock::Dependency;
use rustsec::package::Package;
use rustsec::{Database, Lockfile, Vulnerability};
use time::format_description::well_known::iso8601;
use time::OffsetDateTime;

const CARGO_TOML: &str = "Cargo.toml";
const LOCKFILE: &str = "Cargo.lock";
const PACKAGE_MANAGER: &str = "cargo";
const REPORT_VERSION: &str = "15.0.7";
const ANALYZER_ID: &str = "gitlab_cargo_audit";
const ANALYZER_NAME: &str = "gitlab-cargo-audit";
const ANALYZER_VENDOR: &str = "dcoles";
const ANALYZER_URL: &str = "https://github.com/dcoles/gitlab-cargo-audit";
const SCANNER_ID: &str = "cargo_audit";
const SCANNER_NAME: &str = "cargo-audit";
const SCANNER_VENDOR: &str = "RustSec";
const SCANNER_URL: &str = "https://github.com/RustSec/rustsec/tree/main/cargo-audit";

const ISO8601_CFG: iso8601::EncodedConfig = iso8601::Config::DEFAULT
    .set_formatted_components(iso8601::FormattedComponents::DateTime)
    .set_time_precision(iso8601::TimePrecision::Second {
        decimal_digits: None,
    })
    .encode();

/// produces a gitlab consumable cargo-audit report
#[derive(FromArgs)]
struct App {
    /// an optional output path.
    ///
    /// contents are written as utf-8
    #[argh(option)]
    output_path: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let app: App = argh::from_env();

    if !Path::new(LOCKFILE).exists() && Path::new(CARGO_TOML).exists() {
        // Try to generate `Cargo.lock`
        let status = Command::new("cargo")
            .arg("generate-lockfile")
            .status()
            .context("failed to execute `cargo generate-lockfile`")?;
        if !status.success() {
            anyhow::bail!("`cargo generate-lockfile` terminated with an error: {status}");
        }
    }

    let start = OffsetDateTime::now_utc();

    let lockfile = Lockfile::load(LOCKFILE).context("failed to load lockfile")?;
    let dependency_tree = lockfile
        .dependency_tree()
        .context("failed to generate dependency tree")?;
    let database = Database::fetch().context("failed to fetch advisory-db")?;
    let vulnerabilities = database.vulnerabilities(&lockfile);

    let end = OffsetDateTime::now_utc();

    print_vulnerabilities(&vulnerabilities);

    let report = report::Report {
        version: REPORT_VERSION.to_string(),
        vulnerabilities: report_vulnerabilities(&vulnerabilities),
        scan: report::Scan {
            analyzer: report::Analyzer {
                id: ANALYZER_ID.to_string(),
                name: ANALYZER_NAME.to_string(),
                url: Some(ANALYZER_URL.to_string()),
                vendor: report::Vendor {
                    name: ANALYZER_VENDOR.to_string(),
                },
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            scanner: report::Scanner {
                id: SCANNER_ID.to_string(),
                name: SCANNER_NAME.to_string(),
                url: Some(SCANNER_URL.to_string()),
                vendor: report::Vendor {
                    name: SCANNER_VENDOR.to_string(),
                },
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            start_time: start.format(&iso8601::Iso8601::<ISO8601_CFG>).unwrap(),
            end_time: end.format(&iso8601::Iso8601::<ISO8601_CFG>).unwrap(),
            status: report::ScanStatus::Success,
            r#type: report::ScanType::DependencyScanning,
        },
        dependency_files: dependency_files(&dependency_tree),
    };

    let output: Box<dyn std::io::Write> = match app.output_path {
        Some(path) => {
            let output = std::fs::File::create(path)?;
            Box::new(output)
        }
        None => Box::new(io::stdout().lock()),
    };

    serde_json::to_writer_pretty(output, &report)?;

    Ok(())
}

/// Print list of vulnerabilities
fn print_vulnerabilities(vulnerabilities: &[Vulnerability]) {
    if vulnerabilities.is_empty() {
        eprintln!("No vulnerabilities detected");
        return;
    }

    eprintln!(
        "Warning: {} vulnerabilities detected",
        vulnerabilities.len()
    );
    for vuln in vulnerabilities {
        eprintln!(
            "- [{}] {} ({})",
            vuln.advisory.package, vuln.advisory.title, vuln.advisory.id
        );
        eprintln!(
            "  See https://rustsec.org/advisories/{} for details",
            vuln.advisory.id
        );
    }
}

fn dependency_files(dependency_tree: &Tree) -> Vec<report::DependencyFile> {
    // The roots are the packages in this workspace (or just the standalone package)
    let roots: Vec<_> = dependency_tree
        .nodes()
        .iter()
        .filter_map(|(dep, &index)| {
            if dep.source.is_none() {
                Some(index)
            } else {
                None
            }
        })
        .collect();

    let graph = dependency_tree.graph();

    let mut dependency_files = vec![];
    for &root in &roots {
        let package = &graph[root];
        dependency_files.push(report::DependencyFile {
            path: format!("{LOCKFILE} ({} {})", package.name, package.version),
            package_manager: PACKAGE_MANAGER.to_string(),
            dependencies: report_dependencies(graph, root),
        });
    }

    dependency_files.into_iter().collect()
}

/// Build list of [`report::Dependency`] from a dependency tree.
fn report_dependencies(
    graph: &Graph<Package, Dependency>,
    root: NodeIndex,
) -> Vec<report::Dependency> {
    let direct: HashSet<_> = graph
        .neighbors_directed(root, Direction::Outgoing)
        .collect();

    let mut dependencies = HashSet::new();

    let mut bfs = Bfs::new(&graph, root);
    while let Some(u) = bfs.next(&graph) {
        for v in graph.neighbors(u) {
            dependencies.insert(v);
        }
    }

    dependencies
        .into_iter()
        .map(|v| {
            let package = &graph[v];

            report::Dependency {
                package: Some(report::Package {
                    name: Some(package.name.as_str().to_owned()),
                }),
                version: Some(package.version.to_string()),
                iid: Some(v.index()),
                direct: Some(direct.contains(&v)),
                dependency_path: None,
            }
        })
        .collect()
}

/// Build list of [`report::Vulnerability`] from list of [`Vulnerability`]s.
fn report_vulnerabilities(vulnerabilities: &[Vulnerability]) -> Vec<report::Vulnerability> {
    vulnerabilities
        .iter()
        .map(|vuln| {
            report::Vulnerability {
                id: vuln.advisory.id.to_string(), // FIXME: Should be a UUID
                name: Some(format!(
                    "[{}] {}",
                    vuln.advisory.package, vuln.advisory.title
                )),
                description: Some(vuln.advisory.description.clone()),
                severity: vuln
                    .advisory
                    .cvss
                    .as_ref()
                    .map(|cvss| map_severity(cvss.severity()))
                    .unwrap_or_default(),
                identifiers: vec![
                    report::Identifier {
                        r#type: String::from("rustsec"),
                        name: vuln.advisory.id.to_string(),
                        value: vuln.advisory.id.to_string(),
                        url: Some(format!(
                            "https://rustsec.org/advisories/{}",
                            vuln.advisory.id
                        )),
                    }, // TODO: Add aliases
                ],
                links: if let Some(url) = &vuln.advisory.url {
                    vec![report::Link {
                        url: url.to_string(),
                        ..Default::default()
                    }]
                } else {
                    vec![]
                },
                location: report::Location {
                    file: String::from(LOCKFILE),
                    dependency: report::Dependency {
                        package: Some(report::Package {
                            name: Some(vuln.package.name.to_string()),
                        }),
                        version: Some(vuln.package.version.to_string()),
                        ..Default::default()
                    },
                },
                ..Default::default()
            }
        })
        .collect()
}

fn map_severity(severity: Severity) -> report::Severity {
    match severity {
        Severity::None => report::Severity::Info,
        Severity::Low => report::Severity::Low,
        Severity::Medium => report::Severity::Medium,
        Severity::High => report::Severity::High,
        Severity::Critical => report::Severity::Critical,
    }
}
