mod report;

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::process::Command;

use anyhow::Context;
use petgraph::graph::NodeIndex;
use petgraph::visit::Bfs;
use rustsec::advisory::Severity;
use rustsec::cargo_lock::dependency::Tree;
use rustsec::{Database, Vulnerability, Lockfile};
use serde_json;

const CARGO_TOML: &str = "Cargo.toml";
const LOCKFILE: &str = "Cargo.lock";
const PACKAGE_MANAGER: &str = "cargo";
const REPORT_VERSION: &str = "14.0.6";
const SCANNER_ID: &str = "cargo_audit";
const SCANNER_NAME: &str = "cargo-audit";

fn main() -> anyhow::Result<()> {
    if !Path::new(LOCKFILE).exists() && Path::new(CARGO_TOML).exists() {
        // Try to generate `Cargo.lock`
        let status = Command::new("cargo").arg("generate-lockfile").status().context("failed to execute `cargo generate-lockfile`")?;
        if !status.success() {
            anyhow::bail!("`cargo generate-lockfile` terminated with an error: {status}");
        }
    }

    let lockfile = Lockfile::load(LOCKFILE).context("failed to load lockfile")?;
    let cargo_toml = load_toml(CARGO_TOML).context("failed to load Cargo.toml")?;
    let packages = discover_packages(&cargo_toml).context("failed to discover packages")?;
    let dependency_tree = lockfile.dependency_tree().context("failed to generate dependency tree")?;
    let database = Database::fetch().context("failed to fetch advisory-db")?;
    let vulnerabilities = database.vulnerabilities(&lockfile);

    print_vulnerabilities(&vulnerabilities);

    let report = report::Report {
        version: REPORT_VERSION.to_string(),
        vulnerabilities: report_vulnerabilities(&vulnerabilities),
        dependency_files: vec![
            report::DependencyFile {
                path: LOCKFILE.to_string(),
                package_manager: PACKAGE_MANAGER.to_string(),
                dependencies: report_dependencies(&dependency_tree, &packages)
            }
        ],
    };

    let stdout = io::stdout();
    let stdout = stdout.lock();

    serde_json::to_writer_pretty(stdout, &report)?;

    Ok(())
}

/// Load TOML file
fn load_toml(path: impl AsRef<Path>) -> io::Result<toml::Value> {
    let mut file = File::open(path.as_ref())?;

    let mut buf  = Vec::new();
    file.read_to_end(&mut buf)?;

    Ok(toml::from_slice(&buf)?)
}

/// Discover package names in package/workspace
fn discover_packages(cargo_toml: &toml::Value) -> anyhow::Result<HashSet<String>> {
    let mut packages = HashSet::new();

    if let Some(package) = cargo_toml.get("package") {
        let name = package.get("name").and_then(toml::Value::as_str)
            .ok_or(anyhow::anyhow!("missing package name"))?;

        packages.insert(name.to_string());
    } else if let Some(workspace) = cargo_toml.get("workspace") {
        let members = workspace.get("members").and_then(toml::Value::as_array)
            .map(|m| m.iter().filter_map(toml::Value::as_str).map(str::to_string))
            .ok_or(anyhow::anyhow!("missing package members"))?;

        packages.extend(members);
    } else {
        anyhow::bail!("missing package or workspace");
    }

    Ok(packages)
}

/// Print list of vulnerabilities
fn print_vulnerabilities(vulnerabilities: &[Vulnerability]) {
    if vulnerabilities.is_empty() {
        eprintln!("No vulnerabilities detected");
        return;
    }

    eprintln!("Warning: {} vulnerabilities detected", vulnerabilities.len());
    for vuln in vulnerabilities {
        eprintln!("- [{}] {} ({})", vuln.advisory.package, vuln.advisory.title, vuln.advisory.id);
        eprintln!("  See https://rustsec.org/advisories/{} for details", vuln.advisory.id);
    }
}

/// Build list of [`report::Dependency`] from a dependency tree.
fn report_dependencies(dependency_tree: &Tree, packages: &HashSet<String>) -> Vec<report::Dependency> {
    let graph = dependency_tree.graph();

    let mut dependencies = Vec::new();
    for root in dependency_tree.roots() {
        if !packages.contains(graph[root].name.as_str()) {
            continue;
        }

        let mut predecessor = vec![NodeIndex::end(); graph.node_count()];
        let mut bfs = Bfs::new(&graph, root);
        while let Some(u) = bfs.next(&graph) {
            for v in graph.neighbors(u) {
                let package = &graph[v];
                predecessor[v.index()] = u;

                let dependency_path = dependency_path(&predecessor, v);

                dependencies.push(report::Dependency {
                    package: Some(report::Package {
                        name: Some(package.name.as_str().to_owned()),
                    }),
                    version: Some(package.version.to_string()),
                    iid: Some(v.index()),
                    direct: Some(dependency_path.is_empty()),
                    dependency_path: Some(dependency_path),
                });
            }
        }
    }

    dependencies
}

/// Ancestors of the dependency, starting from a direct project dependency, and ending with an immediate parent of the dependency.
/// The dependency itself is excluded from the path. Direct dependencies have no path.
fn dependency_path(predecessor: &[NodeIndex], mut nx: NodeIndex) -> Vec<report::IID> {
    let mut path = Vec::new();
    loop {
        nx = predecessor[nx.index()];
        if predecessor[nx.index()] == NodeIndex::end() {
            // `nx` is the root
            break;
        }

        path.push(report::IID { iid: nx.index() });
    }

    path.reverse();

    path
}

/// Build list of [`report::Vulnerability`] from list of [`Vulnerability`]s.
fn report_vulnerabilities(vulnerabilities: &[Vulnerability]) -> Vec<report::Vulnerability> {
    vulnerabilities.iter().map(|vuln| {
        report::Vulnerability {
            id: Some(vuln.advisory.id.to_string()),  // FIXME: Should be a UUID
            category: String::from("dependency_scanning"),
            name: Some(vuln.advisory.title.to_string()),
            message: Some(format!("[{}] {}", vuln.advisory.package, vuln.advisory.title)),
            description: Some(vuln.advisory.description.clone()),
            cve: vuln.advisory.id.to_string(),
            severity: vuln.advisory.cvss.as_ref().map(|cvss| map_severity(cvss.severity()))
                .unwrap_or_default(),
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

fn map_severity(severity: Severity) -> report::Severity {
    match severity {
        Severity::None => report::Severity::Info,
        Severity::Low => report::Severity::Low,
        Severity::Medium => report::Severity::Medium,
        Severity::High => report::Severity::High,
        Severity::Critical => report::Severity::Critical,
    }
}
