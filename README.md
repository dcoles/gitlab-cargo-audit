# GitLab cargo-audit

Convert [`cargo-audit`](https://crates.io/crates/cargo-audit) report to
GitLab's [Dependency Scanning format](https://docs.gitlab.com/ee/user/application_security/dependency_scanning/index.html#reports-json-format).

## Usage

Add the following to your `.gitlab-ci.yml`:

```yaml
audit:
  stage: test
  script:
    - cargo audit
  after_script:
    - cargo audit --json | gitlab-cargo-audit > dependency-report.json
  artifacts:
    when: always
    reports:
      dependency_scanning: dependency-report.json
```
