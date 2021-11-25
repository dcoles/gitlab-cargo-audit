# GitLab cargo-audit

Generate GitLab [Dependency Scanning report](https://docs.gitlab.com/ee/user/application_security/dependency_scanning/) using [`cargo-audit`](https://github.com/rustsec/rustsec).

## Usage

Add the following to your `.gitlab-ci.yml`:

```yaml
audit:
  stage: test
  script:
    - cargo audit
  after_script:
    - gitlab-cargo-audit > dependency-report.json
  artifacts:
    when: always
    reports:
      dependency_scanning: dependency-report.json
```
