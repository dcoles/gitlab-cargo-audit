# GitLab cargo-audit

Generate GitLab [Dependency Scanning report](https://docs.gitlab.com/ee/user/application_security/dependency_scanning/) using [`cargo-audit`](https://github.com/rustsec/rustsec).

## Usage

Add the following to your `.gitlab-ci.yml`:

```yaml
audit:
  stage: test
  script:
    - gitlab-cargo-audit > gl-dependency-scanning-report.json
  artifacts:
    when: always
    reports:
      dependency_scanning: gl-dependency-scanning-report.json
```

## License

Dual licensed under the [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE) licenses.
