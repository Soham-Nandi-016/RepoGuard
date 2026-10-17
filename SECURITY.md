# Security Policy: RepoGuard

## Supported Versions
| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Principles
RepoGuard operates on strict local-first principles:
1. **Zero Execution of Analyzed Code**: RepoGuard parses Python source trees into ASTs without executing `import` statements or runtime code.
2. **Zero Cloud Uploads**: All AST parsing, secret entropy checks, and hygiene evaluations run locally on CPU.
3. **Safe Secret Redaction**: Secrets and tokens are automatically masked in CLI, HTML reports, and API responses.

## Reporting a Vulnerability
If you discover a security vulnerability in RepoGuard itself, please do not disclose it publicly.
Contact the project maintainers via email at `security@repoguard.internal` or reach out to the University of Mumbai lab coordinator.
We will respond within 48 hours.
