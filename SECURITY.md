# Security policy

Quarters' baseline changes user-state paths. It does not reduce the authority
of the process, so a process launched through Quarters can read every host file
that the real account can read.

Security reports should not include real credentials, exported homes, command
histories or personal paths. Replace them with the smallest synthetic example.
Report vulnerabilities privately through [GitHub's security advisory
form](https://github.com/Agenxy/quarters/security/advisories/new). Do not open a
public issue before a fix or coordinated disclosure is ready.

## Supported version

This repository is an alpha. Only the current `main` revision is supported.

## Relevant findings

Examples include path traversal outside a validated space root, accidental
credential-variable inheritance, removal of an unvalidated path, secret values
in JSON or errors, a capability request that silently degrades, or a mismatch
between a documented and enforced authority boundary.

The full boundary is in [the threat model](docs/security/THREAT-MODEL.md).
