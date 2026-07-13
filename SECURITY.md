# Security Policy

## Reporting a Vulnerability

Please do not open a public issue for an unpatched vulnerability in SELF.

Send a private report through GitHub's security-advisory interface for this
repository. Include:

- Affected version and component
- Reproduction steps using a harmless local fixture
- Security impact
- Suggested remediation, if known

Do not include real credentials, stolen data, mainnet exploitation steps, or
targets you are not authorized to test.

## Scope

Security reports may cover SELF's parser, detector engine, report generation,
dependency handling, built-in review profiles, and CI behavior. False negatives in
individual heuristic rules are welcome as normal bug reports unless they create
a broader integrity problem such as silently disabling a detector family.

## Disclosure

Please allow reasonable time for validation and a coordinated fix before public
disclosure. Confirmed reporters will be credited unless they prefer anonymity.
