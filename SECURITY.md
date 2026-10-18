# Security Policy

## Reporting a vulnerability

Please report security issues **privately** via GitHub Security Advisories
("Report a vulnerability" on the repository's **Security** tab) rather than
opening a public issue.

## No real secrets in this repository

The working tree and full git history have been scanned for credentials
(provider tokens, private keys, API keys). There are **no live secrets**.

`examples/sample-app` intentionally contains **synthetic placeholder
credentials** so Anti-REA's own scanner has something to detect — e.g. AWS's
public documentation example key `AKIAIOSFODNN7EXAMPLE` (allowlisted by secret
scanners) and an obvious fake signing secret. These are not real and grant no
access. Domains use the reserved `*.example.com` space (RFC 2606).

## CI hardening

The GitHub Actions workflow:

- runs with least-privilege permissions (`contents: read`),
- pins third-party actions to full commit SHAs (supply-chain hardening),
- disables credential persistence on checkout (`persist-credentials: false`),
- uses **no** repository secrets, and
- triggers on `pull_request` (not `pull_request_target`) with no untrusted
  input interpolated into shell steps.

## Scope

Anti-REA is a defensive hardening toolkit. It does not include, bundle, or
redistribute third-party reverse-engineering code (see [NOTICE](NOTICE)).
