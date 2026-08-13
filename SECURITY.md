# Security policy

## Supported versions

The latest `eip-search` 3.x release receives security fixes.

## Reporting a vulnerability

Use this repository's
[private vulnerability reporting](https://github.com/exploitintel/eip-search/security/advisories/new).
Do not disclose a suspected vulnerability in a public issue.

Include the affected command and version, reproduction steps with secrets and
access tokens removed, the security impact, and any suggested remediation.

## Sensitive material

Never include API access tokens, short-lived PoC access tokens, downloaded PoC
archives, private API responses, credentials, or non-public corpus material in
a report, issue, pull request, fixture, log, or diagnostic transcript.

The CLI treats acquired content as hostile. Do not execute PoC code, extract
downloaded archives, or build or run acquired Docker labs while reproducing a
client issue.
