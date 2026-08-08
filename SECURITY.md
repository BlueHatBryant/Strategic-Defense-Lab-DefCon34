# Security policy

## Scope

This repository contains an offline defensive training lab and optional demonstration infrastructure. It does not operate a hosted service or process user data.

## Reporting a repository vulnerability

Use a private GitHub security advisory when available. Do not publish working credentials, private account details, customer information, or exploit details that affect systems you do not own. If private advisories are unavailable, contact the repository owner through a non-public channel listed on their GitHub profile.

Useful reports include:

- release packaging that accidentally includes instructor-only, local, or sensitive files;
- unsafe optional infrastructure defaults;
- command behavior that writes outside the repository or contacts external services unexpectedly;
- fixture data that appears to identify a real person or organization;
- technically inaccurate security guidance that could create harm when copied.

## Supported versions

The latest GitHub release and the current primary branch receive corrections. Conference snapshot tags are historical and may not receive updates.

## Safe-use boundary

The repository is for defensive education with synthetic evidence. Do not use it to test third-party systems. The intentionally over-broad IAM policy is a reading fixture and must never be deployed. Optional AWS resources should be used only in an authorized non-production sandbox after review of current documentation and organizational controls.
