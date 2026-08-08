# Contributing

Contributions that improve technical accuracy, accessibility, portability, detection engineering, or independent learning are welcome after the repository owner selects a public license.

## Before opening a change

- Use only synthetic data or events from systems you own and are explicitly authorized to assess.
- Never submit credentials, customer data, proprietary logs, internal-only URLs, real sensitive prompts, or personal information.
- Open an issue before changing the scenario's core learning objectives or expected outcomes.
- Keep the offline path dependency-free unless there is a compelling, documented reason to change that constraint.

## Development workflow

1. Create a branch from the repository's primary branch.
2. Make the smallest coherent change.
3. Update documentation, fixtures, implementation, and solutions together when behavior changes.
4. Add or update standard-library `unittest` coverage.
5. Run:

```bash
python3 -m unittest discover -s tests -v
python3 tools/workshop.py verify
python3 tools/demo.py --fast --no-color
python3 scripts/package_release.py
```

6. Confirm the generated archive contains no `instructor/`, `solutions/`, PowerPoint files, caches, local work, or secrets.

## Fixture standards

- Use RFC 5737 documentation IPv4 ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- Use clearly fictional account IDs, tenant IDs, projects, domains, and identities.
- Keep epoch `time` and ISO `time_dt` consistent.
- Keep `type_uid = class_uid × 100 + activity_id`.
- Describe normalized teaching representations honestly; do not imply they are raw exports.
- Preserve provider details under `unmapped` unless the selected OCSF version/profile has a justified common mapping.
- Never model an IAM permission such as `iam:PassRole` as a standalone API event unless the mapper explicitly creates a derived analytic event and documents it.

## Detection standards

A rule change should include positive, negative, and adversarial cases. Approved behavior must be narrowly defined and owned. Avoid subject-only or IP-only suppression. Document event-time windows, ordering, de-duplication, missing fields, and SIEM-specific syntax.

## Documentation standards

Write for a learner without an instructor present. Use the sequence orient → inspect → hypothesize → test → explain → extend. Put spoilers in `solutions/` or `instructor/`; add staged hints for non-obvious tasks.
