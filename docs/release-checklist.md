# Public release and presenter-PC checklist

## Current technical state

- [x] Both attendee modes are complete: HTML Workbook and Hardcore Mode.
- [x] Synthetic IAM, model invocation, Guardrail, and OCSF fixtures validate.
- [x] The starter detector exposes the attack plus the intentional tuning false positive.
- [x] Automated tests cover the exact release baseline and adversarial deviations.
- [x] The custom participant archive excludes complete solution directories, the answer key under `instructor/`, PowerPoint files, slide generators, optional AWS deployment material, caches, and local work.
- [x] Presenter material is maintained separately from the public workshop tree.
- [x] The workshop runs offline with Python 3.10+ and no cloud account.

## Still required before the first public GitHub release

- [ ] Confirm repository ownership and select an explicit reuse license with any required employer or sponsor approval.
- [ ] Initialize Git and inspect `git status --ignored` before the first commit.
- [ ] Create the GitHub repository and choose the public URL used in the deck/QR code.
- [ ] Push a branch and confirm the GitHub Actions workflow passes on Linux, macOS, and Windows.
- [ ] Create a tagged release, such as `defcon34` or `v1.0.0`.
- [ ] Attach `dist/strategic-defense-lab.zip` and `dist/strategic-defense-lab.zip.sha256` as release assets.
- [ ] Confirm the published checksum matches the uploaded ZIP.
- [ ] Review public links and current AWS/OCSF documentation.
- [ ] Confirm no credentials, customer data, internal-only links, proprietary logs, or presenter-only files are tracked.

## What belongs in the GitHub repository

Keep the reusable workshop source:

```text
.github/                 CI workflow
README.md                Public landing page and status
data/                     Synthetic evidence
labs/                     Part A and Part B exercises
docs/                     Workbook and reusable guides
detections/               Starter and engine-neutral rule design
queries/                  Portable OCSF-oriented SQL design
solutions/                Clearly marked post-exercise spoilers
instructor/answer-key.md  Clearly marked post-exercise spoiler
tools/                    Offline workshop runner and quick tour
scripts/package_release.py
infra/                    Optional source-only AWS demonstration
scripts/deploy.sh         Optional source-only AWS demonstration
scripts/cleanup.sh        Optional source-only AWS demonstration
tests/                    Regression and adversarial tests
CONTRIBUTING.md, SECURITY.md, .editorconfig, .gitignore
```

The full GitHub source contains post-exercise reference material. During the lab, direct attendees to the **GitHub Release participant ZIP**, not GitHub's automatically generated source archive.

## What belongs only on the presenter PC

Keep these outside the GitHub repository:

```text
Strategic-Defense-DEFCON34.pptx
presenter-one-pager.md
slide-generation source and legacy deck archive
local copy of the participant ZIP and SHA-256
one clean extracted participant folder for emergency distribution/demo
USB copy or other offline fallback
```

Before presenting, verify the deck contains the current room, time, sponsor text, final download URL/QR, and the checksum of the exact uploaded participant ZIP.

## Repeatable final validation

```bash
python3 -m unittest discover -s tests -v
python3 tools/workshop.py verify
python3 tools/demo.py --fast --no-color
python3 scripts/package_release.py
```

Then extract the generated ZIP into a clean temporary directory and run:

```bash
python3 tools/workshop.py verify
python3 -m unittest discover -s tests -v
```

## Suggested versioning

- Tag the delivered conference snapshot, for example `defcon34`.
- Use semantic releases (`v1.0.0`, `v1.1.0`) for the reusable lab.
- Record fixture, detection, and schema changes in release notes.
- Avoid changing expected evidence silently; update tests and solution explanations together.
