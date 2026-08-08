# Instructor guide

## Session facts

- **Title:** Strategic Defense: Securing the AI Stack and Hunting Across Clouds
- **Format:** 120-minute DEF CON event path or 60-minute condensed reusable path
- **Primary mode:** offline; Python 3.10+; no accounts or network after download
- **Status:** workshop content and attendee paths are complete; presenter logistics and public distribution URL remain release-time inputs

Event-specific presenter, sponsor, room, URL, and checksum information belongs in the presenter-owned deck and release notes rather than the reusable lab instructions.

## Delivery recommendation

Use the offline path as the critical path. Explain OCSF, workload federation, and multi-cloud security with the deck, then use the repository for evidence review and tuning. Do not depend on a live Bedrock or cloud-account demonstration.

State the scenario accurately: the AI-agent and CI-federation evidence are **two incidents** that teach the same workload-identity and authorization principle; the lab does not establish a causal chain between them.

## Attendee modes

Offer both modes at the beginning and keep everyone on the same exercise checkpoints:

- **HTML Workbook — guided mode:** attendees open [`site/index.html`](site/index.html) locally for integrated instructions, architecture, copyable platform-specific commands, staged hints, progress, and notes export. Recommend this to first-time OCSF learners and anyone using a basic editor.
- **Hardcore Mode — files and terminal:** attendees use [`participant-guide.md`](participant-guide.md), the Markdown labs, raw JSON/JSONL fixtures, their editor, and terminal. Recommend this to learners who want direct evidence handling or prefer VS Code/Notepad++.

The modes use identical evidence and commands, so partners can work together even when one uses the workbook and the other uses raw files. Project the current checkpoint and command rather than requiring the room to use one interface. The only required edit in either mode is `work/cross-cloud-federation-config.json`.

## 120-minute DEF CON event path

| Clock | Activity |
|---|---|
| 16:00–16:10 | Safety, multi-cloud architecture, mode choice, extraction, and `verify` |
| 16:10–16:40 | Part A IAM, invocation evidence, and layered controls |
| 16:40–16:50 | Part A debrief and catch-up buffer |
| 16:50–17:05 | OCSF normalization and Authentication-to-API identity chain |
| 17:05–17:25 | Cross-cloud timeline investigation |
| 17:25–17:50 | Starter detector, exact behavioral baseline, and four tests |
| 17:50–18:00 | Takeaways, production caveats, repository, and next steps |

The 60-minute run below remains a condensed reusable path for meetups and internal sessions.

## Before the session

- [ ] Run the complete release checklist in [`release-checklist.md`](release-checklist.md).
- [ ] Distribute the participant archive and SHA-256 before the session if possible; it omits the complete answer key and reference detector config.
- [ ] Test extraction and `verify` on a clean Windows, macOS, and Linux environment.
- [ ] Keep a local/USB fallback.
- [ ] Open the participant guide, both labs, and terminal at readable zoom.
- [ ] Reset `work/` or use a clean archive before rehearsing.
- [ ] Complete a timed rehearsal in 55 minutes or less.
- [ ] If demonstrating AWS, validate and deploy the optional stack once in an authorized sandbox before the event; otherwise omit it.

## 60-minute run of show

### 00:00–00:04 — Frame and verify

Establish synthetic evidence, defensive scope, and the two-incident structure. Attendees run:

```bash
python3 tools/workshop.py verify
```

### 00:04–00:10 — A1: effective authority

Attendees inspect the broad policy, identify action/resource wildcards and privilege delegation, then run `iam`. Emphasize that PassRole also needs a compatible role-accepting service API and trust relationship.

### 00:10–00:20 — A2: evidence over keywords

Use `prompts --evidence`; assign pairs two records each if the room is large. Collect classifications before running `prompts`. Spend most discussion time on benign security discussion versus unapproved retrieved instructions.

### 00:20–00:27 — A3: layered controls

Map one control to each layer. Explain tagged user input, PII input/output behavior, deterministic tool authorization, hidden-Unicode handling, and output encoding. Do not describe Guardrails as a guarantee.

### 00:27–00:34 — OCSF and multi-cloud framing

Use the deck to explain why provider-specific logs need a common event model. Run `schema` and annotate one Authentication event. Explain `actor`, target `user`, source, session, cloud, and preserved federation claims.

### 00:34–00:43 — B2: timeline

Have attendees search for `198.51.100.42` and identify the subject before running `timeline`. Ask when the second-provider threshold is reached and which later actions satisfy the detector.

### 00:43–00:56 — B3: tune and test

Run the starter: two active alerts are expected. Pair attendees to create a work config and populate the complete main-release baseline. Completion is `test-detection` with four passes, including provider-role binding. If time is tight, give Hint 2; do not replace the exercise with the reference solution immediately.

### 00:56–01:00 — Debrief

Ask attendees to state:

1. the deterministic control that stopped the indirect tool request;
2. the stable federation identity evidence;
3. why source IP and approved subject are insufficient alone;
4. one production adaptation their SIEM requires.

## Facilitation and recovery

- **Python unavailable:** pair the learner; use `tools/demo.py --fast --no-color` as a projected fallback.
- **Download fails:** use the local archive and published checksum.
- **JSON is hard to read:** use `prompts --evidence` and the OCSF field guide.
- **Detection config has JSON errors:** direct learners to B3 Hint 1.
- **Time slips:** shorten A1 comparison and manual B2 review; preserve the edit/test detector loop.
- **Advanced learner finishes early:** ask them to make the approved subject deviate on one dimension and explain why it alerts.
- **Live AWS demo fails:** stop troubleshooting and continue offline.

## Optional AWS demonstration

The stack creates a Bedrock Guardrail, a KMS key with regional CloudWatch Logs service access scoped by log-group encryption context, and an encrypted log group. It does not invoke a model, configure model invocation logging, deploy an agent, or deploy the vulnerable IAM fixture.

Deployment changes an AWS account and can incur charges. In a complete GitHub source checkout, review the optional `infra/` material and current AWS documentation, then use only an authorized sandbox. The participant ZIP intentionally omits the deployment material.

## Content cautions

- Provider fixtures are normalized teaching representations, not raw exports.
- Source IP is supporting context and may be shared or absent.
- `unmapped` preserves provider claims without asserting a universal field mapping.
- Prompt filters can false-positive and false-negative.
- An approved subject can be compromised; only exact expected behavior is suppressed here.
- Never place real credentials, customer prompts, or production logs in a public workshop issue.
