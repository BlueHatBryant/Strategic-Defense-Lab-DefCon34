# Self-guided participant guide

## Strategic Defense: Securing the AI Stack and Hunting Across Clouds

You are a defender for fictional Northstar Robotics. You will investigate two related incidents: an AI support agent processes an unapproved retrieval document, and a separate feature-branch deployment identity appears across AWS, Azure, and GCP. The common lesson is that workload authorization defines impact and telemetry must preserve stable identity context.

**Time:** 75–90 minutes. **Requirements:** Python 3.10+, terminal, and text editor. **Cloud access:** none.

**Status:** the self-guided workshop is content-complete. Both modes below use the same validated fixtures and finish with four automated detector outcomes. Run `verify` first; every reported group should pass.

### Choose your mode

Both modes use the same synthetic evidence, Python runner, learning objectives, detector, and completion tests. You can switch modes at any point.

- **HTML Workbook — guided mode (recommended for first-time learners):** after extracting the archive, open [`site/index.html`](site/index.html) in a browser. It combines instructions, copyable Windows/macOS/Linux commands, architecture context, answer fields, progress, staged hints, and the OCSF walkthrough in one page. Commands still run in your terminal; only the detector configuration requires a text editor.
- **Hardcore Mode — files and terminal:** continue with this Markdown guide, open the raw JSON/JSONL fixtures in VS Code, Notepad++, or another plain-text editor, keep your own notes, and run every command manually. Start each exercise from the linked files and use [`hints.md`](hints.md) only when needed.

Hardcore Mode is not a different or more dangerous lab; it simply removes the browser workbook’s navigation, saved notes, copy buttons, and progress assistance. For a record-by-record introduction before Part B in either mode, use the [annotated OCSF Authentication and API Activity sample](ocsf-sample.md).

## 1. Verify the bundle — 2 minutes

From the repository root:

```bash
python3 tools/workshop.py verify
```

Every line should begin with `PASS`. Verification checks fixture structure, IAM and Guardrail behavior, OCSF time/type/activity invariants, detector behavior, and required infrastructure policy markers. It does not deploy or contact any cloud service.

If it fails, read the first `FAIL` line, confirm you are in the repository root, and obtain a fresh archive before changing evidence files.

## 2. Use the evidence-first method

For every exercise:

1. Read the question and evidence without opening `solutions/` or `instructor/`.
2. Write a short hypothesis in your own notes.
3. Record at least two evidence fields—not only a suspicious keyword.
4. Run the reveal or test command.
5. Explain why the relevant control acted or failed.
6. Complete the checkpoint before moving on.

Stuck for more than three minutes? Open [`hints.md`](hints.md) and use only Hint 1 for that exercise. Escalate to Hint 2 or 3 only if needed.

## 3. Part A — AI stack boundaries, 30–35 minutes

Open [`../labs/part-a-ai-stack.md`](../labs/part-a-ai-stack.md).

You will:

- review an over-broad execution policy and a constrained replacement;
- classify eight normalized invocation records;
- distinguish direct, indirect, disclosure, and PII handling behavior;
- map controls to IAM, Guardrails, retrieval, application/tool authorization, and output handling.

Checkpoint commands:

```bash
python3 tools/workshop.py iam
python3 tools/workshop.py prompts --evidence
python3 tools/workshop.py prompts
```

Do not run the final `prompts` command until you have classified the records yourself.

## 4. Part B — OCSF and cross-cloud identity, 35–45 minutes

Open [`../labs/part-b-ocsf.md`](../labs/part-b-ocsf.md) and keep [`ocsf-field-guide.md`](ocsf-field-guide.md) nearby.

You will:

- orient to Authentication (`3002`) and API Activity (`6003`) events;
- reconstruct one federation subject across three providers;
- run an intentionally noisy detector;
- create and edit a candidate configuration;
- prove your tuning with positive, negative, and adversarial tests.

Commands:

```bash
python3 tools/workshop.py schema
python3 tools/workshop.py timeline
python3 tools/workshop.py detect
python3 tools/workshop.py start-detection
# Edit work/cross-cloud-federation-config.json
python3 tools/workshop.py detect --config work/cross-cloud-federation-config.json --show-suppressed
python3 tools/workshop.py test-detection --config work/cross-cloud-federation-config.json
```

Your first detector run should show **two active alerts**. Do not simply allowlist a subject. Build an exact behavior baseline using subject, source, provider set, provider-qualified roles, issuer, audience set, and permitted operations.

## 5. Final reflection — 5 minutes

Answer these without the key:

1. Which IAM permission created privilege-delegation risk, and what else would an attacker need to exploit it?
2. Why was the unapproved retrieval record stronger prompt-attack evidence than a keyword match?
3. Which control stopped the risky tool request when the Guardrail did not?
4. Why do prompt-attack filters require correctly tagged user-controlled input?
5. What are the risks of hidden Unicode characters in model inputs and outputs?
6. Which stable identity claim connected AWS, Azure, and GCP?
7. At what time did the suspicious identity first meet the multi-provider threshold?
8. Why did a subject-only allowlist fail the adversarial detector test?
9. Which parts of the SQL/YAML references must be adapted to a real analytics engine?

Then, in a full repository checkout, compare with the answer key at `instructor/answer-key.md`. The participant archive intentionally omits complete answers.

## Optional extensions

- Change the approved source IP in your work config and confirm the release candidate alerts.
- Remove one expected audience and inspect the failed test.
- Add a denied authentication event and decide whether it belongs in the primary rule or a separate reconnaissance rule.
- Design an alternate correlation path for logs where source IP is missing or shared by a proxy.
- Map one raw provider event from your own authorized lab into the fields documented in the OCSF guide; do not use customer or production data.

## Rules of engagement

- Analyze only included synthetic data or explicitly authorized systems.
- Never deploy `data/iam/agent-execution-role-overbroad.json`.
- Do not use the optional infrastructure stack in a production account.
- Do not copy real credentials, customer logs, or sensitive prompts into issues or pull requests.
- Treat retrieved content and model output as untrusted input.
