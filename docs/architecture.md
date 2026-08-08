# Workshop architecture

## Design goals

- Work offline with Python 3.10+ and no third-party packages.
- Support both a 60-minute facilitated session and a 75–90 minute independent lab.
- Produce visible progress every few minutes without replacing learner analysis with answer-only commands.
- Teach evidence-based AI-agent defense and cross-cloud detection without offensive activity.
- Separate normalized teaching fixtures from claims about raw provider exports.
- Make false-positive tuning testable, not merely a discussion prompt.

## Learning objectives

Learners will be able to:

1. Explain why an autonomous agent's effective authorization defines maximum blast radius.
2. Identify wildcard, privilege-delegation, broad data-access, and unscoped logging permissions.
3. Distinguish direct, indirect, transformed, benign, and PII-related invocation behavior using multiple signals.
4. Explain what belongs in Bedrock Guardrails versus IAM, retrieval, application/tool authorization, output handling, and monitoring.
5. Read OCSF Authentication and API Activity fields across three providers.
6. Reconstruct a federation subject from authentication through sensitive API activity.
7. Implement and test a composite approved-workflow baseline without masking deviations.

## Scenario: two incidents, one security principle

Northstar Robotics experiences two separate incidents:

### Incident A — AI support agent

An unapproved retrieval document claims higher authority and asks the support agent to read a production deployment secret. Prompt-attack filtering misses the indirect instruction, but deterministic application policy denies the tool request. Review of the execution role reveals that a second control failure could otherwise create broad impact.

### Incident B — deployment federation

A feature-branch CI subject successfully exchanges credentials for privileged identities in Azure, AWS, and GCP. Sensitive API activity follows. A normal main-branch release also spans AWS and GCP and reads one expected bootstrap secret, creating a realistic tuning decision.

The lab does not claim Incident A caused Incident B. The connection is architectural: both agents and CI jobs are workload identities whose reachable authority must be constrained and observable.

## Evidence flow

```text
Part A
IAM policies ---------------------> static scope analysis
Normalized invocation evidence ---> contextual classification
Guardrail teaching design --------> control-layer mapping

Part B
OCSF-normalized events -----------> schema orientation + timeline
Starter JSON config --------------> two active candidates
Learner work config --------------> exact behavior baseline
Adversarial test -----------------> attack kept + release suppressed + deviation kept
```

## Detection semantics

A candidate incident requires:

1. successful Authentication (`class_uid: 3002`);
2. one non-empty federation subject and source IP;
3. at least two distinct providers in a rolling 15-minute event-time window;
4. a configured sensitive API Activity (`class_uid: 6003`) at or after the provider threshold;
5. no exact match to a composite approved-workflow baseline.

The baseline compares subject, source, provider set, target-role set, provider-qualified role pairs, issuer, audience set, and allowed sensitive operations. This deliberately prevents an approved subject from suppressing behavior that appears from a new source, binds a familiar role name to the wrong provider, or reaches new providers, roles, audiences, or operations.

The Python runner de-duplicates overlapping windows into one candidate per subject/source for this small fixture. Production analytics must define incident keys, late-arriving data behavior, de-duplication, and missing/shared-IP paths for the selected engine.

## Guardrail and application boundary

| Layer | Responsibility |
|---|---|
| IAM | Resource/action scope and no unnecessary role delegation |
| Input preparation | Provenance, trust state, correct Guardrail tags, hidden-Unicode stripping |
| Guardrails | Prompt-attack input filtering, denied topics, configured PII handling |
| Retrieval | Approved sources, document trust, instruction/data separation |
| Tool authorization | Deterministic allowlists, parameter checks, approval gates |
| Output handling | Validation, context-appropriate encoding, no automatic execution |
| Monitoring | Invocation, tool-decision, identity, and cloud API telemetry |

Guardrails are probabilistic and require representative testing. Tool and IAM authorization remain deterministic enforcement boundaries.

## Teaching method

Every exercise follows: orient → inspect → hypothesize → test → explain → extend. Commands have distinct roles:

- evidence commands improve readability without giving the answer;
- reveal commands let learners compare reasoning;
- starter commands create intentional failure or noise;
- test commands verify both expected and adversarial behavior;
- hints escalate gradually rather than immediately disclosing solutions.

## Delivery modes

### Instructor-led, 60 minutes

Use slides for the OCSF and multi-cloud framing, keep the offline commands on the critical path, and perform detection tuning in pairs. The instructor guide provides a compressed schedule.

### Self-guided, 75–90 minutes

Learners complete evidence tables, use staged hints, edit a detector config, and finish reflection questions. No instructor or cloud access is required.

### Advanced extension

Learners adapt the SQL/YAML design to a chosen analytics engine, add late/missing/shared-source cases, or map provider events from an explicitly authorized test environment.

## Success criteria

- The bundle verifies without network access.
- Learners identify the indirect retrieval attack and deterministic tool denial.
- Learners explain why `iam:PassRole` is dangerous but not a standalone API operation.
- Learners identify the feature-branch subject and the multi-provider threshold time.
- A learner config passes all four detector tests.
- The lab states where normalization or engine-specific adaptation remains necessary.
