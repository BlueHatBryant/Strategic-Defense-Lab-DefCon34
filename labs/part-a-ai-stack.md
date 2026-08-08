# Part A — Securing the AI stack

**Time:** 30–35 minutes  
**Goal:** constrain the agent's authority, classify invocation evidence without keyword shortcuts, and place each safeguard at the correct layer.

## Mental model

A model does not create cloud authority by itself. Maximum impact is bounded by the workload's effective permissions, reachable tools and data, network paths, and approval controls. Guardrails can reduce model-layer risk, but probabilistic filtering cannot replace deterministic authorization.

## Exercise A1 — Review the execution policy (8 minutes)

Open [`../data/iam/agent-execution-role-overbroad.json`](../data/iam/agent-execution-role-overbroad.json). Do not run the helper yet.

Create a table in your notes:

| Statement | Excessive action? | Excessive resource? | Plausible impact |
|---|---|---|---|
| `AllAgentDocuments` | | | |
| `AllBedrockActions` | | | |
| `DecryptAnyKey` | | | |
| `PrivilegeDelegation` | | | |
| `WriteAnyLogGroup` | | | |

Answer:

1. Which statement includes a privilege-delegation permission?
2. Why does that permission not create escalation by itself? What compatible service action and role trust would also be needed?
3. Which statements can affect resources unrelated to the support agent?
4. What should an agent need if it only reads one document prefix, invokes one model, decrypts those objects, and writes its own logs?

Reveal the static findings:

```bash
python3 tools/workshop.py iam
```

Now compare with [`../data/iam/agent-execution-role-least-privilege.json`](../data/iam/agent-execution-role-least-privilege.json). Locate:

- separate bucket-list and object-read permissions;
- one approved object prefix;
- one foundation-model ARN;
- one KMS key plus `kms:ViaService` and encryption-context conditions;
- one log-stream pattern;
- no IAM actions.

**Production caveat:** the S3 KMS encryption context can differ when S3 Bucket Keys are enabled. Treat this fixture as a scoped teaching example, not a universal copy/paste policy.

**Checkpoint:** complete: “If an attacker controls agent context, maximum impact is bounded by ______.”

Need help? Use [A1 hints](../docs/hints.md#exercise-a1--iam-review).

## Exercise A2 — Classify invocation evidence (12 minutes)

The file [`../data/bedrock/model-invocations.jsonl`](../data/bedrock/model-invocations.jsonl) is a normalized teaching representation, not a raw Bedrock export. Print it in readable form without answers:

```bash
python3 tools/workshop.py prompts --evidence
```

Classify each of the eight records as one of:

- ordinary request;
- benign security discussion;
- direct prompt attack;
- indirect prompt attack from retrieved content;
- system/developer instruction disclosure attempt;
- PII anonymization;
- PII blocking.

Record:

| Request | Classification | Signal 1 | Signal 2 | Guardrail action | Deterministic control |
|---|---|---|---|---|---|
| `req-1001` | | | | | |
| `req-1002` | | | | | |
| `req-1003` | | | | | |
| `req-1004` | | | | | |
| `req-1005` | | | | | |
| `req-1006` | | | | | |
| `req-1008` | | | | | |
| `req-1007` | | | | | |

Use these evidence categories:

- **Intent:** explanation, override, transformation, or data movement?
- **Provenance:** user, approved retrieval, or unapproved retrieval?
- **Boundary crossing:** does data claim higher authority than its source permits?
- **Tool behavior:** which tool and arguments were proposed, and who authorized them?
- **Assessment:** which Guardrail policy acted, if any?
- **Outcome:** blocked, anonymized, denied by the application, or allowed?

Only after completing the table, reveal the reference classifications:

```bash
python3 tools/workshop.py prompts
```

Explain why searching for `ignore previous instructions` both false-positives on defensive discussion and misses transformed or indirect attacks.

Need help? Use [A2 hints](../docs/hints.md#exercise-a2--invocation-evidence).

## Exercise A3 — Place controls at the correct layer (10 minutes)

Open [`../data/bedrock/guardrail-config.json`](../data/bedrock/guardrail-config.json). It deliberately combines two kinds of information:

- `content_policy_config`, `topic_policy_config`, `sensitive_information_policy_config`, and `messages` describe Guardrail behavior.
- `input_handling` and `required_application_controls` describe controls the surrounding application must implement.

Build this table:

| Threat or failure | Guardrail | IAM | Retrieval/application | Monitoring/response |
|---|---:|---:|---:|---:|
| Direct prompt attack | | | | |
| Unapproved retrieved instructions | | | | |
| Secret-reading tool request | | | | |
| PII in input/output | | | | |
| Hidden Unicode tag characters | | | | |
| System-instruction disclosure | | | | |
| Excessive cloud permissions | | | | |

Confirm these distinctions:

1. Prompt-attack filtering applies to correctly tagged **input**; its output strength is `NONE` because this filter type is not an output classifier.
2. PII controls apply to configured entities in both input and output; anonymization and blocking have different outcomes.
3. Denied topics reduce disclosure attempts but do not make prompts a safe secret store.
4. Retrieved text has data provenance, not system authority.
5. Tool allowlists and parameter checks must execute outside the model.
6. Applications passing text to or from models should strip Unicode tag-block characters (`U+E0000–U+E007F`) and orphaned surrogates until stable, in addition to preserving safe canonical text handling.
7. Model output requires context-appropriate validation and encoding before rendering or executing anything.

### Part A checkpoint

You are done when you can explain:

- why `req-1004` remains dangerous even though the secret tool call was denied;
- which control prevented impact;
- how least privilege would reduce impact if application authorization also failed;
- why Guardrails are one layer rather than the security boundary.
