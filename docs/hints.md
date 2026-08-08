# Staged hints

Use one hint level at a time. Hint 1 identifies where to look; Hint 2 identifies the reasoning pattern; Hint 3 is close to the answer. A full GitHub checkout also contains complete explanations in `instructor/answer-key.md` and `solutions/`; the participant archive intentionally omits them.

## Exercise A1 — IAM review

### Hint 1

For each statement, compare `Action` and `Resource` with the agent's stated job. Look for `*` in either position.

### Hint 2

One IAM action lets a caller supply a role to a compatible AWS service. The permission is dangerous when the caller can also invoke a service action that accepts the role and the role trusts that service.

### Hint 3

Focus on `iam:PassRole`. Also flag `s3:*`, `bedrock:*`, every resource `*`, decrypting unrelated keys, and writing unrelated log groups. The replacement should contain no IAM actions.

## Exercise A2 — Invocation evidence

### Hint 1

Do not begin with attack phrases. Compare source provenance, requested authority, Guardrail assessment, tool decision, and outcome.

### Hint 2

A discussion *about* injection does not redirect the agent. Retrieved text claiming to be a system update does not gain system authority merely because it was retrieved.

### Hint 3

- One direct override is blocked by `PROMPT_ATTACK`.
- One unapproved document requests `GetSecretValue`; the Guardrail misses it, but application policy denies the tool.
- One transformation request targets hidden instructions.
- Email is anonymized; the explicitly invalid synthetic SSN is blocked.

## Exercise A3 — Control layers

### Hint 1

Ask which component has the final authority to perform an action. A model can propose a tool call; application code and cloud authorization decide whether it happens.

### Hint 2

Prompt-attack filtering needs correctly tagged input. PII policy can inspect input and output. IAM cannot classify text, and Guardrails cannot scope an S3 ARN.

### Hint 3

A complete design includes least-privilege IAM, trusted retrieval/provenance, prompt and PII filters, deterministic tool and parameter authorization, hidden-Unicode stripping, approval gates, egress restrictions, output validation/encoding, and telemetry.

## Exercise B1 — OCSF orientation

### Hint 1

Start with `class_uid`, then read actor, target user, cloud, source, session, and `unmapped` claims.

### Hint 2

`actor.user.uid` represents the initiating identity; `user.uid` represents the target cloud principal in Authentication events. The provider's original event name is retained in metadata/unmapped.

### Hint 3

Authentication is class `3002`; API Activity is `6003`. The shared workload claim is `unmapped.federation_subject`; issuer, audience, and target role remain visible nearby.

## Exercise B2 — Timeline

### Hint 1

Search for `198.51.100.42`, sort by `time`, and group API events back to authentication with subject and session.

### Hint 2

The same feature-branch subject reaches Azure first, then AWS, then GCP. Secret reads and policy modification establish higher confidence than authentication alone.

### Hint 3

The multi-provider threshold is reached when AWS becomes the second provider. The later AWS secret read and GCP policy update satisfy ordered privileged follow-on behavior.

## Exercise B3 — Detection tuning

### Hint 1

Run with `--show-suppressed` after each edit. JSON syntax errors usually mean a missing comma, quote, bracket, or brace.

### Hint 2

Populate every field in the approved workflow object from the main-branch records and starter alert. Sets and provider–role pairs must match exactly; operation matching is intentionally limited to expected sensitive actions.

### Hint 3

The approved behavior uses:

- subject ending in `refs/heads/main`;
- source `192.0.2.25`;
- providers AWS and GCP;
- roles `ReleaseDeployer` and `release-deployer`;
- provider–role pairs `AWS:ReleaseDeployer` and `GCP:release-deployer`;
- issuer `https://token.actions.example.test`;
- the AWS STS and GCP workload-pool audiences;
- only `GetSecretValue` as the sensitive operation.

In a full GitHub checkout, you can compare with `solutions/cross-cloud-federation-config.json`. In the participant archive, rely on the four automated test outcomes.
