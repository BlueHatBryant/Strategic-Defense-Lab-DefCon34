# Instructor answer key

Contains complete spoilers.

## A1 — IAM

Highest-risk delegation statement: `PrivilegeDelegation`, because `iam:PassRole` on `*` can allow a workload to supply a more privileged role to a compatible service API when that role trusts the service. PassRole is not a standalone API call; exploitation also requires a role-accepting action and compatible trust.

Other findings:

- `s3:*` on `*` grants destructive and broad data/control-plane access.
- `bedrock:*` on `*` exceeds one approved inference action/model.
- `kms:Decrypt` on `*` can expose unrelated data if key policy and context also permit it.
- Logs writes are unscoped.

The replacement separates bucket listing and object reads, scopes one prefix/model/key/log stream, applies KMS service/context conditions, and removes IAM actions. S3 Bucket Keys can change the encryption context; the fixture is not a universal policy template.

Checkpoint: impact is bounded by **effective permissions, reachable tools/data, network paths, and approval controls**.

## A2 — Invocation evidence

- `req-1001`: ordinary support summarization.
- `req-1002`: benign security discussion; attack vocabulary appears in defensive context with no override or tool request.
- `req-1003`: direct prompt attack; override/disclosure intent; prompt-attack filter blocks it.
- `req-1004`: indirect retrieved-content attack; an unapproved document claims system authority and requests `GetSecretValue`. The Guardrail misses it; deterministic application policy denies the tool.
- `req-1005`: transformed system/developer instruction disclosure request; denied-topic policy blocks it.
- `req-1006`: email PII is anonymized.
- `req-1008`: explicitly invalid synthetic SSN-shaped input is blocked.
- `req-1007`: ordinary approved retrieval and allowed knowledge lookup.

Strong analysis uses provenance, authority boundary, intent, tool name/arguments, authorization decision, assessment, and outcome. Keyword-only hunting false-positives on `req-1002` and can miss transformed or indirect attacks.

## A3 — Layered design

Guardrail responsibilities in the teaching design:

- prompt-attack filtering on correctly tagged input;
- denied topic for hidden-instruction disclosure;
- configured PII anonymization/blocking on input/output;
- neutral blocked messages.

Application/platform responsibilities:

- least-privilege IAM;
- trusted retrieval and provenance enforcement;
- deterministic tool/parameter authorization;
- hidden Unicode tag-block and orphaned-surrogate stripping on model inputs/outputs until stable;
- approval gates, egress restrictions, and secret isolation;
- output validation and context-appropriate encoding;
- invocation, tool-decision, and audit telemetry.

## B1 — OCSF

- Authentication: class `3002`.
- API Activity: class `6003`.
- Secret reads use activity `2` / Read and type `600302`.
- The initiating workload appears in `actor.user.uid`; the target cloud principal appears in `user.uid` for authentication.
- Provider-specific issuer, audience, subject, role, and event name are preserved under `unmapped` in this teaching mapping.

Issuer + audience + subject are stronger identity/trust evidence than display name or IP. Session ID helps connect later API activity. IP can be shared by NAT, proxies, and CI runners.

## B2 — Suspicious timeline

Subject: `repo:northstar-robotics/agent-deploy:ref:refs/heads/feature-debug` from `198.51.100.42`.

1. 23:35 Azure workload sign-in → `DeploymentContributor`.
2. 23:36 Azure Key Vault `SecretGet`.
3. 23:38 AWS `AssumeRoleWithWebIdentity` → `AgentDeploymentAdmin`; this reaches the second-provider threshold.
4. 23:39 AWS Secrets Manager `GetSecretValue`; ordered privileged follow-on begins.
5. 23:41 GCP token exchange → `agent-deployer` service account.
6. 23:43 GCP `SetIamPolicy`.

Strong preventive control: constrain each provider trust by exact issuer/audience/subject and approved repository/ref. At response time, disable the compromised federation path and sessions according to the organization's incident process.

## B3 — Detection tuning

The starter intentionally produces two active candidates:

- approved main release from `192.0.2.25`, AWS + GCP, expected roles/audiences, and one bootstrap `GetSecretValue`;
- feature-debug incident from `198.51.100.42`, Azure + AWS + GCP, privileged roles, secret access, and policy modification.

The reference config suppresses the release only when the complete expected behavior matches, including each role's provider. One adversarial test puts a familiar GCP role name on the AWS API activity; another rewrites the attack to use the approved subject. Both still alert because provider-role binding, source, provider set, audiences, or operations deviate.

Completion output:

```text
PASS: feature-debug attack alerts
PASS: exact approved release behavior is suppressed
PASS: expected role name on the wrong provider still alerts
PASS: approved subject with unexpected behavior still alerts
```

Production work still requires SIEM-specific windows, late-event handling, de-duplication, field mappings, approved-baseline ownership, and alternate correlation when IP is shared or missing.
