# Optional AWS demonstration stack

The self-guided workshop is completely offline. This stack is an instructor-only visual demonstration of a Bedrock Guardrail and encrypted log destination. It is not required for any exercise.

## Resources created

- One Amazon Bedrock Guardrail with input prompt-attack filtering, a denied disclosure topic, and PII controls
- One symmetric customer-managed KMS key and alias
- One KMS-encrypted CloudWatch log group with 3,653-day retention

It does **not** create or invoke a model, configure model invocation logging, create an agent/execution role, upload evidence, or deploy the intentionally vulnerable policy.

## Security decisions

- The KMS policy grants the regional CloudWatch Logs service principal the required cryptographic operations.
- Key use is restricted to the exact workshop log-group ARN through `kms:EncryptionContext:aws:logs:arn` and to the current account with `aws:SourceAccount`.
- The account principal can delegate administration through IAM; deployment still depends on the caller's authorized permissions.
- Prompt-attack filtering applies to input. Applications must correctly tag user-controlled input when invoking the Guardrail.
- PII anonymization/blocking is configured by entity type and applies when the Guardrail assesses prompts or responses.
- No S3 bucket, public resource, secret, VPC, or model endpoint is created.
- Tags identify resources and synthetic-only scope.

## Pre-deployment review

Deployment changes an AWS account and can incur charges. Before proceeding:

1. Use an authorized, non-production sandbox.
2. Confirm the selected Region supports Bedrock Guardrails.
3. Review current Bedrock, CloudWatch Logs, KMS, and CloudFormation documentation.
4. Run `aws cloudformation validate-template` with the intended credentials.
5. Review the caller identity and resulting change set.
6. Plan cleanup and understand that KMS deletion has a seven-day waiting period.

## Deploy

```bash
./scripts/deploy.sh us-east-1
```

The script validates the template, displays caller identity, and requires typing `DEPLOY`.

## Cleanup

```bash
CONFIRM_DELETE=defcon34-strategic-defense \
  ./scripts/cleanup.sh us-east-1
```

After stack deletion, verify the KMS key is pending deletion and that no unexpected resources remain.

## Production warning

Do not copy this minimal demonstration directly into production. A production design needs application-specific filter testing, input tagging in actual invocations, hidden-Unicode handling, deterministic tool authorization, least privilege, model invocation integration, monitoring, incident response, retention/legal review, baseline ownership, drift detection, and the organization's infrastructure delivery controls.

References:

- [Create and use Bedrock Guardrails](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html)
- [Tag user input for prompt-attack filtering](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-tagging.html)
- [Encrypt CloudWatch Logs with KMS](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html)
