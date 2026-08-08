# OCSF field guide for the lab

This guide explains the normalized fields used in Part B. It is not a claim that each record is a byte-for-byte provider export or that every provider field has one lossless OCSF destination.

## Worked example

Start with [`ocsf-sample.md`](ocsf-sample.md) for complete selected-field JSON and annotations. Its two records form this chain:

```text
feature-debug OIDC subject
  -> Authentication 3002 / WorkloadIdentitySignIn
  -> target Azure service principal: DeploymentContributor
  -> provider session: az-attack-01
  -> API Activity 6003 / SecretGet
  -> Azure Key Vault deployment-token
```

On Authentication, `actor.user` is the external workload and `user` is the provider principal being obtained. On API Activity, `actor.user` is the provider principal performing the operation. The same `session.uid` and preserved `unmapped.federation_subject` connect the records without pretending that the external repository/ref string directly called Key Vault.

## Read an event in six questions

| Question | OCSF location used here | Example |
|---|---|---|
| What happened? | `class_uid`, `class_name`, `activity_id`, `activity_name` | Authentication / Logon |
| When? | `time` and `time_dt` | epoch ms and ISO 8601 |
| Did it succeed? | `status_id`, `status` | `1`, `Success` |
| Who initiated it? | `actor.user.uid` | repository/ref federation subject |
| Which cloud principal or API? | `user.uid` for authentication; `api.operation` for API activity | role ARN / `SetIamPolicy` |
| From where and in which session? | `src_endpoint.ip`, `session.uid` | documentation IP / provider session |

## Class and type identifiers

The fixture targets OCSF 1.3 concepts:

- `3002` — Authentication
- `6003` — API Activity
- `activity_id: 1` — Logon in Authentication
- `activity_id: 2` — Read in API Activity
- `activity_id: 3` — Update in API Activity
- `type_uid = class_uid × 100 + activity_id`

The validator checks the type formula and ensures secret retrieval is represented as Read rather than Create.

## Actor versus target

For an authentication event:

- `actor.user.uid` is the workload identity initiating federation.
- `user.uid` is the cloud principal obtained or targeted: AWS role, Azure service principal, or GCP service account.

For API Activity, `actor.user.uid` remains the acting identity and `api.operation` describes the action. `session.uid` connects activity to the relevant provider session when available.

## Workload federation claims

Three claims are central to trust policy and detection:

- **Issuer (`iss`)** — who issued the token?
- **Audience (`aud`)** — for which relying party or exchange endpoint was it intended?
- **Subject (`sub`)** — which repository, branch, workload, or other principal does it represent?

This lab retains them as:

```text
unmapped.token_issuer
unmapped.token_audience
unmapped.federation_subject
```

They remain under `unmapped` because the teaching fixture prioritizes honest preservation over asserting a universal mapping for every source pipeline. A production OCSF mapper should use the schema version, extensions, profiles, and source-specific mapping guidance selected by that organization.

## Provider concept comparison

| Common concept | AWS example | Azure example | GCP example |
|---|---|---|---|
| Federation event | `AssumeRoleWithWebIdentity` | workload identity sign-in | `GenerateAccessToken` |
| Cloud scope | account | tenant/subscription context | project |
| Target principal | role ARN | service principal | service account |
| Source | CloudTrail source IP | sign-in IP | audit caller IP |
| Follow-on secret read | Secrets Manager `GetSecretValue` | Key Vault `SecretGet` | provider-specific secret access if present |
| Policy change | role/policy API | role assignment/policy API | `SetIamPolicy` |

Actual raw structures and available fields vary by service, log type, configuration, and export pipeline. The fixture normalizes only what the exercise needs.

## Correlation method

The detector groups successful events by exact `federation_subject` and source IP, then evaluates rolling event-time windows:

1. Start at an authentication event.
2. Count distinct providers during the next 15 minutes.
3. Record when the configured provider threshold is first reached.
4. Require a configured sensitive API operation at or after that threshold.
5. Compare the complete candidate behavior with approved workflow baselines.
6. Suppress only an exact match; new source, provider, provider–role pairing, issuer, audience, or operation remains visible.

Source IP is supporting context, not a stable identity key by itself. NAT gateways, proxies, VPNs, and CI runners can aggregate many workloads. Production designs need alternate paths when IP is unavailable or shared.

## Why exact behavior baselines matter

Allowlisting only a subject assumes that subject cannot be compromised. The lab's adversarial test reuses the approved subject with the attack's source, providers, roles, audiences, and actions. A subject-only filter hides it; the composite baseline does not.

## Further reading

- [OCSF schema browser](https://schema.ocsf.io/)
- [OCSF schema repository](https://github.com/ocsf/ocsf-schema)
- [OCSF examples](https://github.com/ocsf/examples)
