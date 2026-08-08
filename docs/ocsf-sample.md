# Annotated OCSF sample — workload federation to API activity

This walkthrough uses selected fields from two records in [`../data/ocsf/cross-cloud-events.jsonl`](../data/ocsf/cross-cloud-events.jsonl). The records are normalized teaching representations targeting OCSF 1.3 concepts; they are not byte-for-byte Microsoft Entra ID or Azure resource-log exports.

The investigation question is:

> Which external workload obtained a cloud principal, and what did that provider principal do afterward?

## Sample 1 — Authentication (`class_uid: 3002`)

```json
{
  "time": 1786232100000,
  "time_dt": "2026-08-08T23:35:00Z",
  "class_uid": 3002,
  "class_name": "Authentication",
  "activity_id": 1,
  "activity_name": "Logon",
  "type_uid": 300201,
  "status_id": 1,
  "status": "Success",
  "metadata": {
    "version": "1.3.0",
    "product": {
      "name": "Microsoft Entra ID Sign-in Logs",
      "vendor_name": "Microsoft"
    },
    "event_code": "WorkloadIdentitySignIn"
  },
  "cloud": {
    "provider": "Azure",
    "account": {
      "uid": "00000000-1111-2222-3333-444444444444"
    },
    "region": "eastus"
  },
  "actor": {
    "user": {
      "uid": "repo:northstar-robotics/agent-deploy:ref:refs/heads/feature-debug",
      "name": "unapproved-feature-workflow",
      "type": "Workload"
    }
  },
  "user": {
    "uid": "00000000-aaaa-bbbb-cccc-111111111111",
    "name": "DeploymentContributor",
    "type": "Service Principal"
  },
  "src_endpoint": {
    "ip": "198.51.100.42"
  },
  "session": {
    "uid": "az-attack-01"
  },
  "unmapped": {
    "federation_subject": "repo:northstar-robotics/agent-deploy:ref:refs/heads/feature-debug",
    "identity_provider": "token.actions.example.test",
    "token_issuer": "https://token.actions.example.test",
    "token_audience": "api://AzureADTokenExchange",
    "target_role": "DeploymentContributor",
    "provider_event_name": "WorkloadIdentitySignIn"
  }
}
```

### Read it in nine questions

| Question | Field | What this record says |
|---|---|---|
| When did it happen? | `time_dt` | `2026-08-08T23:35:00Z` |
| What kind of event is it? | `class_uid`, `class_name` | Authentication (`3002`) |
| What activity occurred? | `activity_id`, `activity_name` | Logon (`1`) |
| Did it succeed? | `status_id`, `status` | Yes—Success (`1`) |
| Which provider produced it? | `cloud.provider` | Azure |
| Who initiated federation? | `actor.user.uid` | The `feature-debug` CI/OIDC subject |
| Which cloud principal was obtained? | `user.name`, `user.type` | `DeploymentContributor` service principal |
| From where, in which session? | `src_endpoint.ip`, `session.uid` | `198.51.100.42`, session `az-attack-01` |
| Which trust claims matter? | `unmapped.token_issuer`, `token_audience`, `federation_subject` | Issuer, Azure exchange audience, and exact repository/ref subject |

`type_uid` follows the fixture's OCSF relationship:

```text
type_uid = class_uid × 100 + activity_id
300201   = 3002 × 100 + 1
```

The external workload is the **initiator**, while `DeploymentContributor` is the **provider principal obtained through authentication**. Display names alone are weak; issuer, audience, exact subject, source, and target principal together provide stronger context.

## Sample 2 — API Activity (`class_uid: 6003`)

One minute later, the Azure service principal uses the resulting session:

```json
{
  "time": 1786232160000,
  "time_dt": "2026-08-08T23:36:00Z",
  "class_uid": 6003,
  "class_name": "API Activity",
  "activity_id": 2,
  "activity_name": "Read",
  "type_uid": 600302,
  "status_id": 1,
  "status": "Success",
  "metadata": {
    "version": "1.3.0",
    "product": {
      "name": "Azure Activity and Resource Logs",
      "vendor_name": "Microsoft"
    },
    "event_code": "SecretGet"
  },
  "cloud": {
    "provider": "Azure",
    "account": {
      "uid": "00000000-1111-2222-3333-444444444444"
    },
    "region": "eastus"
  },
  "actor": {
    "user": {
      "uid": "00000000-aaaa-bbbb-cccc-111111111111",
      "name": "DeploymentContributor",
      "type": "Service Principal"
    }
  },
  "src_endpoint": {
    "ip": "198.51.100.42"
  },
  "session": {
    "uid": "az-attack-01"
  },
  "api": {
    "operation": "SecretGet",
    "service": {
      "name": "Azure Key Vault"
    }
  },
  "unmapped": {
    "federation_subject": "repo:northstar-robotics/agent-deploy:ref:refs/heads/feature-debug",
    "target_role": "DeploymentContributor",
    "provider_event_name": "SecretGet",
    "resource": "vaults/northstar-prod/secrets/deployment-token"
  }
}
```

### What changed between the two classes?

| Authentication | API Activity |
|---|---|
| `actor.user.uid` is the external workload subject initiating federation. | `actor.user.uid` is the Azure service principal actually calling the API. |
| `user` identifies the cloud principal obtained or targeted. | `api.operation` and `api.service.name` identify what the provider principal did. |
| Issuer and audience explain why the token was accepted. | Resource and operation explain the follow-on impact. |
| `session.uid` establishes the provider session. | The same `session.uid` links the API action back to that authentication. |

The original federation subject is preserved under `unmapped.federation_subject` on the API event. This avoids the inaccurate claim that a repository/ref string directly called Key Vault while retaining the identity context needed for correlation.

## Build the chain

```text
issuer + audience + federation subject
                 |
                 v
Azure Authentication (3002)
actor = external workload
user  = DeploymentContributor
session = az-attack-01
                 |
                 v
Azure API Activity (6003)
actor = DeploymentContributor
operation = SecretGet
session = az-attack-01
federation subject preserved under unmapped
```

Apply the same method to AWS and GCP:

1. Find a successful Authentication event.
2. Record the workload subject, issuer, audience, source, target principal, and session.
3. Find API Activity with the same provider session and preserved subject.
4. Record the provider principal, operation, service, and resource.
5. Repeat across providers inside the event-time window.

## What the record proves—and does not prove

It supports the claim that the feature-branch workload successfully obtained an Azure service principal and that the resulting provider principal read a Key Vault secret in the same session. It does **not**, by itself, prove how the workload credential was obtained, whether the secret contents were later used, or that this Azure action alone meets the lab's multi-cloud detector threshold.

Continue with [`../labs/part-b-ocsf.md`](../labs/part-b-ocsf.md) to correlate the Azure sequence with AWS and GCP activity.
