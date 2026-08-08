# Part B — Cross-cloud threat hunting with OCSF

**Time:** 35–45 minutes  
**Goal:** use a common schema to reconstruct workload federation behavior across AWS, Azure, and GCP, then tune and test a rolling-window detector.

Keep [`../docs/ocsf-field-guide.md`](../docs/ocsf-field-guide.md) open. Before reading the one-line JSONL fixture, walk through [`../docs/ocsf-sample.md`](../docs/ocsf-sample.md), which annotates one Authentication event and its linked API Activity record field by field. The fixtures are OCSF-normalized teaching records, not raw provider exports.

## Exercise B1 — Orient to the schema (8 minutes)

Run:

```bash
python3 tools/workshop.py schema
```

The fixture uses:

- `class_uid: 3002` — Authentication;
- `class_uid: 6003` — API Activity;
- `activity_id` — action within the class (`1` Logon, `2` Read, `3` Update here);
- `type_uid` — `class_uid × 100 + activity_id`;
- `status_id: 1` — Success in these records.

Open [`../data/ocsf/cross-cloud-events.jsonl`](../data/ocsf/cross-cloud-events.jsonl) and find one authentication from each provider. Fill in:

| Provider | Native event code | Actor/federation subject | Target principal | Source | Session | Audience |
|---|---|---|---|---|---|---|
| AWS | | | | | | |
| Azure | | | | | | |
| GCP | | | | | | |

Questions:

1. Which fields normalize cleanly across all providers?
2. Which claims remain under `unmapped`, and why is that more honest than forcing an uncertain mapping?
3. Why are issuer + audience + subject stronger than display name or IP alone?
4. What does `session.uid` add when connecting authentication to later API activity?

Need help? Use [B1 hints](../docs/hints.md#exercise-b1--ocsf-orientation).

## Exercise B2 — Reconstruct the suspicious pivot (12 minutes)

Search the fixture for source `198.51.100.42`. Before using the timeline helper, record:

- first successful authentication time;
- federation subject;
- providers and cloud accounts reached;
- target role/service principal/service account in each provider;
- sensitive API operations and sessions;
- earliest defensible prevention or containment point.

Draw:

```text
issuer + subject + audience
          |
          v
provider authentication -> cloud session -> API activity
          |
          +---- repeat across providers inside the event-time window
```

Now reveal the ordered view:

```bash
python3 tools/workshop.py timeline
```

Notice that the detector's “multi-cloud threshold” is not reached until the second distinct provider authenticates. The reference detector requires a privileged operation at or after that threshold and before the rolling 15-minute window closes. Earlier single-provider activity remains useful investigation context but does not satisfy the ordered follow-on condition by itself.

Need help? Use [B2 hints](../docs/hints.md#exercise-b2--timeline).

## Exercise B3 — Tune the detector (20 minutes)

### Step 1: establish the baseline

Run the intentionally noisy starter:

```bash
python3 tools/workshop.py detect
```

Expected shape: **two active candidates**. One is the feature-branch incident. The other is a legitimate main-branch release that also spans two providers and reads a bootstrap secret. This is deliberate: “multi-cloud plus secret access” is not automatically malicious.

For each candidate, compare:

- exact subject;
- source IP;
- provider set;
- target-role set;
- provider–role pairs;
- token issuer;
- audience set;
- privileged operations.

### Step 2: create your candidate configuration

```bash
python3 tools/workshop.py start-detection
```

This creates `work/cross-cloud-federation-config.json`. Open it and add one object to `approved_workflows`. Use this structure, deriving values from the approved release evidence:

```json
{
  "name": "descriptive-baseline-name",
  "subject": "exact value",
  "source_ips": ["exact expected source"],
  "providers": ["exact", "provider", "set"],
  "target_roles": ["exact", "role", "set"],
  "provider_role_pairs": ["Provider:exact-role", "OtherProvider:exact-role"],
  "token_issuers": ["exact issuer"],
  "token_audiences": ["exact", "audience", "set"],
  "operations": ["only expected sensitive operations"]
}
```

Do **not** change `min_providers`, remove sensitive operations, or allowlist only the subject. A subject can be compromised; a safe suppression must describe the complete expected behavior.

### Step 3: inspect and test

```bash
python3 tools/workshop.py detect \
  --config work/cross-cloud-federation-config.json \
  --show-suppressed

python3 tools/workshop.py test-detection \
  --config work/cross-cloud-federation-config.json
```

Completion requires four passes:

1. The feature-debug incident remains an active alert.
2. The exact expected main release is suppressed.
3. A familiar role name used on the wrong provider still alerts.
4. The main subject performing the attack's unexpected behavior still alerts.

The last two cases are why aggregate role sets and subject-only allowlists are unsafe.

If your test fails, use [B3 hints](../docs/hints.md#exercise-b3--detection-tuning) one level at a time. After attempting the exercise, users of the full GitHub repository can compare with `solutions/cross-cloud-federation-config.json`; the participant archive omits that file.

### Step 4: review portable detection artifacts

Compare your behavior with:

- [`../queries/ocsf-cross-cloud-federation.sql`](../queries/ocsf-cross-cloud-federation.sql)
- [`../detections/cross-cloud-federation.yml`](../detections/cross-cloud-federation.yml)

Identify what your target analytics engine must supply:

- event-time arithmetic and rolling windows;
- nested-field access;
- distinct-provider and exact-set aggregation;
- ordering after the provider threshold;
- overlapping-window incident de-duplication;
- a strategy when source IP is missing or shared.

### Part B checkpoint

Explain, in your own words:

> The detector does not alert merely because one IP touched multiple clouds. It correlates ______, reaches a threshold at ______, requires ______ afterward, and suppresses a release only when ______.

## Advanced extensions

1. Add Azure to the approved provider set without changing the fixture. Explain why broadening an unused baseline is risky.
2. Change the approved source to `198.51.100.42`; confirm the adversarial test still prevents suppression because other behavior differs.
3. Design a second rule for failed authentications and unusual issuer/audience combinations.
4. Decide how to correlate when CI traffic comes through a shared proxy and `src_endpoint.ip` has low identity value.
5. Extend the API list using actual events from an authorized test environment; do not add IAM permission names as if they were standalone API operations.
