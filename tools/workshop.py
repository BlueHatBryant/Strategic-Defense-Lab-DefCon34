#!/usr/bin/env python3
"""Offline runner for the Strategic Defense self-guided workshop.

Uses only the Python standard library. All identities, prompts, and events are
synthetic. Run ``python3 tools/workshop.py --help`` to list the exercises.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
STARTER_CONFIG = ROOT / "detections/cross-cloud-federation-starter.json"
SOLUTION_CONFIG = ROOT / "solutions/cross-cloud-federation-config.json"
WORK_CONFIG = ROOT / "work/cross-cloud-federation-config.json"
ATTACK_SUBJECT = "repo:northstar-robotics/agent-deploy:ref:refs/heads/feature-debug"
APPROVED_SUBJECT = "repo:northstar-robotics/agent-deploy:ref:refs/heads/main"

REQUIRED_FILES = [
    "README.md",
    "docs/architecture.md",
    "docs/participant-guide.md",
    "docs/hints.md",
    "docs/ocsf-field-guide.md",
    "docs/ocsf-sample.md",
    "docs/site/index.html",
    "labs/part-a-ai-stack.md",
    "labs/part-b-ocsf.md",
    "data/iam/agent-execution-role-overbroad.json",
    "data/iam/agent-execution-role-least-privilege.json",
    "data/bedrock/model-invocations.jsonl",
    "data/bedrock/guardrail-config.json",
    "data/ocsf/cross-cloud-events.jsonl",
    "queries/ocsf-cross-cloud-federation.sql",
    "detections/cross-cloud-federation.yml",
    "detections/cross-cloud-federation-starter.json",
    "scripts/package_release.py",
    "tests/test_workshop.py",
    "tests/test_release.py",
    "CONTRIBUTING.md",
    "SECURITY.md",
]


def load_json(relative_path: str | Path) -> Any:
    path = Path(relative_path)
    if not path.is_absolute():
        path = ROOT / path
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_jsonl(relative_path: str | Path) -> list[dict[str, Any]]:
    path = Path(relative_path)
    if not path.is_absolute():
        path = ROOT / path
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {error}") from error
    return records


def nested(record: dict[str, Any], *path: str, default: Any = None) -> Any:
    current: Any = record
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def actions(statement: dict[str, Any]) -> list[str]:
    value = statement.get("Action", [])
    return [value] if isinstance(value, str) else list(value)


def command_iam(_: argparse.Namespace) -> int:
    policy = load_json("data/iam/agent-execution-role-overbroad.json")
    print("IAM REVIEW — findings\n")
    findings = 0
    for statement in policy.get("Statement", []):
        sid = statement.get("Sid", "(unnamed)")
        statement_actions = actions(statement)
        resources = statement.get("Resource", [])
        resources = [resources] if isinstance(resources, str) else resources
        issues: list[str] = []
        if any(action == "*" or action.endswith(":*") for action in statement_actions):
            issues.append("wildcard action")
        if "*" in resources:
            issues.append("unscoped resource")
        if "iam:PassRole" in statement_actions:
            issues.append("privilege delegation via iam:PassRole")
        if issues:
            findings += len(issues)
            print(f"- {sid}: {', '.join(issues)}")
            print(f"  actions={statement_actions} resources={resources}")
    print(f"\n{findings} risky patterns across {len(policy.get('Statement', []))} statements.")
    print("Remediation: exact actions + exact resources/conditions; remove IAM delegation.")
    print("Next: compare with data/iam/agent-execution-role-least-privilege.json.")
    return 0


def classify_invocation(record: dict[str, Any]) -> tuple[str, list[str]]:
    request_text = nested(record, "input", "text", default="").lower()
    retrieval = record.get("retrieval", [])
    assessments = nested(record, "guardrail", "assessments", default=[])
    policies = {item.get("policy") for item in assessments}
    tools = record.get("requested_tools", [])

    unapproved_retrieval = any(item.get("trust_state") == "UNAPPROVED" for item in retrieval)
    denied_tool = any(
        tool.get("authorization_decision", "").startswith("DENY") for tool in tools
    )
    if unapproved_retrieval and denied_tool:
        return "INDIRECT_PROMPT_ATTACK", [
            "unapproved retrieved content crosses an instruction boundary",
            "tool request denied by deterministic application policy",
        ]
    if "PROMPT_ATTACK" in policies and nested(record, "guardrail", "action") == "BLOCKED":
        return "DIRECT_PROMPT_ATTACK", [
            "instruction override or disclosure intent",
            "prompt-attack assessment blocked the input",
        ]
    if "DENIED_TOPIC" in policies:
        return "SYSTEM_PROMPT_DISCLOSURE", [
            "hidden-instruction transformation request",
            "denied-topic assessment blocked the input",
        ]
    if "SENSITIVE_INFORMATION" in policies:
        entity_actions = {
            entity.get("action")
            for assessment in assessments
            for entity in assessment.get("entities", [])
        }
        if "BLOCK" in entity_actions:
            classification = "PII_BLOCKING"
        elif "ANONYMIZE" in entity_actions:
            classification = "PII_ANONYMIZATION"
        else:
            classification = "PII_CONCERN"
        return classification, [
            "sensitive-information assessment",
            f"configured PII action(s): {', '.join(sorted(entity_actions))}",
        ]
    if "prompt-injection test" in request_text or "prompt injection test" in request_text:
        return "BENIGN_SECURITY_DISCUSSION", [
            "defensive explanatory intent",
            "no instruction override or tool request",
        ]
    return "ORDINARY", ["no suspicious provenance, tool, or guardrail signal"]


def print_invocation_evidence(records: list[dict[str, Any]]) -> None:
    print("MODEL INVOCATION EVIDENCE — classify before revealing answers\n")
    for record in records:
        print(f"[{record['request_id']}] {record['timestamp']} source={nested(record, 'input', 'source')}")
        print(f"  input: {nested(record, 'input', 'text')}")
        for retrieved in record.get("retrieval", []):
            print(
                "  retrieval: "
                f"id={retrieved.get('document_id')} trust={retrieved.get('trust_state')}"
            )
            print(f"    text: {retrieved.get('text')}")
        for tool in record.get("requested_tools", []):
            print(
                "  tool: "
                f"{tool.get('name')} decision={tool.get('authorization_decision')} "
                f"arguments={json.dumps(tool.get('arguments', {}), sort_keys=True)}"
            )
        assessments = nested(record, "guardrail", "assessments", default=[])
        policy_names = [item.get("policy") for item in assessments]
        print(
            f"  guardrail: action={nested(record, 'guardrail', 'action')} "
            f"policies={policy_names or ['none']}"
        )
        print()


def command_prompts(args: argparse.Namespace) -> int:
    records = load_jsonl("data/bedrock/model-invocations.jsonl")
    if getattr(args, "evidence", False):
        print_invocation_evidence(records)
        return 0

    print("MODEL INVOCATION HUNT — answer reveal\n")
    for record in records:
        classification, signals = classify_invocation(record)
        guardrail_action = nested(record, "guardrail", "action")
        print(f"- {record['request_id']}: {classification} (guardrail={guardrail_action})")
        print(f"  evidence: {'; '.join(signals)}")
    review_count = sum(classify_invocation(item)[0] != "ORDINARY" for item in records)
    print(f"\nReviewed {len(records)} invocations; {review_count} require classification or review.")
    return 0


def command_schema(_: argparse.Namespace) -> int:
    events = load_jsonl("data/ocsf/cross-cloud-events.jsonl")
    providers = Counter(nested(event, "cloud", "provider") for event in events)
    classes = Counter(f"{event.get('class_uid')} {event.get('class_name')}" for event in events)
    print("OCSF FIXTURE SUMMARY\n")
    print("Providers:")
    for provider, count in sorted(providers.items()):
        print(f"- {provider}: {count}")
    print("Classes:")
    for class_name, count in sorted(classes.items()):
        print(f"- {class_name}: {count}")
    print("Common hunt fields:")
    for field in (
        "time / time_dt",
        "class_uid / activity_id / type_uid",
        "cloud.provider / cloud.account.uid",
        "actor.user.uid / user.uid",
        "src_endpoint.ip / session.uid",
        "unmapped.federation_subject",
        "unmapped.token_issuer / token_audience / target_role",
    ):
        print(f"- {field}")
    print("Provider-specific federation details intentionally remain in unmapped.")
    print("Next: use docs/ocsf-field-guide.md while inspecting the JSONL fixture.")
    return 0


def suspicious_events(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        [
            event
            for event in events
            if nested(event, "src_endpoint", "ip") == "198.51.100.42"
        ],
        key=lambda event: event["time"],
    )


def command_timeline(_: argparse.Namespace) -> int:
    events = suspicious_events(load_jsonl("data/ocsf/cross-cloud-events.jsonl"))
    print("CROSS-CLOUD TIMELINE — 198.51.100.42\n")
    for event in events:
        operation = nested(event, "api", "operation") or nested(
            event, "unmapped", "provider_event_name"
        )
        print(
            f"{event['time_dt']}  {nested(event, 'cloud', 'provider'):<5} "
            f"{event['class_name']:<14} {operation}"
        )
        print(
            f"  subject={nested(event, 'unmapped', 'federation_subject')} "
            f"target={nested(event, 'unmapped', 'target_role')} "
            f"session={nested(event, 'session', 'uid')}"
        )
    providers = sorted({nested(event, "cloud", "provider") for event in events})
    print(f"\nProviders reached: {', '.join(providers)}")
    return 0


def validate_detection_config(config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(config, dict):
        return ["detection config must be an object"]

    allowed_top_level = {
        "name",
        "description",
        "window_minutes",
        "min_providers",
        "privileged_operations",
        "approved_workflows",
    }
    unexpected_top_level = sorted(set(config) - allowed_top_level)
    if unexpected_top_level:
        errors.append(f"unexpected top-level fields: {', '.join(unexpected_top_level)}")
    if not isinstance(config.get("window_minutes"), int) or config.get("window_minutes", 0) <= 0:
        errors.append("window_minutes must be a positive integer")
    if not isinstance(config.get("min_providers"), int) or config.get("min_providers", 0) < 2:
        errors.append("min_providers must be an integer of at least 2")

    def validate_string_array(value: Any, field: str) -> None:
        if (
            not isinstance(value, list)
            or not value
            or not all(isinstance(item, str) and item.strip() for item in value)
        ):
            errors.append(f"{field} must be a non-empty string array")
            return
        if len(value) != len(set(value)):
            errors.append(f"{field} must not contain duplicates")

    validate_string_array(config.get("privileged_operations"), "privileged_operations")
    workflows = config.get("approved_workflows", [])
    if not isinstance(workflows, list):
        errors.append("approved_workflows must be an array")
        return errors

    required_workflow_fields = {
        "subject",
        "source_ips",
        "providers",
        "target_roles",
        "provider_role_pairs",
        "token_issuers",
        "token_audiences",
        "operations",
    }
    allowed_workflow_fields = required_workflow_fields | {"name"}
    array_fields = required_workflow_fields - {"subject"}
    for index, workflow in enumerate(workflows):
        prefix = f"approved_workflows[{index}]"
        if not isinstance(workflow, dict):
            errors.append(f"{prefix} must be an object")
            continue
        missing = sorted(required_workflow_fields - set(workflow))
        if missing:
            errors.append(f"{prefix} missing fields: {', '.join(missing)}")
        unexpected = sorted(set(workflow) - allowed_workflow_fields)
        if unexpected:
            errors.append(f"{prefix} has unexpected fields: {', '.join(unexpected)}")
        subject = workflow.get("subject")
        if not isinstance(subject, str) or not subject.strip():
            errors.append(f"{prefix}.subject must be a non-empty string")
        if "name" in workflow and (
            not isinstance(workflow["name"], str) or not workflow["name"].strip()
        ):
            errors.append(f"{prefix}.name must be a non-empty string")
        for field in sorted(array_fields):
            validate_string_array(workflow.get(field), f"{prefix}.{field}")
    return errors


def load_detection_config(path: str | Path) -> dict[str, Any]:
    config = load_json(path)
    errors = validate_detection_config(config)
    if errors:
        raise ValueError("invalid detection config: " + "; ".join(errors))
    return config


def exact_set_match(observed: Iterable[str], expected: Iterable[str]) -> bool:
    return {item for item in observed if item} == {item for item in expected if item}


def matches_approved_workflow(alert: dict[str, Any], workflow: dict[str, Any]) -> bool:
    """Suppress only when the complete observed behavior matches an approved baseline."""
    return (
        alert["subject"] == workflow["subject"]
        and alert["source_ip"] in workflow["source_ips"]
        and exact_set_match(alert["providers"], workflow["providers"])
        and exact_set_match(alert["target_roles"], workflow["target_roles"])
        and exact_set_match(
            alert["provider_role_pairs"], workflow["provider_role_pairs"]
        )
        and exact_set_match(alert["token_issuers"], workflow["token_issuers"])
        and exact_set_match(alert["token_audiences"], workflow["token_audiences"])
        and set(alert["operations"]).issubset(set(workflow["operations"]))
    )


def evaluate_detection(
    events: list[dict[str, Any]], config: dict[str, Any]
) -> list[dict[str, Any]]:
    """Return candidate incidents, including whether each was safely suppressed.

    A candidate requires one subject/source pair to reach the configured provider
    count inside a rolling event-time window. Privileged activity must happen at
    or after the provider-count threshold is reached, not merely after the first
    authentication.
    """
    window_ms = config["window_minutes"] * 60 * 1000
    min_providers = config["min_providers"]
    privileged_operations = set(config["privileged_operations"])
    auth_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    api_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        subject = nested(event, "unmapped", "federation_subject")
        source_ip = nested(event, "src_endpoint", "ip")
        if not subject or not source_ip or event.get("status_id") != 1:
            continue
        key = (subject, source_ip)
        if event.get("class_uid") == 3002:
            auth_groups[key].append(event)
        elif event.get("class_uid") == 6003:
            api_groups[key].append(event)

    candidates: list[dict[str, Any]] = []
    last_window_end: dict[tuple[str, str], int] = {}
    for key, auth_events in auth_groups.items():
        subject, source_ip = key
        auth_events.sort(key=lambda event: event["time"])
        for first in auth_events:
            if first["time"] <= last_window_end.get(key, -1):
                continue
            window_end = first["time"] + window_ms
            window_auth = [
                event for event in auth_events if first["time"] <= event["time"] <= window_end
            ]
            observed_providers: set[str] = set()
            threshold_time: int | None = None
            for event in window_auth:
                observed_providers.add(nested(event, "cloud", "provider"))
                if len(observed_providers) >= min_providers:
                    threshold_time = event["time"]
                    break
            if threshold_time is None:
                continue
            privileged = [
                event
                for event in api_groups.get(key, [])
                if threshold_time <= event["time"] <= window_end
                and nested(event, "api", "operation") in privileged_operations
            ]
            if not privileged:
                continue

            providers = sorted({nested(event, "cloud", "provider") for event in window_auth})
            operations = sorted({nested(event, "api", "operation") for event in privileged})
            target_roles = sorted(
                {
                    nested(event, "unmapped", "target_role")
                    for event in [*window_auth, *privileged]
                    if nested(event, "unmapped", "target_role")
                }
            )
            provider_role_pairs = sorted(
                {
                    f"{nested(event, 'cloud', 'provider')}:"
                    f"{nested(event, 'unmapped', 'target_role')}"
                    for event in [*window_auth, *privileged]
                    if nested(event, "cloud", "provider")
                    and nested(event, "unmapped", "target_role")
                }
            )
            token_issuers = sorted(
                {
                    nested(event, "unmapped", "token_issuer")
                    for event in window_auth
                    if nested(event, "unmapped", "token_issuer")
                }
            )
            token_audiences = sorted(
                {
                    nested(event, "unmapped", "token_audience")
                    for event in window_auth
                    if nested(event, "unmapped", "token_audience")
                }
            )
            alert = {
                "subject": subject,
                "source_ip": source_ip,
                "first_seen": first["time_dt"],
                "threshold_time": next(
                    event["time_dt"] for event in window_auth if event["time"] == threshold_time
                ),
                "window_end": window_end,
                "providers": providers,
                "operations": operations,
                "target_roles": target_roles,
                "provider_role_pairs": provider_role_pairs,
                "token_issuers": token_issuers,
                "token_audiences": token_audiences,
                "suppressed": False,
                "suppression_name": None,
            }
            for workflow in config.get("approved_workflows", []):
                if matches_approved_workflow(alert, workflow):
                    alert["suppressed"] = True
                    alert["suppression_name"] = workflow.get("name", "approved workflow")
                    break
            candidates.append(alert)
            last_window_end[key] = window_end
            break
    return sorted(candidates, key=lambda alert: alert["first_seen"])


def detect(
    events: list[dict[str, Any]], config: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    if config is None:
        config = load_detection_config(STARTER_CONFIG)
    return [alert for alert in evaluate_detection(events, config) if not alert["suppressed"]]


def print_alert(alert: dict[str, Any], prefix: str = "ALERT") -> None:
    print(f"{prefix} subject={alert['subject']}")
    print(
        f"  source={alert['source_ip']} first_seen={alert['first_seen']} "
        f"multi_cloud_at={alert['threshold_time']}"
    )
    print(f"  providers={','.join(alert['providers'])}")
    print(f"  target_roles={','.join(alert['target_roles'])}")
    print(f"  provider_role_pairs={','.join(alert['provider_role_pairs'])}")
    print(f"  privileged_operations={','.join(alert['operations'])}")


def command_detect(args: argparse.Namespace) -> int:
    config_path = Path(args.config) if args.config else STARTER_CONFIG
    try:
        config = load_detection_config(config_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    candidates = evaluate_detection(load_jsonl("data/ocsf/cross-cloud-events.jsonl"), config)
    active = [alert for alert in candidates if not alert["suppressed"]]
    suppressed = [alert for alert in candidates if alert["suppressed"]]
    print(f"CROSS-CLOUD FEDERATION DETECTION — {config_path}\n")
    if not active:
        print("No active alerts.")
    for alert in active:
        print_alert(alert)
    if args.show_suppressed:
        for alert in suppressed:
            print()
            print_alert(alert, prefix=f"SUPPRESSED ({alert['suppression_name']})")
    print(f"\n{len(active)} active alert(s); {len(suppressed)} safely suppressed candidate(s).")
    return 0


def command_start_detection(args: argparse.Namespace) -> int:
    output = Path(args.output)
    if not output.is_absolute():
        output = ROOT / output
    if output.exists() and not args.force:
        print(f"ERROR: {output} already exists; use --force to reset it.", file=sys.stderr)
        return 2
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(STARTER_CONFIG, output)
    print(f"Created editable detector configuration: {output}")
    print("Run it with:")
    print(f"  python3 tools/workshop.py detect --config {output}")
    print("When tuned, test it with:")
    print(f"  python3 tools/workshop.py test-detection --config {output}")
    return 0


def command_test_detection(args: argparse.Namespace) -> int:
    config_path = Path(args.config)
    try:
        config = load_detection_config(config_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"FAIL: {error}")
        print("Hint: run `python3 tools/workshop.py start-detection` first.")
        return 1
    candidates = evaluate_detection(load_jsonl("data/ocsf/cross-cloud-events.jsonl"), config)
    by_subject = {alert["subject"]: alert for alert in candidates}
    failures: list[str] = []
    attack = by_subject.get(ATTACK_SUBJECT)
    approved = by_subject.get(APPROVED_SUBJECT)
    if attack is None or attack["suppressed"]:
        failures.append("the feature-debug attack must remain an active alert")
    if approved is None:
        failures.append("the approved release candidate was not evaluated")
    elif not approved["suppressed"]:
        failures.append("the exact approved release behavior should be suppressed")

    # Adversarial check: an expected role name on the wrong provider must alert.
    role_swap_events = [
        json.loads(json.dumps(event))
        for event in load_jsonl("data/ocsf/cross-cloud-events.jsonl")
        if nested(event, "unmapped", "federation_subject") == APPROVED_SUBJECT
    ]
    for event in role_swap_events:
        if event.get("class_uid") == 6003:
            event["unmapped"]["target_role"] = "release-deployer"
    role_swap = evaluate_detection(role_swap_events, config)
    if not role_swap or all(alert["suppressed"] for alert in role_swap):
        failures.append("an expected role name used on the wrong provider must alert")

    # Adversarial check: the approved subject must alert when it deviates to Azure.
    attack_events = [
        json.loads(json.dumps(event))
        for event in load_jsonl("data/ocsf/cross-cloud-events.jsonl")
        if nested(event, "unmapped", "federation_subject") == ATTACK_SUBJECT
    ]
    for event in attack_events:
        event["unmapped"]["federation_subject"] = APPROVED_SUBJECT
        event["actor"]["user"]["uid"] = APPROVED_SUBJECT
    deviating = evaluate_detection(attack_events, config)
    if not deviating or all(alert["suppressed"] for alert in deviating):
        failures.append(
            "an approved subject with unexpected source/providers/roles/actions must alert"
        )

    print(f"DETECTION TEST — {config_path}\n")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        print("\nUse an exact composite baseline: subject + source + providers +")
        print("provider-role pairs + issuer + audiences + operations. See docs/hints.md.")
        return 1
    print("PASS: feature-debug attack alerts")
    print("PASS: exact approved release behavior is suppressed")
    print("PASS: expected role name on the wrong provider still alerts")
    print("PASS: approved subject with unexpected behavior still alerts")
    return 0


def iso_to_epoch_ms(value: str) -> int:
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)


def validate() -> list[str]:
    errors: list[str] = []
    for relative_path in REQUIRED_FILES:
        if not (ROOT / relative_path).is_file():
            errors.append(f"missing required file: {relative_path}")
    if errors:
        return errors

    try:
        broad = load_json("data/iam/agent-execution-role-overbroad.json")
        least = load_json("data/iam/agent-execution-role-least-privilege.json")
        guardrail = load_json("data/bedrock/guardrail-config.json")
        invocations = load_jsonl("data/bedrock/model-invocations.jsonl")
        events = load_jsonl("data/ocsf/cross-cloud-events.jsonl")
        starter = load_detection_config(STARTER_CONFIG)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return [str(error)]

    broad_actions = [action for statement in broad["Statement"] for action in actions(statement)]
    least_actions = [action for statement in least["Statement"] for action in actions(statement)]
    least_resources = [statement.get("Resource") for statement in least["Statement"]]
    if "iam:PassRole" not in broad_actions:
        errors.append("over-broad policy must contain the static iam:PassRole lesson")
    if any(action == "*" or action.endswith(":*") for action in least_actions):
        errors.append("least-privilege fixture contains a wildcard action")
    if "*" in least_resources:
        errors.append("least-privilege fixture contains an unscoped resource")

    if len(invocations) != 8:
        errors.append(f"expected 8 invocation records, found {len(invocations)}")
    request_ids = {record.get("request_id") for record in invocations}
    if len(request_ids) != len(invocations):
        errors.append("invocation request IDs are not unique")
    blocked_message = nested(guardrail, "messages", "blocked_input")
    for record in invocations:
        assessments = nested(record, "guardrail", "assessments", default=[])
        entity_actions = {
            entity.get("action")
            for assessment in assessments
            for entity in assessment.get("entities", [])
        }
        observed_action = nested(record, "guardrail", "action")
        if "BLOCK" in entity_actions and observed_action != "BLOCKED":
            errors.append(f"{record.get('request_id')} has BLOCK PII but is not BLOCKED")
        if "BLOCK" not in entity_actions and "ANONYMIZE" in entity_actions and observed_action != "ANONYMIZED":
            errors.append(f"{record.get('request_id')} has anonymized PII but wrong action")
        if observed_action == "BLOCKED" and nested(record, "output", "text") != blocked_message:
            errors.append(f"{record.get('request_id')} does not use configured blocked message")

    if len(events) != 10:
        errors.append(f"expected 10 OCSF events, found {len(events)}")
    for index, event in enumerate(events, start=1):
        for required in ("time", "time_dt", "class_uid", "activity_id", "type_uid", "status_id", "cloud", "actor"):
            if required not in event:
                errors.append(f"OCSF event {index} missing {required}")
        ip = nested(event, "src_endpoint", "ip", default="")
        if not ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
            errors.append(f"OCSF event {index} uses non-documentation IP {ip}")
        if event.get("time_dt") and event.get("time") != iso_to_epoch_ms(event["time_dt"]):
            errors.append(f"OCSF event {index} time and time_dt disagree")
        expected_type = event.get("class_uid", 0) * 100 + event.get("activity_id", 0)
        if event.get("type_uid") != expected_type:
            errors.append(f"OCSF event {index} type_uid is inconsistent")
        operation = nested(event, "api", "operation")
        if operation in {"SecretGet", "GetSecretValue"} and event.get("activity_id") != 2:
            errors.append(f"OCSF event {index} secret retrieval must be Read activity")
        if event.get("class_uid") == 6003:
            if nested(event, "actor", "user", "uid") == nested(
                event, "unmapped", "federation_subject"
            ):
                errors.append(
                    f"OCSF event {index} API actor must identify the provider principal"
                )
            if nested(event, "actor", "user", "name") != nested(
                event, "unmapped", "target_role"
            ):
                errors.append(
                    f"OCSF event {index} API actor name and target role disagree"
                )

    filter_types = {
        item.get("type")
        for item in nested(guardrail, "content_policy_config", "filters", default=[])
    }
    if "PROMPT_ATTACK" not in filter_types:
        errors.append("guardrail fixture lacks a prompt-attack filter")
    if not nested(guardrail, "sensitive_information_policy_config", "pii_entities"):
        errors.append("guardrail fixture lacks PII entities")

    starter_candidates = evaluate_detection(events, starter)
    starter_active = [alert for alert in starter_candidates if not alert["suppressed"]]
    if {alert["subject"] for alert in starter_active} != {ATTACK_SUBJECT, APPROVED_SUBJECT}:
        errors.append("starter detector must expose one attack and one tuning false positive")
    if SOLUTION_CONFIG.is_file():
        try:
            solution = load_detection_config(SOLUTION_CONFIG)
            solution_candidates = evaluate_detection(events, solution)
            active = [alert for alert in solution_candidates if not alert["suppressed"]]
            suppressed = [alert for alert in solution_candidates if alert["suppressed"]]
            if [alert["subject"] for alert in active] != [ATTACK_SUBJECT]:
                errors.append("solution detector must retain exactly the feature-debug alert")
            if [alert["subject"] for alert in suppressed] != [APPROVED_SUBJECT]:
                errors.append("solution detector must suppress only the approved release")
        except (OSError, ValueError, json.JSONDecodeError) as error:
            errors.append(str(error))

    template_path = ROOT / "infra/template.yaml"
    if template_path.is_file():
        template = template_path.read_text(encoding="utf-8")
        for marker in (
            "AWS::Bedrock::Guardrail",
            "AWS::Logs::LogGroup",
            "KmsKeyId:",
            "RetentionInDays: 3653",
            "logs.${AWS::Region}.${AWS::URLSuffix}",
            "kms:EncryptionContext:aws:logs:arn",
            "@secure_recommendation:",
        ):
            if marker not in template:
                errors.append(f"CloudFormation template missing marker: {marker}")
    return errors


def command_verify(_: argparse.Namespace) -> int:
    errors = validate()
    print("WORKSHOP VERIFICATION\n")
    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1
    print(f"PASS: {len(REQUIRED_FILES)} required self-guided files present")
    print("PASS: JSON and JSONL fixtures parse")
    print("PASS: IAM and Guardrail behavior invariants")
    print("PASS: OCSF time, type, activity, and documentation-IP invariants")
    print("PASS: starter detector exposes attack plus tuning false positive")
    if SOLUTION_CONFIG.is_file():
        print("PASS: optional solution keeps attack and safely suppresses release")
    else:
        print("PASS: optional solution omitted; learner tuning path remains available")
    template_path = ROOT / "infra/template.yaml"
    if template_path.is_file():
        print("PASS: optional AWS demo has secure CloudFormation policy markers")
    else:
        print("PASS: optional AWS demo omitted from this offline bundle")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify = subparsers.add_parser("verify", help="validate the complete lab bundle")
    verify.set_defaults(function=command_verify)

    iam = subparsers.add_parser("iam", help="reveal IAM policy findings")
    iam.set_defaults(function=command_iam)

    prompts = subparsers.add_parser("prompts", help="review or reveal invocation evidence")
    prompts.add_argument(
        "--evidence",
        action="store_true",
        help="print readable evidence without classifications",
    )
    prompts.set_defaults(function=command_prompts)

    schema = subparsers.add_parser("schema", help="summarize OCSF fixture structure")
    schema.set_defaults(function=command_schema)

    timeline = subparsers.add_parser("timeline", help="reconstruct the suspicious timeline")
    timeline.set_defaults(function=command_timeline)

    detection = subparsers.add_parser("detect", help="run a configurable detector")
    detection.add_argument(
        "--config",
        help="JSON config path (default: intentionally noisy starter config)",
    )
    detection.add_argument(
        "--show-suppressed",
        action="store_true",
        help="also display candidates suppressed by an exact behavior baseline",
    )
    detection.set_defaults(function=command_detect)

    start = subparsers.add_parser(
        "start-detection", help="create an editable detector config in work/"
    )
    start.add_argument(
        "--output", default="work/cross-cloud-federation-config.json"
    )
    start.add_argument("--force", action="store_true", help="overwrite an existing work file")
    start.set_defaults(function=command_start_detection)

    test = subparsers.add_parser(
        "test-detection", help="test a tuned config against positive and negative cases"
    )
    test.add_argument(
        "--config", default="work/cross-cloud-federation-config.json"
    )
    test.set_defaults(function=command_test_detection)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.function(args)


if __name__ == "__main__":
    sys.exit(main())
