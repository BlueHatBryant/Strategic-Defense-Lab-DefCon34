from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import workshop  # noqa: E402


class WorkshopValidationTests(unittest.TestCase):
    def test_full_validation_has_no_errors(self) -> None:
        self.assertEqual([], workshop.validate())

    def test_invocation_classifications(self) -> None:
        records = workshop.load_jsonl("data/bedrock/model-invocations.jsonl")
        observed = {
            record["request_id"]: workshop.classify_invocation(record)[0]
            for record in records
        }
        self.assertEqual(
            {
                "req-1001": "ORDINARY",
                "req-1002": "BENIGN_SECURITY_DISCUSSION",
                "req-1003": "DIRECT_PROMPT_ATTACK",
                "req-1004": "INDIRECT_PROMPT_ATTACK",
                "req-1005": "SYSTEM_PROMPT_DISCLOSURE",
                "req-1006": "PII_ANONYMIZATION",
                "req-1008": "PII_BLOCKING",
                "req-1007": "ORDINARY",
            },
            observed,
        )

    def test_ocsf_time_type_and_secret_read_semantics(self) -> None:
        for event in workshop.load_jsonl("data/ocsf/cross-cloud-events.jsonl"):
            self.assertEqual(event["time"], workshop.iso_to_epoch_ms(event["time_dt"]))
            self.assertEqual(
                event["type_uid"], event["class_uid"] * 100 + event["activity_id"]
            )
            if workshop.nested(event, "api", "operation") in {
                "SecretGet",
                "GetSecretValue",
            }:
                self.assertEqual(2, event["activity_id"])
                self.assertEqual("Read", event["activity_name"])

    def test_api_actors_are_provider_principals_linked_to_auth_sessions(self) -> None:
        events = workshop.load_jsonl("data/ocsf/cross-cloud-events.jsonl")
        auth_sessions = {
            (
                workshop.nested(event, "cloud", "provider"),
                workshop.nested(event, "session", "uid"),
                workshop.nested(event, "unmapped", "federation_subject"),
            )
            for event in events
            if event["class_uid"] == 3002
        }
        for event in events:
            if event["class_uid"] != 6003:
                continue
            subject = workshop.nested(event, "unmapped", "federation_subject")
            self.assertNotEqual(subject, workshop.nested(event, "actor", "user", "uid"))
            self.assertEqual(
                workshop.nested(event, "unmapped", "target_role"),
                workshop.nested(event, "actor", "user", "name"),
            )
            self.assertIn(
                (
                    workshop.nested(event, "cloud", "provider"),
                    workshop.nested(event, "session", "uid"),
                    subject,
                ),
                auth_sessions,
            )

    def test_sql_reference_contains_exact_composite_guards(self) -> None:
        sql = (ROOT / "queries/ocsf-cross-cloud-federation.sql").read_text(
            encoding="utf-8"
        )
        for marker in (
            "approved_release_provider_count = 2",
            "approved_release_auth_role_count = 2",
            "approved_release_provider_role_pair_count = 2",
            "unexpected_release_provider_role_pair_count = 0",
            "approved_release_audience_count = 2",
            "unexpected_release_api_role_count = 0",
            "activity.provider = 'AWS' AND activity.target_role = 'ReleaseDeployer'",
            "activity.time BETWEEN window.multi_cloud_time",
        ):
            self.assertIn(marker, sql)


class DetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.events = workshop.load_jsonl("data/ocsf/cross-cloud-events.jsonl")
        self.starter = workshop.load_detection_config(workshop.STARTER_CONFIG)
        self.solution = (
            workshop.load_detection_config(workshop.SOLUTION_CONFIG)
            if workshop.SOLUTION_CONFIG.is_file()
            else None
        )

    def test_starter_exposes_attack_and_false_positive(self) -> None:
        candidates = workshop.evaluate_detection(self.events, self.starter)
        self.assertEqual(
            {workshop.ATTACK_SUBJECT, workshop.APPROVED_SUBJECT},
            {candidate["subject"] for candidate in candidates},
        )
        self.assertFalse(any(candidate["suppressed"] for candidate in candidates))

    @unittest.skipUnless(
        workshop.SOLUTION_CONFIG.is_file(), "reference solution not in participant archive"
    )
    def test_solution_retains_attack_and_suppresses_exact_release(self) -> None:
        candidates = workshop.evaluate_detection(self.events, self.solution)
        active = [item for item in candidates if not item["suppressed"]]
        suppressed = [item for item in candidates if item["suppressed"]]
        self.assertEqual([workshop.ATTACK_SUBJECT], [item["subject"] for item in active])
        self.assertEqual(
            [workshop.APPROVED_SUBJECT], [item["subject"] for item in suppressed]
        )

    @unittest.skipUnless(
        workshop.SOLUTION_CONFIG.is_file(), "reference solution not in participant archive"
    )
    def test_expected_role_on_wrong_provider_is_not_suppressed(self) -> None:
        events = [
            copy.deepcopy(event)
            for event in self.events
            if workshop.nested(event, "unmapped", "federation_subject")
            == workshop.APPROVED_SUBJECT
        ]
        for event in events:
            if event["class_uid"] == 6003:
                event["unmapped"]["target_role"] = "release-deployer"
        candidates = workshop.evaluate_detection(events, self.solution)
        self.assertEqual(1, len(candidates))
        self.assertFalse(candidates[0]["suppressed"])
        self.assertIn("AWS:release-deployer", candidates[0]["provider_role_pairs"])

    def test_privileged_action_must_follow_provider_threshold(self) -> None:
        attack_events = [
            event
            for event in self.events
            if workshop.nested(event, "unmapped", "federation_subject")
            == workshop.ATTACK_SUBJECT
        ]
        # Keep the Azure read before the second provider, but remove every later
        # sensitive action. Authentication alone must not create an alert.
        attack_events = [
            event
            for event in attack_events
            if workshop.nested(event, "api", "operation")
            not in {"GetSecretValue", "SetIamPolicy"}
        ]
        self.assertEqual([], workshop.evaluate_detection(attack_events, self.starter))

    @unittest.skipUnless(
        workshop.SOLUTION_CONFIG.is_file(), "reference solution not in participant archive"
    )
    def test_approved_subject_with_attack_behavior_is_not_suppressed(self) -> None:
        attack_events = [
            copy.deepcopy(event)
            for event in self.events
            if workshop.nested(event, "unmapped", "federation_subject")
            == workshop.ATTACK_SUBJECT
        ]
        for event in attack_events:
            event["unmapped"]["federation_subject"] = workshop.APPROVED_SUBJECT
            event["actor"]["user"]["uid"] = workshop.APPROVED_SUBJECT
        candidates = workshop.evaluate_detection(attack_events, self.solution)
        self.assertEqual(1, len(candidates))
        self.assertFalse(candidates[0]["suppressed"])

    def test_provider_outside_window_does_not_correlate(self) -> None:
        events = [
            copy.deepcopy(event)
            for event in self.events
            if workshop.nested(event, "unmapped", "federation_subject")
            == workshop.APPROVED_SUBJECT
        ]
        # Move the GCP authentication and the later API activity beyond the AWS
        # anchor's 15-minute window. No window now contains two providers plus a
        # qualifying follow-on action.
        for event in events:
            if workshop.nested(event, "cloud", "provider") == "GCP" or event.get("class_uid") == 6003:
                event["time"] += 20 * 60 * 1000
        self.assertEqual([], workshop.evaluate_detection(events, self.starter))

    def test_invalid_config_is_rejected(self) -> None:
        config = json.loads(json.dumps(self.starter))
        config["min_providers"] = 1
        self.assertIn(
            "min_providers must be an integer of at least 2",
            workshop.validate_detection_config(config),
        )

    @unittest.skipUnless(
        workshop.SOLUTION_CONFIG.is_file(), "reference solution not in participant archive"
    )
    def test_malformed_approved_workflow_cannot_create_substring_bypass(self) -> None:
        config = json.loads(json.dumps(self.solution))
        workflow = config["approved_workflows"][0]
        workflow["source_ips"] = "192.0.2.250"
        errors = workshop.validate_detection_config(config)
        self.assertIn(
            "approved_workflows[0].source_ips must be a non-empty string array",
            errors,
        )

    @unittest.skipUnless(
        workshop.SOLUTION_CONFIG.is_file(), "reference solution not in participant archive"
    )
    def test_empty_duplicate_and_unexpected_workflow_values_are_rejected(self) -> None:
        config = json.loads(json.dumps(self.solution))
        workflow = config["approved_workflows"][0]
        workflow["providers"] = []
        workflow["operations"] = ["GetSecretValue", "GetSecretValue"]
        workflow["typo_field"] = ["unsafe"]
        errors = workshop.validate_detection_config(config)
        self.assertIn(
            "approved_workflows[0].providers must be a non-empty string array",
            errors,
        )
        self.assertIn(
            "approved_workflows[0].operations must not contain duplicates",
            errors,
        )
        self.assertIn(
            "approved_workflows[0] has unexpected fields: typo_field",
            errors,
        )


if __name__ == "__main__":
    unittest.main()
