"""Check the response boundary independently of scoring and process APIs."""
import unittest
from types import SimpleNamespace

from ciphersentry.response import evaluate_response


def assessment(**changes):
    values = {
        "level": "High", "score": 95, "pid": 43210,
        "process_name": "CipherSentry lab worker",
        "eligible_for_containment": True, "attribution": "cooperative_lab",
        "features": {"process_context": {"pid": 43210, "create_time": 1000.25,
                     "executable": "C:\\Python312\\python.exe", "name": "python.exe", "parent_pid": 43200}},
    }
    values.update(changes)
    return SimpleNamespace(**values)


class ResponsePolicyTests(unittest.TestCase):
    def test_default_policy_is_alert_only_even_for_valid_high_risk_lab(self):
        decision = evaluate_response(assessment(), managed_identity_valid=True, worker_running=True)
        self.assertEqual(decision.action, "alert_only")
        self.assertFalse(decision.allowed)
        self.assertIn("disabled", decision.reason)

    def test_simulation_requires_every_separate_safety_condition(self):
        decision = evaluate_response(assessment(), mode="simulation", managed_identity_valid=True, worker_running=True)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.action, "suspend_lab")
        self.assertTrue(all(decision.checks.values()))
        self.assertEqual(decision.to_dict()["reason"], decision.reason)
        for extra in ({"managed_identity_valid": False}, {"worker_running": False}, {"worker_released": True}):
            with self.subTest(extra=extra):
                arguments = {"mode": "simulation", "managed_identity_valid": True, "worker_running": True, **extra}
                denied = evaluate_response(assessment(), **arguments)
                self.assertFalse(denied.allowed)
                self.assertEqual(denied.action, "alert_only")

    def test_unattributed_or_external_telemetry_cannot_control_process(self):
        for source in ("unavailable", "verified", "etw", "unknown"):
            with self.subTest(source=source):
                result = evaluate_response(assessment(attribution=source), "simulation", True, False, True)
                self.assertFalse(result.allowed)
                self.assertIn("not a cooperative", result.reason)

    def test_score_alone_and_familiar_or_signed_name_do_not_authorize_action(self):
        evidence = assessment(eligible_for_containment=False, process_name="FamiliarSignedApp.exe")
        evidence.features["process_context"]["signature_status"] = "valid"
        result = evaluate_response(evidence, "simulation", True, False, True)
        self.assertFalse(result.allowed)
        self.assertFalse(result.checks["corroborating_evidence"])

    def test_missing_or_inconsistent_identity_fails_closed(self):
        for context in ({}, {"pid": 43211, "create_time": 1000, "executable": "worker.exe"},
                        {"pid": 43210, "create_time": float("nan"), "executable": "worker.exe"},
                        {"pid": 43210, "create_time": True, "executable": "worker.exe"},
                        {"pid": 43210, "create_time": 1000, "executable": ""}, None):
            with self.subTest(context=context):
                result = evaluate_response(assessment(features={"process_context": context}), "simulation", True, False, True)
                self.assertFalse(result.allowed)
                self.assertFalse(result.checks["stable_process_context"])

    def test_essential_process_exclusion_remains_even_with_other_flags_set(self):
        evidence = assessment()
        evidence.features["process_context"]["name"] = "lsass.exe"
        result = evaluate_response(evidence, "simulation", True, False, True)
        self.assertFalse(result.allowed)
        self.assertFalse(result.checks["essential_process_excluded"])

    def test_low_and_uncertain_states_never_request_suspension(self):
        for level, action in (("Low", "monitor"), ("Uncertain", "gather_evidence"), ("Elevated", "gather_evidence")):
            with self.subTest(level=level):
                result = evaluate_response(assessment(level=level), "simulation", True, False, True)
                self.assertEqual(result.action, action)
                self.assertFalse(result.allowed)

    def test_unknown_mode_or_risk_level_fails_closed(self):
        self.assertFalse(evaluate_response(assessment(), "automatic", True, False, True).allowed)
        result = evaluate_response(assessment(level="malware-confirmed"), "simulation", True, False, True)
        self.assertFalse(result.allowed)
        self.assertIn("Unsupported", result.reason)


if __name__ == "__main__":
    unittest.main()
