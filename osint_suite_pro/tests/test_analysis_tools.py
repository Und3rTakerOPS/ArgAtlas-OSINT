import unittest

from analysis_tools import (
    compare_scan_results,
    detect_account_pattern,
    generate_alerts,
    suggest_account_correlations,
)


class AnalysisToolsTestCase(unittest.TestCase):
    def test_suggest_account_correlations_returns_match_for_similar_accounts(self):
        scans = [
            {"username": "alice_dev", "active_platforms": ["GitHub", "Reddit", "YouTube", "LinkedIn"]},
            {"username": "alice.dev", "active_platforms": ["GitHub", "Reddit", "YouTube", "X / Twitter"]},
            {"username": "bob_ops", "active_platforms": ["GitHub"]},
        ]

        correlations = suggest_account_correlations(scans)

        self.assertTrue(correlations)
        self.assertEqual(correlations[0]["account1"], "alice_dev")
        self.assertEqual(correlations[0]["account2"], "alice.dev")

    def test_detect_account_pattern_extracts_repeated_patterns(self):
        scans = [
            {"username": "alpha_red", "active_platforms": ["GitHub", "Reddit"]},
            {"username": "alpha_blue", "active_platforms": ["GitHub"]},
            {"username": "alpha_green", "active_platforms": ["YouTube"]},
        ]

        patterns = detect_account_pattern(scans)

        self.assertIn("prefix:alp (3x)", patterns["naming_patterns"])
        self.assertEqual(patterns["platform_preferences"][0][0], "GitHub")

    def test_generate_alerts_returns_risk_and_presence_alerts(self):
        result = {
            "risk_assessment": {"score": 82, "level": "High"},
            "profile_status": {
                "GitHub": {"exists": True},
                "Reddit": {"exists": True},
                "YouTube": {"exists": True},
                "X / Twitter": {"exists": True},
            },
            "github_api": {"followers": 20000},
        }

        alerts = generate_alerts(1, result)
        alert_types = {alert["type"] for alert in alerts}

        self.assertIn("HIGH_RISK_SCORE", alert_types)
        self.assertIn("HIGH_FOLLOWER_COUNT", alert_types)

    def test_compare_scan_results_reports_added_removed_and_deltas(self):
        previous = {
            "profile_status": {"GitHub": {"exists": True}, "Reddit": {"exists": True}},
            "risk_assessment": {"score": 40},
            "github_api": {"followers": 10},
        }
        current = {
            "profile_status": {"GitHub": {"exists": True}, "YouTube": {"exists": True}},
            "risk_assessment": {"score": 55},
            "github_api": {"followers": 15},
        }

        comparison = compare_scan_results(previous, current)

        self.assertEqual(comparison["added_platforms"], ["YouTube"])
        self.assertEqual(comparison["removed_platforms"], ["Reddit"])
        self.assertEqual(comparison["risk_delta"], 15.0)
        self.assertEqual(comparison["followers_delta"], 5)


if __name__ == "__main__":
    unittest.main()