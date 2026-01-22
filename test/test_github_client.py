import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'scripts'))

from github_client import GitHubClient, VALID_SEVERITIES
from dotenv import load_dotenv

load_dotenv()


class TestGitHubClientSeverityFiltering(unittest.TestCase):
    """Tests for severity filtering in GitHubClient.get_active_alerts()"""

    @classmethod
    def setUpClass(cls):
        cls.client = GitHubClient('pvpres', 'purposeful_errors', token=os.getenv("GH_TOKEN"))

    def test_get_alerts_no_filter_returns_all(self):
        """When no severity filter is provided, all alerts should be returned."""
        alerts = self.client.get_active_alerts()
        self.assertIsInstance(alerts, list)

    def test_get_alerts_with_single_severity(self):
        """Filtering by a single severity should return only matching alerts."""
        alerts = self.client.get_active_alerts(severity=["high"])
        self.assertIsInstance(alerts, list)
        for alert in alerts:
            sev = alert.get("rule", {}).get("security_severity_level", "")
            self.assertEqual(sev, "high")

    def test_get_alerts_with_multiple_severities(self):
        """Filtering by multiple severities should return alerts matching any of them."""
        alerts = self.client.get_active_alerts(severity=["high", "medium"])
        self.assertIsInstance(alerts, list)
        for alert in alerts:
            sev = alert.get("rule", {}).get("security_severity_level", "")
            self.assertIn(sev, ["high", "medium"])

    def test_get_alerts_case_insensitive(self):
        """Severity filtering should be case-insensitive."""
        alerts_lower = self.client.get_active_alerts(severity=["high"])
        alerts_upper = self.client.get_active_alerts(severity=["HIGH"])
        alerts_mixed = self.client.get_active_alerts(severity=["High"])
        self.assertEqual(len(alerts_lower), len(alerts_upper))
        self.assertEqual(len(alerts_lower), len(alerts_mixed))

    def test_invalid_severity_raises_error(self):
        """Invalid severity values should raise ValueError."""
        with self.assertRaises(ValueError) as context:
            self.client.get_active_alerts(severity=["invalid_severity"])
        self.assertIn("Invalid severity values", str(context.exception))
        self.assertIn("invalid_severity", str(context.exception))

    def test_mixed_valid_invalid_severity_raises_error(self):
        """Mix of valid and invalid severities should raise ValueError."""
        with self.assertRaises(ValueError) as context:
            self.client.get_active_alerts(severity=["high", "not_a_severity"])
        self.assertIn("Invalid severity values", str(context.exception))

    def test_empty_severity_list_returns_all(self):
        """Empty severity list should return all alerts (same as None)."""
        alerts_none = self.client.get_active_alerts(severity=None)
        alerts_empty = self.client.get_active_alerts(severity=[])
        self.assertEqual(len(alerts_none), len(alerts_empty))

    def test_valid_severities_constant(self):
        """VALID_SEVERITIES should contain all expected values."""
        expected = {"critical", "high", "medium", "low", "warning", "note", "error"}
        self.assertEqual(VALID_SEVERITIES, expected)

    def test_no_duplicate_alerts_with_overlapping_severities(self):
        """When filtering by multiple severities, no duplicate alerts should be returned."""
        alerts = self.client.get_active_alerts(severity=["high", "high"])
        alert_ids = [a.get("number") for a in alerts]
        self.assertEqual(len(alert_ids), len(set(alert_ids)))


if __name__ == "__main__":
    unittest.main()
