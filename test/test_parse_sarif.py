"""
Unit tests for the SARIF parser module.

These tests use real SARIF data fetched from the pvpres/small_scale_security_tests
repository via the GitHubClient to verify the parser functions work correctly
with actual CodeQL output.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from github_client import GitHubClient
from parse_sarif import (
    minify_sarif,
    get_remediation_batches,
    _normalize_path,
    build_active_alert_index,
    minify_sarif_state_aware,
    get_remediation_batches_state_aware
)


class TestParseSarifWithRealData(unittest.TestCase):
    """Test SARIF parser functions using real data from GitHub API."""

    @classmethod
    def setUpClass(cls):
        """Fetch SARIF data once for all tests."""
        cls.client = GitHubClient('pvpres', 'small_scale_security_tests')
        cls.sarif_data = cls.client.get_sarif_data()
        cls.minified_data = minify_sarif(cls.sarif_data)

    def test_sarif_data_fetched_successfully(self):
        """Verify that SARIF data was fetched from the GitHub API."""
        self.assertIsNotNone(self.sarif_data)
        self.assertIn('runs', self.sarif_data)
        self.assertGreater(len(self.sarif_data['runs']), 0)

    def test_minify_sarif_returns_list(self):
        """Verify minify_sarif returns a list of results."""
        self.assertIsInstance(self.minified_data, list)

    def test_minify_sarif_extracts_results(self):
        """Verify minify_sarif extracts the expected number of results."""
        self.assertGreater(len(self.minified_data), 0)

    def test_minified_result_has_required_fields(self):
        """Verify each minified result contains all required fields."""
        required_fields = ['ruleId', 'message', 'severity', 'target', 'source', 'sink']
        for result in self.minified_data:
            for field in required_fields:
                self.assertIn(field, result, f"Missing field: {field}")

    def test_minified_result_rule_id_format(self):
        """Verify ruleId follows the expected format (e.g., 'py/command-line-injection')."""
        for result in self.minified_data:
            rule_id = result['ruleId']
            self.assertIsNotNone(rule_id)
            self.assertIsInstance(rule_id, str)
            self.assertIn('/', rule_id, f"ruleId should contain '/': {rule_id}")

    def test_minified_result_message_is_string(self):
        """Verify message is a non-empty string."""
        for result in self.minified_data:
            message = result['message']
            self.assertIsInstance(message, str)

    def test_minified_result_severity_is_numeric(self):
        """Verify severity is a numeric value when present."""
        for result in self.minified_data:
            severity = result['severity']
            if severity is not None:
                self.assertIsInstance(severity, (int, float))
                self.assertGreaterEqual(severity, 0.0)
                self.assertLessEqual(severity, 10.0)

    def test_minified_result_target_structure(self):
        """Verify target contains file and line information."""
        for result in self.minified_data:
            target = result['target']
            if target is not None:
                self.assertIn('file', target)
                self.assertIn('line', target)
                self.assertIsInstance(target['file'], str)

    def test_command_line_injection_result(self):
        """Verify the py/command-line-injection result is correctly parsed."""
        cmd_injection_results = [
            r for r in self.minified_data 
            if r['ruleId'] == 'py/command-line-injection'
        ]
        self.assertGreater(len(cmd_injection_results), 0, 
                          "Expected at least one py/command-line-injection result")
        
        result = cmd_injection_results[0]
        self.assertEqual(result['severity'], 9.8)
        self.assertIsNotNone(result['target'])
        self.assertEqual(result['target']['file'], 'app.py')
        self.assertEqual(result['target']['line'], 10)
        self.assertIsNotNone(result['source'])
        self.assertIn('app.py', result['source'])

    def test_flask_debug_result(self):
        """Verify the py/flask-debug result is correctly parsed."""
        flask_debug_results = [
            r for r in self.minified_data 
            if r['ruleId'] == 'py/flask-debug'
        ]
        self.assertGreater(len(flask_debug_results), 0,
                          "Expected at least one py/flask-debug result")
        
        result = flask_debug_results[0]
        self.assertEqual(result['severity'], 7.5)
        self.assertIsNotNone(result['target'])
        self.assertEqual(result['target']['file'], 'app.py')
        self.assertEqual(result['target']['line'], 14)

    def test_code_flow_source_extraction(self):
        """Verify source is extracted from codeFlows for path-problem queries."""
        cmd_injection_results = [
            r for r in self.minified_data 
            if r['ruleId'] == 'py/command-line-injection'
        ]
        if cmd_injection_results:
            result = cmd_injection_results[0]
            self.assertIsNotNone(result['source'], 
                                "Expected source to be extracted from codeFlows")
            self.assertIn(':', result['source'], 
                         "Source should be in 'file:line' format")

    def test_code_flow_sink_extraction(self):
        """Verify sink is extracted from codeFlows for path-problem queries."""
        cmd_injection_results = [
            r for r in self.minified_data 
            if r['ruleId'] == 'py/command-line-injection'
        ]
        if cmd_injection_results:
            result = cmd_injection_results[0]
            self.assertIsNotNone(result['sink'],
                                "Expected sink to be extracted from codeFlows")
            self.assertIn(':', result['sink'],
                         "Sink should be in 'file:line' format")


class TestGetRemediationBatches(unittest.TestCase):
    """Test get_remediation_batches function using real data."""

    @classmethod
    def setUpClass(cls):
        """Fetch and minify SARIF data once for all tests."""
        cls.client = GitHubClient('pvpres', 'small_scale_security_tests')
        cls.sarif_data = cls.client.get_sarif_data()
        cls.minified_data = minify_sarif(cls.sarif_data)
        cls.batches = get_remediation_batches(cls.minified_data)

    def test_batches_returns_dict(self):
        """Verify get_remediation_batches returns a dictionary."""
        self.assertIsInstance(self.batches, dict)

    def test_batches_keys_are_rule_ids(self):
        """Verify batch keys are ruleId strings."""
        for key in self.batches.keys():
            self.assertIsInstance(key, str)
            self.assertIn('/', key, f"Key should be a ruleId with '/': {key}")

    def test_batches_filter_low_severity(self):
        """Verify vulnerabilities with severity < 7.0 are filtered out."""
        for rule_id, batch in self.batches.items():
            self.assertGreaterEqual(batch['severity'], 7.0,
                                   f"Rule {rule_id} has severity < 7.0")

    def test_batch_structure(self):
        """Verify each batch has the correct structure."""
        for rule_id, batch in self.batches.items():
            self.assertIn('severity', batch)
            self.assertIn('tasks', batch)
            self.assertIsInstance(batch['severity'], (int, float))
            self.assertIsInstance(batch['tasks'], list)

    def test_task_structure(self):
        """Verify each task in a batch has the correct structure."""
        for rule_id, batch in self.batches.items():
            for task in batch['tasks']:
                self.assertIn('file', task)
                self.assertIn('line', task)
                self.assertIn('source', task)

    def test_command_line_injection_in_batches(self):
        """Verify py/command-line-injection is included in batches (severity 9.8 >= 7.0)."""
        self.assertIn('py/command-line-injection', self.batches,
                     "Expected py/command-line-injection in batches (severity 9.8)")
        
        batch = self.batches['py/command-line-injection']
        self.assertEqual(batch['severity'], 9.8)
        self.assertGreater(len(batch['tasks']), 0)
        
        task = batch['tasks'][0]
        self.assertEqual(task['file'], 'app.py')
        self.assertEqual(task['line'], 10)

    def test_flask_debug_in_batches(self):
        """Verify py/flask-debug is included in batches (severity 7.5 >= 7.0)."""
        self.assertIn('py/flask-debug', self.batches,
                     "Expected py/flask-debug in batches (severity 7.5)")
        
        batch = self.batches['py/flask-debug']
        self.assertEqual(batch['severity'], 7.5)
        self.assertGreater(len(batch['tasks']), 0)
        
        task = batch['tasks'][0]
        self.assertEqual(task['file'], 'app.py')
        self.assertEqual(task['line'], 14)

    def test_output_format_matches_specification(self):
        """Verify output format matches the specified structure."""
        for rule_id, batch in self.batches.items():
            self.assertIsInstance(rule_id, str)
            self.assertIsInstance(batch['severity'], (int, float))
            self.assertIsInstance(batch['tasks'], list)
            
            for task in batch['tasks']:
                self.assertIsInstance(task.get('file'), (str, type(None)))
                self.assertIsInstance(task.get('line'), (int, type(None)))


class TestMinifySarifEdgeCases(unittest.TestCase):
    """Test minify_sarif with edge cases."""

    def test_empty_sarif_data(self):
        """Verify minify_sarif handles empty SARIF data."""
        result = minify_sarif({})
        self.assertEqual(result, [])

    def test_sarif_with_no_runs(self):
        """Verify minify_sarif handles SARIF with empty runs array."""
        result = minify_sarif({'runs': []})
        self.assertEqual(result, [])

    def test_sarif_with_no_results(self):
        """Verify minify_sarif handles runs with no results."""
        sarif = {
            'runs': [
                {
                    'results': [],
                    'tool': {'driver': {'name': 'TestTool'}}
                }
            ]
        }
        result = minify_sarif(sarif)
        self.assertEqual(result, [])


class TestGetRemediationBatchesEdgeCases(unittest.TestCase):
    """Test get_remediation_batches with edge cases."""

    def test_empty_minified_data(self):
        """Verify get_remediation_batches handles empty input."""
        result = get_remediation_batches([])
        self.assertEqual(result, {})

    def test_all_low_severity(self):
        """Verify get_remediation_batches filters out all low severity items."""
        minified = [
            {'ruleId': 'test/rule', 'severity': 5.0, 
             'target': {'file': 'test.py', 'line': 1}, 'source': 'test.py:1'}
        ]
        result = get_remediation_batches(minified)
        self.assertEqual(result, {})

    def test_severity_threshold_boundary(self):
        """Verify severity threshold is exclusive (< 7.0 filtered, >= 7.0 included)."""
        minified = [
            {'ruleId': 'test/below', 'severity': 6.9,
             'target': {'file': 'test.py', 'line': 1}, 'source': None},
            {'ruleId': 'test/at', 'severity': 7.0,
             'target': {'file': 'test.py', 'line': 2}, 'source': None},
            {'ruleId': 'test/above', 'severity': 7.1,
             'target': {'file': 'test.py', 'line': 3}, 'source': None}
        ]
        result = get_remediation_batches(minified)
        
        self.assertNotIn('test/below', result)
        self.assertIn('test/at', result)
        self.assertIn('test/above', result)

    def test_multiple_instances_same_rule(self):
        """Verify multiple instances of same rule are grouped together."""
        minified = [
            {'ruleId': 'test/rule', 'severity': 8.0,
             'target': {'file': 'a.py', 'line': 1}, 'source': 'src.py:1'},
            {'ruleId': 'test/rule', 'severity': 9.0,
             'target': {'file': 'b.py', 'line': 2}, 'source': 'src.py:2'}
        ]
        result = get_remediation_batches(minified)
        
        self.assertIn('test/rule', result)
        self.assertEqual(len(result['test/rule']['tasks']), 2)
        self.assertEqual(result['test/rule']['severity'], 9.0)

    def test_none_severity_filtered(self):
        """Verify items with None severity are filtered out."""
        minified = [
            {'ruleId': 'test/rule', 'severity': None,
             'target': {'file': 'test.py', 'line': 1}, 'source': None}
        ]
        result = get_remediation_batches(minified)
        self.assertEqual(result, {})

    def test_none_target_filtered(self):
        """Verify items with None target are filtered out."""
        minified = [
            {'ruleId': 'test/rule', 'severity': 9.0,
             'target': None, 'source': None}
        ]
        result = get_remediation_batches(minified)
        self.assertEqual(result, {})


class TestNormalizePath(unittest.TestCase):
    """Test _normalize_path helper function."""

    def test_normalize_none(self):
        """Verify _normalize_path handles None input."""
        self.assertEqual(_normalize_path(None), "")

    def test_normalize_empty_string(self):
        """Verify _normalize_path handles empty string."""
        self.assertEqual(_normalize_path(""), "")

    def test_normalize_simple_path(self):
        """Verify _normalize_path returns simple paths unchanged."""
        self.assertEqual(_normalize_path("app.py"), "app.py")
        self.assertEqual(_normalize_path("src/app.py"), "src/app.py")

    def test_normalize_leading_dot_slash(self):
        """Verify _normalize_path removes leading './'."""
        self.assertEqual(_normalize_path("./app.py"), "app.py")
        self.assertEqual(_normalize_path("./src/app.py"), "src/app.py")

    def test_normalize_leading_slash(self):
        """Verify _normalize_path removes leading '/'."""
        self.assertEqual(_normalize_path("/app.py"), "app.py")
        self.assertEqual(_normalize_path("/src/app.py"), "src/app.py")

    def test_normalize_combined_prefixes(self):
        """Verify _normalize_path handles combined prefixes."""
        self.assertEqual(_normalize_path("./app.py"), "app.py")


class TestBuildActiveAlertIndex(unittest.TestCase):
    """Test build_active_alert_index function."""

    def test_empty_alerts(self):
        """Verify build_active_alert_index handles empty alerts list."""
        result = build_active_alert_index([])
        self.assertEqual(result, {})

    def test_single_alert(self):
        """Verify build_active_alert_index correctly indexes a single alert."""
        alerts = [{
            "number": 1,
            "rule": {"id": "py/sql-injection"},
            "most_recent_instance": {
                "location": {"path": "app.py", "start_line": 42}
            }
        }]
        result = build_active_alert_index(alerts)
        
        self.assertEqual(len(result), 1)
        self.assertIn(("py/sql-injection", "app.py", 42), result)
        self.assertEqual(result[("py/sql-injection", "app.py", 42)], 1)

    def test_multiple_alerts(self):
        """Verify build_active_alert_index correctly indexes multiple alerts."""
        alerts = [
            {
                "number": 1,
                "rule": {"id": "py/command-line-injection"},
                "most_recent_instance": {
                    "location": {"path": "app.py", "start_line": 10}
                }
            },
            {
                "number": 2,
                "rule": {"id": "py/flask-debug"},
                "most_recent_instance": {
                    "location": {"path": "app.py", "start_line": 14}
                }
            }
        ]
        result = build_active_alert_index(alerts)
        
        self.assertEqual(len(result), 2)
        self.assertEqual(result[("py/command-line-injection", "app.py", 10)], 1)
        self.assertEqual(result[("py/flask-debug", "app.py", 14)], 2)

    def test_alert_missing_fields(self):
        """Verify build_active_alert_index skips alerts with missing fields."""
        alerts = [
            {"number": 1},
            {"number": 2, "rule": {"id": "test/rule"}},
            {"number": 3, "rule": {"id": "test/rule"}, "most_recent_instance": {}},
            {
                "number": 4,
                "rule": {"id": "test/rule"},
                "most_recent_instance": {"location": {"path": "app.py"}}
            }
        ]
        result = build_active_alert_index(alerts)
        self.assertEqual(result, {})

    def test_path_normalization(self):
        """Verify build_active_alert_index normalizes paths."""
        alerts = [{
            "number": 1,
            "rule": {"id": "py/test"},
            "most_recent_instance": {
                "location": {"path": "./app.py", "start_line": 10}
            }
        }]
        result = build_active_alert_index(alerts)
        
        self.assertIn(("py/test", "app.py", 10), result)


class TestStateAwareFunctionsWithRealData(unittest.TestCase):
    """Test state-aware functions using real data from GitHub API."""

    @classmethod
    def setUpClass(cls):
        """Fetch alerts and SARIF data once for all tests."""
        cls.client = GitHubClient('pvpres', 'small_scale_security_tests')
        cls.alerts = cls.client.get_active_alerts()
        cls.sarif_data = cls.client.get_sarif_data()
        cls.alert_index = build_active_alert_index(cls.alerts)
        cls.minified_state_aware = minify_sarif_state_aware(cls.sarif_data, cls.alert_index)
        cls.batches_state_aware = get_remediation_batches_state_aware(cls.minified_state_aware)

    def test_alerts_fetched_successfully(self):
        """Verify alerts were fetched from the GitHub API."""
        self.assertIsInstance(self.alerts, list)

    def test_alert_index_built_successfully(self):
        """Verify alert index was built from alerts."""
        self.assertIsInstance(self.alert_index, dict)
        if self.alerts:
            self.assertGreater(len(self.alert_index), 0)

    def test_minify_sarif_state_aware_returns_list(self):
        """Verify minify_sarif_state_aware returns a list."""
        self.assertIsInstance(self.minified_state_aware, list)

    def test_minify_sarif_state_aware_filters_to_active_alerts(self):
        """Verify minify_sarif_state_aware only includes results matching active alerts."""
        for result in self.minified_state_aware:
            alert_number = result.get('alert_number')
            self.assertIsNotNone(alert_number, "Each result should have an alert_number")
            
            alert_numbers_in_index = set(self.alert_index.values())
            self.assertIn(alert_number, alert_numbers_in_index,
                         f"Alert number {alert_number} should be in the active alert index")

    def test_minify_sarif_state_aware_includes_alert_number(self):
        """Verify each minified result includes the alert_number field."""
        required_fields = ['alert_number', 'ruleId', 'message', 'severity', 'target', 'source', 'sink']
        for result in self.minified_state_aware:
            for field in required_fields:
                self.assertIn(field, result, f"Missing field: {field}")

    def test_minify_sarif_state_aware_matches_alert_count(self):
        """Verify the number of minified results matches the number of active alerts."""
        self.assertEqual(len(self.minified_state_aware), len(self.alert_index),
                        "Number of minified results should match number of indexed alerts")

    def test_command_line_injection_state_aware(self):
        """Verify py/command-line-injection is correctly processed with alert tracking."""
        cmd_injection_results = [
            r for r in self.minified_state_aware
            if r['ruleId'] == 'py/command-line-injection'
        ]
        
        if cmd_injection_results:
            result = cmd_injection_results[0]
            self.assertIsNotNone(result['alert_number'])
            self.assertEqual(result['target']['file'], 'app.py')
            self.assertEqual(result['target']['line'], 10)

    def test_flask_debug_state_aware(self):
        """Verify py/flask-debug is correctly processed with alert tracking."""
        flask_debug_results = [
            r for r in self.minified_state_aware
            if r['ruleId'] == 'py/flask-debug'
        ]
        
        if flask_debug_results:
            result = flask_debug_results[0]
            self.assertIsNotNone(result['alert_number'])
            self.assertEqual(result['target']['file'], 'app.py')
            self.assertEqual(result['target']['line'], 14)

    def test_batches_state_aware_returns_dict(self):
        """Verify get_remediation_batches_state_aware returns a dictionary."""
        self.assertIsInstance(self.batches_state_aware, dict)

    def test_batches_state_aware_includes_alert_numbers(self):
        """Verify each task in state-aware batches includes alert_number."""
        for rule_id, batch in self.batches_state_aware.items():
            for task in batch['tasks']:
                self.assertIn('alert_number', task,
                             f"Task in {rule_id} batch should have alert_number")
                self.assertIsNotNone(task['alert_number'])

    def test_batches_state_aware_task_structure(self):
        """Verify each task in state-aware batches has the correct structure."""
        for rule_id, batch in self.batches_state_aware.items():
            self.assertIn('severity', batch)
            self.assertIn('tasks', batch)
            
            for task in batch['tasks']:
                self.assertIn('alert_number', task)
                self.assertIn('file', task)
                self.assertIn('line', task)
                self.assertIn('source', task)


class TestStateAwareFunctionsEdgeCases(unittest.TestCase):
    """Test state-aware functions with edge cases."""

    def test_minify_sarif_state_aware_empty_sarif(self):
        """Verify minify_sarif_state_aware handles empty SARIF data."""
        result = minify_sarif_state_aware({}, {})
        self.assertEqual(result, [])

    def test_minify_sarif_state_aware_empty_index(self):
        """Verify minify_sarif_state_aware returns empty list when no alerts match."""
        sarif = {
            'runs': [{
                'results': [{
                    'ruleId': 'test/rule',
                    'message': {'text': 'Test message'},
                    'locations': [{
                        'physicalLocation': {
                            'artifactLocation': {'uri': 'test.py'},
                            'region': {'startLine': 10}
                        }
                    }]
                }],
                'tool': {'driver': {'name': 'TestTool', 'rules': []}}
            }]
        }
        result = minify_sarif_state_aware(sarif, {})
        self.assertEqual(result, [])

    def test_minify_sarif_state_aware_partial_match(self):
        """Verify minify_sarif_state_aware only includes matching results."""
        sarif = {
            'runs': [{
                'results': [
                    {
                        'ruleId': 'test/rule1',
                        'message': {'text': 'Test 1'},
                        'locations': [{
                            'physicalLocation': {
                                'artifactLocation': {'uri': 'test.py'},
                                'region': {'startLine': 10}
                            }
                        }]
                    },
                    {
                        'ruleId': 'test/rule2',
                        'message': {'text': 'Test 2'},
                        'locations': [{
                            'physicalLocation': {
                                'artifactLocation': {'uri': 'test.py'},
                                'region': {'startLine': 20}
                            }
                        }]
                    }
                ],
                'tool': {'driver': {'name': 'TestTool', 'rules': []}}
            }]
        }
        alert_index = {('test/rule1', 'test.py', 10): 1}
        
        result = minify_sarif_state_aware(sarif, alert_index)
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['ruleId'], 'test/rule1')
        self.assertEqual(result[0]['alert_number'], 1)

    def test_get_remediation_batches_state_aware_empty(self):
        """Verify get_remediation_batches_state_aware handles empty input."""
        result = get_remediation_batches_state_aware([])
        self.assertEqual(result, {})

    def test_get_remediation_batches_state_aware_severity_filter(self):
        """Verify get_remediation_batches_state_aware filters by severity."""
        minified = [
            {
                'alert_number': 1,
                'ruleId': 'test/low',
                'severity': 5.0,
                'target': {'file': 'test.py', 'line': 1},
                'source': None
            },
            {
                'alert_number': 2,
                'ruleId': 'test/high',
                'severity': 9.0,
                'target': {'file': 'test.py', 'line': 2},
                'source': None
            }
        ]
        result = get_remediation_batches_state_aware(minified)
        
        self.assertNotIn('test/low', result)
        self.assertIn('test/high', result)
        self.assertEqual(result['test/high']['tasks'][0]['alert_number'], 2)


if __name__ == '__main__':
    from dotenv import load_dotenv
    load_dotenv()
    unittest.main(verbosity=2)
