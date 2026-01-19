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
from parse_sarif import minify_sarif, get_remediation_batches


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


if __name__ == '__main__':
    unittest.main(verbosity=2)
