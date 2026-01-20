"""
Unit tests for alert claiming and unclaiming functionality.

These tests verify the claim_github_alerts and unclaim_github_alerts functions
that prevent race conditions between simultaneously running orchestrator instances.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from devin_orchestrator import (
    claim_github_alerts,
    unclaim_github_alerts,
    _get_bot_username,
    _get_authenticated_user,
    CLAIM_RETRY_ATTEMPTS,
    CLAIM_RETRY_DELAY_SECONDS
)

TEST_OWNER = 'pvpres'
TEST_REPO = 'small_scale_security_tests'
TEST_ALERT_NUMBERS = [1, 2]


class TestGetAuthenticatedUser(unittest.TestCase):
    """Test _get_authenticated_user helper function."""

    @patch('devin_orchestrator._get_github_token')
    @patch('devin_orchestrator.requests.get')
    def test_get_authenticated_user_success(self, mock_get, mock_token):
        """Verify _get_authenticated_user returns the login from API response."""
        mock_token.return_value = 'test-token'
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'login': 'pat-owner-user'}
        mock_get.return_value = mock_response

        result = _get_authenticated_user()

        self.assertEqual(result, 'pat-owner-user')
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        self.assertEqual(call_args.args[0], 'https://api.github.com/user')

    @patch('devin_orchestrator._get_github_token')
    @patch('devin_orchestrator.requests.get')
    def test_get_authenticated_user_api_failure(self, mock_get, mock_token):
        """Verify _get_authenticated_user raises RuntimeError on API failure."""
        mock_token.return_value = 'test-token'
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = 'Unauthorized'
        mock_get.return_value = mock_response

        with self.assertRaises(RuntimeError) as context:
            _get_authenticated_user()
        self.assertIn('401', str(context.exception))

    @patch('devin_orchestrator._get_github_token')
    @patch('devin_orchestrator.requests.get')
    def test_get_authenticated_user_missing_login(self, mock_get, mock_token):
        """Verify _get_authenticated_user raises RuntimeError when login field missing."""
        mock_token.return_value = 'test-token'
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'id': 12345}  # No 'login' field
        mock_get.return_value = mock_response

        with self.assertRaises(RuntimeError) as context:
            _get_authenticated_user()
        self.assertIn('login', str(context.exception))


class TestGetBotUsername(unittest.TestCase):
    """Test _get_bot_username helper function."""

    @patch.dict(os.environ, {'DEVIN_BOT_USERNAME': 'test-bot'})
    def test_get_bot_username_from_env(self):
        """Verify _get_bot_username returns the environment variable value."""
        result = _get_bot_username()
        self.assertEqual(result, 'test-bot')

    @patch('devin_orchestrator._get_authenticated_user')
    @patch.dict(os.environ, {}, clear=True)
    def test_get_bot_username_fallback_to_authenticated_user(self, mock_auth_user):
        """Verify _get_bot_username falls back to authenticated user when env var is missing."""
        mock_auth_user.return_value = 'pat-owner-user'
        if 'DEVIN_BOT_USERNAME' in os.environ:
            del os.environ['DEVIN_BOT_USERNAME']
        
        result = _get_bot_username()
        
        self.assertEqual(result, 'pat-owner-user')
        mock_auth_user.assert_called_once()

    @patch('devin_orchestrator._get_authenticated_user')
    @patch.dict(os.environ, {'DEVIN_BOT_USERNAME': ''})
    def test_get_bot_username_empty_fallback_to_authenticated_user(self, mock_auth_user):
        """Verify _get_bot_username falls back to authenticated user when env var is empty."""
        mock_auth_user.return_value = 'pat-owner-user'
        
        result = _get_bot_username()
        
        self.assertEqual(result, 'pat-owner-user')
        mock_auth_user.assert_called_once()

    @patch('devin_orchestrator._get_authenticated_user')
    @patch.dict(os.environ, {}, clear=True)
    def test_get_bot_username_fallback_failure(self, mock_auth_user):
        """Verify _get_bot_username raises RuntimeError when fallback fails."""
        mock_auth_user.side_effect = RuntimeError('API failure')
        if 'DEVIN_BOT_USERNAME' in os.environ:
            del os.environ['DEVIN_BOT_USERNAME']
        
        with self.assertRaises(RuntimeError) as context:
            _get_bot_username()
        self.assertIn('API failure', str(context.exception))


class TestClaimGitHubAlerts(unittest.TestCase):
    """Test claim_github_alerts function."""

    @patch('devin_orchestrator._get_bot_username')
    @patch('devin_orchestrator._get_github_token')
    @patch('devin_orchestrator.requests.patch')
    def test_claim_single_alert_success(self, mock_patch, mock_token, mock_username):
        """Verify successful claiming of a single alert."""
        mock_token.return_value = 'test-token'
        mock_username.return_value = 'test-bot'
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_patch.return_value = mock_response

        result = claim_github_alerts(TEST_OWNER, TEST_REPO, [1])

        self.assertEqual(result, {1: True})
        mock_patch.assert_called_once()
        call_args = mock_patch.call_args
        self.assertIn('assignees', call_args.kwargs['json'])
        self.assertEqual(call_args.kwargs['json']['assignees'], ['test-bot'])

    @patch('devin_orchestrator._get_bot_username')
    @patch('devin_orchestrator._get_github_token')
    @patch('devin_orchestrator.requests.patch')
    def test_claim_multiple_alerts_success(self, mock_patch, mock_token, mock_username):
        """Verify successful claiming of multiple alerts."""
        mock_token.return_value = 'test-token'
        mock_username.return_value = 'test-bot'
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_patch.return_value = mock_response

        result = claim_github_alerts(TEST_OWNER, TEST_REPO, [1, 2, 3])

        self.assertEqual(result, {1: True, 2: True, 3: True})
        self.assertEqual(mock_patch.call_count, 3)

    @patch('devin_orchestrator._get_bot_username')
    @patch('devin_orchestrator._get_github_token')
    @patch('devin_orchestrator.requests.patch')
    @patch('devin_orchestrator.time.sleep')
    def test_claim_alert_failure_with_retry(self, mock_sleep, mock_patch, mock_token, mock_username):
        """Verify retry logic when claiming fails."""
        mock_token.return_value = 'test-token'
        mock_username.return_value = 'test-bot'
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = 'Internal Server Error'
        mock_patch.return_value = mock_response

        result = claim_github_alerts(TEST_OWNER, TEST_REPO, [1], max_retries=3, retry_delay=0.1)

        self.assertEqual(result, {1: False})
        self.assertEqual(mock_patch.call_count, 3)

    @patch('devin_orchestrator._get_bot_username')
    @patch('devin_orchestrator._get_github_token')
    @patch('devin_orchestrator.requests.patch')
    @patch('devin_orchestrator.time.sleep')
    def test_claim_alert_retry_then_success(self, mock_sleep, mock_patch, mock_token, mock_username):
        """Verify alert is claimed after retry succeeds."""
        mock_token.return_value = 'test-token'
        mock_username.return_value = 'test-bot'
        
        fail_response = MagicMock()
        fail_response.status_code = 500
        fail_response.text = 'Internal Server Error'
        
        success_response = MagicMock()
        success_response.status_code = 200
        
        mock_patch.side_effect = [fail_response, success_response]

        result = claim_github_alerts(TEST_OWNER, TEST_REPO, [1], max_retries=3, retry_delay=0.1)

        self.assertEqual(result, {1: True})
        self.assertEqual(mock_patch.call_count, 2)

    @patch('devin_orchestrator._get_bot_username')
    @patch('devin_orchestrator._get_github_token')
    @patch('devin_orchestrator.requests.patch')
    @patch('devin_orchestrator.time.sleep')
    def test_claim_alert_request_exception(self, mock_sleep, mock_patch, mock_token, mock_username):
        """Verify handling of request exceptions during claiming."""
        mock_token.return_value = 'test-token'
        mock_username.return_value = 'test-bot'
        
        import requests
        mock_patch.side_effect = requests.RequestException('Connection error')

        result = claim_github_alerts(TEST_OWNER, TEST_REPO, [1], max_retries=2, retry_delay=0.1)

        self.assertEqual(result, {1: False})
        self.assertEqual(mock_patch.call_count, 2)

    @patch('devin_orchestrator._get_bot_username')
    @patch('devin_orchestrator._get_github_token')
    @patch('devin_orchestrator.requests.patch')
    def test_claim_empty_alert_list(self, mock_patch, mock_token, mock_username):
        """Verify claiming with empty alert list returns empty dict."""
        mock_token.return_value = 'test-token'
        mock_username.return_value = 'test-bot'

        result = claim_github_alerts(TEST_OWNER, TEST_REPO, [])

        self.assertEqual(result, {})
        mock_patch.assert_not_called()

    @patch('devin_orchestrator._get_bot_username')
    @patch('devin_orchestrator._get_github_token')
    @patch('devin_orchestrator.requests.patch')
    def test_claim_alert_correct_url(self, mock_patch, mock_token, mock_username):
        """Verify correct API URL is used for claiming."""
        mock_token.return_value = 'test-token'
        mock_username.return_value = 'test-bot'
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_patch.return_value = mock_response

        claim_github_alerts('test-owner', 'test-repo', [42])

        call_args = mock_patch.call_args
        expected_url = 'https://api.github.com/repos/test-owner/test-repo/code-scanning/alerts/42'
        self.assertEqual(call_args.args[0], expected_url)

    @patch('devin_orchestrator._get_bot_username')
    @patch('devin_orchestrator._get_github_token')
    @patch('devin_orchestrator.requests.patch')
    def test_claim_alert_correct_headers(self, mock_patch, mock_token, mock_username):
        """Verify correct headers are sent for claiming."""
        mock_token.return_value = 'test-token'
        mock_username.return_value = 'test-bot'
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_patch.return_value = mock_response

        claim_github_alerts(TEST_OWNER, TEST_REPO, [1])

        call_args = mock_patch.call_args
        headers = call_args.kwargs['headers']
        self.assertEqual(headers['Authorization'], 'Bearer test-token')
        self.assertEqual(headers['Accept'], 'application/vnd.github+json')
        self.assertEqual(headers['X-GitHub-Api-Version'], '2022-11-28')


class TestUnclaimGitHubAlerts(unittest.TestCase):
    """Test unclaim_github_alerts function."""

    @patch('devin_orchestrator._get_github_token')
    @patch('devin_orchestrator.requests.patch')
    def test_unclaim_single_alert_success(self, mock_patch, mock_token):
        """Verify successful unclaiming of a single alert."""
        mock_token.return_value = 'test-token'
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_patch.return_value = mock_response

        result = unclaim_github_alerts(TEST_OWNER, TEST_REPO, [1])

        self.assertEqual(result, {1: True})
        mock_patch.assert_called_once()
        call_args = mock_patch.call_args
        self.assertIn('assignees', call_args.kwargs['json'])
        self.assertEqual(call_args.kwargs['json']['assignees'], [])

    @patch('devin_orchestrator._get_github_token')
    @patch('devin_orchestrator.requests.patch')
    def test_unclaim_multiple_alerts_success(self, mock_patch, mock_token):
        """Verify successful unclaiming of multiple alerts."""
        mock_token.return_value = 'test-token'
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_patch.return_value = mock_response

        result = unclaim_github_alerts(TEST_OWNER, TEST_REPO, [1, 2, 3])

        self.assertEqual(result, {1: True, 2: True, 3: True})
        self.assertEqual(mock_patch.call_count, 3)

    @patch('devin_orchestrator._get_github_token')
    @patch('devin_orchestrator.requests.patch')
    @patch('devin_orchestrator.time.sleep')
    def test_unclaim_alert_failure_with_retry(self, mock_sleep, mock_patch, mock_token):
        """Verify retry logic when unclaiming fails."""
        mock_token.return_value = 'test-token'
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = 'Internal Server Error'
        mock_patch.return_value = mock_response

        result = unclaim_github_alerts(TEST_OWNER, TEST_REPO, [1], max_retries=3, retry_delay=0.1)

        self.assertEqual(result, {1: False})
        self.assertEqual(mock_patch.call_count, 3)

    @patch('devin_orchestrator._get_github_token')
    @patch('devin_orchestrator.requests.patch')
    @patch('devin_orchestrator.time.sleep')
    def test_unclaim_alert_retry_then_success(self, mock_sleep, mock_patch, mock_token):
        """Verify alert is unclaimed after retry succeeds."""
        mock_token.return_value = 'test-token'
        
        fail_response = MagicMock()
        fail_response.status_code = 500
        fail_response.text = 'Internal Server Error'
        
        success_response = MagicMock()
        success_response.status_code = 200
        
        mock_patch.side_effect = [fail_response, success_response]

        result = unclaim_github_alerts(TEST_OWNER, TEST_REPO, [1], max_retries=3, retry_delay=0.1)

        self.assertEqual(result, {1: True})
        self.assertEqual(mock_patch.call_count, 2)

    @patch('devin_orchestrator._get_github_token')
    @patch('devin_orchestrator.requests.patch')
    @patch('devin_orchestrator.time.sleep')
    def test_unclaim_alert_request_exception(self, mock_sleep, mock_patch, mock_token):
        """Verify handling of request exceptions during unclaiming."""
        mock_token.return_value = 'test-token'
        
        import requests
        mock_patch.side_effect = requests.RequestException('Connection error')

        result = unclaim_github_alerts(TEST_OWNER, TEST_REPO, [1], max_retries=2, retry_delay=0.1)

        self.assertEqual(result, {1: False})
        self.assertEqual(mock_patch.call_count, 2)

    @patch('devin_orchestrator._get_github_token')
    @patch('devin_orchestrator.requests.patch')
    def test_unclaim_empty_alert_list(self, mock_patch, mock_token):
        """Verify unclaiming with empty alert list returns empty dict."""
        mock_token.return_value = 'test-token'

        result = unclaim_github_alerts(TEST_OWNER, TEST_REPO, [])

        self.assertEqual(result, {})
        mock_patch.assert_not_called()

    @patch('devin_orchestrator._get_github_token')
    @patch('devin_orchestrator.requests.patch')
    def test_unclaim_alert_correct_url(self, mock_patch, mock_token):
        """Verify correct API URL is used for unclaiming."""
        mock_token.return_value = 'test-token'
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_patch.return_value = mock_response

        unclaim_github_alerts('test-owner', 'test-repo', [42])

        call_args = mock_patch.call_args
        expected_url = 'https://api.github.com/repos/test-owner/test-repo/code-scanning/alerts/42'
        self.assertEqual(call_args.args[0], expected_url)


class TestClaimUnclaimIntegration(unittest.TestCase):
    """Integration tests for claim/unclaim workflow."""

    @patch('devin_orchestrator._get_bot_username')
    @patch('devin_orchestrator._get_github_token')
    @patch('devin_orchestrator.requests.patch')
    def test_claim_then_unclaim_workflow(self, mock_patch, mock_token, mock_username):
        """Verify alerts can be claimed and then unclaimed."""
        mock_token.return_value = 'test-token'
        mock_username.return_value = 'test-bot'
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_patch.return_value = mock_response

        claim_result = claim_github_alerts(TEST_OWNER, TEST_REPO, TEST_ALERT_NUMBERS)
        self.assertEqual(claim_result, {1: True, 2: True})

        unclaim_result = unclaim_github_alerts(TEST_OWNER, TEST_REPO, TEST_ALERT_NUMBERS)
        self.assertEqual(unclaim_result, {1: True, 2: True})

        self.assertEqual(mock_patch.call_count, 4)

    @patch('devin_orchestrator._get_bot_username')
    @patch('devin_orchestrator._get_github_token')
    @patch('devin_orchestrator.requests.patch')
    def test_partial_claim_success(self, mock_patch, mock_token, mock_username):
        """Verify partial success when some alerts fail to claim."""
        mock_token.return_value = 'test-token'
        mock_username.return_value = 'test-bot'
        
        success_response = MagicMock()
        success_response.status_code = 200
        
        fail_response = MagicMock()
        fail_response.status_code = 404
        fail_response.text = 'Not Found'
        
        mock_patch.side_effect = [success_response, fail_response, success_response]

        result = claim_github_alerts(TEST_OWNER, TEST_REPO, [1, 2, 3], max_retries=1, retry_delay=0.01)

        self.assertEqual(result[1], True)
        self.assertEqual(result[2], False)
        self.assertEqual(result[3], True)


class TestConstants(unittest.TestCase):
    """Test that constants are properly defined."""

    def test_claim_retry_attempts_defined(self):
        """Verify CLAIM_RETRY_ATTEMPTS constant is defined."""
        self.assertIsInstance(CLAIM_RETRY_ATTEMPTS, int)
        self.assertGreater(CLAIM_RETRY_ATTEMPTS, 0)

    def test_claim_retry_delay_defined(self):
        """Verify CLAIM_RETRY_DELAY_SECONDS constant is defined."""
        self.assertIsInstance(CLAIM_RETRY_DELAY_SECONDS, (int, float))
        self.assertGreater(CLAIM_RETRY_DELAY_SECONDS, 0)


@unittest.skipUnless(
    os.getenv('GH_TOKEN') and os.getenv('RUN_REAL_API_TESTS', '').lower() == 'true',
    'Skipping real API tests: GH_TOKEN and RUN_REAL_API_TESTS=true required'
)
class TestRealAPIIntegration(unittest.TestCase):
    """
    Real API integration tests for claim/unclaim functionality.
    
    These tests make actual API calls to GitHub to verify that alerts
    in pvpres/small_scale_security_tests can be claimed and unclaimed.
    
    Prerequisites:
    - GH_TOKEN environment variable must be set with a valid GitHub token
      (with security_events write permission)
    - RUN_REAL_API_TESTS=true must be set to explicitly enable these tests
    - DEVIN_BOT_USERNAME is optional - if not set, falls back to PAT owner
    - The authenticated user must have write access to the test repository
    """

    def test_claim_and_unclaim_real_alerts(self):
        """
        Verify that the 2 alerts in pvpres/small_scale_security_tests
        can be claimed and subsequently unclaimed via the real GitHub API.
        """
        claim_result = claim_github_alerts(
            TEST_OWNER, 
            TEST_REPO, 
            TEST_ALERT_NUMBERS,
            max_retries=3,
            retry_delay=1.0
        )
        
        for alert_num in TEST_ALERT_NUMBERS:
            self.assertTrue(
                claim_result.get(alert_num, False),
                f"Failed to claim alert #{alert_num}"
            )
        
        unclaim_result = unclaim_github_alerts(
            TEST_OWNER,
            TEST_REPO,
            TEST_ALERT_NUMBERS,
            max_retries=3,
            retry_delay=1.0
        )
        
        for alert_num in TEST_ALERT_NUMBERS:
            self.assertTrue(
                unclaim_result.get(alert_num, False),
                f"Failed to unclaim alert #{alert_num}"
            )

    def test_claim_single_alert_real_api(self):
        """Verify claiming a single alert via real API."""
        alert_num = TEST_ALERT_NUMBERS[0]
        
        claim_result = claim_github_alerts(
            TEST_OWNER,
            TEST_REPO,
            [alert_num],
            max_retries=3,
            retry_delay=1.0
        )
        
        self.assertTrue(
            claim_result.get(alert_num, False),
            f"Failed to claim alert #{alert_num}"
        )
        
        unclaim_result = unclaim_github_alerts(
            TEST_OWNER,
            TEST_REPO,
            [alert_num],
            max_retries=3,
            retry_delay=1.0
        )
        
        self.assertTrue(
            unclaim_result.get(alert_num, False),
            f"Failed to unclaim alert #{alert_num}"
        )

    def test_unclaim_already_unclaimed_alert(self):
        """Verify unclaiming an already unclaimed alert succeeds."""
        alert_num = TEST_ALERT_NUMBERS[0]
        
        unclaim_result = unclaim_github_alerts(
            TEST_OWNER,
            TEST_REPO,
            [alert_num],
            max_retries=3,
            retry_delay=1.0
        )
        
        self.assertTrue(
            unclaim_result.get(alert_num, False),
            f"Failed to unclaim already unclaimed alert #{alert_num}"
        )


if __name__ == '__main__':
    unittest.main()
