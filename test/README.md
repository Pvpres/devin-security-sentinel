# Test Directory

This directory contains integration tests and test scripts for the Security Sentinel system. These tests verify connectivity with external APIs and validate core functionality.

## Test Files

### test_alert_claiming.py

Unit tests for the alert claiming/unclaiming workflow. Tests the `AlertClaimManager` class and its ability to prevent race conditions between concurrent orchestrator runs.

Test coverage:
- Claiming alerts assigns them to the bot user
- Unclaiming alerts releases them back to the pool
- Concurrent claim attempts are handled correctly

### test_devin_activation.py

Integration test for Devin AI API connectivity. Verifies that sessions can be created and their status can be retrieved.

Functions:
- `test_devin_activation()`: Create a test session and verify API response
- `test_devin_api()`: Check the status of an existing session

Environment variables:
- `DEVIN_API_KEY`: API key for Devin AI authentication

### test_devin_claim.py

Integration test for the complete claim/unclaim workflow against a real GitHub repository. Tests the end-to-end flow of claiming alerts, waiting, and then unclaiming them.

Environment variables:
- `GH_TOKEN`: GitHub Personal Access Token with security_events scope

### test_get_default_branch.py

Test for GitHub default branch detection. Verifies that the GitHubClient can correctly identify the default branch of a repository, which is important for fetching SARIF data from the correct branch reference.

Environment variables:
- `GH_TOKEN`: GitHub Personal Access Token

### test_github_client.py

Integration test for the GitHubClient class. Tests fetching alerts and analysis IDs from a real GitHub repository.

Environment variables:
- `GH_TOKEN`: GitHub Personal Access Token with security_events scope

### test_parse_sarif.py

Comprehensive unit tests for the SARIF processing engine. Tests minification, severity extraction, code flow endpoint extraction, and batch creation.

Test coverage:
- Minification of verbose SARIF data
- Severity extraction from multiple locations (result props, rule props, defaultConfiguration)
- Code flow endpoint extraction (source/sink)
- Batch creation with filtering and grouping
- Edge cases (empty data, missing fields, boundary conditions)

## Running Tests

Most tests require environment variables to be set. Create a `.env` file in the project root:

```bash
GH_TOKEN=ghp_your_github_token_here
DEVIN_API_KEY=your_devin_api_key_here
```

Run individual test files:

```bash
# Activate virtual environment
source venv/bin/activate

# Run a specific test
python test/test_parse_sarif.py
python test/test_github_client.py
python test/test_devin_activation.py
```

Note: Integration tests (`test_devin_activation.py`, `test_devin_claim.py`, `test_github_client.py`) make real API calls and may incur costs or rate limits. Use them sparingly and primarily for validation during development.
