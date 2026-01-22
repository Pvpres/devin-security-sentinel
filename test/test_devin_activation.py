"""
Integration Tests for Devin AI API Connectivity.

This module provides tests to verify connectivity and authentication with
the Devin AI API. It includes functions to create test sessions and check
their status.

Environment Variables:
    DEVIN_API_KEY: API key for Devin AI authentication.
"""

import os
import time
import requests
import json
from dotenv import load_dotenv


def test_devin_activation(url: str, pr: bool) -> dict:
    """
    Test Devin AI API activation by creating a new session.
    
    Creates a test session that analyzes a repository for security vulnerabilities.
    Optionally requests a PR to be created with comments about the issues.
    
    Args:
        url: The Devin API sessions endpoint URL.
        pr: If True, request a PR to be created; if False, analysis only.
        
    Returns:
        The API response JSON containing session_id and other details.
        
    Raises:
        AssertionError: If the API returns a non-200 status code.
    """
    headers = {"Authorization": f"Bearer {os.getenv('DEVIN_API_KEY')}", "Content-Type": "application/json"}
    payload = {
    "prompt": f"List all the files and security vulnerabilities in the repository. pvpres/small_scale_security_tests. Provide a summary of the vulnerabilities and suggest remediation steps. Push a PR that simply comments where the issues are. DO NOT FIX ANY ISSUES YOURSELF.",
    }
    prompt_no_pr = f"List all the files and security vulnerabilities in the repository. pvpres/small_scale_security_tests. Provide a summary of the vulnerabilities and suggest remediation steps. DO NOT PUSH A PR OR FIX ANY ISSUES YOURSELF."
    if not pr:
        payload['prompt'] = prompt_no_pr
    response = requests.post(url, headers=headers, json=payload)
    print(response.status_code)
    assert response.status_code == 200
    print("Devin activation test passed.")
    return response.json()


def test_devin_api(url: str, session_id: str) -> None:
    """
    Check the status of an existing Devin AI session.
    
    Retrieves and prints the current status of a session, useful for
    verifying that sessions are progressing as expected.
    
    Args:
        url: The Devin API sessions endpoint URL.
        session_id: The session ID to check.
    """
    headers = {"Authorization": f"Bearer {os.getenv('DEVIN_API_KEY')}", "Content-Type": "application/json"}
    session_url = f"{url}/{session_id}"
    response = requests.get(session_url, headers=headers)
    print(response.status_code)
    print("Response is:", response.json())


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    url = "https://api.devin.ai/v1/sessions"
    print("Running Devin activation test...")
    id = test_devin_activation(url, False)
    print(id)
    time.sleep(150)  # Wait for 3 minutes before checking the session status
    test_devin_api(url, id['session_id'])
