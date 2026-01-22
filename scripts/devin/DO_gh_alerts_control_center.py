"""
GitHub Alert Control Center for Security Sentinel.

This module provides functions for managing GitHub code scanning alerts during
the remediation process. It handles claiming (assigning), unclaiming, and
closing alerts to prevent race conditions between concurrent orchestrator runs.

The claiming mechanism assigns alerts to a bot user before remediation begins,
ensuring that multiple orchestrator instances don't attempt to fix the same
vulnerabilities simultaneously.

Key Functions:
    claim_github_alerts: Assign alerts to the bot user to prevent conflicts.
    unclaim_github_alerts: Release alerts back to the pool for retry.
    close_github_alerts: Mark alerts as dismissed after successful remediation.

Environment Variables:
    GH_TOKEN: GitHub Personal Access Token with security_events write permission.
    DEVIN_BOT_USERNAME: Optional bot username for claiming (defaults to PAT owner).
"""

import requests
import os
import time
from .DO_config import get_github_token

CLAIM_RETRY_ATTEMPTS = 3
CLAIM_RETRY_DELAY_SECONDS = 2
GITHUB_API_BASE = "https://api.github.com"

def _get_bot_username() -> str:
    """
    Get the bot username for claiming alerts.
    
    Returns the username from DEVIN_BOT_USERNAME environment variable if set,
    otherwise falls back to the authenticated user (PAT owner).
    
    Returns:
        The bot username string
    
    Raises:
        RuntimeError: If fallback to authenticated user fails
    """
    username = os.getenv("DEVIN_BOT_USERNAME")
    if username:
        return username
    # Fall back to the authenticated user (PAT owner)
    return _get_authenticated_user()

def _get_authenticated_user() -> str:
    """
    Get the username of the authenticated GitHub user (PAT owner).
    
    Makes a GET request to https://api.github.com/user to retrieve
    the login (username) of the token owner.
    
    Returns:
        The username string of the authenticated user
    
    Raises:
        RuntimeError: If the API call fails or returns invalid data
    """
    token = get_github_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    response = requests.get("https://api.github.com/user", headers=headers)
    if response.status_code != 200:
        raise RuntimeError(f"Failed to get authenticated user: HTTP {response.status_code}: {response.text[:100]}")
    data = response.json()
    if "login" not in data:
        raise RuntimeError("Failed to get authenticated user: 'login' field not in response")
    return data["login"]

def claim_github_alerts(
    owner: str,
    repo: str,
    alert_numbers: list[int],
    max_retries: int = CLAIM_RETRY_ATTEMPTS,
    retry_delay: float = CLAIM_RETRY_DELAY_SECONDS
) -> dict[int, bool]:
    """
    Claim GitHub code scanning alerts by assigning them to the bot user.
    
    This prevents race conditions where multiple orchestrator instances
    might try to fix the same alerts simultaneously. Alerts are assigned
    to the bot user specified by DEVIN_BOT_USERNAME environment variable.
    
    Uses retry logic with exponential backoff for transient failures.
    
    Args:
        owner: GitHub repository owner
        repo: GitHub repository name
        alert_numbers: List of alert numbers to claim
        max_retries: Maximum number of retry attempts per alert (default: 3)
        retry_delay: Base delay between retries in seconds (default: 2)
    
    Returns:
        Dictionary mapping alert_number to success status (True/False)
    """
    token = get_github_token()
    bot_username = _get_bot_username()
    
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    results: dict[int, bool] = {}
    
    for alert_number in alert_numbers:
        url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}"
        
        success = False
        last_error = None
        
        for attempt in range(max_retries):
            try:
                payload = {
                    "assignees": [bot_username]
                }
                
                response = requests.patch(url, headers=headers, json=payload, timeout=30)
                
                if response.status_code == 200:
                    success = True
                    print(f"[Claim] Alert #{alert_number} claimed successfully by {bot_username}")
                    break
                else:
                    last_error = f"HTTP {response.status_code}: {response.text[:100]}"
                    print(f"[Claim] Attempt {attempt + 1}/{max_retries} failed for alert #{alert_number}: {last_error}")
            
            except requests.RequestException as e:
                last_error = str(e)
                print(f"[Claim] Attempt {attempt + 1}/{max_retries} error for alert #{alert_number}: {e}")
            
            if attempt < max_retries - 1:
                delay = retry_delay * (2 ** attempt)
                time.sleep(delay)
        
        results[alert_number] = success
        if not success:
            print(f"[Claim] Failed to claim alert #{alert_number} after {max_retries} attempts: {last_error}")
        
        time.sleep(0.5)
    
    return results
def unclaim_github_alerts(
    owner: str,
    repo: str,
    alert_numbers: list[int],
    max_retries: int = CLAIM_RETRY_ATTEMPTS,
    retry_delay: float = CLAIM_RETRY_DELAY_SECONDS
) -> dict[int, bool]:
    """
    Unclaim GitHub code scanning alerts by removing all assignees.
    
    This releases alerts back to the pool so they can be picked up by
    future orchestrator runs. Used when remediation fails or is partial.
    
    Uses retry logic with exponential backoff for transient failures.
    
    Args:
        owner: GitHub repository owner
        repo: GitHub repository name
        alert_numbers: List of alert numbers to unclaim
        max_retries: Maximum number of retry attempts per alert (default: 3)
        retry_delay: Base delay between retries in seconds (default: 2)
    
    Returns:
        Dictionary mapping alert_number to success status (True/False)
    """
    token = get_github_token()
    
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    results: dict[int, bool] = {}
    
    for alert_number in alert_numbers:
        url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}"
        
        success = False
        last_error = None
        
        for attempt in range(max_retries):
            try:
                payload = {
                    "assignees": []
                }
                
                response = requests.patch(url, headers=headers, json=payload, timeout=30)
                
                if response.status_code == 200:
                    success = True
                    print(f"[Unclaim] Alert #{alert_number} unclaimed successfully")
                    break
                else:
                    last_error = f"HTTP {response.status_code}: {response.text[:100]}"
                    print(f"[Unclaim] Attempt {attempt + 1}/{max_retries} failed for alert #{alert_number}: {last_error}")
            
            except requests.RequestException as e:
                last_error = str(e)
                print(f"[Unclaim] Attempt {attempt + 1}/{max_retries} error for alert #{alert_number}: {e}")
            
            if attempt < max_retries - 1:
                delay = retry_delay * (2 ** attempt)
                time.sleep(delay)
        
        results[alert_number] = success
        if not success:
            print(f"[Unclaim] Failed to unclaim alert #{alert_number} after {max_retries} attempts: {last_error}")
        
        time.sleep(0.5)
    
    return results

def close_github_alerts(
    owner: str,
    repo: str,
    alert_numbers: list[int],
    reason: str = "used in tests"
) -> dict[int, bool]:
    """
    Close GitHub code scanning alerts after successful remediation.
    
    Args:
        owner: GitHub repository owner
        repo: GitHub repository name
        alert_numbers: List of alert numbers to close
        reason: Dismissal reason (e.g., "false positive", "won't fix", "used in tests")
    
    Returns:
        Dictionary mapping alert_number to success status (True/False)
    """
    token = get_github_token()
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    results: dict[int, bool] = {}
    
    for alert_number in alert_numbers:
        url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}"
        
        try:
            payload = {
                "state": "dismissed",
                "dismissed_reason": reason
            }
            
            response = requests.patch(url, headers=headers, json=payload, timeout=30)
            
            if response.status_code == 200:
                results[alert_number] = True
                print(f"[Close] Alert #{alert_number} closed successfully")
            else:
                results[alert_number] = False
                print(f"[Close] Failed to close alert #{alert_number}: {response.status_code}")
        
        except requests.RequestException as e:
            results[alert_number] = False
            print(f"[Close] Error closing alert #{alert_number}: {e}")
        
        time.sleep(0.5)
    
    return results

