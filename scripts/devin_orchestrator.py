"""
Security Sentinel Orchestrator for Devin AI.

This module implements a high-performance, parallelized orchestrator that manages
GitHub security alerts, dispatches parallel remediation sessions to Devin AI,
monitors execution health, and reconciles outcomes back to GitHub.

Architecture:
- Parallelism: Uses ThreadPoolExecutor for concurrent batch processing
- State Awareness: Tracks alert claims and session mappings throughout lifecycle
- Resilience: Wraps all external API calls with error handling

Key Components:
- create_devin_prompt: Generates XML-formatted prompts for Sub-Devin workers
- claim_github_alerts: Claims alerts via GitHub REST API before remediation
- poll_session_status: Monitors Devin sessions with timeout and stagnation detection
- dispatch_threads: Manages parallel execution of remediation batches
- handle_session_outcome: Reconciles session results back to GitHub
- run_orchestrator: Main entry point coordinating the entire workflow
"""

import os
import time
import threading
from typing import Any
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


DEVIN_API_BASE = "https://api.devin.ai/v1"
GITHUB_API_BASE = "https://api.github.com"

POLL_INTERVAL_SECONDS = 150
SESSION_TIMEOUT_SECONDS = 20 * 60
STAGNATION_THRESHOLD_SECONDS = 5 * 60

MAX_WORKERS_DEFAULT = 3

CLAIM_RETRY_ATTEMPTS = 3
CLAIM_RETRY_DELAY_SECONDS = 2


class SessionStatus(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    STUCK = "stuck"
    TIMEOUT = "timeout"
    PENDING = "pending"
    RUNNING = "running"


@dataclass
class SessionResult:
    status: SessionStatus
    session_id: str
    batch_id: str
    alert_numbers: list[int]
    pr_url: str | None = None
    error_message: str | None = None
    fixed_alerts: list[int] = field(default_factory=list)
    unfixed_alerts: list[int] = field(default_factory=list)


@dataclass
class OrchestratorState:
    """Thread-safe state container for the orchestrator."""
    session_to_alerts: dict[str, list[int]] = field(default_factory=dict)
    session_to_batch: dict[str, str] = field(default_factory=dict)
    results: list[SessionResult] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def register_session(self, session_id: str, batch_id: str, alert_numbers: list[int]) -> None:
        with self.lock:
            self.session_to_alerts[session_id] = alert_numbers
            self.session_to_batch[session_id] = batch_id

    def add_result(self, result: SessionResult) -> None:
        with self.lock:
            self.results.append(result)

    def get_alerts_for_session(self, session_id: str) -> list[int]:
        with self.lock:
            return self.session_to_alerts.get(session_id, [])


def _get_github_token() -> str:
    token = os.getenv("GH_TOKEN")
    if not token:
        raise ValueError("GH_TOKEN environment variable is not set")
    return token


def _get_devin_api_key() -> str:
    key = os.getenv("DEVIN_API_KEY")
    if not key:
        raise ValueError("DEVIN_API_KEY environment variable is not set")
    return key


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
    token = _get_github_token()
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
    token = _get_github_token()
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
    token = _get_github_token()
    
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


def create_devin_prompt(
    task_description: str,
    batch_data: dict[str, Any],
    batch_id: str,
    owner: str,
    repo: str
) -> str:
    """
    Generate a high-density, XML-formatted prompt for Sub-Devin workers.
    
    The prompt includes:
    - Task description with clear remediation instructions
    - Minified batch data with file paths, line numbers, and code flows
    - Instructions to fix vulnerabilities, run tests, and open a PR
    
    Args:
        task_description: Human-readable description of the vulnerability batch
        batch_data: Minified batch data from get_remediation_batches_state_aware()
                    Format: {severity: float, tasks: [{alert_number, file, line, source}]}
        batch_id: Identifier for the vulnerability batch (typically the ruleId)
        owner: GitHub repository owner
        repo: GitHub repository name
    
    Returns:
        XML-formatted prompt string optimized for Devin AI processing
    """
    tasks = batch_data.get("tasks", [])
    severity = batch_data.get("severity", 0)
    
    vulnerabilities_xml = ""
    for task in tasks:
        vulnerabilities_xml += f"""
    <vulnerability>
      <rule>{batch_id}</rule>
      <file>{task.get('file', 'unknown')}</file>
      <line>{task.get('line', 'unknown')}</line>
      <source>{task.get('source', 'N/A')}</source>
      <alert_number>{task.get('alert_number', 'N/A')}</alert_number>
    </vulnerability>"""

    prompt = f"""<security_remediation_task>
  <metadata>
    <batch_id>{batch_id}</batch_id>
    <repository>{owner}/{repo}</repository>
    <task_type>vulnerability_remediation</task_type>
  </metadata>

  <description>
    {task_description}
  </description>

  <vulnerabilities>{vulnerabilities_xml}
  </vulnerabilities>

  <instructions>
    <step>1. Clone the repository {owner}/{repo} if not already available</step>
    <step>2. Analyze each vulnerability location listed above</step>
    <step>3. Implement secure fixes for all vulnerabilities in this batch</step>
    <step>4. Ensure fixes follow security best practices (input validation, parameterized queries, etc.)</step>
    <step>5. Run all existing tests to verify fixes don't break functionality</step>
    <step>6. Create a new branch named 'security-fix/{batch_id}'</step>
    <step>7. Commit all changes with descriptive commit messages</step>
    <step>8. Open a GitHub Pull Request with title: 'Security Fix: {batch_id}'</step>
    <step>9. Include a summary of all fixes in the PR description</step>
  </instructions>

  <requirements>
    <requirement>All vulnerabilities in this batch must be addressed</requirement>
    <requirement>Tests must pass after fixes are applied</requirement>
    <requirement>PR must be created and ready for review</requirement>
  </requirements>
</security_remediation_task>"""

    return prompt


def extract_alert_numbers(batch_data: dict[str, Any]) -> list[int]:
    """
    Extract alert numbers from batch data.
    
    The batch data from get_remediation_batches_state_aware() already contains
    all alert numbers needed. This function extracts them without making any
    API calls.
    
    Args:
        batch_data: Batch data containing tasks with alert_number fields
                    Format: {severity: float, tasks: [{alert_number, file, line, source}]}
    
    Returns:
        List of alert numbers extracted from the batch data
    """
    tasks = batch_data.get("tasks", [])
    alert_numbers = [
        task.get("alert_number") 
        for task in tasks 
        if task.get("alert_number") is not None
    ]
    return alert_numbers


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
    token = _get_github_token()
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


def create_devin_session(
    prompt: str,
    idempotency_key: str | None = None
) -> dict[str, Any] | None:
    """
    Create a new Devin AI session with the given prompt.
    
    Args:
        prompt: The task prompt for Devin
        idempotency_key: Optional key for idempotent session creation
    
    Returns:
        Session response dictionary containing session_id, or None on failure
    """
    api_key = _get_devin_api_key()
    url = f"{DEVIN_API_BASE}/sessions"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    payload: dict[str, Any] = {
        "prompt": prompt
    }
    
    if idempotency_key:
        payload["idempotency_key"] = idempotency_key
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=60)
        
        if response.status_code == 200:
            session_data = response.json()
            print(f"[Devin] Session created: {session_data.get('session_id', 'unknown')}")
            return session_data
        else:
            print(f"[Devin] Failed to create session: {response.status_code} - {response.text}")
            return None
    
    except requests.RequestException as e:
        print(f"[Devin] Error creating session: {e}")
        return None


def get_devin_session_status(session_id: str) -> dict[str, Any] | None:
    """
    Get the current status of a Devin AI session.
    
    Args:
        session_id: The session ID to query
    
    Returns:
        Session status dictionary, or None on failure
    """
    api_key = _get_devin_api_key()
    url = f"{DEVIN_API_BASE}/session/{session_id}"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"[Devin] Failed to get session status: {response.status_code}")
            return None
    
    except requests.RequestException as e:
        print(f"[Devin] Error getting session status: {e}")
        return None


def poll_session_status(
    session_id: str,
    poll_interval: int = POLL_INTERVAL_SECONDS,
    timeout: int = SESSION_TIMEOUT_SECONDS,
    stagnation_threshold: int = STAGNATION_THRESHOLD_SECONDS
) -> SessionResult:
    """
    Poll a Devin session until completion, timeout, or stagnation.
    
    This function implements the core polling loop that keeps worker threads
    alive while Sub-Devin is actively coding. It includes:
    - Regular polling every 150 seconds (configurable)
    - 20-minute timeout (configurable)
    - Stagnation detection: marks session as "stuck" if no new logs for 5 minutes
    
    Args:
        session_id: The Devin session ID to monitor
        poll_interval: Seconds between status checks (default: 150)
        timeout: Maximum seconds to wait for completion (default: 1200)
        stagnation_threshold: Seconds without progress before marking stuck (default: 300)
    
    Returns:
        SessionResult with status (success, failure, partial, stuck, timeout)
    """
    start_time = time.time()
    last_activity_time = start_time
    last_status_message = ""
    last_structured_output = None
    
    print(f"[Poll] Starting to monitor session {session_id}")
    print(f"[Poll] Timeout: {timeout}s, Poll interval: {poll_interval}s, Stagnation threshold: {stagnation_threshold}s")
    
    while True:
        elapsed = time.time() - start_time
        
        if elapsed > timeout:
            print(f"[Poll] Session {session_id} timed out after {elapsed:.0f}s")
            return SessionResult(
                status=SessionStatus.TIMEOUT,
                session_id=session_id,
                batch_id="",
                alert_numbers=[],
                error_message=f"Session timed out after {timeout} seconds"
            )
        
        session_data = get_devin_session_status(session_id)
        
        if session_data is None:
            print(f"[Poll] Failed to get status for session {session_id}, will retry...")
            time.sleep(poll_interval)
            continue
        
        status = session_data.get("status_enum", session_data.get("status", "unknown"))
        status_message = session_data.get("status_message", "")
        structured_output = session_data.get("structured_output")
        
        if status_message != last_status_message or structured_output != last_structured_output:
            last_activity_time = time.time()
            last_status_message = status_message
            last_structured_output = structured_output
            print(f"[Poll] Session {session_id} - Status: {status}, Message: {status_message[:100] if status_message else 'N/A'}...")
        
        stagnation_time = time.time() - last_activity_time
        if stagnation_time > stagnation_threshold:
            print(f"[Poll] Session {session_id} appears stuck (no activity for {stagnation_time:.0f}s)")
            return SessionResult(
                status=SessionStatus.STUCK,
                session_id=session_id,
                batch_id="",
                alert_numbers=[],
                error_message=f"Session stagnated for {stagnation_time:.0f} seconds"
            )
        
        pull_request = session_data.get("pull_request")
        pr_url = pull_request.get("url") if pull_request else None
        
        if pr_url:
            print(f"[Poll] Session {session_id} has PR: {pr_url} - marking as success")
            return SessionResult(
                status=SessionStatus.SUCCESS,
                session_id=session_id,
                batch_id="",
                alert_numbers=[],
                pr_url=pr_url
            )
        
        if status in ("finished", "completed", "success"):
            print(f"[Poll] Session {session_id} completed successfully")
            return SessionResult(
                status=SessionStatus.SUCCESS,
                session_id=session_id,
                batch_id="",
                alert_numbers=[],
                pr_url=pr_url
            )
        
        if status in ("failed", "error", "cancelled"):
            error_msg = status_message or f"Session ended with status: {status}"
            print(f"[Poll] Session {session_id} failed: {error_msg}")
            return SessionResult(
                status=SessionStatus.FAILURE,
                session_id=session_id,
                batch_id="",
                alert_numbers=[],
                error_message=error_msg
            )
        
        if status == "blocked":
            print(f"[Poll] Session {session_id} is blocked (no PR found), treating as failure")
            return SessionResult(
                status=SessionStatus.FAILURE,
                session_id=session_id,
                batch_id="",
                alert_numbers=[],
                error_message="Session is blocked and requires manual intervention"
            )
        
        print(f"[Poll] Session {session_id} still running (elapsed: {elapsed:.0f}s, status: {status})")
        time.sleep(poll_interval)


def handle_session_outcome(
    result: SessionResult,
    owner: str,
    repo: str
) -> SessionResult:
    """
    Reconcile session outcome with GitHub alert states.
    
    Implements outcome reconciliation logic:
    - Success: Confirm PR creation, close all associated alerts
    - Failure: Unclaim all alerts so they can be retried
    - Partial Success: Close fixed alerts, unclaim unfixed alerts
    - Stuck/Timeout: Unclaim all alerts so they can be retried
    
    Args:
        result: The SessionResult from poll_session_status
        owner: GitHub repository owner
        repo: GitHub repository name
    
    Returns:
        Updated SessionResult with reconciliation details
    """
    alert_numbers = result.alert_numbers
    
    if not alert_numbers:
        print(f"[Outcome] No alerts associated with session {result.session_id}")
        return result
    
    print(f"[Outcome] Processing outcome for session {result.session_id}: {result.status.value}")
    
    if result.status == SessionStatus.SUCCESS:
        print(f"[Outcome] Session succeeded, closing {len(alert_numbers)} alerts")
        close_results = close_github_alerts(owner, repo, alert_numbers, reason="used in tests")
        
        result.fixed_alerts = [num for num, success in close_results.items() if success]
        result.unfixed_alerts = [num for num, success in close_results.items() if not success]
        
        if result.unfixed_alerts:
            print(f"[Outcome] Warning: Failed to close alerts: {result.unfixed_alerts}")
    
    elif result.status == SessionStatus.FAILURE:
        print(f"[Outcome] Session failed, unclaiming {len(alert_numbers)} alerts for retry")
        unclaim_results = unclaim_github_alerts(owner, repo, alert_numbers)
        
        unclaimed = [num for num, success in unclaim_results.items() if success]
        failed_unclaims = [num for num, success in unclaim_results.items() if not success]
        
        if failed_unclaims:
            print(f"[Outcome] Warning: Failed to unclaim alerts: {failed_unclaims}")
        
        result.unfixed_alerts = alert_numbers
    
    elif result.status == SessionStatus.PARTIAL:
        fixed = result.fixed_alerts or []
        unfixed = [n for n in alert_numbers if n not in fixed]
        
        if fixed:
            print(f"[Outcome] Closing {len(fixed)} fixed alerts")
            close_github_alerts(owner, repo, fixed, reason="used in tests")
        
        if unfixed:
            print(f"[Outcome] Unclaiming {len(unfixed)} unfixed alerts for retry")
            unclaim_results = unclaim_github_alerts(owner, repo, unfixed)
            
            failed_unclaims = [num for num, success in unclaim_results.items() if not success]
            if failed_unclaims:
                print(f"[Outcome] Warning: Failed to unclaim alerts: {failed_unclaims}")
            
            result.unfixed_alerts = unfixed
    
    elif result.status in (SessionStatus.STUCK, SessionStatus.TIMEOUT):
        print(f"[Outcome] Session {result.status.value}, unclaiming {len(alert_numbers)} alerts for retry")
        unclaim_results = unclaim_github_alerts(owner, repo, alert_numbers)
        
        failed_unclaims = [num for num, success in unclaim_results.items() if not success]
        if failed_unclaims:
            print(f"[Outcome] Warning: Failed to unclaim alerts: {failed_unclaims}")
        
        result.unfixed_alerts = alert_numbers
    
    return result


def process_batch(
    batch_id: str,
    batch_data: dict[str, Any],
    owner: str,
    repo: str,
    state: OrchestratorState
) -> SessionResult:
    """
    Process a single remediation batch end-to-end.
    
    This function is executed by worker threads and handles:
    1. Extracting alert numbers from batch data
    2. Starting a Devin session
    3. Polling for completion
    4. Handling the final outcome
    
    Args:
        batch_id: The vulnerability rule ID (batch identifier)
        batch_data: Batch data containing severity and tasks with alert_number fields
        owner: GitHub repository owner
        repo: GitHub repository name
        state: Shared orchestrator state for tracking
    
    Returns:
        SessionResult with final status and details
    """
    print(f"\n[Batch] Processing batch: {batch_id}")
    
    tasks = batch_data.get("tasks", [])
    severity = batch_data.get("severity", 0)
    alert_numbers = extract_alert_numbers(batch_data)
    
    print(f"[Batch] Batch {batch_id}: {len(tasks)} tasks, severity {severity}, alerts: {alert_numbers}")
    
    if not alert_numbers:
        print(f"[Batch] No alerts found in batch {batch_id}")
        return SessionResult(
            status=SessionStatus.FAILURE,
            session_id="",
            batch_id=batch_id,
            alert_numbers=[],
            error_message="No alerts found in batch data"
        )
    
    print(f"[Batch] Claiming {len(alert_numbers)} alerts for batch {batch_id}")
    claim_results = claim_github_alerts(owner, repo, alert_numbers)
    
    claimed_alerts = [num for num, success in claim_results.items() if success]
    failed_claims = [num for num, success in claim_results.items() if not success]
    
    if not claimed_alerts:
        print(f"[Batch] Failed to claim any alerts for batch {batch_id}, skipping")
        return SessionResult(
            status=SessionStatus.FAILURE,
            session_id="",
            batch_id=batch_id,
            alert_numbers=alert_numbers,
            error_message=f"Failed to claim alerts: {failed_claims}"
        )
    
    if failed_claims:
        print(f"[Batch] Warning: Could not claim alerts {failed_claims}, proceeding with {len(claimed_alerts)} claimed alerts")
        alert_numbers = claimed_alerts
    
    task_description = f"Fix {len(tasks)} security vulnerabilities of type '{batch_id}' with severity {severity}"
    
    prompt = create_devin_prompt(
        task_description=task_description,
        batch_data=batch_data,
        batch_id=batch_id,
        owner=owner,
        repo=repo
    )
    
    idempotency_key = f"sentinel-{owner}-{repo}-{batch_id}-{int(time.time())}"
    session_response = create_devin_session(prompt, idempotency_key)
    
    if not session_response:
        print(f"[Batch] Failed to create Devin session for batch {batch_id}")
        return SessionResult(
            status=SessionStatus.FAILURE,
            session_id="",
            batch_id=batch_id,
            alert_numbers=alert_numbers,
            error_message="Failed to create Devin session"
        )
    
    session_id = session_response.get("session_id", "")
    print(f"[Batch] Devin session created: {session_id} for batch {batch_id}")
    
    state.register_session(session_id, batch_id, alert_numbers)
    
    result = poll_session_status(session_id)
    
    result.batch_id = batch_id
    result.alert_numbers = alert_numbers
    
    result = handle_session_outcome(result, owner, repo)
    
    state.add_result(result)
    
    return result


def dispatch_threads(
    batches: dict[str, dict[str, Any]],
    owner: str,
    repo: str,
    max_workers: int = MAX_WORKERS_DEFAULT
) -> list[SessionResult]:
    """
    Dispatch remediation batches to parallel worker threads.
    
    Uses ThreadPoolExecutor to process batches concurrently while
    enforcing a conservative max_workers limit to avoid API rate limits.
    
    Each thread:
    1. Extracts alert numbers from batch data
    2. Starts a Devin session
    3. Polls for completion
    4. Handles the final outcome
    
    Args:
        batches: Dictionary of remediation batches {batch_id: batch_data}
        owner: GitHub repository owner
        repo: GitHub repository name
        max_workers: Maximum concurrent threads (default: 3)
    
    Returns:
        List of SessionResult objects for all processed batches
    """
    if not batches:
        print("[Dispatch] No batches to process")
        return []
    
    print(f"\n[Dispatch] Starting parallel processing of {len(batches)} batches with {max_workers} workers")
    
    state = OrchestratorState()
    results: list[SessionResult] = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_batch = {
            executor.submit(
                process_batch,
                batch_id,
                batch_data,
                owner,
                repo,
                state
            ): batch_id
            for batch_id, batch_data in batches.items()
        }
        
        for future in as_completed(future_to_batch):
            batch_id = future_to_batch[future]
            try:
                result = future.result()
                results.append(result)
                print(f"[Dispatch] Batch {batch_id} completed with status: {result.status.value}")
            except Exception as e:
                print(f"[Dispatch] Batch {batch_id} raised exception: {e}")
                results.append(SessionResult(
                    status=SessionStatus.FAILURE,
                    session_id="",
                    batch_id=batch_id,
                    alert_numbers=[],
                    error_message=str(e)
                ))
    
    return results


def print_summary(results: list[SessionResult]) -> None:
    """Print a human-readable summary of the orchestrator run."""
    total = len(results)
    successes = sum(1 for r in results if r.status == SessionStatus.SUCCESS)
    failures = sum(1 for r in results if r.status == SessionStatus.FAILURE)
    partials = sum(1 for r in results if r.status == SessionStatus.PARTIAL)
    stuck = sum(1 for r in results if r.status == SessionStatus.STUCK)
    timeouts = sum(1 for r in results if r.status == SessionStatus.TIMEOUT)
    
    total_alerts = sum(len(r.alert_numbers) for r in results)
    fixed_alerts = sum(len(r.fixed_alerts) for r in results)
    unfixed_alerts = sum(len(r.unfixed_alerts) for r in results)
    
    print("\n" + "=" * 60)
    print("           SENTINEL RUN SUMMARY")
    print("=" * 60)
    print(f"\nBatch Statistics:")
    print(f"  Total Batches:     {total}")
    print(f"  Successes:         {successes}")
    print(f"  Partial Successes: {partials}")
    print(f"  Failures:          {failures}")
    print(f"  Stuck Sessions:    {stuck}")
    print(f"  Timeouts:          {timeouts}")
    
    print(f"\nAlert Statistics:")
    print(f"  Total Alerts:      {total_alerts}")
    print(f"  Fixed Alerts:      {fixed_alerts}")
    print(f"  Unfixed Alerts:    {unfixed_alerts}")
    
    if results:
        print(f"\nDetailed Results:")
        for r in results:
            status_icon = {
                SessionStatus.SUCCESS: "[OK]",
                SessionStatus.FAILURE: "[FAIL]",
                SessionStatus.PARTIAL: "[PARTIAL]",
                SessionStatus.STUCK: "[STUCK]",
                SessionStatus.TIMEOUT: "[TIMEOUT]"
            }.get(r.status, "[?]")
            
            print(f"  {status_icon} {r.batch_id}")
            if r.session_id:
                print(f"       Session: {r.session_id}")
            if r.pr_url:
                print(f"       PR: {r.pr_url}")
            if r.error_message:
                print(f"       Error: {r.error_message[:80]}...")
            if r.fixed_alerts:
                print(f"       Fixed: {r.fixed_alerts}")
            if r.unfixed_alerts:
                print(f"       Unfixed: {r.unfixed_alerts}")
    
    print("\n" + "=" * 60)


def run_orchestrator(
    batches: dict[str, dict[str, Any]],
    owner: str | None = None,
    repo: str | None = None,
    max_workers: int = MAX_WORKERS_DEFAULT
) -> list[SessionResult]:
    """
    Main entry point for the Security Sentinel Orchestrator.
    
    Coordinates the entire remediation workflow:
    1. Validates input batches and configuration
    2. Dispatches batches to parallel worker threads
    3. Monitors all sessions until completion
    4. Prints a human-readable summary
    
    Args:
        batches: Dictionary of remediation batches from get_remediation_batches_state_aware()
                 Format: {ruleId: {severity: float, tasks: [{alert_number, file, line, source}]}}
        owner: GitHub repository owner (defaults to env var GITHUB_OWNER)
        repo: GitHub repository name (defaults to env var GITHUB_REPO)
        max_workers: Maximum concurrent worker threads (default: 3)
    
    Returns:
        List of SessionResult objects for all processed batches
    
    Example:
        >>> from scripts.github_client import GitHubClient
        >>> from scripts.parse_sarif import (
        ...     build_active_alert_index,
        ...     minify_sarif_state_aware,
        ...     get_remediation_batches_state_aware
        ... )
        >>> 
        >>> client = GitHubClient("owner", "repo")
        >>> alerts = client.get_active_alerts()
        >>> index = build_active_alert_index(alerts)
        >>> sarif = client.get_sarif_data()
        >>> minified = minify_sarif_state_aware(sarif, index)
        >>> batches = get_remediation_batches_state_aware(minified)
        >>> 
        >>> results = run_orchestrator(batches, owner="owner", repo="repo")
    """
    owner = owner or os.getenv("GITHUB_OWNER", "")
    repo = repo or os.getenv("GITHUB_REPO", "")
    
    if not owner or not repo:
        raise ValueError("Repository owner and name must be provided or set via GITHUB_OWNER/GITHUB_REPO env vars")
    
    print("\n" + "=" * 60)
    print("     SECURITY SENTINEL ORCHESTRATOR")
    print("=" * 60)
    print(f"\nRepository: {owner}/{repo}")
    print(f"Batches to process: {len(batches)}")
    print(f"Max workers: {max_workers}")
    
    if not batches:
        print("\nNo batches to process. Exiting.")
        return []
    
    for batch_id, batch_data in batches.items():
        tasks = batch_data.get("tasks", [])
        severity = batch_data.get("severity", 0)
        print(f"  - {batch_id}: {len(tasks)} tasks, severity {severity}")
    
    print("\nStarting remediation...")
    
    try:
        _get_github_token()
        _get_devin_api_key()
    except ValueError as e:
        print(f"\nConfiguration error: {e}")
        return []
    
    results = dispatch_threads(batches, owner, repo, max_workers)
    
    print_summary(results)
    
    return results


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python devin_orchestrator.py <owner> <repo>")
        print("\nThis script requires the following environment variables:")
        print("  GH_TOKEN - GitHub Personal Access Token")
        print("  DEVIN_API_KEY - Devin AI API Key")
        sys.exit(1)
    
    target_owner = sys.argv[1]
    target_repo = sys.argv[2]
    
    from github_client import GitHubClient
    from parse_sarif import (
        build_active_alert_index,
        minify_sarif_state_aware,
        get_remediation_batches_state_aware
    )
    
    print(f"Fetching security data for {target_owner}/{target_repo}...")
    
    client = GitHubClient(target_owner, target_repo)
    
    alerts = client.get_active_alerts()
    if not alerts:
        print("No active alerts found.")
        sys.exit(0)
    
    print(f"Found {len(alerts)} active alerts")
    
    alert_index = build_active_alert_index(alerts)
    
    sarif_data = client.get_sarif_data()
    if not sarif_data:
        print("Failed to fetch SARIF data.")
        sys.exit(1)
    
    minified = minify_sarif_state_aware(sarif_data, alert_index)
    print(f"Minified to {len(minified)} results matching active alerts")
    
    remediation_batches = get_remediation_batches_state_aware(minified)
    print(f"Created {len(remediation_batches)} remediation batches")
    
    run_orchestrator(remediation_batches, owner=target_owner, repo=target_repo)





