from typing import Any
import os
import requests
import time

POLL_INTERVAL_SECONDS = 150
SESSION_TIMEOUT_SECONDS = 15 * 60
STAGNATION_THRESHOLD_SECONDS = 5 * 60
from DO_models import SessionStatus, SessionResult

MAX_WORKERS_DEFAULT = 3
DEVIN_API_BASE = "https://api.devin.ai/v1"


def _get_devin_api_key() -> str:
    key = os.getenv("DEVIN_API_KEY")
    if not key:
        raise ValueError("DEVIN_API_KEY environment variable is not set")
    return key

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