"""Batch processing and parallel thread management."""

import time
import threading
from typing import Any, TYPE_CHECKING
from concurrent.futures import ThreadPoolExecutor, as_completed

from .DO_models import SessionStatus, SessionResult, OrchestratorState
from .DO_gh_alerts_control_center import claim_github_alerts
from .DO_prompts import create_devin_prompt
from .DO_session import create_devin_session, poll_session_status
from .DO_outcomes import handle_session_outcome
from .DO_config import MAX_WORKERS_DEFAULT, MAX_ACTIVE_SESSIONS

# Import from parent scripts directory
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from termination_logic import send_sleep_message

if TYPE_CHECKING:
    from scripts.slack_client import SentinelDashboard

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

def process_batch(
    batch_id: str,
    batch_data: dict[str, Any],
    owner: str,
    repo: str,
    state: OrchestratorState,
    session_semaphore: threading.Semaphore | None = None,
    dashboard: "SentinelDashboard | None" = None
) -> SessionResult:
    """
    Process a single remediation batch end-to-end.
    
    This function is executed by worker threads and handles:
    1. Acquiring a session slot (via semaphore)
    2. Extracting alert numbers from batch data
    3. Starting a Devin session
    4. Polling for completion
    5. Terminating the session to free the slot
    6. Handling the final outcome
    
    Args:
        batch_id: The vulnerability rule ID (batch identifier)
        batch_data: Batch data containing severity and tasks with alert_number fields
        owner: GitHub repository owner
        repo: GitHub repository name
        state: Shared orchestrator state for tracking
        session_semaphore: Optional semaphore to limit concurrent active sessions
        dashboard: Optional SentinelDashboard for Slack updates
    
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
    
    if session_semaphore:
        print(f"[Batch] Waiting for session slot for batch {batch_id}...")
        session_semaphore.acquire()
        print(f"[Batch] Acquired session slot for batch {batch_id}")
    
    session_id = ""
    try:
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
        session_url = session_response.get("url")
        print(f"[Batch] Devin session created: {session_id} for batch {batch_id}")
        
        if dashboard:
            dashboard.update(batch_id, "Started", session_id=session_id, session_url=session_url)
        
        state.register_session(session_id, batch_id, alert_numbers)
        
        if dashboard:
            dashboard.update(batch_id, "Analyzing...", session_id=session_id, session_url=session_url)
        
        result = poll_session_status(session_id, session_url=session_url)
        
        result.batch_id = batch_id
        result.alert_numbers = alert_numbers
        
        result = handle_session_outcome(result, owner, repo)
        
        state.add_result(result)
        
        final_status = f"Completed: {result.status.value}"
        if dashboard:
            dashboard.update(batch_id, final_status, session_id=session_id, pr_url=result.pr_url, session_url=result.session_url)
        
        return result
    
    finally:
        if session_id:
            print(f"[Batch] Sending sleep message to session {session_id} for batch {batch_id}")
            send_sleep_message(session_id)
        
        if session_semaphore:
            session_semaphore.release()
            print(f"[Batch] Released session slot for batch {batch_id}")


def dispatch_threads(
    batches: dict[str, dict[str, Any]],
    owner: str,
    repo: str,
    max_workers: int = MAX_WORKERS_DEFAULT,
    available_session_slots: int = MAX_ACTIVE_SESSIONS,
    dashboard: "SentinelDashboard | None" = None
) -> list[SessionResult]:
    """
    Dispatch remediation batches to parallel worker threads.
    
    Uses ThreadPoolExecutor to process batches concurrently while
    enforcing a conservative max_workers limit to avoid API rate limits.
    Uses a semaphore to limit concurrent active Devin sessions.
    
    Each thread:
    1. Acquires a session slot (via semaphore)
    2. Extracts alert numbers from batch data
    3. Starts a Devin session
    4. Polls for completion
    5. Sends sleep message to session (preserves session for later review)
    6. Handles the final outcome
    
    Args:
        batches: Dictionary of remediation batches {batch_id: batch_data}
        owner: GitHub repository owner
        repo: GitHub repository name
        max_workers: Maximum concurrent threads (default: 3)
        available_session_slots: Number of available session slots (default: MAX_ACTIVE_SESSIONS)
        dashboard: Optional SentinelDashboard for Slack updates
    
    Returns:
        List of SessionResult objects for all processed batches
    """
    if not batches:
        print("[Dispatch] No batches to process")
        return []
    
    print(f"\n[Dispatch] Starting parallel processing of {len(batches)} batches with {max_workers} workers")
    print(f"[Dispatch] Available session slots: {available_session_slots}")
    
    state = OrchestratorState()
    results: list[SessionResult] = []
    
    session_semaphore = threading.Semaphore(available_session_slots)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_batch = {
            executor.submit(
                process_batch,
                batch_id,
                batch_data,
                owner,
                repo,
                state,
                session_semaphore,
                dashboard
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
