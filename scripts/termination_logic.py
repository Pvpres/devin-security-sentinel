"""
Termination and Session Management Logic for Devin AI Sessions.

This module contains functions for managing Devin session lifecycle,
including termination and sleep-based cleanup. These functions are
separated from the main orchestrator to allow explicit control over
session cleanup without automatic termination.

The preferred approach is to use sleep messages instead of termination,
which preserves session history for later review while still freeing
up session capacity.

Key Functions:
- send_sleep_message: Send a sleep/pause message to a session (preferred)
- terminate_devin_session: Permanently terminate a session (use sparingly)
- cleanup_sentinel_sessions: Clean up only sessions created by this program
- get_available_session_slots: Calculate available slots without terminating
"""

import os
import time
from typing import Any

import requests


DEVIN_API_BASE = "https://api.devin.ai/v1"
MAX_ACTIVE_SESSIONS = 5

SENTINEL_SESSION_MARKERS = [
    "<security_remediation_task>",
    "<task_type>vulnerability_remediation</task_type>",
    "sentinel-",
]


def _get_devin_api_key() -> str:
    """Get the Devin API key from environment variables."""
    key = os.getenv("DEVIN_API_KEY")
    if not key:
        raise ValueError("DEVIN_API_KEY environment variable is not set")
    return key


def send_sleep_message(
    session_id: str,
    message: str = "Please pause and wait for further instructions. This session has completed its assigned security remediation task."
) -> bool:
    """
    Send a sleep/pause message to a Devin AI session.
    
    This is the preferred method for cleaning up sessions as it preserves
    the session history for later review while signaling to Devin that
    the task is complete.
    
    Args:
        session_id: The session ID to send the message to
        message: The message to send (default: pause instruction)
    
    Returns:
        True if the message was sent successfully, False otherwise
    """
    api_key = _get_devin_api_key()
    url = f"{DEVIN_API_BASE}/sessions/{session_id}/message"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "message": message
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        
        if response.status_code == 200:
            print(f"[Sleep] Sent sleep message to session {session_id}")
            return True
        else:
            print(f"[Sleep] Failed to send message to session {session_id}: {response.status_code}")
            return False
    
    except requests.RequestException as e:
        print(f"[Sleep] Error sending message to session {session_id}: {e}")
        return False


def terminate_devin_session(session_id: str) -> bool:
    """
    Terminate a Devin AI session permanently.
    
    WARNING: Once terminated, the session cannot be resumed. This should
    only be used when session history is not needed. Prefer using
    send_sleep_message() instead.
    
    Args:
        session_id: The session ID to terminate
    
    Returns:
        True if termination was successful, False otherwise
    """
    api_key = _get_devin_api_key()
    url = f"{DEVIN_API_BASE}/sessions/{session_id}"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.delete(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            print(f"[Terminate] Session {session_id} terminated successfully")
            return True
        else:
            print(f"[Terminate] Failed to terminate session {session_id}: {response.status_code}")
            return False
    
    except requests.RequestException as e:
        print(f"[Terminate] Error terminating session {session_id}: {e}")
        return False


def list_devin_sessions(limit: int = 100) -> list[dict[str, Any]]:
    """
    List all Devin AI sessions for the organization.
    
    Args:
        limit: Maximum number of sessions to return (default: 100)
    
    Returns:
        List of session dictionaries, or empty list on failure
    """
    api_key = _get_devin_api_key()
    url = f"{DEVIN_API_BASE}/sessions"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    params = {"limit": limit}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            sessions = data.get("sessions", [])
            return sessions
        else:
            print(f"[Sessions] Failed to list sessions: {response.status_code}")
            return []
    
    except requests.RequestException as e:
        print(f"[Sessions] Error listing sessions: {e}")
        return []


def is_sentinel_session(session: dict[str, Any]) -> bool:
    """
    Check if a session was created by the Security Sentinel program.
    
    Identifies sentinel sessions by checking for characteristic markers
    in the session title or other identifying fields.
    
    Args:
        session: Session dictionary from list_devin_sessions()
    
    Returns:
        True if the session was created by the sentinel program
    """
    title = session.get("title", "") or ""
    
    title_lower = title.lower()
    if "security" in title_lower and ("fix" in title_lower or "remediation" in title_lower):
        return True
    
    if "sentinel" in title_lower:
        return True
    
    if "codeql" in title_lower or "code scanning" in title_lower:
        return True
    
    return False


def get_active_session_count() -> int:
    """
    Get the count of currently active Devin sessions.
    
    Returns:
        Number of sessions with status 'working', 'running', or 'pending'
    """
    sessions = list_devin_sessions()
    
    active_statuses = {"working", "running", "pending"}
    active_count = sum(
        1 for s in sessions
        if s.get("status_enum", s.get("status", "")).lower() in active_statuses
    )
    
    return active_count


def get_available_session_slots() -> int:
    """
    Calculate the number of available session slots without terminating any sessions.
    
    This function checks the current active session count and calculates
    how many new sessions can be opened without exceeding the limit.
    
    Returns:
        Number of available session slots (0 to MAX_ACTIVE_SESSIONS)
    """
    active_count = get_active_session_count()
    available = max(0, MAX_ACTIVE_SESSIONS - active_count)
    
    print(f"[Capacity] Active sessions: {active_count}/{MAX_ACTIVE_SESSIONS}, Available slots: {available}")
    return available


def can_open_sessions(count: int) -> bool:
    """
    Check if a specified number of new sessions can be opened.
    
    Args:
        count: Number of sessions to check for
    
    Returns:
        True if the requested number of sessions can be opened
    """
    available = get_available_session_slots()
    return available >= count


def cleanup_sentinel_sessions(
    use_sleep: bool = True,
    only_inactive: bool = True
) -> int:
    """
    Clean up sessions created by the Security Sentinel program.
    
    This function identifies sessions created by this program and either
    sends them a sleep message (preferred) or terminates them.
    
    IMPORTANT: This only affects sessions created by this program for
    CodeQL security fixes, not other active sessions.
    
    Args:
        use_sleep: If True, send sleep messages instead of terminating (default: True)
        only_inactive: If True, only clean up inactive sessions (default: True)
    
    Returns:
        Number of sessions cleaned up
    """
    sessions = list_devin_sessions()
    
    if not sessions:
        print("[Cleanup] No sessions found")
        return 0
    
    active_statuses = {"working", "running", "pending"}
    
    sentinel_sessions = [s for s in sessions if is_sentinel_session(s)]
    
    if not sentinel_sessions:
        print("[Cleanup] No sentinel sessions found")
        return 0
    
    print(f"[Cleanup] Found {len(sentinel_sessions)} sentinel sessions")
    
    if only_inactive:
        target_sessions = [
            s for s in sentinel_sessions
            if s.get("status_enum", s.get("status", "")).lower() not in active_statuses
        ]
    else:
        target_sessions = sentinel_sessions
    
    if not target_sessions:
        print("[Cleanup] No target sessions to clean up")
        return 0
    
    print(f"[Cleanup] Cleaning up {len(target_sessions)} sessions (use_sleep={use_sleep})")
    
    cleaned_count = 0
    for session in target_sessions:
        session_id = session.get("session_id", "")
        status = session.get("status_enum", session.get("status", "unknown"))
        
        if not session_id:
            continue
        
        if use_sleep:
            if send_sleep_message(session_id):
                cleaned_count += 1
                print(f"[Cleanup] Sent sleep message to session {session_id} (was: {status})")
        else:
            if terminate_devin_session(session_id):
                cleaned_count += 1
                print(f"[Cleanup] Terminated session {session_id} (was: {status})")
        
        time.sleep(0.5)
    
    print(f"[Cleanup] Cleaned up {cleaned_count} sentinel sessions")
    return cleaned_count


def cleanup_inactive_sessions(use_sleep: bool = True) -> int:
    """
    Clean up all inactive (non-working) Devin sessions.
    
    This function lists all sessions and cleans up those that are not
    actively working (e.g., finished, blocked, failed).
    
    WARNING: This affects ALL sessions, not just sentinel sessions.
    Consider using cleanup_sentinel_sessions() instead.
    
    Args:
        use_sleep: If True, send sleep messages instead of terminating (default: True)
    
    Returns:
        Number of sessions cleaned up
    """
    sessions = list_devin_sessions()
    
    if not sessions:
        print("[Cleanup] No sessions found")
        return 0
    
    active_statuses = {"working", "running", "pending"}
    inactive_sessions = [
        s for s in sessions
        if s.get("status_enum", s.get("status", "")).lower() not in active_statuses
    ]
    
    if not inactive_sessions:
        print("[Cleanup] No inactive sessions to clean up")
        return 0
    
    print(f"[Cleanup] Found {len(inactive_sessions)} inactive sessions to clean up")
    
    cleaned_count = 0
    for session in inactive_sessions:
        session_id = session.get("session_id", "")
        status = session.get("status_enum", session.get("status", "unknown"))
        
        if not session_id:
            continue
        
        if use_sleep:
            if send_sleep_message(session_id):
                cleaned_count += 1
                print(f"[Cleanup] Sent sleep message to session {session_id} (was: {status})")
        else:
            if terminate_devin_session(session_id):
                cleaned_count += 1
                print(f"[Cleanup] Terminated session {session_id} (was: {status})")
        
        time.sleep(0.5)
    
    print(f"[Cleanup] Cleaned up {cleaned_count} inactive sessions")
    return cleaned_count
