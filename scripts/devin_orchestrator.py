"""
Security Sentinel Orchestrator for Devin AI.

Main entry point for the orchestrator. Coordinates the entire remediation workflow:
1. Validates input batches and configuration
2. Dispatches batches to parallel worker threads
3. Monitors all sessions until completion
4. Prints a human-readable summary
"""

import os
import sys
from typing import Any
from dotenv import load_dotenv

from scripts.devin.DO_models import SessionResult
from scripts.devin.DO_batch_processor import dispatch_threads
from scripts.devin.DO_reporting import print_summary
from scripts.devin.DO_config import MAX_WORKERS_DEFAULT, get_devin_api_key


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
    2. Checks available session capacity (without terminating existing sessions)
    3. Dispatches batches to parallel worker threads
    4. Monitors all sessions until completion
    5. Prints a human-readable summary
    
    Args:
        batches: Dictionary of remediation batches from get_remediation_batches_state_aware()
                 Format: {ruleId: {severity: float, tasks: [{alert_number, file, line, source}]}}
        owner: GitHub repository owner (defaults to env var GITHUB_OWNER)
        repo: GitHub repository name (defaults to env var GITHUB_REPO)
        max_workers: Maximum concurrent worker threads (default: 3)
    
    Returns:
        List of SessionResult objects for all processed batches
    
    Example:
        >>> from github_client import GitHubClient
        >>> from parse_sarif import (
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
    print(f"Max active sessions: {MAX_ACTIVE_SESSIONS}")
    
    if not batches:
        print("\nNo batches to process. Exiting.")
        return []
    
    for batch_id, batch_data in batches.items():
        tasks = batch_data.get("tasks", [])
        severity = batch_data.get("severity", 0)
        print(f"  - {batch_id}: {len(tasks)} tasks, severity {severity}")
    
    try:
        get_devin_api_key()
    except ValueError as e:
        print(f"\nConfiguration error: {e}")
        return []
    
    print("\n[Pre-flight] Checking available session capacity...")
    available_slots = get_available_session_slots()
    
    if available_slots == 0:
        active_count = get_active_session_count()
        print(f"\n[Pre-flight] ERROR: No session slots available ({active_count}/{MAX_ACTIVE_SESSIONS} active)")
        print("[Pre-flight] All sessions are currently active. Please wait for them to complete.")
        print("[Pre-flight] To manually clean up sessions, use: from scripts.termination_logic import cleanup_sentinel_sessions")
        return []
    
    print(f"\n[Pre-flight] Session slots available: {available_slots}/{MAX_ACTIVE_SESSIONS}")
    
    print("\nStarting remediation...")
    
    results = dispatch_threads(batches, owner, repo, max_workers, available_slots)
    
    print_summary(results)
    
    return results


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python devin_orchestrator.py <owner> <repo>")
        print("\nThis script requires the following environment variables:")
        print("  GH_TOKEN - GitHub Personal Access Token")
        print("  DEVIN_API_KEY - Devin AI API Key")
        sys.exit(1)
    
    load_dotenv()
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





