"""
Session Outcome Reconciliation for Security Sentinel.

This module handles the reconciliation of Devin session outcomes with GitHub
alert states. After a session completes (successfully or not), this module
updates the corresponding GitHub alerts appropriately.

Outcome Handling:
    SUCCESS: Close all associated alerts (mark as fixed).
    FAILURE: Unclaim all alerts so they can be retried in future runs.
    PARTIAL: Close fixed alerts, unclaim unfixed alerts.
    STUCK/TIMEOUT: Unclaim all alerts for retry.
"""

from .DO_models import SessionStatus, SessionResult
from .DO_gh_alerts_control_center import (
    claim_github_alerts,
    unclaim_github_alerts,
    close_github_alerts,
)


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
