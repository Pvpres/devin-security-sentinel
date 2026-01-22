"""
Reporting and Summary Generation for Security Sentinel.

This module provides functions for generating human-readable summaries of
orchestrator runs. It displays batch statistics, alert statistics, and
detailed results for each processed batch.
"""

from .DO_models import SessionStatus, SessionResult


def print_summary(results: list[SessionResult]) -> None:
    """
    Print a human-readable summary of the orchestrator run.
    
    Displays comprehensive statistics including batch counts by status,
    alert counts (total, fixed, unfixed), and detailed per-batch results
    with session URLs and PR links where available.
    
    Args:
        results: List of SessionResult objects from the completed run.
    """
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
