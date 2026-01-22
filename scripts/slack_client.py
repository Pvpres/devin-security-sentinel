"""
Slack Dashboard Client for Security Sentinel.

This module provides the SentinelDashboard class for real-time Slack notifications
during security remediation runs. It displays batch progress, session status,
and final summary reports using Slack's Block Kit for rich formatting.

The dashboard operates in two modes:
1. Slack Mode: When SLACK_BOT_TOKEN and SLACK_CHANNEL_ID are configured, updates
   are posted to Slack with live-updating messages.
2. Terminal Fallback: When Slack credentials are missing, status updates are
   printed to the terminal instead.

Environment Variables:
    SLACK_BOT_TOKEN: Slack Bot OAuth Token for API authentication.
    SLACK_CHANNEL_ID: Target Slack channel ID for posting updates.

Example:
    >>> from scripts.slack_client import SentinelDashboard
    >>> dashboard = SentinelDashboard(batch_names=['py/sql-injection', 'py/xss'])
    >>> dashboard.update('py/sql-injection', 'Started', session_id='abc123')
    >>> dashboard.finalize_report(results)
"""

import os
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

if TYPE_CHECKING:
    from scripts.devin.DO_models import SessionResult

DEVIN_SESSION_URL_BASE = "https://app.devin.ai/sessions"


@dataclass
class BatchInfo:
    """
    Stores tracking information for each remediation batch.
    
    This dataclass holds the current state of a batch being processed,
    including its status and any associated URLs for tracking progress.
    
    Attributes:
        status: Current status text (e.g., 'In Queue', 'Started', 'Analyzing', 'Fixed').
        session_id: Optional Devin session ID for URL construction fallback.
        session_url: Optional direct URL to the Devin session (preferred over session_id).
        pr_url: Optional URL to the pull request if a fix was created.
    """
    status: str
    session_id: str | None = None
    session_url: str | None = None
    pr_url: str | None = None


class SentinelDashboard:
    """
    Real-time Slack dashboard for monitoring Security Sentinel remediation runs.
    
    This class manages a live-updating Slack message that displays the status
    of all remediation batches being processed. It uses Slack's Block Kit for
    rich formatting and supports both active swarm monitoring and final summary
    reports.
    
    The dashboard is thread-safe and can be updated from multiple worker threads
    simultaneously. When Slack credentials are not available, it falls back to
    terminal output.
    
    Attributes:
        lock: Threading lock for thread-safe updates.
        msg_ts: Slack message timestamp for updating existing messages.
        start_time: Unix timestamp when the dashboard was created.
        batch_info: Dictionary mapping batch names to their BatchInfo objects.
        enabled: Whether Slack integration is active.
        client: Slack WebClient instance (only when enabled).
        channel: Target Slack channel ID.
    """
    
    def __init__(self, batch_names: list[str], channel_id: str | None = None):
        """
        Initialize the Slack dashboard with batch tracking.
        
        Sets up the dashboard to track the specified batches and attempts to
        connect to Slack. If Slack credentials are missing or connection fails,
        the dashboard falls back to terminal output mode.
        
        Args:
            batch_names: List of batch identifiers to track (e.g., rule IDs).
            channel_id: Optional Slack channel ID. If not provided, uses
                       SLACK_CHANNEL_ID environment variable.
        """
        self.lock = threading.Lock()
        self.msg_ts: str | None = None
        self.start_time = time.time()
        
        self.batch_info: dict[str, BatchInfo] = {
            name: BatchInfo(status="In Queue") for name in batch_names
        }
        
        token = os.getenv("SLACK_BOT_TOKEN")
        self.channel = channel_id or os.getenv("SLACK_CHANNEL_ID")
        
        if not token or not self.channel:
            print("Slack credentials missing. Dashboard is disabled (Terminal Fallback Active).")
            self.enabled = False
            return

        try:
            self.client = WebClient(token=token)
            self.enabled = True
            self._ensure_access()
        except Exception as e:
            print(f"Slack Initialization failed: {e}")
            self.enabled = False

    def _ensure_access(self) -> None:
        """
        Attempt to join the Slack channel to ensure posting permissions.
        
        This method tries to join the configured channel. If the bot is already
        a member or the channel is public, this succeeds silently. Warnings are
        printed for permission issues but don't disable the dashboard.
        """
        if not self.enabled:
            return
        try:
            self.client.conversations_join(channel=self.channel)
        except SlackApiError as e:
            print(f"Slack join warning: {e.response['error']}")

    def update(
        self,
        batch_name: str,
        status: str,
        session_id: str | None = None,
        session_url: str | None = None,
        pr_url: str | None = None
    ) -> None:
        """
        Thread-safe update method called by worker threads.
        
        Args:
            batch_name: The batch identifier (e.g., 'py/sql_injection')
            status: Current status text (e.g., 'Started', 'Analyzing', 'Fixed')
            session_id: Optional Devin session ID (fallback for URL construction)
            session_url: Optional Devin session URL from API (preferred)
            pr_url: Optional PR URL if a fix was created
        """
        display_status = self._format_status_with_emoji(status)

        if not self.enabled:
            print(f"[Sentinel Log] {batch_name}: {display_status}")
            return

        with self.lock:
            if batch_name in self.batch_info:
                info = self.batch_info[batch_name]
                info.status = display_status
                if session_id:
                    info.session_id = session_id
                if session_url:
                    info.session_url = session_url
                if pr_url:
                    info.pr_url = pr_url
            self._render_active_swarm()

    def _format_status_with_emoji(self, status: str) -> str:
        """
        Map status keywords to emojis for visual polish in Slack messages.
        
        Args:
            status: Raw status text to format.
            
        Returns:
            Status text prefixed with an appropriate emoji based on keywords.
        """
        if "Started" in status:
            return f"🚀 {status}"
        elif "Analyzing" in status:
            return f"🔍 {status}"
        elif "Fixed" in status or "PR" in status:
            return f"✅ {status}"
        elif "Error" in status or "Failed" in status:
            return f"❌ {status}"
        return status

    def _render_active_swarm(self) -> None:
        """
        Construct and transmit the Slack Block Kit structure for active runs.
        
        Builds a rich message showing all batches and their current status,
        with links to Devin sessions or PRs where available. This method is
        called after each status update to refresh the Slack message.
        """
        blocks = [
            {
                "type": "header", 
                "text": {"type": "plain_text", "text": "Security Sentinel: Active Swarm"}
            },
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"*Status:* Remediating {len(self.batch_info)} vulnerability batches..."}]
            },
            {"type": "divider"}
        ]
        
        for name, info in self.batch_info.items():
            status_text = info.status
            if info.pr_url:
                status_text += f" (<{info.pr_url}|View PR>)"
            elif info.session_url:
                status_text += f" (<{info.session_url}|View Session>)"
            elif info.session_id:
                devin_url = f"{DEVIN_SESSION_URL_BASE}/{info.session_id}"
                status_text += f" (<{devin_url}|View Session>)"
            
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Batch:* `{name}`\n*Status:* {status_text}"}
            })

        self._transmit(blocks)

    def finalize_report(self, results: "list[SessionResult] | None" = None) -> None:
        """
        Replaces the dashboard with a detailed summary once swarm finishes.
        
        Similar to print_summary(), this renders:
        - Batch statistics (total, successes, failures, etc.)
        - Alert statistics (fixed, unfixed)
        - Per-batch results with PR links or Devin session links
        
        Args:
            results: Optional list of SessionResult objects from the orchestrator.
                     If not provided, uses batch_info for a simpler summary.
        """
        if results:
            self._finalize_with_results(results)
        else:
            self._finalize_from_batch_info()

    def _finalize_with_results(self, results: "list[SessionResult]") -> None:
        """Render final summary using SessionResult objects."""
        from scripts.devin.DO_models import SessionStatus
        
        duration = int((time.time() - self.start_time) / 60)
        
        total = len(results)
        successes = sum(1 for r in results if r.status == SessionStatus.SUCCESS)
        failures = sum(1 for r in results if r.status == SessionStatus.FAILURE)
        partials = sum(1 for r in results if r.status == SessionStatus.PARTIAL)
        stuck = sum(1 for r in results if r.status == SessionStatus.STUCK)
        timeouts = sum(1 for r in results if r.status == SessionStatus.TIMEOUT)
        
        total_alerts = sum(len(r.alert_numbers) for r in results)
        fixed_alerts = sum(len(r.fixed_alerts) for r in results)
        unfixed_alerts = sum(len(r.unfixed_alerts) for r in results)
        
        hours_saved = successes * 2
        
        successful_results = [r for r in results if r.status == SessionStatus.SUCCESS]
        failed_results = [r for r in results if r.status in (
            SessionStatus.FAILURE, SessionStatus.PARTIAL, SessionStatus.STUCK, SessionStatus.TIMEOUT
        )]
        
        blocks = [
            {
                "type": "header", 
                "text": {"type": "plain_text", "text": "Mission Complete: Sentinel Summary"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Duration:* {duration} mins | *Manual Effort Saved:* ~{hours_saved} hrs"}
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*Batch Statistics*"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Total:* {total}"},
                    {"type": "mrkdwn", "text": f"*Successes:* {successes}"},
                    {"type": "mrkdwn", "text": f"*Failures:* {failures}"},
                    {"type": "mrkdwn", "text": f"*Partial:* {partials}"},
                    {"type": "mrkdwn", "text": f"*Stuck:* {stuck}"},
                    {"type": "mrkdwn", "text": f"*Timeouts:* {timeouts}"}
                ]
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*Alert Statistics*"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Total Alerts:* {total_alerts}"},
                    {"type": "mrkdwn", "text": f"*Fixed:* {fixed_alerts}"},
                    {"type": "mrkdwn", "text": f"*Unfixed:* {unfixed_alerts}"}
                ]
            }
        ]
        
        if successful_results:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*Successfully Fixed*"}
            })
            
            for r in successful_results:
                batch_id = r.batch_id
                if r.pr_url:
                    link_text = f"`{batch_id}` : <{r.pr_url}|View PR>"
                elif r.session_url:
                    link_text = f"`{batch_id}` : <{r.session_url}|View Devin Session>"
                elif r.session_id:
                    devin_url = f"{DEVIN_SESSION_URL_BASE}/{r.session_id}"
                    link_text = f"`{batch_id}` : <{devin_url}|View Devin Session>"
                else:
                    link_text = f"`{batch_id}` : No session available"
                
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": link_text}
                })
        
        if failed_results:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "header",
                "text": {"type": "plain_text", "text": "NEEDS HUMAN REVIEW", "emoji": True}
            })
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{len(failed_results)} batch(es) require manual review:*"}
            })
            
            for r in failed_results:
                batch_id = r.batch_id
                status_label = r.status.value.upper()
                if r.session_url:
                    link_text = f"`{batch_id}` [{status_label}] : <{r.session_url}|View Devin Session>"
                elif r.session_id:
                    devin_url = f"{DEVIN_SESSION_URL_BASE}/{r.session_id}"
                    link_text = f"`{batch_id}` [{status_label}] : <{devin_url}|View Devin Session>"
                else:
                    link_text = f"`{batch_id}` [{status_label}] : No session available"
                
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": link_text}
                })
        
        self._print_terminal_summary(results)
        
        if not self.enabled:
            return
        
        with self.lock:
            self._transmit(blocks)

    def _finalize_from_batch_info(self) -> None:
        """Render final summary using batch_info (fallback when no results provided)."""
        duration = int((time.time() - self.start_time) / 60)
        
        successful_batches = [(name, info) for name, info in self.batch_info.items() if info.pr_url]
        failed_batches = [(name, info) for name, info in self.batch_info.items() if not info.pr_url]
        
        successes = len(successful_batches)
        total = len(self.batch_info)
        hours_saved = successes * 2
        
        blocks = [
            {
                "type": "header", 
                "text": {"type": "plain_text", "text": "Mission Complete: Sentinel Summary"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Duration:* {duration} mins | *Manual Effort Saved:* ~{hours_saved} hrs"}
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Batches Processed:* {total}"},
                    {"type": "mrkdwn", "text": f"*Successes:* {successes}"},
                    {"type": "mrkdwn", "text": "*Agent:* Devin (Cognition AI)"}
                ]
            }
        ]
        
        if successful_batches:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*Successfully Fixed*"}
            })
            
            for name, info in successful_batches:
                link_text = f"`{name}` : <{info.pr_url}|View PR>"
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": link_text}
                })
        
        if failed_batches:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "header",
                "text": {"type": "plain_text", "text": "NEEDS HUMAN REVIEW", "emoji": True}
            })
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{len(failed_batches)} batch(es) require manual review:*"}
            })
            
            for name, info in failed_batches:
                if info.session_url:
                    link_text = f"`{name}` : <{info.session_url}|View Devin Session>"
                elif info.session_id:
                    devin_url = f"{DEVIN_SESSION_URL_BASE}/{info.session_id}"
                    link_text = f"`{name}` : <{devin_url}|View Devin Session>"
                else:
                    link_text = f"`{name}` : No session available"
                
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": link_text}
                })
        
        print("All batches processed. Sentinel Run Complete.")
        
        if not self.enabled:
            return
        
        with self.lock:
            self._transmit(blocks)

    def _print_terminal_summary(self, results: "list[SessionResult]") -> None:
        """
        Print a formatted summary to the terminal.
        
        This method mirrors the functionality of print_summary from DO_reporting,
        providing a consistent summary format regardless of whether Slack is enabled.
        
        Args:
            results: List of SessionResult objects from the orchestrator run.
        """
        from scripts.devin.DO_models import SessionStatus
        
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
        print("           SENTINEL RUN SUMMARY (Slack Dashboard)")
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
            if r.pr_url:
                print(f"       PR: {r.pr_url}")
            elif r.session_url:
                print(f"       Devin: {r.session_url}")
            elif r.session_id:
                print(f"       Devin: {DEVIN_SESSION_URL_BASE}/{r.session_id}")
        
        print("\n" + "=" * 60)

    def _transmit(self, blocks: list) -> None:
        """
        Handle the actual Slack API calls for posting or updating messages.
        
        Posts a new message if this is the first transmission, or updates the
        existing message using the stored timestamp. Disables the dashboard
        on API errors to prevent log spam.
        
        Args:
            blocks: List of Slack Block Kit block objects to send.
        """
        try:
            if not self.msg_ts:
                response = self.client.chat_postMessage(channel=self.channel, blocks=blocks)
                self.msg_ts = response['ts']
            else:
                self.client.chat_update(channel=self.channel, ts=self.msg_ts, blocks=blocks)
        except SlackApiError as e:
            print(f"Slack API Error: {e.response['error']}")
            self.enabled = False # Disable UI to prevent log spam if token/channel fails
