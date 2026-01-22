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
    """Stores tracking information for each batch."""
    status: str
    session_id: str | None = None
    pr_url: str | None = None


class SentinelDashboard:
    def __init__(self, batch_names: list[str], channel_id: str | None = None):
        self.lock = threading.Lock()
        self.msg_ts: str | None = None
        self.start_time = time.time()
        
        self.batch_info: dict[str, BatchInfo] = {
            name: BatchInfo(status="In Queue") for name in batch_names
        }
        
        # 1. Credential Detection
        token = os.getenv("SLACK_BOT_TOKEN")
        self.channel = channel_id or os.getenv("SLACK_CHANNEL_ID")
        
        if not token or not self.channel:
            print("Slack credentials missing. Dashboard is disabled (Terminal Fallback Active).")
            self.enabled = False
            return

        # 2. Client Initialization
        try:
            self.client = WebClient(token=token)
            self.enabled = True
            self._ensure_access()
        except Exception as e:
            print(f"⚠️ Slack Initialization failed: {e}")
            self.enabled = False

    def _ensure_access(self):
        """Attempts to join the channel to ensure posting permissions."""
        if not self.enabled: return
        try:
            self.client.conversations_join(channel=self.channel)
        except SlackApiError as e:
            print(f"⚠️ Slack join warning: {e.response['error']}")

    def update(
        self,
        batch_name: str,
        status: str,
        session_id: str | None = None,
        pr_url: str | None = None
    ) -> None:
        """
        Thread-safe update method called by worker threads.
        
        Args:
            batch_name: The batch identifier (e.g., 'py/sql_injection')
            status: Current status text (e.g., 'Started', 'Analyzing', 'Fixed')
            session_id: Optional Devin session ID for building session URLs
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
                if pr_url:
                    info.pr_url = pr_url
            self._render_active_swarm()

    def _format_status_with_emoji(self, status: str) -> str:
        """Map status keywords to emojis for visual polish."""
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
        """Constructs the JSON Block Kit structure for active runs."""
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
                if r.session_id:
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
                if info.session_id:
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
        """Print summary to terminal (mirrors print_summary from DO_reporting)."""
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
            elif r.session_id:
                print(f"       Devin: {DEVIN_SESSION_URL_BASE}/{r.session_id}")
        
        print("\n" + "=" * 60)

    def _transmit(self, blocks):
        """Handles the actual Slack API calls for post/update."""
        try:
            if not self.msg_ts:
                response = self.client.chat_postMessage(channel=self.channel, blocks=blocks)
                self.msg_ts = response['ts']
            else:
                self.client.chat_update(channel=self.channel, ts=self.msg_ts, blocks=blocks)
        except SlackApiError as e:
            print(f"Slack API Error: {e.response['error']}")
            self.enabled = False # Disable UI to prevent log spam if token/channel fails
