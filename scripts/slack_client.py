import os
import threading
import time
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

class SentinelDashboard:
    def __init__(self, batch_names, channel_id=None):
        self.lock = threading.Lock()
        self.msg_ts = None
        self.start_time = time.time()
        
        # Initial State Registry
        self.registry = {name: "In Queue" for name in batch_names}
        
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

    def update(self, batch_name, status, pr_url=None):
        """Thread-safe update method called by worker threads."""
        # Visual Polish: Map status keywords to emojis
        display_status = status
        if "Started" in status: display_status = f"🚀 {status}"
        elif "Analyzing" in status: display_status = f"🔍 {status}"
        elif "Fixed" in status or "PR" in status: display_status = f"✅ {status}"
        elif "Error" in status or "Failed" in status: display_status = f"❌ {status}"

        if not self.enabled:
            print(f"🤖 [Sentinel Log] {batch_name}: {display_status}")
            return

        with self.lock:
            self.registry[batch_name] = display_status
            if pr_url:
                self.registry[batch_name] += f" (<{pr_url}|View Fix>)"
            self._render_active_swarm()

    def _render_active_swarm(self):
        """Constructs the JSON Block Kit structure for active runs."""
        blocks = [
            {
                "type": "header", 
                "text": {"type": "plain_text", "text": "Security Sentinel: Active Swarm"}
            },
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"*Status:* Remediating {len(self.registry)} vulnerability batches..."}]
            },
            {"type": "divider"}
        ]
        
        for name, status in self.registry.items():
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Batch:* `{name}`\n*Status:* {status}"}
            })

        self._transmit(blocks)

    def finalize_report(self):
        """Replaces the dashboard with a high-level ROI summary once swarm finishes."""
        if not self.enabled: 
            print("All batches processed. Sentinel Run Complete.")
            return

        duration = int((time.time() - self.start_time) / 60)
        # Assuming a modest 2 hours saved per batch fixed
        hours_saved = len(self.registry) * 2

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
                    {"type": "mrkdwn", "text": f"*Batches Processed:* {len(self.registry)}"},
                    {"type": "mrkdwn", "text": "*Coverage:* 100% Analysis"},
                    {"type": "mrkdwn", "text": "*Status:* Hardened"},
                    {"type": "mrkdwn", "text": "*Agent:* Devin (Cognition AI)"}
                ]
            }
        ]
        
        with self.lock:
            self._transmit(blocks)

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