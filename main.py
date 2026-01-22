from scripts.github_client import GitHubClient
from scripts.parse_sarif import run_state_aware_parse
from scripts.devin_orchestrator import run_orchestrator
import time
import sys
import os


def write_github_output(name: str, value: str) -> None:
    """Write output to GitHub Actions output file if running in CI."""
    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"{name}={value}\n")



def main():
    if len(sys.argv) < 3:
        print("Usage: python main.py <owner> <repo> [<branch>] [<slack_channel_id>]")
        print("\nThis script requires the following environment variables:")
        print("  GH_TOKEN - GitHub Personal Access Token")
        print("  DEVIN_API_KEY - Devin AI API Key")
        print("\nOptional environment variables for Slack integration:")
        print("  SLACK_BOT_TOKEN - Slack Bot OAuth Token")
        print("  SLACK_CHANNEL_ID - Slack Channel ID (can also be passed as 4th argument)")
        sys.exit(1)
    
    owner = sys.argv[1] #required
    repo = sys.argv[2] #required
    branch = None
    if len(sys.argv) > 3:
        branch = sys.argv[3] or None
    
    slack_channel_id = None
    if len(sys.argv) > 4:
        slack_channel_id = sys.argv[4] or None

    GH_TOKEN = os.getenv("GH_TOKEN")
    DEVIN_API_KEY = os.getenv("DEVIN_API_KEY")
    SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
    SLACK_CHANNEL_ID = slack_channel_id or os.getenv("SLACK_CHANNEL_ID")
    
    if not GH_TOKEN:
        print("::error::Missing GH_TOKEN environment variable")
        sys.exit(1)
    
    if not DEVIN_API_KEY:
        print("::error::Missing DEVIN_API_KEY environment variable")
        sys.exit(1)
    
    if SLACK_BOT_TOKEN and SLACK_CHANNEL_ID:
        print("Slack integration enabled - dashboard updates will be sent to Slack")
    else:
        print("Slack integration disabled - using terminal output only")
    
    start = time.time()
    
    client = GitHubClient(owner, repo, branch=branch)
    alerts = client.get_active_alerts()
    
    if not alerts:
        print("No active unassigned alerts found.")
        write_github_output("alerts_found", "0")
        write_github_output("batches_created", "0")
        write_github_output("status", "no_alerts")
        sys.exit(0)
    print(f"Found {len(alerts)} active alerts")
    write_github_output("alerts_found", str(len(alerts)))
    
    sarif_data = client.get_sarif_data()
    if not sarif_data:
        print("Failed to fetch SARIF data.")
        write_github_output("batches_created", "0")
        write_github_output("status", "failed")
        sys.exit(1)
    
    batches = run_state_aware_parse(sarif_data, alerts)
    if not batches:
        print("No remediation batches created.")
        write_github_output("batches_created", "0")
        write_github_output("status", "no_alerts")
        sys.exit(0)
    
    print(f"Created {len(batches)} remediation batches")
    write_github_output("batches_created", str(len(batches)))
    run_orchestrator(batches, owner=owner, repo=repo, max_workers=4, slack_channel_id=SLACK_CHANNEL_ID)
    end = time.time()
    print(f"Total execution time: {end - start:.2f} seconds")
    write_github_output("status", "success")
    

if __name__ == "__main__":
    sys.exit(main())
