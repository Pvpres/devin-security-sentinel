from scripts.github_client import GitHubClient
from scripts.parse_sarif import run_state_aware_parse
from scripts.devin_orchestrator import run_orchestrator
import time
import sys
import os



def main():
    if len(sys.argv) < 3:
        print("Usage: python devin_orchestrator.py <owner> <repo> [<branch>]")
        print("\nThis script requires the following environment variables:")
        print("  GH_TOKEN - GitHub Personal Access Token")
        print("  DEVIN_API_KEY - Devin AI API Key")
        sys.exit(1)
    
    owner = sys.argv[1] #required
    repo = sys.argv[2] #required
    if len(sys.argv) > 3:
        branch = sys.argv[3] or None

    GH_TOKEN = os.getenv("GH_TOKEN")
    DEVIN_API_KEY = os.getenv("DEVIN_API_KEY")
    
    if not GH_TOKEN:
        print("::error::Missing GH_TOKEN environment variable")
        sys.exit(1)
    
    if not DEVIN_API_KEY:
        print("::error::Missing DEVIN_API_KEY environment variable")
        sys.exit(1)
    
    start = time.time()
    
    client = GitHubClient(owner, repo, branch=branch)
    alerts = client.get_active_alerts()
    
    if not alerts:
        print("No active unassigned alerts found.")
        sys.exit(0)
    print(f"Found {len(alerts)} active alerts")
    
    sarif_data = client.get_sarif_data()
    if not sarif_data:
        print("Failed to fetch SARIF data.")
        sys.exit(1)
    
    batches = run_state_aware_parse(sarif_data, alerts)
    if not batches:
        print("No remediation batches created.")
        sys.exit(0)
    
    print(f"Created {len(batches)} remediation batches")
    run_orchestrator(batches, owner=owner, repo=repo, max_workers=4)
    end = time.time()
    print(f"Total execution time: {end - start:.2f} seconds")
    

if __name__ == "__main__":
    sys.exit(main())