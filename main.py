from scripts.github_client import GitHubClient
from scripts.parse_sarif import run_state_aware_parse
from scripts.devin_orchestrator import run_orchestrator
import time



def main(owner:str, repo:str, branch:str = None, max_workers:int = 3):
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
    run_orchestrator(batches, owner=owner, repo=repo, max_workers=max_workers)
    end = time.time()
    print(f"Total execution time: {end - start:.2f} seconds")
    

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python devin_orchestrator.py <owner> <repo>")
        print("\nThis script requires the following environment variables:")
        print("  GH_TOKEN - GitHub Personal Access Token")
        print("  DEVIN_API_KEY - Devin AI API Key")
        sys.exit(1)
    
    from dotenv import load_dotenv
    load_dotenv()
    
    target_owner = sys.argv[1]
    target_repo = sys.argv[2]
    
    branch = None
    if len(sys.argv) == 4:
        branch = sys.argv[3]
    
    max_workers = 3
    if len(sys.argv) == 5:
        max_workers = int(sys.argv[4])
        
    main(target_owner, target_repo, branch=branch, max_workers=max_workers)