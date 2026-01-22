"""
Integration Test for GitHubClient.

This script tests the GitHubClient class against a real GitHub repository.
It verifies that alerts can be fetched and analysis IDs can be retrieved.

Environment Variables:
    GH_TOKEN: GitHub Personal Access Token with security_events scope.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'scripts'))

from github_client import GitHubClient
from dotenv import load_dotenv

load_dotenv()

print(os.getenv("GH_TOKEN"))
client = GitHubClient('pvpres', 'purposeful_errors', token=os.getenv("GH_TOKEN"))
alerts = client.get_active_alerts()
print("Alerts:", alerts)
print("Keys", alerts[0].keys())


print("Analysis IDs by category:", client._get_latest_analysis_ids_by_category())
