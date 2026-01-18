import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from github_client import GitHubClient
from dotenv import load_dotenv

load_dotenv()

client = GitHubClient('pvpres', 'small_scale_security_tests', token=os.getenv("GH_TEST_TOKEN"))
alerts = client.get_active_code_scanning_alerts()
print("Alerts:", alerts)
print("Keys", alerts[0].keys())