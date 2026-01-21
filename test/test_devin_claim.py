import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'scripts'))

from github_client import GitHubClient
from devin_orchestrator import claim_github_alerts, unclaim_github_alerts
from dotenv import load_dotenv
import time

load_dotenv()


client = GitHubClient('pvpres', 'small_scale_security_tests', token=os.getenv("GH_TOKEN"))
alerts = client.get_active_alerts()
print("Alerts:", alerts)

response = claim_github_alerts('pvpres', 'small_scale_security_tests', [1,2])
print("Claim response:", response)

time.sleep(30)

alerts_after_claim = client.get_active_alerts()
print("Alerts after claim attempt:", alerts_after_claim)

unclaim_response = unclaim_github_alerts('pvpres', 'small_scale_security_tests', [1,2])
print("Unclaim response:", unclaim_response)
alerts_after_unclaim = client.get_active_alerts()



