import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'scripts'))
from dotenv import load_dotenv
from github_client import GitHubClient
import requests
load_dotenv()

client = GitHubClient('pvpres', 'small_scale_security_tests', token=os.getenv("GH_TOKEN"))
url = f"https://api.github.com/repos/{client.owner}/{client.repo}"
headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {os.getenv('GH_TOKEN')}"}
response = requests.get(url, headers=headers)
default_branch = response.json()["default_branch"]
print("Default branch:", default_branch)



obj = client.get_active_alerts()
print(len(obj))

data = client._get_latest_analysis_ids_by_category()
print("Latest analysis IDs by category:", data)

# client.get_active_alerts(branch=default_branch)
# print(client.get_active_alerts(branch="non_existent_branch"))


