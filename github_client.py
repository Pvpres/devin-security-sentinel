import os
import requests

class GitHubClient:
    def __init__(self, owner: str, repo: str, token: str = None):
        self.token = token or os.getenv("GH_TOKEN")
        self.owner = owner
        self.repo = repo
        self.codescan_url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts"

    # def get_repo_contents(self, owner: str, repo: str, path: str = ""):
    #     url = f"{self.base_url}/repos/{owner}/{repo}/contents/{path}"
    #     headers = {
    #         "Authorization": f"Bearer {self.token}",
    #         "Accept": "application/vnd.github.v3+json"
    #     }
    #     response = requests.get(url, headers=headers)
    #     response.raise_for_status()
    #     return response.json()

    def get_active_code_scanning_alerts(self) -> dict:
        headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {self.token}"}
        params = {"state": "open"}

        response = requests.get(self.codescan_url, headers=headers, params=params)

        if response.status_code == 200:
            return response.json()
        else:
            print(f"Failed to fetch code scanning alerts: {response.status_code}")
            return {}
        
    
    # def enable_default_scanning(self, repo_slug):
    #     # repo_slug example: "pvpres/new-target-repo"
    #     url = f"https://api.github.com/repos/{repo_slug}/code-scanning/default-setup"
    #     headers = {
    #         "Authorization": f"token {self.token}",
    #         "Accept": "application/vnd.github+json"
    #     }
    #     # State 'labeled' tells GitHub to start the default configuration
    #     data = {"state": "labeled"} 
    
    #     response = requests.patch(url, headers=headers, json=data)
    #     return response.status_code == 200