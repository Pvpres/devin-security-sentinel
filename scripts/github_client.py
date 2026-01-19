import os
import requests


#add functionality in alerts later so user can edit yaml file if thet only want
#alerts of a certain file, only critical issues, etc
class GitHubClient:
    def __init__(self, owner: str, repo: str, token: str = None):
        self._token = token
        self.owner = owner
        self.repo = repo
        self.codescan_url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts"
        self.analyses_url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/analyses"

    @property
    def token(self) -> str:
        """Fetch token on-demand to avoid storing it longer than necessary."""
        return self._token or os.getenv("GH_TOKEN")

    # def get_repo_contents(self, owner: str, repo: str, path: str = ""):
    #     url = f"{self.base_url}/repos/{owner}/{repo}/contents/{path}"
    #     headers = {
    #         "Authorization": f"Bearer {self.token}",
    #         "Accept": "application/vnd.github.v3+json"
    #     }
    #     response = requests.get(url, headers=headers)
    #     response.raise_for_status()
    #     return response.json()

    def get_active_alerts(self) -> dict:
        headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {self.token}"}
        params = {"state": "open"}

        response = requests.get(self.codescan_url, headers=headers, params=params)

        if response.status_code == 200:
            return response.json()
        else:
            print(f"Failed to fetch code scanning alerts: {response.status_code}")
            return {}

    def get_latest_analysis(self) -> dict:
        """
        Fetches the analysis ID for the given repository owner and name.

        Returns an empty dictionary if no active alerts are found.

        :return: A dictionary containing the analysis ID.
        :rtype: dict
        """
        
        headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {self.token}"}

        response = requests.get(self.analyses_url, headers=headers)

        if response.status_code == 200:
            analyses = response.json()
            
            if analyses:
                print("Analyses found:", analyses)
                #the most recent analysis is the first in the list
                return analyses[0]
            else:
                print("No analyses found.")
                return {}
        else:
            print(f"Failed to fetch analyses: {response.status_code}")
            return {}
    
    def get_sarif_data(self) -> dict:
        analysis = self.get_latest_analysis()
        if not analysis:
            return {}
        
        id = analysis.get("id", "")
        if not id:
            return {}
        sarif_url = f"{self.analyses_url}/{id}"
        headers = {"Accept": "application/sarif+json", "Authorization": f"Bearer {self.token}"}
        response = requests.get(sarif_url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Failed to fetch SARIF data: {response.status_code}")
            return {}
        