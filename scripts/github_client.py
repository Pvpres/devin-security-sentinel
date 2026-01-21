import os
import requests


#add functionality in alerts later so user can edit yaml file if thet only want
#alerts of a certain file, only critical issues, etc
class GitHubClient:
    def __init__(self, owner: str, repo: str, token: str = None, branch: str = None):
        """
        Initialize the GitHub client with the given owner and repository.

        Args:
            owner (str): The owner of the repository.
            repo (str): The name of the repository.
            token (str, optional): The GitHub personal access token. Defaults to None.
        """
        self._token = token
        self.owner = owner
        self.repo = repo
        self.codescan_url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts"
        self.analyses_url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/analyses"
        self.branch = branch if branch is not None else self._get_default_branch()

    @property
    def token(self) -> str:
        """Fetch token on-demand to avoid storing it longer than necessary."""
        token_value = self._token or os.getenv("GH_TOKEN")
        if not token_value:
            raise ValueError("GH_TOKEN environment variable is not set and no token was provided")
        return token_value

    #add severity filer later
    def get_active_alerts(self, severity: list[str] = None) -> dict:
        """
        Fetch all active code scanning alerts for the given repository.

        Args:
            severity (list[str], optional): List of severity levels to filter by. Defaults to None.

        Returns:
            dict: A dictionary containing the active code scanning alerts.
        """
        headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {self.token}"}
        #only get alerts not already assigned to someone in the organization
        
        params = {"state": "open", "assignees" : "none", "ref": self.branch, "per_page": 100}

        response = requests.get(self.codescan_url, headers=headers, params=params)
        if response.status_code == 200:
            alerts = response.json()
            # if severity:
            #     sev_set = set(s.lower() for s in severity)
            #     alerts = [a for a in alerts if a.get("rule", {}).get("security_severity_level", "") in sev_set]
            return alerts
        else:
            print(f"Failed to fetch code scanning alerts: {response.status_code}")
            return {}

    def _get_latest_analysis_id(self) -> dict:
        """
        Fetches the analysis ID for the given repository owner and name.

        Returns an empty dictionary if no active alerts are found.

        :return: A dictionary containing the analysis ID.
        :rtype: dict
        """
        
        headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {self.token}"}
        params = {"ref": self.branch, "per_page": 1}
        response = requests.get(self.analyses_url, headers=headers, params=params)
        if response.status_code == 200:
            analyses = response.json()
            if analyses:
                #the most recent analysis is the first in the list
                return analyses[0].get("id", "")
            else:
                print("No analyses found.")
                return {}
        else:
            print(f"Failed to fetch analyses: {response.status_code}")
            return {}
    
    def get_sarif_data(self) -> dict:
        """
        Fetches the SARIF data for the given repository owner and name.

        Returns an empty dictionary if no active alerts are found.

        :return: A dictionary containing the SARIF data.
        :rtype: dict
        """
        id = self._get_latest_analysis_id()
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
    
    def _get_default_branch(self) -> str:
        """
        Fetch the default branch of the repository.

        Returns:
            str: The name of the default branch.
        """
        url = f"https://api.github.com/repos/{self.owner}/{self.repo}"
        headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {self.token}"}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json().get("default_branch")
        else:
            print(f"Failed to fetch repository info: {response.status_code}")
            raise ValueError("Could not determine default branch")
        