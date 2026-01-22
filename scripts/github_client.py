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

    def _get_latest_analysis_ids_by_category(self) -> dict[str, int]:
        """
        Fetches the latest analysis ID for each language/tool category.

        GitHub Code Scanning creates separate analyses for different languages
        (e.g., JavaScript, Python). This method returns the most recent analysis
        ID for each category to ensure complete SARIF coverage across all languages.

        Returns:
            dict[str, int]: A dictionary mapping category strings to analysis IDs.
                           Empty dict if no analyses are found.

        Example:
            {
                "/language:javascript-typescript": 914193227,
                "/language:python": 914192873
            }
        """
        headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {self.token}"}
        params = {"ref": self.branch, "per_page": 100}
        response = requests.get(self.analyses_url, headers=headers, params=params)
        if response.status_code == 200:
            analyses = response.json()
            if not analyses:
                print("No analyses found.")
                return {}

            latest_by_category: dict[str, int] = {}
            for analysis in analyses:
                category = analysis.get("category", "")
                analysis_id = analysis.get("id")
                if category and analysis_id and category not in latest_by_category:
                    latest_by_category[category] = analysis_id

            return latest_by_category
        else:
            print(f"Failed to fetch analyses: {response.status_code}")
            return {}
    
    def get_sarif_data(self) -> dict:
        """
        Fetches and merges SARIF data from all language analyses.

        GitHub Code Scanning creates separate analyses for different languages.
        This method fetches SARIF from each language's latest analysis and merges
        them into a single SARIF structure with combined runs.

        Returns:
            dict: A merged SARIF dictionary containing runs from all language analyses.
                  Returns empty dict if no analyses are found.

        Example:
            The returned SARIF will have a 'runs' array containing results from
            all languages (e.g., both JavaScript and Python vulnerabilities).
        """
        analysis_ids_by_category = self._get_latest_analysis_ids_by_category()
        if not analysis_ids_by_category:
            return {}

        headers = {"Accept": "application/sarif+json", "Authorization": f"Bearer {self.token}"}
        merged_sarif: dict = {"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", "version": "2.1.0", "runs": []}

        for category, analysis_id in analysis_ids_by_category.items():
            sarif_url = f"{self.analyses_url}/{analysis_id}"
            response = requests.get(sarif_url, headers=headers)
            if response.status_code == 200:
                sarif_data = response.json()
                runs = sarif_data.get("runs", [])
                merged_sarif["runs"].extend(runs)
            else:
                print(f"Failed to fetch SARIF data for category {category}: {response.status_code}")

        return merged_sarif if merged_sarif["runs"] else {}
    
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
        