# devin-security-sentinel

Automated security vulnerability remediation system that bridges GitHub's code scanning capabilities with AI-powered fix generation via Devin AI.

## Usage

Add this action to your workflow to automatically remediate security vulnerabilities detected by CodeQL:

```yaml
- name: Run Devin Security Sentinel
  uses: Pvpres/devin-security-sentinel@v1
  with:
    owner: ${{ github.repository_owner }}
    repo: ${{ github.event.repository.name }}
    branch: ${{ github.ref_name }}
    github_token: ${{ secrets.GH_PAT }}
    devin_api_key: ${{ secrets.DEVIN_API_KEY }}
```

See `samples/sample.yml` for a complete workflow example.

## Required Permissions

The GitHub token must have the following permissions:
- `security-events: read` - Required to fetch CodeQL alerts and SARIF data
- `contents: read` - Required to access repository information

For classic Personal Access Tokens (PAT), enable the `repo` scope.

## Inputs

| Input | Required | Description |
|-------|----------|-------------|
| `owner` | Yes | Repository owner |
| `repo` | Yes | Repository name |
| `branch` | No | Branch to analyze (defaults to repository default branch) |
| `github_token` | Yes | GitHub Personal Access Token with security-events read permission |
| `devin_api_key` | Yes | Devin AI API key |

## Outputs

| Output | Description |
|--------|-------------|
| `alerts_found` | Number of active alerts found |
| `batches_created` | Number of remediation batches created |
| `status` | Execution status: `success`, `no_alerts`, or `failed` |

## How It Works

1. Fetches active, unassigned CodeQL security alerts from the target repository
2. Retrieves SARIF data from the latest CodeQL analysis
3. Filters high-severity vulnerabilities (severity >= 7.0)
4. Groups vulnerabilities by rule type into remediation batches
5. Dispatches batches to Devin AI for automated fix generation
