# Sample Workflows

This directory contains example GitHub Actions workflow files for integrating Devin Security Sentinel into your CI/CD pipeline. Each sample demonstrates a different configuration approach.

## Quick Start

1. Choose the sample workflow that best fits your needs
2. Copy it to your repository's `.github/workflows/` directory
3. Add the required secrets to your repository (Settings > Secrets > Actions):
   - `DEVIN_API_KEY` (required): Your Devin AI API key
   - `SLACK_BOT_TOKEN` (optional): Slack Bot OAuth Token for notifications
   - `SLACK_CHANNEL_ID` (optional): Target Slack channel for updates

## Sample Workflows

### sample_default_workflow.yml

The recommended starting point for most users. This workflow includes:
- CodeQL security scanning
- Devin AI remediation
- Slack integration (optional)
- Comprehensive comments explaining each section

Use this when you want a complete, well-documented workflow that you can customize.

### sample_one_devin_job.yml

A minimal single-job workflow that runs CodeQL and Devin remediation sequentially in one job.

Use this when you want:
- The simplest possible setup
- Minimal configuration
- All steps in a single job for easier debugging

### sample_two_seperate_jobs.yml

A two-job workflow that separates CodeQL scanning from Devin remediation.

Use this when you want:
- Separate job status visibility in GitHub Actions UI
- Clearer separation of concerns
- The ability to run other jobs in parallel with CodeQL
- More granular control over job permissions

## Use Cases

### Basic Security Remediation

For repositories that want automated security fixes on every push to main:

```yaml
on:
  push:
    branches:
      - main
```

Use `sample_one_devin_job.yml` for the simplest setup.

### Scheduled Security Audits

For repositories that want periodic security scans without blocking development:

```yaml
on:
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight UTC
```

Add this trigger to any of the sample workflows.

### Manual Security Reviews

For repositories that want on-demand security remediation:

```yaml
on:
  workflow_dispatch:
```

All sample workflows include this trigger by default.

### Multi-Language Projects

For repositories with multiple programming languages:

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v3
  with:
    languages: python, javascript, typescript
```

Modify the `languages` field in any sample workflow.

### Slack Notifications

For teams that want real-time progress updates in Slack:

1. Create a Slack App with Bot Token Scopes: `chat:write`, `chat:update`
2. Install the app to your workspace
3. Add `SLACK_BOT_TOKEN` and `SLACK_CHANNEL_ID` to repository secrets
4. The sample workflows already include Slack configuration

## Configuration Reference

### Required Inputs

| Input | Description |
|-------|-------------|
| `owner` | Repository owner (use `${{ github.repository_owner }}`) |
| `repo` | Repository name (use `${{ github.event.repository.name }}`) |
| `github_token` | GitHub token with `security_events` scope |
| `devin_api_key` | Devin AI API key |

### Optional Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `branch` | Branch to analyze | Triggered branch |
| `slack_bot_token` | Slack Bot OAuth Token | None |
| `slack_channel_id` | Slack channel ID | None |

### Outputs

| Output | Description |
|--------|-------------|
| `alerts_found` | Number of active alerts found |
| `batches_created` | Number of remediation batches created |
| `status` | Execution status (success, no_alerts, failed) |

## Troubleshooting

### No alerts found

If the action reports no alerts:
1. Verify CodeQL is configured for your repository's languages
2. Check the GitHub Security tab for existing alerts
3. Ensure the branch parameter matches the scanned branch

### Authentication errors

If you see authentication errors:
1. Verify `DEVIN_API_KEY` is set correctly in repository secrets
2. For private repositories, use a PAT with `security_events` scope instead of `GITHUB_TOKEN`

### Slack notifications not working

If Slack updates aren't appearing:
1. Verify the bot token has `chat:write` and `chat:update` scopes
2. Ensure the bot is invited to the target channel
3. Check that `SLACK_CHANNEL_ID` is the channel ID (not the channel name)
