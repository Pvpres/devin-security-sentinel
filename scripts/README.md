# Scripts Directory

This directory contains the core modules for the Security Sentinel system. These modules handle GitHub API integration, SARIF data processing, Slack notifications, and orchestration logic.

## Module Overview

### github_client.py

The GitHub Code Scanning API client for fetching security alerts and SARIF analysis data. This module provides the `GitHubClient` class which handles authentication, pagination, and multi-language analysis merging.

Key functionality:
- Fetch active (open, unassigned) security alerts from a repository
- Retrieve SARIF analysis data filtered by branch reference
- Support for multiple CodeQL language analyses (Python, JavaScript, etc.)
- Automatic pagination for repositories with many alerts

Environment variables:
- `GH_TOKEN`: GitHub Personal Access Token with `security_events` read permission

### parse_sarif.py

SARIF (Static Analysis Results Interchange Format) processing engine. This module transforms verbose SARIF v2.1.0 reports into optimized formats for LLM consumption.

Key functionality:
- Minify SARIF data by extracting only essential fields (ruleId, severity, locations)
- Filter vulnerabilities by severity threshold (default: 7.0+)
- Group vulnerabilities by rule ID for batch processing
- Extract code flow endpoints (source/sink) for path-problem queries

### slack_client.py

Real-time Slack dashboard for monitoring remediation progress. This module provides the `SentinelDashboard` class which displays batch status, session updates, and final summary reports.

Key functionality:
- Live-updating Slack messages using Block Kit formatting
- Batch progress tracking with status emojis
- Final summary reports with statistics and PR links
- Graceful fallback to terminal output when Slack is not configured

Environment variables:
- `SLACK_BOT_TOKEN`: Slack Bot OAuth Token for API authentication
- `SLACK_CHANNEL_ID`: Target Slack channel ID for posting updates

### termination_logic.py

Session termination and sleep message handling. This module provides utilities for gracefully terminating Devin sessions and sending sleep/wake messages.

### devin_orchestrator.py

Main orchestration logic that coordinates the remediation workflow. This module ties together all other components to process batches and manage Devin sessions.

## Subdirectory

### devin/

Contains the Devin AI integration modules. See [devin/README.md](devin/README.md) for details on the orchestrator components including session management, batch processing, and outcome handling.
