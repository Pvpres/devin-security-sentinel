"""Configuration constants for Security Sentinel Orchestrator."""

import os

# Devin AI API Configuration
DEVIN_API_BASE = "https://api.devin.ai/v1"

# GitHub API Configuration  
GITHUB_API_BASE = "https://api.github.com"

# Session Polling Configuration
POLL_INTERVAL_SECONDS = 150
SESSION_TIMEOUT_SECONDS = 15 * 60  # 15 minutes
STAGNATION_THRESHOLD_SECONDS = 5 * 60  # 5 minutes

# Batch Processing Configuration
MAX_WORKERS_DEFAULT = 4

# Alert Claiming Configuration
CLAIM_RETRY_ATTEMPTS = 3
CLAIM_RETRY_DELAY_SECONDS = 2

# Active Session Management
MAX_ACTIVE_SESSIONS = 5

#Active sessions allowed by api
MAX_ACTIVE_SESSIONS = 5


def get_devin_api_key() -> str:
    """Get Devin API key from environment variable."""
    key = os.getenv("DEVIN_API_KEY")
    if not key:
        raise ValueError("DEVIN_API_KEY environment variable is not set")
    return key

def get_github_token() -> str:
    token = os.getenv("GH_TOKEN")
    if not token:
        raise ValueError("GH_TOKEN environment variable is not set")
    return token
