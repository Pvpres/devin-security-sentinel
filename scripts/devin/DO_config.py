"""
Configuration Constants for Security Sentinel Orchestrator.

This module centralizes all configuration constants used throughout the
Security Sentinel system. It includes API endpoints, timing parameters,
and helper functions for retrieving secrets from environment variables.

Configuration Categories:
    API Endpoints: Base URLs for Devin AI and GitHub APIs.
    Session Polling: Timing parameters for monitoring Devin sessions.
    Batch Processing: Concurrency limits for parallel remediation.
    Alert Claiming: Retry logic for GitHub alert assignment.
    Session Management: Limits on concurrent active sessions.

Environment Variables:
    DEVIN_API_KEY: API key for Devin AI authentication.
    GH_TOKEN: GitHub Personal Access Token with security_events scope.
"""

import os

# Devin AI API Configuration
DEVIN_API_BASE = "https://api.devin.ai/v1"

# GitHub API Configuration  
GITHUB_API_BASE = "https://api.github.com"

# Session Polling Configuration
POLL_INTERVAL_SECONDS = 150  # Time between status checks
SESSION_TIMEOUT_SECONDS = 15 * 60  # 15 minutes max wait time
STAGNATION_THRESHOLD_SECONDS = 5 * 60  # 5 minutes without activity = stuck

# Batch Processing Configuration
MAX_WORKERS_DEFAULT = 4  # Maximum concurrent worker threads

# Alert Claiming Configuration
CLAIM_RETRY_ATTEMPTS = 3  # Number of retries for failed claims
CLAIM_RETRY_DELAY_SECONDS = 2  # Base delay between retries (exponential backoff)

# Active Session Management
MAX_ACTIVE_SESSIONS = 5  # Maximum concurrent Devin sessions allowed by API


def get_devin_api_key() -> str:
    """
    Retrieve the Devin API key from environment variables.
    
    Returns:
        The DEVIN_API_KEY environment variable value.
        
    Raises:
        ValueError: If DEVIN_API_KEY is not set.
    """
    key = os.getenv("DEVIN_API_KEY")
    if not key:
        raise ValueError("DEVIN_API_KEY environment variable is not set")
    return key


def get_github_token() -> str:
    """
    Retrieve the GitHub token from environment variables.
    
    Returns:
        The GH_TOKEN environment variable value.
        
    Raises:
        ValueError: If GH_TOKEN is not set.
    """
    token = os.getenv("GH_TOKEN")
    if not token:
        raise ValueError("GH_TOKEN environment variable is not set")
    return token
