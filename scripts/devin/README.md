# Devin Orchestrator Modules

This directory contains the Devin AI integration modules for the Security Sentinel system. These modules handle session management, batch processing, prompt generation, and outcome reconciliation.

## Module Overview

### DO_config.py

Configuration constants and environment variable helpers. Centralizes all timing parameters, API endpoints, and concurrency limits used throughout the orchestrator.

Key constants:
- `DEVIN_API_BASE`: Devin AI API endpoint
- `POLL_INTERVAL_SECONDS`: Time between session status checks (150s)
- `SESSION_TIMEOUT_SECONDS`: Maximum session wait time (15 minutes)
- `MAX_ACTIVE_SESSIONS`: Concurrent session limit (5)
- `MAX_WORKERS_DEFAULT`: Thread pool size (4)

Environment variables:
- `DEVIN_API_KEY`: API key for Devin AI authentication
- `GH_TOKEN`: GitHub Personal Access Token

### DO_models.py

Data structures for tracking session states and results. Defines the core types used throughout the orchestrator.

Key classes:
- `SessionStatus`: Enum of possible session states (SUCCESS, FAILURE, PARTIAL, STUCK, TIMEOUT, PENDING, RUNNING)
- `SessionResult`: Dataclass containing session outcome details (status, alerts, PR URL, etc.)
- `OrchestratorState`: Thread-safe container for tracking all active sessions

### DO_session.py

Devin AI session management functions. Handles creating sessions, polling for status, and listing active sessions.

Key functions:
- `create_devin_session()`: Create a new Devin session with a prompt
- `poll_session_status()`: Wait for a session to complete with timeout handling
- `get_devin_session_status()`: Get current status of a session
- `get_active_session_count()`: Count currently running sessions

### DO_batch_processor.py

Parallel batch processing using ThreadPoolExecutor. Coordinates the full lifecycle of each remediation batch from claiming alerts through handling outcomes.

Key functions:
- `process_batch()`: Process a single batch end-to-end
- `dispatch_threads()`: Dispatch multiple batches to parallel workers
- `extract_alert_numbers()`: Extract alert numbers from batch data

### DO_prompts.py

Prompt generation for Devin AI remediation tasks. Creates XML-formatted prompts optimized for LLM parsing with structured vulnerability details.

Key functions:
- `create_devin_prompt()`: Generate a remediation prompt for a batch of vulnerabilities

### DO_gh_alerts_control_center.py

GitHub alert management for preventing race conditions. Handles claiming (assigning), unclaiming, and closing alerts during the remediation process.

Key functions:
- `claim_github_alerts()`: Assign alerts to the bot user before remediation
- `unclaim_github_alerts()`: Release alerts back to the pool for retry
- `close_github_alerts()`: Mark alerts as dismissed after successful fix

### DO_outcomes.py

Session outcome reconciliation with GitHub alert states. Updates GitHub alerts based on session results (close fixed alerts, unclaim failed alerts).

Key functions:
- `handle_session_outcome()`: Process a completed session and update GitHub accordingly

### DO_reporting.py

Summary generation for orchestrator runs. Provides human-readable output of batch statistics and results.

Key functions:
- `print_summary()`: Display comprehensive run statistics and per-batch results

## Architecture

The modules follow a clear data flow:

1. **Batch Processing** (`DO_batch_processor.py`) receives batches from the main orchestrator
2. **Alert Claiming** (`DO_gh_alerts_control_center.py`) claims alerts to prevent conflicts
3. **Prompt Generation** (`DO_prompts.py`) creates the remediation prompt
4. **Session Management** (`DO_session.py`) creates and monitors Devin sessions
5. **Outcome Handling** (`DO_outcomes.py`) reconciles results with GitHub
6. **Reporting** (`DO_reporting.py`) generates the final summary

All modules use shared data structures from `DO_models.py` and configuration from `DO_config.py`.
