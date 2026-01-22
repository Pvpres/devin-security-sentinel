"""
Data Models for Security Sentinel Orchestrator.

This module defines the core data structures used throughout the Security
Sentinel system for tracking session states, results, and orchestrator state.

Classes:
    SessionStatus: Enum representing possible states of a Devin session.
    SessionResult: Dataclass containing the outcome of a remediation session.
    OrchestratorState: Thread-safe container for tracking all active sessions.
"""

from typing import Any
from dataclasses import dataclass, field
from enum import Enum
import threading


class SessionStatus(Enum):
    """
    Enumeration of possible Devin session states.
    
    These states represent the lifecycle of a remediation session from
    creation through completion or failure.
    
    Attributes:
        SUCCESS: Session completed successfully with a PR created.
        FAILURE: Session failed to complete the remediation task.
        PARTIAL: Some alerts were fixed but not all.
        STUCK: Session stopped making progress (stagnation detected).
        TIMEOUT: Session exceeded the maximum allowed time.
        PENDING: Session is queued but not yet started.
        RUNNING: Session is actively working on remediation.
    """
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    STUCK = "stuck"
    TIMEOUT = "timeout"
    PENDING = "pending"
    RUNNING = "running"


@dataclass
class SessionResult:
    """
    Result of a completed Devin remediation session.
    
    This dataclass captures all relevant information about a session's outcome,
    including status, associated alerts, and any URLs for tracking.
    
    Attributes:
        status: Final status of the session (from SessionStatus enum).
        session_id: Unique identifier for the Devin session.
        batch_id: Identifier for the vulnerability batch (typically ruleId).
        alert_numbers: List of GitHub alert numbers assigned to this session.
        pr_url: URL to the pull request if one was created.
        session_url: URL to the Devin session for manual review.
        error_message: Description of any error that occurred.
        fixed_alerts: List of alert numbers that were successfully fixed.
        unfixed_alerts: List of alert numbers that remain unfixed.
    """
    status: SessionStatus
    session_id: str
    batch_id: str
    alert_numbers: list[int]
    pr_url: str | None = None
    session_url: str | None = None
    error_message: str | None = None
    fixed_alerts: list[int] = field(default_factory=list)
    unfixed_alerts: list[int] = field(default_factory=list)


@dataclass
class OrchestratorState:
    """
    Thread-safe state container for the orchestrator.
    
    This class maintains the mapping between sessions, batches, and alerts,
    allowing the orchestrator to track progress across multiple concurrent
    worker threads. All operations are protected by a threading lock.
    
    Attributes:
        session_to_alerts: Maps session IDs to their assigned alert numbers.
        session_to_batch: Maps session IDs to their batch identifiers.
        results: List of completed SessionResult objects.
        lock: Threading lock for thread-safe operations.
    """
    session_to_alerts: dict[str, list[int]] = field(default_factory=dict)
    session_to_batch: dict[str, str] = field(default_factory=dict)
    results: list[SessionResult] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def register_session(self, session_id: str, batch_id: str, alert_numbers: list[int]) -> None:
        """
        Register a new session with its associated batch and alerts.
        
        Args:
            session_id: Unique identifier for the Devin session.
            batch_id: Identifier for the vulnerability batch.
            alert_numbers: List of GitHub alert numbers assigned to this session.
        """
        with self.lock:
            self.session_to_alerts[session_id] = alert_numbers
            self.session_to_batch[session_id] = batch_id

    def add_result(self, result: SessionResult) -> None:
        """
        Add a completed session result to the results list.
        
        Args:
            result: SessionResult object containing the session outcome.
        """
        with self.lock:
            self.results.append(result)

    def get_alerts_for_session(self, session_id: str) -> list[int]:
        """
        Retrieve the alert numbers assigned to a session.
        
        Args:
            session_id: Unique identifier for the Devin session.
            
        Returns:
            List of alert numbers, or empty list if session not found.
        """
        with self.lock:
            return self.session_to_alerts.get(session_id, [])
