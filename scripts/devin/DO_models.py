"""
Docstring for scripts.devin.DO_models
Data structures for Devin AI Security Sentinel.
"""
from typing import Any
from dataclasses import dataclass, field
from enum import Enum
import threading

class SessionStatus(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    STUCK = "stuck"
    TIMEOUT = "timeout"
    PENDING = "pending"
    RUNNING = "running"

@dataclass
class SessionResult:
    status: SessionStatus
    session_id: str
    batch_id: str
    alert_numbers: list[int]
    pr_url: str | None = None
    error_message: str | None = None
    fixed_alerts: list[int] = field(default_factory=list)
    unfixed_alerts: list[int] = field(default_factory=list)

@dataclass
class OrchestratorState:
    """Thread-safe state container for the orchestrator."""
    session_to_alerts: dict[str, list[int]] = field(default_factory=dict)
    session_to_batch: dict[str, str] = field(default_factory=dict)
    results: list[SessionResult] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def register_session(self, session_id: str, batch_id: str, alert_numbers: list[int]) -> None:
        with self.lock:
            self.session_to_alerts[session_id] = alert_numbers
            self.session_to_batch[session_id] = batch_id

    def add_result(self, result: SessionResult) -> None:
        with self.lock:
            self.results.append(result)

    def get_alerts_for_session(self, session_id: str) -> list[int]:
        with self.lock:
            return self.session_to_alerts.get(session_id, [])