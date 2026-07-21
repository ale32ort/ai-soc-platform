from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class EvidenceItem(BaseModel):
    source: str
    description: str
    timestamp: datetime | None = None
    data: dict[str, Any] = Field(default_factory=dict)


class TimelineEvent(BaseModel):
    timestamp: datetime
    event_type: str
    description: str
    source: str
    data: dict[str, Any] = Field(default_factory=dict)


class InvestigationTask(BaseModel):
    name: str
    status: str = "pending"
    result: dict[str, Any] = Field(default_factory=dict)
    completed_at: datetime | None = None


class InvestigationCase(BaseModel):
    case_id: str = Field(
        default_factory=lambda: str(uuid4())
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    status: str = "new"

    alert_id: str
    alert_type: str
    host: str | None = None
    user: str | None = None
    severity: str | None = None
    risk_score: int | None = None

    original_alert: dict[str, Any]

    evidence: list[EvidenceItem] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    tasks: list[InvestigationTask] = Field(default_factory=list)

    findings: list[str] = Field(default_factory=list)
    unanswered_questions: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)

    def touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc)

    def add_evidence(
        self,
        *,
        source: str,
        description: str,
        data: dict[str, Any],
        timestamp: datetime | None = None,
    ) -> None:
        self.evidence.append(
            EvidenceItem(
                source=source,
                description=description,
                timestamp=timestamp,
                data=data,
            )
        )
        self.touch()

    def add_timeline_event(
        self,
        *,
        timestamp: datetime,
        event_type: str,
        description: str,
        source: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        self.timeline.append(
            TimelineEvent(
                timestamp=timestamp,
                event_type=event_type,
                description=description,
                source=source,
                data=data or {},
            )
        )

        self.timeline.sort(
            key=lambda event: event.timestamp
        )

        self.touch()

    def add_task(self, name: str) -> None:
        self.tasks.append(
            InvestigationTask(name=name)
        )
        self.touch()

    def complete_task(
        self,
        *,
        name: str,
        result: dict[str, Any],
    ) -> None:
        for task in self.tasks:
            if task.name == name:
                task.status = "completed"
                task.result = result
                task.completed_at = datetime.now(timezone.utc)
                self.touch()
                return

        raise ValueError(f"Task not found: {name}")

    def add_finding(self, finding: str) -> None:
        if finding not in self.findings:
            self.findings.append(finding)
            self.touch()

    def add_recommended_action(self, action: str) -> None:
        if action not in self.recommended_actions:
            self.recommended_actions.append(action)
            self.touch()
