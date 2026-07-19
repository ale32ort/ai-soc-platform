from __future__ import annotations

from models.case import InvestigationCase
from models.investigation_result import InvestigationResult
from tools.llm_provider import LLMProvider


class AIInvestigator:
    """
    Coordinates investigation context creation and AI analysis.
    """

    def __init__(self, provider: LLMProvider) -> None:
        self.provider = provider

    def build_context(self, case: InvestigationCase) -> str:
        lines = [
            f"Alert Type: {case.alert_type}",
            f"Alert ID: {case.alert_id}",
            f"Host: {case.host}",
            f"Severity: {case.severity}",
            f"Risk Score: {case.risk_score}",
            "",
            "Timeline",
            "--------",
        ]

        if case.timeline:
            for event in case.timeline:
                lines.append(
                    f"- {event.timestamp} | "
                    f"{event.event_type} | "
                    f"{event.description}"
                )
        else:
            lines.append("(none)")

        lines.extend([
            "",
            "Evidence",
            "--------",
        ])

        if case.evidence:
            for evidence in case.evidence:
                event_code = evidence.data.get(
                    "event_code",
                    "unknown",
                )

                process_name = evidence.data.get(
                    "process_name",
                    "unknown",
                )

                service_name = evidence.data.get(
                    "service_name",
                    "unknown",
                )

                image_path = evidence.data.get(
                    "image_path",
                    "unknown",
                )

                lines.append(
                    f"- Timestamp: {evidence.timestamp}\n"
                    f"  Source: {evidence.source}\n"
                    f"  Description: {evidence.description}\n"
                    f"  Event Code: {event_code}\n"
                    f"  Process: {process_name}\n"
                    f"  Service: {service_name}\n"
                    f"  Image Path: {image_path}"
                )
        else:
            lines.append("(none)")

        lines.extend([
            "",
            "Existing Findings",
            "-----------------",
        ])

        if case.findings:
            lines.extend(
                f"- {finding}"
                for finding in case.findings
            )
        else:
            lines.append("(none)")

        lines.extend([
            "",
            "Unanswered Questions",
            "--------------------",
        ])

        if case.unanswered_questions:
            lines.extend(
                f"- {question}"
                for question in case.unanswered_questions
            )
        else:
            lines.append("(none)")

        return "\n".join(lines)

    def investigate(
        self,
        case: InvestigationCase,
    ) -> InvestigationResult:
        context = self.build_context(case)
        return self.provider.investigate(context)
