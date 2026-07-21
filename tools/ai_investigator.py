from __future__ import annotations

from models.case import InvestigationCase
from models.investigation_result import InvestigationResult
from tools.llm_provider import LLMProvider

from typing import Any

from tools.elastic_investigation import collect_related_events
from tools.timeline_builder import build_timeline


class AIInvestigator:

    def __init__(
        self,
        provider: LLMProvider,
        es_client: Any,
    ) -> None:
        self.provider = provider
        self.es = es_client

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

                process_executable = evidence.data.get(
                    "process_executable",
                    "unknown",
                )

                command_line = evidence.data.get(
                    "command_line",
                    "unknown",
                )

                parent_process_name = evidence.data.get(
                    "parent_process_name",
                    "unknown",
                )

                parent_process_executable = evidence.data.get(
                    "parent_process_executable",
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

                service_type = evidence.data.get(
                    "service_type",
                    "unknown",
                )

                start_type = evidence.data.get(
                    "start_type",
                    "unknown",
                )

                account_name = evidence.data.get(
                    "account_name",
                    "unknown",
                )

                destination_ip = evidence.data.get(
                    "destination_ip",
                    "unknown",
                )

                destination_port = evidence.data.get(
                    "destination_port",
                    "unknown",
                )

                lines.append(
                    f"- Timestamp: {evidence.timestamp}\n"
                    f"  Source: {evidence.source}\n"
                    f"  Description: {evidence.description}\n"
                    f"  Event Code: {event_code}\n"
                    f"  Process: {process_name}\n"
                    f"  Process Executable: {process_executable}\n"
                    f"  Command Line: {command_line}\n"
                    f"  Parent Process: {parent_process_name}\n"
                    f"  Parent Executable: {parent_process_executable}\n"
                    f"  Service Name: {service_name}\n"
                    f"  Image Path: {image_path}\n"
                    f"  Service Type: {service_type}\n"
                    f"  Start Type: {start_type}\n"
                    f"  Account Name: {account_name}\n"
                    f"  Destination IP: {destination_ip}\n"
                    f"  Destination Port: {destination_port}"
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
        # Collect surrounding evidence
        collect_related_events(
            case,
            self.es,
        )

        # Build chronological timeline
        build_timeline(case)

        # Build AI context
        context = self.build_context(case)

        # Send to Claude
        return self.provider.investigate(context)
