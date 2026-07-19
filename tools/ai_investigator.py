from __future__ import annotations

from models.case import InvestigationCase


class AIInvestigator:
    """
    Performs reasoning over an InvestigationCase.

    Version 1 simply prepares the investigation context.
    Later versions will call Claude/OpenAI.
    """

    def build_context(
        self,
        case: InvestigationCase,
    ) -> str:

        lines = []

        lines.append(
            f"Alert Type: {case.alert_type}"
        )

        lines.append(
            f"Host: {case.host}"
        )

        lines.append(
            f"Severity: {case.severity}"
        )

        lines.append(
            f"Risk Score: {case.risk_score}"
        )

        lines.append("")

        lines.append("Evidence")

        for evidence in case.evidence:

            event_code = evidence.data.get(
                "event_code",
                "unknown",
            )

            process = evidence.data.get(
                "process_name",
                "unknown",
            )

            lines.append(
                f"- Event {event_code} | {process}"
            )

        return "\n".join(lines)
