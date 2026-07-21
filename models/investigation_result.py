from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class InvestigationResult:
    """
    Structured output from the AI investigator.
    """

    verdict: str
    confidence: int
    summary: str

    reasoning: list[str] = field(default_factory=list)

    mitre_techniques: list[str] = field(default_factory=list)

    recommendations: list[str] = field(default_factory=list)

    def pretty_print(self) -> str:
        lines = [
            "========== Investigation Result ==========",
            f"Verdict      : {self.verdict}",
            f"Confidence   : {self.confidence}%",
            "",
            "Summary",
            "-------",
            self.summary,
            "",
            "Reasoning",
            "---------",
        ]

        if self.reasoning:
            lines.extend(f"- {item}" for item in self.reasoning)
        else:
            lines.append("(none)")

        lines.extend([
            "",
            "MITRE ATT&CK",
            "------------",
        ])

        if self.mitre_techniques:
            lines.extend(f"- {technique}" for technique in self.mitre_techniques)
        else:
            lines.append("(none)")

        lines.extend([
            "",
            "Recommendations",
            "---------------",
        ])

        if self.recommendations:
            lines.extend(f"- {item}" for item in self.recommendations)
        else:
            lines.append("(none)")

        return "\n".join(lines)
