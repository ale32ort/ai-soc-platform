from __future__ import annotations

from models.investigation_result import InvestigationResult
from tools.llm_provider import LLMProvider


class MockProvider(LLMProvider):
    """
    Fake provider used for testing.
    """

    def investigate(self, context: str) -> InvestigationResult:

        return InvestigationResult(
            verdict="Likely Benign",
            confidence=95,
            summary="Mock investigation completed successfully.",
            reasoning=[
                "This response came from the mock provider.",
            ],
            recommendations=[
                "No action required.",
            ],
        )
