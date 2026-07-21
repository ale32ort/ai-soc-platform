from __future__ import annotations

from abc import ABC, abstractmethod

from models.investigation_result import InvestigationResult


class LLMProvider(ABC):
    """
    Base interface for all LLM providers.
    """

    @abstractmethod
    def investigate(self, context: str) -> InvestigationResult:
        """
        Analyze an investigation context and return
        a structured InvestigationResult.
        """
        raise NotImplementedError
