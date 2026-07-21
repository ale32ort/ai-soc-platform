from __future__ import annotations

import json
import os

from anthropic import Anthropic
from dotenv import load_dotenv

from models.investigation_result import InvestigationResult
from tools.llm_provider import LLMProvider

load_dotenv()


class AnthropicProvider(LLMProvider):
    """
    Anthropic Claude implementation of the LLMProvider interface.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-sonnet-5",
        max_tokens: int = 1500,
    ) -> None:
        api_key = api_key or os.getenv("ANTHROPIC_API_KEY")

        if not api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY not found. "
                "Please add it to your .env file."
            )

        self.client = Anthropic(api_key=api_key)
        self.model = model
        self.max_tokens = max_tokens

    def investigate(self, context: str) -> InvestigationResult:
        """
        Analyze investigation context using Claude.
        """

        prompt = f"""
You are a Senior SOC Analyst.

Analyze the investigation below.

Respond ONLY with valid JSON.

Use EXACTLY this schema:

{{
  "verdict": "TRUE_POSITIVE | FALSE_POSITIVE | SUSPICIOUS",
  "confidence": 0,
  "summary": "",
  "reasoning": [],
  "mitre_techniques": [],
  "recommendations": []
}}

Investigation Context:

{context}
"""

        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        )

        # Extract all text blocks while ignoring thinking blocks.
        text_parts: list[str] = []

        for block in response.content:
            if getattr(block, "type", None) == "text":
                text_parts.append(block.text)

        if not text_parts:
            raise RuntimeError(
                "Claude returned no text blocks."
            )

        content = "\n".join(text_parts).strip()

        # Remove Markdown code fences if Claude wrapped the JSON.
        if content.startswith("```"):
            lines = content.splitlines()

            if lines and lines[0].startswith("```"):
                lines = lines[1:]

            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]

            content = "\n".join(lines).strip()

        try:
            data = json.loads(content)

        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Claude returned invalid JSON:\n\n{content}"
            ) from exc

        return InvestigationResult(
            verdict=data.get("verdict", "UNKNOWN"),
            confidence=int(data.get("confidence", 0)),
            summary=data.get("summary", ""),
            reasoning=data.get("reasoning", []),
            mitre_techniques=data.get("mitre_techniques", []),
            recommendations=data.get("recommendations", []),
        )
