
from __future__ import annotations

import json
import time
import os
from dataclasses import dataclass
from typing import Any


@dataclass
class LLMResponse:
    content: str
    model: str
    input_tokens: int
    output_tokens: int
    stop_reason: str

    def parse_json(self) -> dict[str, Any]:
        """Extract and parse JSON from the response content."""
        text = self.content
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]
        return json.loads(text.strip())


class LLMClient:
    """Wrapper around the OpenAI API with retry logic and structured output."""

    DEFAULT_MODEL = "gpt-4o"
    MAX_RETRIES = 3
    RETRY_DELAY = 1.0

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        max_tokens: int = 4096,
    ):
        self._api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self._model = model or self.DEFAULT_MODEL
        self._max_tokens = max_tokens
        self._client = None  # lazy init

    def _get_client(self):
        if self._client is None:
            try:
                import openai
                self._client = openai.OpenAI(api_key=self._api_key)
            except ImportError:
                raise RuntimeError("Install openai: pip install openai")
        return self._client

    def complete(
        self,
        system_prompt: str,
        user_message: str,
        temperature: float = 0.0,
        json_mode: bool = False,
    ) -> LLMResponse:
        """Send a message and get a completion with retry logic."""
        client = self._get_client()

        kwargs: dict[str, Any] = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        for attempt in range(self.MAX_RETRIES):
            try:
                response = client.chat.completions.create(**kwargs)
                choice = response.choices[0]

                return LLMResponse(
                    content=choice.message.content or "",
                    model=response.model,
                    input_tokens=response.usage.prompt_tokens,
                    output_tokens=response.usage.completion_tokens,
                    stop_reason=choice.finish_reason,
                )
            except Exception as e:
                if attempt == self.MAX_RETRIES - 1:
                    raise
                time.sleep(self.RETRY_DELAY * (attempt + 1))

        raise RuntimeError("unreachable")

    def complete_structured(
        self,
        system_prompt: str,
        user_message: str,
        schema: dict[str, Any],
    ) -> dict[str, Any]:
        """Get a structured JSON response conforming to the given schema."""
        augmented_system = (
            f"{system_prompt}\n\n"
            f"Respond with valid JSON matching this schema:\n"
            f"```json\n{json.dumps(schema, indent=2)}\n```"
        )
        response = self.complete(augmented_system, user_message, json_mode=True)
        return response.parse_json()
