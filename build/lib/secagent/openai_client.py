"""Thin wrapper around the OpenAI client that returns parsed JSON objects.

Uses the Chat Completions API with JSON response format so it works across the
widest range of models. Retries transient failures with exponential backoff.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict

from openai import OpenAI


class OpenAIJSONClient:
    def __init__(self, api_key: str, model: str, max_retries: int = 3):
        self._client = OpenAI(api_key=api_key)
        self.model = model
        self.max_retries = max_retries

    def complete_json(
        self,
        system: str,
        user: str,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> Dict[str, Any]:
        """Send a prompt and parse the model's reply as a JSON object."""
        last_err: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                resp = self._client.chat.completions.create(
                    model=self.model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    response_format={"type": "json_object"},
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                )
                content = resp.choices[0].message.content or "{}"
                return json.loads(content)
            except json.JSONDecodeError as exc:
                last_err = exc
            except Exception as exc:  # network / rate limit / API errors
                last_err = exc
            time.sleep(2 ** attempt)
        raise RuntimeError(f"OpenAI request failed after {self.max_retries} attempts: {last_err}")
