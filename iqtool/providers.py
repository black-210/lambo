from __future__ import annotations

import json
import os
from typing import Any, Protocol
from urllib.request import Request, urlopen

DEFAULT_MODEL = "gemini-2.5-flash"

SYSTEM_INSTRUCTION = (
    "You are a cautious assistant for defensive, authorized, offline analysis of local evidence "
    "inventories, source review results, measured signal traces, IQ captures, and educational "
    "quantum simulations. Interpret only the supplied report. Separate observations from "
    "hypotheses, cite report fields, explain uncertainty and possible false positives, and offer "
    "safe defensive next steps. Do not claim proof of a physical, quantum, or security "
    "vulnerability, and do not provide instructions for exploiting, interfering with, or "
    "targeting systems."
)


class ChatProvider(Protocol):
    model: str

    def send_message(self, message: str) -> str: ...


def _report_context(report: dict[str, Any]) -> str:
    context: dict[str, Any] = {}
    for key in (
        "analysis",
        "root_name",
        "metrics",
        "summary",
        "comparison",
        "probabilities",
        "gates",
        "findings",
        "spectral_peaks",
        "observations",
        "limitations",
    ):
        if key in report:
            value = report[key]
            context[key] = value[:20] if isinstance(value, list) else value
    if isinstance(report.get("input"), dict):
        context["input"] = {
            key: report["input"][key]
            for key in ("name", "sample_count", "sample_rate_hz", "sha256")
            if key in report["input"]
        }
    return "Analysis report (summary only):\n" + json.dumps(context)


def _openai_compatible_reply(
    base_url: str,
    model: str,
    api_key: str | None,
    messages: list[dict[str, str]],
) -> str:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = Request(
        base_url.rstrip("/") + "/chat/completions",
        data=json.dumps({"model": model, "messages": messages}).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urlopen(request, timeout=60) as response:
        payload = json.loads(response.read().decode("utf-8"))
    try:
        answer = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as error:
        raise ValueError("Model endpoint returned an unexpected chat response.") from error
    if not isinstance(answer, str):
        raise ValueError("Model endpoint returned non-text content.")
    return answer


class GeminiChat:
    def __init__(self, model: str, report: dict[str, Any]) -> None:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("Set GEMINI_API_KEY in your environment to use Gemini chat.")

        from google import genai
        from google.genai import types

        self.model = model
        client = genai.Client(api_key=api_key)
        self._chat = client.chats.create(
            model=model,
            config=types.GenerateContentConfig(system_instruction=SYSTEM_INSTRUCTION),
        )
        self._chat.send_message(_report_context(report))

    def send_message(self, message: str) -> str:
        response = self._chat.send_message(message)
        return response.text or "(The model returned no text.)"


class OpenAICompatibleChat:
    def __init__(self, base_url: str, model: str, report: dict[str, Any]) -> None:
        self.model = model
        self._base_url = base_url
        self._api_key = os.environ.get("OPENAI_COMPATIBLE_API_KEY")
        self._messages = [
            {"role": "system", "content": SYSTEM_INSTRUCTION},
            {"role": "user", "content": _report_context(report)},
        ]

    def send_message(self, message: str) -> str:
        self._messages.append({"role": "user", "content": message})
        answer = _openai_compatible_reply(
            self._base_url, self.model, self._api_key, self._messages
        )
        self._messages.append({"role": "assistant", "content": answer})
        return answer


def create_chat_provider(
    provider: str,
    model: str | None,
    base_url: str | None,
    report: dict[str, Any],
) -> ChatProvider:
    if provider == "gemini":
        return GeminiChat(model or DEFAULT_MODEL, report)
    if provider == "openai-compatible":
        resolved_base_url = base_url or os.environ.get("OPENAI_COMPATIBLE_BASE_URL")
        if not resolved_base_url:
            raise ValueError(
                "Set OPENAI_COMPATIBLE_BASE_URL or pass --base-url for this provider."
            )
        if not model:
            raise ValueError("--model is required for the OpenAI-compatible provider.")
        return OpenAICompatibleChat(resolved_base_url, model, report)
    raise ValueError(f"Unsupported AI provider: {provider}")
