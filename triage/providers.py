"""
Language-model providers.

DeepSeek, Kimi (Moonshot), Qwen and a local Ollama all speak the same
OpenAI-style chat API, so one client covers them; only the address and model
name change. RecordingProvider and ReplayProvider save and replay answers, so
an evaluation can be re-run in CI without an API key or network access.
"""

import hashlib
import json
import os
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

PRESETS = {
    "deepseek": {"base_url": "https://api.deepseek.com", "model": "deepseek-flash"},
    "deepseek-pro": {"base_url": "https://api.deepseek.com", "model": "deepseek-v4-pro"},
    "kimi": {"base_url": "https://api.moonshot.ai/v1", "model": "kimi-k2.5"},
    "ollama": {"base_url": "http://localhost:11434/v1", "model": "qwen2.5:7b"},
}


class ProviderError(Exception):
    pass


class ChatProvider:
    """Any OpenAI-compatible chat completions endpoint."""

    def __init__(self, base_url: str, model: str, api_key: str = "", timeout: int = 60, retries: int = 2):
        if urlparse(base_url).scheme not in ("http", "https"):
            raise ValueError(f"not an http(s) URL: {base_url!r}")
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.retries = retries
        self.name = model

    def complete(self, messages: list[dict]) -> str:
        body = json.dumps({
            "model": self.model,
            "messages": messages,
            "temperature": 0,                         # repeatable answers for evaluation
            "response_format": {"type": "json_object"},
        }).encode()
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        for attempt in range(self.retries + 1):
            request = urllib.request.Request(self.url, data=body, headers=headers, method="POST")  # noqa: S310 - scheme checked in __init__
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                    reply = json.load(response)
                return reply["choices"][0]["message"]["content"] or ""
            except urllib.error.HTTPError as e:
                detail = e.read()[:300].decode(errors="replace")
                if e.code in (429, 500, 502, 503) and attempt < self.retries:
                    time.sleep(2 * (attempt + 1))
                    continue
                raise ProviderError(f"HTTP {e.code}: {detail}") from e
            except (urllib.error.URLError, OSError, KeyError, IndexError, ValueError) as e:
                if attempt < self.retries:
                    time.sleep(2 * (attempt + 1))
                    continue
                raise ProviderError(f"{e.__class__.__name__}: {e}") from e
        raise ProviderError("no answer")


def _key(messages):
    return hashlib.sha256(json.dumps(messages, sort_keys=True).encode()).hexdigest()


class RecordingProvider:
    """Wraps a real provider and saves every answer to a cassette file.

    An unfinished cassette from the same model is resumed: prompts it already
    answered are not sent again, so an interrupted run continues where it
    stopped. A cassette from another model is started afresh.
    """

    def __init__(self, inner, cassette: Path):
        self.inner, self.cassette, self.name = inner, Path(cassette), inner.name
        saved = json.loads(self.cassette.read_text()) if self.cassette.exists() else {}
        self.answers = saved if saved.get("model") == inner.name else {"model": inner.name, "answers": {}}
        self.resumed = len(self.answers["answers"])
        self._lock = threading.Lock()     # the evaluation calls from several threads
        self.cassette.parent.mkdir(parents=True, exist_ok=True)

    def complete(self, messages):
        key = _key(messages)
        with self._lock:
            if key in self.answers["answers"]:
                return self.answers["answers"][key]
        answer = self.inner.complete(messages)
        with self._lock:
            self.answers["answers"][key] = answer
            self.cassette.write_text(json.dumps(self.answers, indent=1, sort_keys=True))
        return answer


class ReplayProvider:
    """Answers from a cassette recorded earlier; no network."""

    def __init__(self, cassette: Path):
        data = json.loads(Path(cassette).read_text())
        # Same name as the live run, so a replay reproduces its report exactly
        self.name, self.answers = data["model"], data["answers"]
        self.missing = 0

    def complete(self, messages):
        try:
            return self.answers[_key(messages)]
        except KeyError:
            self.missing += 1
            raise ProviderError("no recorded answer for this prompt; record again") from None


def from_settings(preset: str | None = None, model: str | None = None, base_url: str | None = None):
    """Build a provider from a preset name and/or TRIAGE_* environment variables."""
    settings = dict(PRESETS.get(preset or os.environ.get("TRIAGE_PROVIDER", ""), {}))
    if preset and preset not in PRESETS:
        raise ValueError(f"unknown provider {preset!r}; choose from {', '.join(PRESETS)}")
    settings["base_url"] = base_url or os.environ.get("TRIAGE_BASE_URL") or settings.get("base_url")
    settings["model"] = model or os.environ.get("TRIAGE_MODEL") or settings.get("model")
    if not settings["base_url"] or not settings["model"]:
        raise ValueError("choose a provider (--provider deepseek|kimi|ollama) or set TRIAGE_BASE_URL and TRIAGE_MODEL")
    api_key = os.environ.get("TRIAGE_API_KEY", "")
    if not api_key and "localhost" not in settings["base_url"] and "127.0.0.1" not in settings["base_url"]:
        raise ValueError("set TRIAGE_API_KEY to your provider's API key")
    return ChatProvider(settings["base_url"], settings["model"], api_key)
