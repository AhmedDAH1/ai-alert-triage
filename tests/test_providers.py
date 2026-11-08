"""The OpenAI-compatible client, against a local stand-in server."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from triage.providers import ChatProvider, ProviderError, ReplayProvider, from_settings


class FakeAPI(BaseHTTPRequestHandler):
    requests, statuses = [], []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeAPI.requests.append((self.path, dict(self.headers), body))
        status = FakeAPI.statuses.pop(0) if FakeAPI.statuses else 200
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        reply = {"choices": [{"message": {"content": '{"verdict": "true_positive"}'}}]} if status == 200 else {"error": "x"}
        self.wfile.write(json.dumps(reply).encode())

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def api():
    server = HTTPServer(("127.0.0.1", 0), FakeAPI)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}/v1"
    server.shutdown()


@pytest.fixture(autouse=True)
def reset():
    FakeAPI.requests, FakeAPI.statuses = [], []


def test_sends_a_deterministic_json_request(api):
    reply = ChatProvider(api, "deepseek-flash", "sk-test", retries=0).complete([{"role": "user", "content": "hi"}])
    path, headers, body = FakeAPI.requests[0]
    assert reply == '{"verdict": "true_positive"}'
    assert path == "/v1/chat/completions"
    assert headers["Authorization"] == "Bearer sk-test"
    assert body["model"] == "deepseek-flash" and body["temperature"] == 0
    assert body["response_format"] == {"type": "json_object"}


def test_retries_rate_limits_and_server_errors(api, monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    FakeAPI.statuses = [429, 503]
    assert ChatProvider(api, "m", retries=2).complete([])
    assert len(FakeAPI.requests) == 3


def test_auth_errors_are_not_retried(api):
    FakeAPI.statuses = [401]
    with pytest.raises(ProviderError, match="401"):
        ChatProvider(api, "m", retries=2).complete([])
    assert len(FakeAPI.requests) == 1


def test_only_http_urls():
    with pytest.raises(ValueError):
        ChatProvider("file:///etc/passwd", "m")


def test_cloud_providers_need_a_key_local_ones_do_not(monkeypatch):
    monkeypatch.delenv("TRIAGE_API_KEY", raising=False)
    for name in ("TRIAGE_PROVIDER", "TRIAGE_BASE_URL", "TRIAGE_MODEL"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError, match="TRIAGE_API_KEY"):
        from_settings("deepseek")
    assert from_settings("ollama").model == "qwen2.5:7b"
    monkeypatch.setenv("TRIAGE_API_KEY", "sk-x")
    assert from_settings("kimi", model="kimi-k2.5").url.endswith("/chat/completions")
    with pytest.raises(ValueError, match="unknown provider"):
        from_settings("chatgpt-free")


def test_replay_refuses_prompts_it_has_not_seen(tmp_path):
    cassette = tmp_path / "c.json"
    cassette.write_text(json.dumps({"model": "m", "answers": {}}))
    with pytest.raises(ProviderError, match="record again"):
        ReplayProvider(cassette).complete([{"role": "user", "content": "new"}])
