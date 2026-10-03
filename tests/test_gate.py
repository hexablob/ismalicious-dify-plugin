import base64
import copy
import json

import httpx
import pytest

import gate_client
from gate_client import GateClient
from tools.check_url import CheckUrlTool
from tools.scan_content import ScanContentTool

CREDENTIALS = {"api_key": "fixture-key", "api_secret": "fixture-secret"}
SCAN = {"verdict": "allow", "injection": {"score": 0.0, "families": [], "spans": []},
        "links": [{"url": "https://unknown.example/?a=1,2#frag", "entity": "unknown.example", "verdict": "unknown", "sources": 0}],
        "links_truncated": False, "mode": "fast", "latency_ms": 1, "future_field": {"preserved": True}}
URL = {"url": "https://unknown.example/?a=1,2#frag", "entity": "unknown.example", "verdict": "allow", "sources": 0, "latency_ms": 1}
REAL_CLIENT = httpx.Client


def install(monkeypatch, handler):
    settings = []
    def factory(**kwargs):
        settings.append(kwargs)
        return REAL_CLIENT(transport=httpx.MockTransport(handler), **kwargs)
    monkeypatch.setattr(gate_client.httpx, "Client", factory)
    return settings


@pytest.mark.parametrize("verdict,allowed", [("allow", True), ("warn", False), ("block", False)])
def test_verdict_and_original_payload(monkeypatch, verdict, allowed):
    payload = copy.deepcopy(SCAN); payload["verdict"] = verdict
    received = []
    def handle(request):
        received.append(request)
        return httpx.Response(200, json=payload)
    settings = install(monkeypatch, handle)
    text = ' Exact é text \\ with "quotes"\nhttps://unknown.example/?a=1,2#frag '
    result = GateClient(CREDENTIALS).scan(text, "https://source.example/?q=x,y#z")
    assert result == {"allowed": allowed, "error": None, "result": payload}
    assert result["result"]["links"][0]["verdict"] == "unknown"
    request = received[0]
    assert request.url.host == "api.ismalicious.com"
    assert request.url.scheme == "https"
    assert request.headers["X-API-KEY"] == base64.b64encode(b"fixture-key:fixture-secret").decode()
    assert json.loads(request.content) == {"content": text, "source_url": "https://source.example/?q=x,y#z", "mode": "fast"}
    assert settings == [{"timeout": 15, "follow_redirects": False, "verify": True}]


def test_truncated_links_refuse(monkeypatch):
    payload = copy.deepcopy(SCAN); payload["links_truncated"] = True
    install(monkeypatch, lambda r: httpx.Response(200, json=payload))
    assert GateClient(CREDENTIALS).scan("text")["allowed"] is False


@pytest.mark.parametrize("status", [301, 302, 307, 400, 401, 403, 429, 500])
def test_http_errors_never_retry_or_follow(monkeypatch, status):
    seen = []
    def handle(request):
        seen.append(request)
        return httpx.Response(status, headers={"Location": "https://attacker.example"})
    install(monkeypatch, handle)
    result = GateClient(CREDENTIALS).scan("must not reach model")
    assert result["allowed"] is False and result["result"] is None
    assert len(seen) == 1
    assert "fixture" not in json.dumps(result)


@pytest.mark.parametrize("payload", [None, [], {}, {**SCAN, "verdict": "unknown"},
    {**SCAN, "links_truncated": "false"}, {**SCAN, "latency_ms": -1},
    {**SCAN, "injection": {"score": 2.0, "families": [], "spans": []}}])
def test_malformed_schema_refuses(monkeypatch, payload):
    install(monkeypatch, lambda r: httpx.Response(200, json=payload))
    assert GateClient(CREDENTIALS).scan("text")["allowed"] is False


def test_bad_json(monkeypatch):
    install(monkeypatch, lambda r: httpx.Response(200, content=b"not json"))
    assert GateClient(CREDENTIALS).scan("text")["allowed"] is False


@pytest.mark.parametrize("error", [httpx.ReadTimeout, httpx.ConnectError])
def test_transport_errors_refuse(monkeypatch, error):
    def handle(request):
        raise error("sensitive exception deliberately not emitted", request=request)
    install(monkeypatch, handle)
    result = GateClient(CREDENTIALS).scan("text")
    assert result["allowed"] is False
    assert "sensitive" not in json.dumps(result)


@pytest.mark.parametrize("text", ["a" * (1024 * 1024), "é" * (512 * 1024), '"' * (512 * 1024)])
def test_serialized_utf8_limit_no_truncation_or_send(monkeypatch, text):
    seen = []
    install(monkeypatch, lambda r: seen.append(r))
    result = GateClient(CREDENTIALS).scan(text)
    assert result["allowed"] is False and not seen


def test_exact_url_no_destination_fetch(monkeypatch):
    seen = []
    def handle(request):
        seen.append(request)
        return httpx.Response(200, json=URL)
    install(monkeypatch, handle)
    result = GateClient(CREDENTIALS).check_url(URL["url"])
    assert result["allowed"] is True and result["result"] == URL
    assert len(seen) == 1
    assert seen[0].url.host == "api.ismalicious.com"
    assert seen[0].url.params["u"] == URL["url"]


@pytest.mark.parametrize("tool,params,payload", [
    (ScanContentTool, {"content": "payload"}, SCAN),
    (CheckUrlTool, {"url": URL["url"]}, URL),
])
def test_released_dify_sdk_tool_messages(monkeypatch, tool, params, payload):
    install(monkeypatch, lambda r: httpx.Response(200, json=payload))
    messages = list(tool.from_credentials(CREDENTIALS).invoke(tool_parameters=params))
    serialized = [m.model_dump(mode="json") for m in messages]
    variables = {m["message"]["variable_name"]: m["message"]["variable_value"] for m in serialized if m["type"] == "variable"}
    assert variables["allowed"] is True
    assert variables["result"]["result"] == payload
    assert "fixture-key" not in json.dumps(serialized)
    assert "fixture-secret" not in json.dumps(serialized)


@pytest.mark.parametrize("verdict", ["block", "warn", "unexpected"])
def test_sdk_failure_cannot_enter_recipe_allow_branch(monkeypatch, verdict):
    payload = {**SCAN, "verdict": verdict}
    install(monkeypatch, lambda r: httpx.Response(200, json=payload))
    messages = [m.model_dump(mode="json") for m in ScanContentTool.from_credentials(CREDENTIALS).invoke(tool_parameters={"content": "untrusted"})]
    allowed = next(m["message"]["variable_value"] for m in messages if m["type"] == "variable" and m["message"]["variable_name"] == "allowed")
    model_inputs = []
    if allowed is True:
        model_inputs.append("untrusted")
    assert not model_inputs
