"""Fixed-origin Gate API client with no retry loop or arbitrary fetch."""
import base64
import json
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

MAX_BODY_BYTES = 1024 * 1024
BASE_URL = "https://api.ismalicious.com"


class GateModel(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)


class LinkVerdict(GateModel):
    url: str
    entity: str
    verdict: Literal["malicious", "suspicious", "clean", "unknown"]
    sources: int = Field(ge=0)


class Span(GateModel):
    start: int = Field(ge=0)
    end: int = Field(ge=0)
    family: str


class Injection(GateModel):
    score: float = Field(ge=0, le=1)
    families: list[str]
    spans: list[Span]


class ScanResponse(GateModel):
    verdict: Literal["block", "warn", "allow"]
    injection: Injection
    links: list[LinkVerdict]
    links_truncated: bool
    mode: Literal["fast", "thorough"]
    latency_ms: int = Field(ge=0)


class UrlResponse(GateModel):
    url: str
    entity: str
    verdict: Literal["block", "warn", "allow"]
    sources: int = Field(ge=0)
    latency_ms: int = Field(ge=0)


def denied(reason: str) -> dict[str, Any]:
    return {"allowed": False, "error": reason, "result": None}


class GateClient:
    def __init__(self, credentials: dict[str, Any]) -> None:
        key, secret = credentials.get("api_key"), credentials.get("api_secret")
        if not isinstance(key, str) or not key or not isinstance(secret, str) or not secret:
            raise ValueError("Both IsMalicious API key and secret are required.")
        self.header = base64.b64encode(f"{key}:{secret}".encode()).decode()

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            with httpx.Client(timeout=15, follow_redirects=False, verify=True) as client:
                response = client.request(method, BASE_URL + path,
                    headers={"X-API-KEY": self.header, "Content-Type": "application/json"}, **kwargs)
            if response.status_code != 200:
                return denied(f"Gate HTTP {response.status_code}; no retry performed.")
            payload = response.json()
            model = ScanResponse if path == "/gate/scan" else UrlResponse
            model.model_validate(payload)
            return {"allowed": payload["verdict"] == "allow" and not payload.get("links_truncated", False),
                    "error": None, "result": payload}
        except (httpx.HTTPError, ValueError, ValidationError):
            return denied("Gate unavailable or malformed response; processing refused.")

    def scan(self, content: Any, source_url: Any = None) -> dict[str, Any]:
        if not isinstance(content, str) or not content:
            return denied("Content must be a non-empty string.")
        if source_url is not None and not isinstance(source_url, str):
            return denied("Source URL must be a string.")
        body: dict[str, Any] = {"content": content, "mode": "fast"}
        if source_url:
            body["source_url"] = source_url
        encoded = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_BODY_BYTES:
            return denied("Serialized scan body exceeds 1 MiB; content was not truncated or sent.")
        return self._request("POST", "/gate/scan", content=encoded)

    def check_url(self, url: Any) -> dict[str, Any]:
        if not isinstance(url, str) or not url:
            return denied("URL must be a non-empty string.")
        return self._request("GET", "/gate/url", params={"u": url})
