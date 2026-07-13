"""
Malleable C2 profile parser and HTTP request/response transformer.
"""

import base64
import random
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class DataEmbedding:
    location: str = "cookie"       # cookie | header | body | uri_param
    param_name: str = "session"    # Must match agent's COOKIE_NAME config
    encoding: str = "base64url"    # base64 | base64url | hex | raw
    prepend: str = ""
    append: str = ""


@dataclass
class ResponseEmbedding:
    location: str = "body"
    content_type: str = "text/html; charset=UTF-8"
    encoding: str = "base64"
    wrapper_before: str = '<html><body><div style="display:none">\n'
    wrapper_after: str = "\n</div></body></html>\n"


@dataclass
class MalleableProfile:
    name: str = "default"
    description: str = ""

    # HTTP settings
    method: str = "GET"
    uri_paths: list[str] = field(default_factory=lambda: ["/api/v1"])
    query_params: dict = field(default_factory=dict)

    # Data embedding
    request_embedding: DataEmbedding = field(default_factory=DataEmbedding)
    response_embedding: ResponseEmbedding = field(default_factory=ResponseEmbedding)

    # Headers
    request_headers: dict = field(default_factory=dict)
    response_headers: dict = field(default_factory=dict)

    # TLS
    certificate: str = ""
    private_key: str = ""
    host_header: str = ""

    # Agent behavior
    sleep: int = 60
    jitter: int = 25
    max_retry: int = 5
    kill_date: str = ""
    working_hours: str = ""
    working_days: str = ""

    def random_uri(self) -> str:
        """Select a random URI path from the profile."""
        return random.choice(self.uri_paths) if self.uri_paths else "/"

    def random_query_string(self) -> str:
        """Build query string with random word substitution."""
        if not self.query_params:
            return ""
        params = []
        for k, v in self.query_params.items():
            if "{random_word}" in str(v):
                v = "".join(random.choices(string.ascii_lowercase, k=random.randint(4, 12)))
            params.append(f"{k}={v}")
        return "?" + "&".join(params)

    def encode_data(self, data: bytes, embedding: DataEmbedding) -> str:
        """Encode binary data per the embedding's encoding scheme."""
        if embedding.encoding == "base64url":
            encoded = base64.urlsafe_b64encode(data).decode()
        elif embedding.encoding == "base64":
            encoded = base64.b64encode(data).decode()
        elif embedding.encoding == "hex":
            encoded = data.hex()
        elif embedding.encoding == "raw":
            encoded = data.decode("latin-1")
        else:
            encoded = base64.b64encode(data).decode()

        return embedding.prepend + encoded + embedding.append

    def decode_data(self, encoded: str, embedding: DataEmbedding) -> bytes:
        """Decode data from the embedding's encoding scheme."""
        # Strip prepend/append
        s = encoded
        if embedding.prepend and s.startswith(embedding.prepend):
            s = s[len(embedding.prepend):]
        if embedding.append and s.endswith(embedding.append):
            s = s[:-len(embedding.append)]

        if embedding.encoding == "base64url":
            # Add padding if needed
            s += "=" * (4 - len(s) % 4) if len(s) % 4 else ""
            return base64.urlsafe_b64decode(s)
        elif embedding.encoding == "base64":
            s += "=" * (4 - len(s) % 4) if len(s) % 4 else ""
            return base64.b64decode(s)
        elif embedding.encoding == "hex":
            return bytes.fromhex(s)
        elif embedding.encoding == "raw":
            return s.encode("latin-1")
        else:
            return base64.b64decode(s)

    def wrap_response(self, encoded_data: str) -> str:
        """Wrap encoded data in response wrapper HTML."""
        return (
            self.response_embedding.wrapper_before
            + encoded_data
            + self.response_embedding.wrapper_after
        )

    def unwrap_response(self, body: str) -> str:
        """Extract encoded data from response wrapper."""
        before = self.response_embedding.wrapper_before
        after = self.response_embedding.wrapper_after

        start = body.find(before) + len(before) if before else 0
        end = body.rfind(after) if after else len(body)

        if end <= start:
            end = len(body)

        return body[start:end].strip()

    def generate_decoy_response(self) -> dict:
        """Generate a fake response for non-beacon requests."""
        return {
            "status": 200,
            "content_type": "text/html",
            "body": "<html><body><h1>404 Not Found</h1></body></html>",
            "headers": dict(self.response_headers),
        }


def load_profile(path: Path) -> MalleableProfile:
    """Load a malleable profile from a YAML file."""
    raw = yaml.safe_load(path.read_text())
    if not raw:
        return MalleableProfile()

    http = raw.get("http", {})
    req_emb = http.get("data_embedding", {}).get("request", {})
    resp_emb = http.get("data_embedding", {}).get("response", {})
    headers = http.get("headers", {})
    tls = http.get("tls", {})
    agent = raw.get("agent", {})

    return MalleableProfile(
        name=raw.get("name", "default"),
        description=raw.get("description", ""),
        method=http.get("method", "GET"),
        uri_paths=http.get("uri_paths", ["/api/v1"]),
        query_params=http.get("query_params", {}),
        request_embedding=DataEmbedding(
            location=req_emb.get("location", "cookie"),
            param_name=req_emb.get("param_name", "session"),
            encoding=req_emb.get("encoding", "base64url"),
            prepend=req_emb.get("prepend", ""),
            append=req_emb.get("append", ""),
        ),
        response_embedding=ResponseEmbedding(
            location=resp_emb.get("location", "body"),
            content_type=resp_emb.get("content_type", "text/html; charset=UTF-8"),
            encoding=resp_emb.get("encoding", "base64"),
            wrapper_before=resp_emb.get("wrapper_before", ""),
            wrapper_after=resp_emb.get("wrapper_after", ""),
        ),
        request_headers=headers.get("request", {}),
        response_headers=headers.get("response", {}),
        certificate=tls.get("certificate", ""),
        private_key=tls.get("private_key", ""),
        host_header=tls.get("host_header", ""),
        sleep=agent.get("sleep", 60),
        jitter=agent.get("jitter", 25),
        max_retry=agent.get("max_retry", 5),
        kill_date=str(agent.get("kill_date", "")),
        working_hours=agent.get("working_hours", ""),
        working_days=agent.get("working_days", ""),
    )
