"""API surface import: OpenAPI/Swagger specs and JS-discovered write endpoints -> injection points."""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlsplit

import yaml

from webguard.http import HttpClient
from webguard.models import InjectionPoint

SPEC_PATHS = ["/openapi.json", "/swagger.json", "/v3/api-docs", "/v2/api-docs", "/api-docs", "/api-docs/swagger.json",
              "/swagger/v1/swagger.json", "/api/swagger.json", "/api/openapi.json", "/openapi.yaml", "/swagger.yaml",
              "/api-docs/swagger.yaml", "/docs/openapi.json"]
SAMPLE = {"integer": "1", "number": "1", "boolean": "true", "string": "test"}


def _sample(schema: dict, name: str) -> str:
    if not isinstance(schema, dict):
        return "test"
    if "example" in schema:
        return str(schema["example"])
    if schema.get("enum"):
        return str(schema["enum"][0])
    fmt = schema.get("format", "")
    if fmt == "email" or "mail" in name.lower():
        return "test@example.com"
    if fmt in ("uri", "url") or "url" in name.lower():
        return "https://example.com/"
    return SAMPLE.get(schema.get("type", "string"), "test")


def _resolve(spec: dict, schema: dict, depth: int = 0) -> dict:
    if depth > 5 or not isinstance(schema, dict):
        return {}
    if "$ref" in schema:
        node = spec
        for part in schema["$ref"].lstrip("#/").split("/"):
            node = node.get(part, {}) if isinstance(node, dict) else {}
        return _resolve(spec, node, depth + 1)
    if "allOf" in schema:
        merged: dict = {"type": "object", "properties": {}}
        for sub in schema["allOf"]:
            merged["properties"].update(_resolve(spec, sub, depth + 1).get("properties", {}))
        return merged
    return schema


def points_from_spec(spec: dict, base_url: str) -> list[InjectionPoint]:
    servers = spec.get("servers") or []
    if servers and isinstance(servers[0], dict) and servers[0].get("url"):
        base = urljoin(base_url, servers[0]["url"])
    else:
        base = urljoin(base_url, spec.get("basePath", "/"))
    base = base.rstrip("/")
    points: list[InjectionPoint] = []
    for path, ops in (spec.get("paths") or {}).items():
        if not isinstance(ops, dict):
            continue
        shared = ops.get("parameters", [])
        for method, op in ops.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete") or not isinstance(op, dict):
                continue
            params = [_resolve(spec, p) for p in shared + op.get("parameters", [])]
            concrete = path
            for p in params:
                if p.get("in") == "path":
                    concrete = concrete.replace("{" + p["name"] + "}", _sample(p.get("schema", p), p["name"]))
            concrete = re.sub(r"\{[^}]+\}", "1", concrete)
            url = base + concrete
            query = {p["name"]: _sample(p.get("schema", p), p["name"]) for p in params if p.get("in") == "query"}
            for name in query:
                points.append(InjectionPoint(url, method.upper() if method.lower() == "get" else "GET", "query", name,
                                             dict(query), source="openapi"))
            body_schema = None
            content = (op.get("requestBody") or {}).get("content", {}) if isinstance(op.get("requestBody"), dict) else {}
            for ctype, media in content.items():
                if "json" in ctype:
                    body_schema = _resolve(spec, media.get("schema", {}))
                    break
            for p in params:  # swagger 2 body parameter
                if p.get("in") == "body":
                    body_schema = _resolve(spec, p.get("schema", {}))
            if body_schema and body_schema.get("properties"):
                body = {k: _sample(_resolve(spec, v), k) for k, v in body_schema["properties"].items()}
                for name in body:
                    points.append(InjectionPoint(url, method.upper(), "json", name, dict(body), source="openapi"))
    return points


async def discover_specs(client: HttpClient, root: str, extra: list[str] = ()) -> list[tuple[str, dict]]:
    found = []
    for path in list(dict.fromkeys([*extra, *SPEC_PATHS])):
        url = path if path.startswith("http") else root + path
        r = await client.safe_get(url)
        if r is None or r.status != 200:
            continue
        text = r.text.strip()
        spec = None
        try:
            spec = json.loads(text) if text.startswith("{") else (yaml.safe_load(text) if "openapi" in text[:200] or "swagger" in text[:200] else None)
        except Exception:
            spec = None
        if isinstance(spec, dict) and ("openapi" in spec or "swagger" in spec) and spec.get("paths"):
            found.append((url, spec))
        elif "swagger-ui" in text.lower():  # swagger UI page: look for the spec URL it loads
            for m in re.finditer(r"""url\s*[:=]\s*["']([^"']+\.(?:json|ya?ml))["']""", text):
                extra_url = urljoin(url, m.group(1))
                if extra_url not in extra:
                    found += await discover_specs(client, root, [extra_url])
    uniq = {u: s for u, s in found}
    return list(uniq.items())


BODY_TEMPLATES = [
    (re.compile(r"(?i)log[-_]?in|sign[-_]?in|authenticat|session|token"), {"email": "test@example.com", "password": "Passw0rd!"}),
    (re.compile(r"(?i)regist|sign[-_]?up|/users?/?$"), {"email": "test@example.com", "password": "Passw0rd!", "username": "test"}),
    (re.compile(r"(?i)reset|forgot|recover"), {"email": "test@example.com", "answer": "test", "new": "Passw0rd!"}),
    (re.compile(r"(?i)review|comment|feedback|complain|message|chat"), {"message": "test", "comment": "test", "author": "test"}),
    (re.compile(r"(?i)search|query|filter"), {"query": "test", "q": "test"}),
    (re.compile(r"(?i)order|basket|cart|checkout|coupon"), {"id": "1", "quantity": "1", "couponData": "test"}),
    (re.compile(r"(?i)upload|import|file|export"), {"file": "test.txt", "format": "json"}),
]


def guess_body(url: str) -> dict[str, str]:
    path = urlsplit(url).path
    for rx, body in BODY_TEMPLATES:
        if rx.search(path):
            return dict(body)
    return {"id": "1", "name": "test"}


def points_from_writes(writes: set[tuple[str, str]]) -> list[InjectionPoint]:
    points = []
    for method, url in sorted(writes):
        if method == "DELETE":
            continue  # never fuzz destructive verbs automatically
        body = guess_body(url)
        for name in body:
            points.append(InjectionPoint(url, method, "json", name, dict(body), source="js-write"))
    return points
