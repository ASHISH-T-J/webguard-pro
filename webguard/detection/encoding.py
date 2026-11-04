"""Encodings, value contexts and per-bug-class input-filter bypass variants.

Two separate ideas live here.

1. **Encoded value contexts** (correct injection, not a bypass). Many parameters carry encoded data:
   ``?data=eyJpZCI6MX0`` (base64 JSON), ``?ref=3132`` (hex), ``?next=%2Fhome`` (pre-encoded). Testing
   ``eyJpZCI6MX0'`` only breaks the encoding. WebGuard decodes the original, injects into the decoded
   value and re-encodes the whole thing (``InjectionPoint.encoding``) - a common false-negative source.

2. **Input-filter bypass variants** (OWASP WSTG-INPV, PortSwigger labs, HackTricks). Applications often
   defend with a blacklist that is defeated by an encoding or normalisation the *application itself*
   applies later: non-recursive stripping (``....//``), a superfluous URL-decode (double encoding), Unicode
   normalisation (full-width characters), HTML-entity decoding after sanitising, null-byte truncation, path
   prefix validation, URL allow-list parsing. Each bug class gets the variants that make sense for it.
   Variants run only when (a) the basic test failed, (b) the application - not a WAF/CDN/rate limiter -
   answered, and (c) a filter was observed or the class is the parameter's leading hypothesis.

Wire semantics: values are sent through httpx, which percent-encodes them once. So an encoder that returns
``%2e%2e%2f`` means the application sees ``%2e%2e%2f`` after its normal decode and ``../`` only if it
decodes *again* (the double-decoding bug). Wire-exact byte sequences such as overlong UTF-8 (``%c0%af``)
are marked :class:`Raw` and inserted into the query string without further escaping.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import string
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import quote, unquote, urlsplit


class Raw(str):
    """A query value that must be placed on the wire exactly as written (no extra percent-encoding)."""


# ----------------------------------------------------------------------------- primitive encoders

def url_encode_all(v: str) -> str:
    """Every byte as %XX (the app sees this after one decode; a second decode yields the payload)."""
    return "".join(f"%{b:02X}" for b in v.encode())


def url_encode_specials(v: str) -> str:
    keep = string.ascii_letters + string.digits
    return "".join(c if c in keep else "".join(f"%{b:02X}" for b in c.encode()) for c in v)


def unicode_js(v: str) -> str:
    """\\uXXXX escapes for non-alphanumerics (JSON / JavaScript string contexts decode these)."""
    return "".join(c if c.isalnum() else f"\\u{ord(c):04x}" for c in v)


def percent_u(v: str) -> str:
    """IIS-style %uXXXX encoding of non-alphanumerics."""
    return "".join(c if c.isalnum() else f"%u{ord(c):04x}" for c in v)


def html_entities(v: str) -> str:
    return "".join(c if c.isalnum() or c == " " else f"&#{ord(c)};" for c in v)


def html_hex_entities(v: str) -> str:
    return "".join(c if c.isalnum() or c == " " else f"&#x{ord(c):x};" for c in v)


FULLWIDTH = {c: chr(ord(c) + 0xFEE0) for c in "<>'\"/.:;()=`|&{}[]$"}


def fullwidth(v: str) -> str:
    """Full-width forms that NFKC normalisation folds back to ASCII (normalise-after-validate bugs)."""
    return "".join(FULLWIDTH.get(c, c) for c in v)


def b64(v: str) -> str:
    return base64.b64encode(v.encode()).decode()


def b64url(v: str) -> str:
    return base64.urlsafe_b64encode(v.encode()).decode().rstrip("=")


def hexenc(v: str) -> str:
    return v.encode().hex()


def case_flip(v: str) -> str:
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(v))


# ----------------------------------------------------------------------------- encoded value contexts

PRINTABLE = re.compile(r"^[\x09\x0a\x0d\x20-\x7e]+$")


def _printable(raw: bytes) -> str | None:
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s if PRINTABLE.match(s) else None


def detect_encoding(value: str) -> str | None:
    """Return the encoding layer of a parameter value (``base64``, ``base64url``, ``hex``, ``url``)."""
    v = value.strip()
    if len(v) < 6:
        return None
    if re.fullmatch(r"(?:[0-9a-f]{2}){4,}", v) and not v.isdigit():
        if _printable(binascii.unhexlify(v)):
            return "hex"
    if re.fullmatch(r"[A-Za-z0-9+/]{6,}={0,2}", v) and len(v) % 4 == 0 and not v.isalpha() and not v.isdigit():
        try:
            if _printable(base64.b64decode(v, validate=True)):
                return "base64"
        except (binascii.Error, ValueError):
            pass
    if re.fullmatch(r"[A-Za-z0-9_-]{8,}={0,2}", v) and not v.isdigit() and not v.isalpha():
        try:
            decoded = _printable(base64.urlsafe_b64decode(v + "=" * (-len(v) % 4)))
        except (binascii.Error, ValueError):
            decoded = None
        # unpadded alphanumerics are ambiguous (IDs, tokens): require JSON-looking or long printable content
        if decoded and (not v.isalnum() or decoded.lstrip().startswith(("{", "[")) or len(v) >= 16):
            return "base64url"
    if re.search(r"%[0-9A-Fa-f]{2}", v) and unquote(v) != v:
        return "url"
    return None


DECODE: dict[str, Callable[[str], str]] = {
    "base64": lambda v: base64.b64decode(v).decode(),
    "base64url": lambda v: base64.urlsafe_b64decode(v + "=" * (-len(v) % 4)).decode(),
    "hex": lambda v: binascii.unhexlify(v).decode(),
    "url": unquote,
}
ENCODE: dict[str, Callable[[str], str]] = {
    "base64": b64, "base64url": b64url, "hex": hexenc, "url": url_encode_specials,
}


def encode_context(value: str, encoding: str) -> str:
    return ENCODE[encoding](value) if encoding in ENCODE else value


def inject_json_string(decoded: str) -> str | None:
    """If the decoded value is a JSON object, return the first string field's value (the injection target)."""
    try:
        data = json.loads(decoded)
    except ValueError:
        return None
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                return str(v)
    return None


# ----------------------------------------------------------------------------- per-class bypass variants

@dataclass(frozen=True)
class Variant:
    name: str
    transform: Callable[[str], str]
    source: str  # where the technique comes from (for the report)


def _traversal(fn: Callable[[str], str]) -> Callable[[str], str]:
    """Apply ``fn`` only to the traversal part ('../' / '..\\\\' runs) of a value."""
    return lambda v: re.sub(r"(?:\.\.[/\\])+", lambda m: fn(m.group(0)), v)


def _overlong(v: str) -> str:
    seq = re.sub(r"\.\./", "..%c0%af", v)
    return Raw("".join(c if c in "%" + string.ascii_letters + string.digits + "/._-" else quote(c) for c in seq))


def _null_ext(original: str) -> Callable[[str], str]:
    ext = re.search(r"\.[A-Za-z0-9]{1,5}$", original or "")
    suffix = ext.group(0) if ext else ".png"
    return lambda v: v + "\x00" + suffix


def _path_prefix(original: str) -> Callable[[str], str]:
    m = re.match(r"^(/?(?:[\w.-]+/)+)", original or "")
    prefix = m.group(1) if m else ""
    return lambda v: (prefix + v) if prefix and v.startswith("..") else v


def _ifs(v: str) -> str:
    return v.replace(" ", "${IFS}")


def _quote_cmd(v: str) -> str:
    return re.sub(r"\b(echo|sleep|ping|set)\b", lambda m: m.group(1)[0] + "''" + m.group(1)[1:], v)


def _allowlist(original: str, mode: str) -> Callable[[str], str]:
    trusted = urlsplit(original).hostname if original.startswith(("http://", "https://")) else None

    def fn(v: str) -> str:
        if not trusted or not v.startswith(("http://", "https://")):
            return v
        p = urlsplit(v)
        if mode == "userinfo":
            return f"{p.scheme}://{trusted}@{p.netloc}{p.path or '/'}"
        if mode == "fragment":
            return f"{p.scheme}://{p.netloc}{p.path or '/'}#{trusted}"
        if mode == "query":
            return f"{p.scheme}://{p.netloc}{p.path or '/'}?{trusted}"
        return v
    return fn


def variants_for(check: str, original: str = "") -> list[Variant]:
    """Filter-bypass variants that are meaningful for a bug class (ordered: most common first)."""
    ps = "PortSwigger Web Security Academy"
    if check == "lfi":
        return [
            Variant("nested-traversal", _traversal(lambda s: s.replace("../", "....//").replace("..\\", "....\\\\")),
                    f"{ps}: traversal sequences stripped non-recursively"),
            Variant("double-url-encoding", _traversal(url_encode_all), f"{ps}: superfluous URL-decode"),
            Variant("overlong-utf8", _overlong, f"{ps} / HackTricks: non-standard encoding ..%c0%af"),
            Variant("path-prefix", _path_prefix(original), f"{ps}: validation of start of path"),
            Variant("null-byte-extension", _null_ext(original), f"{ps}: validation of file extension with null byte"),
            Variant("backslash", _traversal(lambda s: s.replace("/", "\\")), "HackTricks: Windows separators"),
        ]
    if check == "xss":
        return [
            Variant("double-url-encoding", url_encode_specials, "HackTricks: decode-after-sanitise"),
            Variant("html-entities", html_entities, "OWASP: entity decoding after sanitisation"),
            Variant("unicode-fullwidth", fullwidth, "HackTricks: Unicode normalisation (NFKC)"),
            Variant("js-unicode-escapes", unicode_js, f"{ps}: JavaScript string contexts"),
            Variant("case-variation", case_flip, "OWASP XSS Filter Evasion: case-sensitive blacklists"),
        ]
    if check == "sqli":
        return [
            Variant("double-url-encoding", url_encode_specials, "OWASP WSTG-INPV-05: filter evasion"),
            Variant("unicode-fullwidth", fullwidth, "HackTricks: Unicode normalisation"),
            Variant("js-unicode-escapes", unicode_js, "JSON bodies decoded after validation"),
        ]
    if check == "cmdi":
        return [
            Variant("ifs-whitespace", _ifs, "HackTricks: $IFS instead of spaces"),
            Variant("quoted-command", _quote_cmd, "HackTricks: quote insertion in command names"),
            Variant("double-url-encoding", url_encode_specials, "OWASP WSTG-INPV-12"),
        ]
    if check == "ssti":
        return [
            Variant("double-url-encoding", url_encode_specials, "decode-after-validate"),
            Variant("html-entities", html_entities, "template rendered after entity decoding"),
            Variant("unicode-fullwidth", fullwidth, "Unicode normalisation"),
        ]
    if check == "redirect":
        return [
            Variant("double-url-encoding", url_encode_specials, f"{ps}: URL-decoded redirect targets"),
            Variant("backslash", lambda v: v.replace("//", "\\\\", 1), "HackTricks: backslash-slash normalisation"),
            Variant("unicode-fullwidth", fullwidth, "HackTricks: Unicode normalisation of '/' and '.'"),
        ]
    if check == "ssrf":
        return [
            Variant("allowlist-userinfo", _allowlist(original, "userinfo"), f"{ps}: SSRF with whitelist-based filter"),
            Variant("allowlist-fragment", _allowlist(original, "fragment"), f"{ps}: URL parsing inconsistencies"),
            Variant("allowlist-query", _allowlist(original, "query"), "HackTricks: URL format bypass"),
            Variant("double-url-encoding", url_encode_specials, f"{ps}: recursive URL decoding"),
        ]
    if check == "crlf":
        return [Variant("double-url-encoding", url_encode_specials, "OWASP WSTG-INPV-15")]
    return []
