"""PII / secret redaction for reports and screenshots.

Reports are shared with clients, triage teams and bug bounty platforms; they must prove a vulnerability
without re-leaking the data it exposed. The same rules are applied in two forms:

* :func:`redact` masks text (HTML / Markdown / JSON / SARIF reports, HTTP evidence, curl commands) while
  keeping enough shape to show *what* was exposed (``a***@shop.test``, ``**** **** **** 4242``,
  ``0192…[MD5 hash]``).
* :data:`BLUR_JS` blurs the same patterns in the browser before a PoC screenshot is taken.

Masking is irreversible in the generated report; the raw data stays only in the local findings
database (``--no-redact`` disables masking for internal use).
"""

from __future__ import annotations

import re
from collections.abc import Callable

from webguard.signatures import default_db


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
        alt = not alt
    return total % 10 == 0


def _mask_email(m: re.Match) -> str:
    local, domain = m.group(1), m.group(2)
    return f"{local[0]}***@{domain}"


def _mask_card(m: re.Match) -> str:
    digits = re.sub(r"\D", "", m.group(0))
    if not (13 <= len(digits) <= 19) or not _luhn(digits):
        return m.group(0)
    return "**** **** **** " + digits[-4:]


def _mask_hash(kind: str) -> Callable[[re.Match], str]:
    return lambda m: f"{m.group(0)[:4]}…[{kind}]"


def _mask_kv(m: re.Match) -> str:
    return f"{m.group(1)}[redacted]{m.group(3)}"


RULES: list[tuple[str, re.Pattern[str], Callable[[re.Match], str] | str]] = [
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"), "eyJ…[redacted JWT]"),
    ("auth-header", re.compile(r"(?im)^((?:authorization|proxy-authorization|x-api-key|x-auth-token)\s*:\s*(?:\w+\s+)?)(\S.*)$"),
     lambda m: f"{m.group(1)}[redacted]"),
    ("cookie-header", re.compile(r"(?im)^((?:set-)?cookie\s*:\s*)(.+)$"),
     lambda m: m.group(1) + re.sub(r"=([^;,\s]+)", "=[redacted]", m.group(2))),
    ("curl-header", re.compile(r"(-H '(?:Authorization|Cookie|X-Api-Key|X-Auth-Token): ?)([^']+)(')", re.I), _mask_kv),
    ("json-secret", re.compile(r'("(?:password|passwd|pwd|secret|token|access_token|refresh_token|api_?key|'
                               r'client_secret|totpSecret|deluxeToken)"\s*:\s*")([^"]+)(")', re.I), _mask_kv),
    ("bcrypt", re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"), _mask_hash("bcrypt hash")),
    ("sha256", re.compile(r"(?<![A-Za-z0-9])[a-f0-9]{64}(?![A-Za-z0-9])"), _mask_hash("SHA-256 hash")),
    ("sha1", re.compile(r"(?<![A-Za-z0-9])[a-f0-9]{40}(?![A-Za-z0-9])"), _mask_hash("SHA-1 hash")),
    ("md5", re.compile(r"(?<![A-Za-z0-9])[a-f0-9]{32}(?![A-Za-z0-9])"), _mask_hash("MD5 hash")),
    ("email", re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"), _mask_email),
    ("card", re.compile(r"(?<![\d-])(?:\d{4}([ -]?)\d{4}\1\d{4}\1\d{1,7}|\d{4}[ -]?\d{6}[ -]?\d{4,5})(?![\d-])"), _mask_card),
    ("ssn", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"), "***-**-****"),
    ("phone", re.compile(r"(?<![\w.])(?:\+\d{1,3}[\s-]?)?(?:\(\d{2,4}\)[\s-]?|\d{3}[\s-])\d{3,4}[\s-]?\d{0,4}(?![\w.])"),
     lambda m: m.group(0) if len(re.sub(r"\D", "", m.group(0))) < 7 else re.sub(r"\d(?=[\d\s().-]{2,})", "*", m.group(0))),
]


def redact(text: str | None) -> str | None:
    """Mask PII and secrets in free text. Idempotent."""
    if not text:
        return text
    for _name, rx, repl in RULES:
        text = rx.sub(repl, text)
    # known secret formats (AWS keys, provider tokens, ...) from the signature database
    for m in default_db().match_secrets(text):
        if m.meta.get("severity", "MEDIUM") != "INFO" and len(m.value) >= 8 and m.value in text:
            text = text.replace(m.value, m.value[:4] + "…[redacted]")
    return text


def redact_obj(obj):
    """Recursively redact every string in a JSON-like structure."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, list):
        return [redact_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: (v if k in ("fingerprint", "severity", "confidence", "check", "cwe", "owasp", "url", "poc_screenshot")
                    else redact_obj(v)) for k, v in obj.items()}
    return obj


# Browser-side blur (same patterns) - applied right before every PoC screenshot.
BLUR_JS = r"""() => {
  const rules = [
    /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g,
    /\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}/g,
    /(?<![A-Za-z0-9])(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})(?![A-Za-z0-9])/g,
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    /(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)/g,
    /(?<![\w.])(?:\+\d{1,3}[\s-]?)?(?:\(\d{2,4}\)[\s-]?|\d{3}[\s-])\d{3,4}[\s-]?\d{0,4}(?![\w.])/g,
    /(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g,
    /((?:authorization|cookie|set-cookie|x-api-key)\s*:\s*)(.+)/gi,
    /("(?:password|passwd|secret|token|access_token|api_?key|deluxeToken|totpSecret)"\s*:\s*")([^"]+)"/gi,
  ];
  const luhn = s => { const d = s.replace(/\D/g, ''); if (d.length < 13 || d.length > 19) return false;
    let t = 0, alt = false; for (let i = d.length - 1; i >= 0; i--) { let n = +d[i];
      if (alt) { n *= 2; if (n > 9) n -= 9; } t += n; alt = !alt; } return t % 10 === 0; };
  const root = document.body || document.documentElement;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const nodes = []; while (walker.nextNode()) nodes.push(walker.currentNode);
  let count = 0;
  for (const node of nodes) {
    const text = node.nodeValue; if (!text || !text.trim()) continue;
    const spans = [];
    rules.forEach((rx, idx) => { rx.lastIndex = 0; let m;
      while ((m = rx.exec(text)) !== null) {
        let start = m.index, end = m.index + m[0].length;
        if (idx === 5 && m[0].replace(/\D/g, '').length < 7) continue;
        if (idx === 6 && !luhn(m[0])) continue;
        if ((idx === 7 || idx === 8) && m[1]) start += m[1].length;     // keep the header/field name readable
        if (idx === 8) end -= 1;
        spans.push([start, end]);
      } });
    if (!spans.length) continue;
    spans.sort((a, b) => a[0] - b[0]);
    const merged = []; for (const s of spans) { const l = merged[merged.length - 1];
      if (l && s[0] <= l[1]) l[1] = Math.max(l[1], s[1]); else merged.push(s.slice()); }
    const frag = document.createDocumentFragment(); let pos = 0;
    for (const [s, e] of merged) {
      frag.appendChild(document.createTextNode(text.slice(pos, s)));
      const b = document.createElement('span'); b.textContent = text.slice(s, e);
      b.setAttribute('style', 'filter:blur(5px);background:rgba(128,128,128,.25)');
      b.setAttribute('data-redacted', '1'); frag.appendChild(b); pos = e; count++;
    }
    frag.appendChild(document.createTextNode(text.slice(pos)));
    node.parentNode.replaceChild(frag, node);
  }
  for (const el of document.querySelectorAll('input[type=password], input[type=email], input[name*=card i]')) {
    el.style.filter = 'blur(5px)'; count++;
  }
  return count;
}"""
