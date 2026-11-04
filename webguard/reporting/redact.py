"""Personal-data (PII) masking for reports and screenshots.

Reports are shared with clients, triage teams and bug bounty platforms. They must prove a vulnerability
without re-leaking the *personal data* of the people whose records were exposed. Only personal
information is masked:

* identity: e-mail addresses, phone numbers, personal names, postal addresses, dates of birth,
  national identifiers (SSN, passport, tax ID)
* financial: payment card numbers (Luhn-checked), IBANs, bank account / routing numbers, CVV, expiry

Technical evidence is **not** masked: hashes, tokens, API keys, cookies, headers, payloads, URLs, IPs and
versions stay readable because they are what proves (and lets the client fix) the vulnerability.
Recon-phase results are never masked either (see :func:`redact_finding`). Terminal output is raw.

* :func:`redact` masks text while keeping the shape (``a***@shop.test``, ``**** **** **** 4242``).
* :data:`BLUR_JS` blurs the same personal data in the browser before a PoC screenshot is taken.
"""

from __future__ import annotations

import re
from collections.abc import Callable

MASK = "[redacted]"

# JSON / form field names that hold personal or financial data ("name" alone is too generic: products,
# parameters and files have names too)
PII_KEYS = (
    r"first_?name|last_?name|full_?name|middle_?name|sur_?name|given_?name|family_?name|customer_?name|"
    r"holder_?name|card_?holder(?:_?name)?|contact_?name|legal_?name|maiden_?name|"
    r"address(?:_?line_?\d)?|street(?:_?address)?|home_?address|billing_?address|shipping_?address|"
    r"post_?code|postal_?code|zip_?code|zip|"
    r"dob|date_?of_?birth|birth_?date|birthday|"
    r"phone(?:_?number)?|mobile(?:_?number)?|tel(?:ephone)?|"
    r"ssn|social_?security(?:_?number)?|national_?id|passport(?:_?number)?|tax_?id|nin|"
    r"iban|bic|swift|account_?number|acct_?(?:no|num)|routing_?number|sort_?code|bank_?account|"
    r"card_?number|cc_?number|credit_?card|pan|cvv|cvc|cvv2|card_?expiry|exp(?:iry)?_?date"
)
_KEY_RX = re.compile(rf"(?i)^(?:{PII_KEYS})$")


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
    return f"{m.group(1)[0]}***@{m.group(2)}"


def _mask_card(m: re.Match) -> str:
    digits = re.sub(r"\D", "", m.group(0))
    if not (13 <= len(digits) <= 19) or not _luhn(digits):
        return m.group(0)
    return "**** **** **** " + digits[-4:]


def _mask_iban(m: re.Match) -> str:
    raw = re.sub(r"\s", "", m.group(0))
    return f"{raw[:2]}** **** {raw[-4:]}"


def _mask_phone(m: re.Match) -> str:
    if len(re.sub(r"\D", "", m.group(0))) < 7:
        return m.group(0)
    return re.sub(r"\d(?=[\d\s().-]{2,})", "*", m.group(0))


RULES: list[tuple[str, re.Pattern[str], Callable[[re.Match], str] | str]] = [
    # "lastName": "Smith"  /  "cvv": 123   (JSON and JS objects)
    ("pii-field", re.compile(rf'(?i)(["\']?\b(?:{PII_KEYS})\b["\']?\s*:\s*)("[^"\n]{{1,200}}"|\'[^\'\n]{{1,200}}\'|(?:\d[\d -]{{0,30}}\d|\d)(?![\w.:/]))'),
     lambda m: m.group(1) + (f'"{MASK}"' if m.group(2)[:1] in "\"'" else MASK)),
    # first_name=John  (form bodies / query strings in evidence)
    ("pii-param", re.compile(rf"(?i)(?<![\w-])((?:{PII_KEYS})=)([^&\s'\"<]{{1,200}})"), lambda m: m.group(1) + MASK),
    ("email", re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"), _mask_email),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?\b"), _mask_iban),
    ("card", re.compile(r"(?<![\d-])(?:\d{4}([ -]?)\d{4}\1\d{4}\1\d{1,7}|\d{4}[ -]?\d{6}[ -]?\d{4,5})(?![\d-])"), _mask_card),
    ("ssn", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"), "***-**-****"),
    ("phone", re.compile(r"(?<![\w.])(?:\+\d{1,3}[\s-]?)?(?:\(\d{2,4}\)[\s-]?|\d{3}[\s-])\d{3,4}[\s-]?\d{0,4}(?![\w.])"),
     _mask_phone),
]


def redact(text: str | None) -> str | None:
    """Mask personal data in free text. Idempotent; technical values are left alone."""
    if not text:
        return text
    for _name, rx, repl in RULES:
        text = rx.sub(repl, text)
    return text


# identifiers and technical fields that never contain personal data (and must stay exact)
KEEP_KEYS = {"fingerprint", "severity", "confidence", "check", "cwe", "owasp", "url", "poc_screenshot", "payload",
             "parameter", "location", "method", "tags", "references", "remediation", "phase", "cvss"}


def redact_obj(obj, key: str | None = None):
    """Recursively mask personal data in a JSON-like structure."""
    if isinstance(obj, str):
        if key and _KEY_RX.match(key):  # {"lastName": "Smith"} as a parsed structure
            return MASK
        return redact(obj)
    if isinstance(obj, list):
        return [redact_obj(x, key) for x in obj]
    if isinstance(obj, dict):
        return {k: (v if k in KEEP_KEYS else redact_obj(v, k)) for k, v in obj.items()}
    if isinstance(obj, int | float) and not isinstance(obj, bool) and key and _KEY_RX.match(key):
        return MASK
    return obj


def is_recon(finding: dict) -> bool:
    """Recon-phase results (asset inventory, fingerprints, exposed services) are reported unmasked."""
    return (finding.get("context") or {}).get("phase") == "recon"


# assessment metadata that is free text written about the findings; everything else in the metadata is
# recon / inventory data (hosts, URLs, technologies, coverage) and stays as collected
NARRATIVE_META = ("narrative", "attack_chains", "issues")


def redact_meta(meta: dict) -> dict:
    return {k: (redact_obj(v) if k in NARRATIVE_META else v) for k, v in meta.items()}


def redact_finding(finding: dict) -> dict:
    return finding if is_recon(finding) else redact_obj(finding)


# Browser-side blur of the same personal data - applied right before every PoC screenshot.
BLUR_JS = r"""() => {
  const KEYS = '__PII_KEYS__';
  const rules = [
    new RegExp('(["\']?\\b(?:' + KEYS + ')\\b["\']?\\s*:\\s*)("[^"\\n]{1,200}"|\'[^\'\\n]{1,200}\'|(?:\\d[\\d -]{0,30}\\d|\\d)(?![\\w.:/]))', 'gi'),
    new RegExp('(?<![\\w-])((?:' + KEYS + ')=)([^&\\s\'"<]{1,200})', 'gi'),
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?\b/g,
    /(?<![\d-])(?:\d{4}([ -]?)\d{4}\1\d{4}\1\d{1,7}|\d{4}[ -]?\d{6}[ -]?\d{4,5})(?![\d-])/g,
    /(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)/g,
    /(?<![\w.])(?:\+\d{1,3}[\s-]?)?(?:\(\d{2,4}\)[\s-]?|\d{3}[\s-])\d{3,4}[\s-]?\d{0,4}(?![\w.])/g,
  ];
  const keyRx = new RegExp('^(?:' + KEYS + ')$', 'i');
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
        if (idx <= 1) start += m[1].length;                                  // keep the field name readable
        if (idx === 4 && !luhn(m[0])) continue;
        if (idx === 6 && m[0].replace(/\D/g, '').length < 7) continue;
        if (end > start) spans.push([start, end]);
      } });
    // <td>Smith</td> next to a "Last name" label / column header
    const label = node.parentElement && node.parentElement.previousElementSibling;
    if (!spans.length && label && keyRx.test((label.textContent || '').trim().replace(/[\s:-]+/g, '_'))) {
      spans.push([text.search(/\S/), text.trimEnd().length]);
    }
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
  const AUTOCOMPLETE = /^(name|given-name|family-name|additional-name|street-address|address-line\d|postal-code|tel|email|bday|cc-number|cc-csc|cc-exp|cc-name)$/i;
  for (const el of document.querySelectorAll('input, textarea')) {
    const n = (el.getAttribute('name') || el.id || '').replace(/[\[\]-]/g, '_');
    if (el.type === 'email' || el.type === 'tel' || AUTOCOMPLETE.test(el.getAttribute('autocomplete') || '')
        || keyRx.test(n)) {
      if (el.value) { el.style.filter = 'blur(5px)'; count++; }
    }
  }
  return count;
}""".replace("__PII_KEYS__", PII_KEYS.replace("\\", "\\\\"))
