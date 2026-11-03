"""Benchmark WebGuard against OWASP Juice Shop (third-party, intentionally vulnerable).

    docker run -d -p 3000:3000 bkimminich/juice-shop
    python benchmarks/juice_shop.py [--url http://127.0.0.1:3000] [--budget-requests N] [--llm claude]

Ground truth: vulnerabilities that are reachable *without an account* and fall into classes WebGuard
tests (from the Juice Shop challenge list). Authenticated-only challenges (NoSQL review injection,
XXE via complaint upload, ...) are excluded; WebGuard reports those endpoints as a coverage gap.
The order-tracking reflected XSS (#/track-result?id) is excluded because the containerised build strips
'<' and '>' from the order id (verified manually: /rest/track-order/abc<iframe> -> "abciframe").
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from webguard.ai.reasoner import make_reasoner  # noqa: E402
from webguard.assessment.agent import AssessmentAgent  # noqa: E402
from webguard.config import ScanConfig  # noqa: E402
from webguard.models import Severity  # noqa: E402
from webguard.scope import Scope  # noqa: E402


def has(check, url_part="", text=""):
    return lambda fs: any(f.check == check and url_part in f.url and text.lower() in (f.title + f.evidence).lower()
                          for f in fs)


GROUND_TRUTH = [
    ("SQL injection in product search (/rest/products/search?q)", has("sqli", "/rest/products/search")),
    ("Login SQL injection auth bypass (/rest/user/login)", has("auth", "/rest/user/login")),
    ("DOM XSS via search query (#/search?q)", has("dom_xss")),
    ("Open redirect allow-list bypass (/redirect?to)", has("redirect", "/redirect")),
    ("Directory listing exposing confidential docs (/ftp)", has("exposure", "/ftp", "listing")),
    ("Exposed Prometheus metrics (/metrics)", has("exposure", "/metrics")),
    ("Password hashes exposed by API (/rest/memories)", has("data_exposure", "/rest/memories")),
    ("Swagger API documentation exposed (/api-docs)", lambda fs: any(f.check == "exposure" and "swagger" in f.title.lower() for f in fs)),
    ("CORS allows any origin", has("cors")),
    ("Verbose error messages / error handling", has("disclosure")),
    ("Sensitive data in JWT payload (password hash)", has("jwt", "", "sensitive claims")),
    ("Unlinked key material directory (/encryptionkeys)", lambda fs: any("/encryptionkeys" in f.url or "/encryptionkeys" in f.evidence for f in fs)),
    ("Exposed access logs directory (/support/logs)", lambda fs: any("/support/logs" in f.url or "/support/logs" in f.evidence for f in fs)),
    ("Public admin configuration endpoint (/rest/admin/application-configuration)",
     lambda fs: any("/rest/admin/application-configuration" in f.url and f.severity >= Severity.LOW for f in fs)),
    ("Missing security hardening headers", has("headers", "", "missing security headers")),
]


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:3000")
    ap.add_argument("--budget-requests", type=int)
    ap.add_argument("--rate", type=float, default=100)
    ap.add_argument("--llm", default="local")
    ap.add_argument("--out", default=str(Path(__file__).parent / "results"))
    args = ap.parse_args()
    cfg = ScanConfig(rate_limit=args.rate, concurrency=20, time_delay=3, model_path=Path("/nonexistent"))
    agent = AssessmentAgent(cfg, Scope.for_target(args.url), make_reasoner(args.llm),
                            budget_requests=args.budget_requests, on_status=lambda m: print("  ", m, flush=True))
    t0 = time.time()
    res = await agent.run(args.url)
    elapsed = time.time() - t0
    hits = [(name, bool(pred(res.findings))) for name, pred in GROUND_TRUTH]
    found = sum(ok for _, ok in hits)
    print(f"\nRecall: {found}/{len(GROUND_TRUTH)} ({found / len(GROUND_TRUTH):.0%}) in {elapsed:.0f}s, "
          f"{res.stats['requests']} requests, {len(res.findings)} findings")
    for name, ok in hits:
        print(f"  {'✔' if ok else '✘'} {name}")
    unmatched = [f for f in res.findings if f.severity >= Severity.MEDIUM and not any(
        pred([f]) for _, pred in GROUND_TRUTH)]
    print(f"\nMEDIUM+ findings outside the ground-truth list (review manually): {len(unmatched)}")
    for f in unmatched:
        print(f"  {f.severity.name:8} {f.confidence.name:9} {f.title} @ {f.url} {f.parameter or ''}")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    tag = f"juice-shop_{args.llm}_{args.budget_requests or 'full'}"
    (out / f"{tag}.json").write_text(json.dumps({
        "target": "OWASP Juice Shop (bkimminich/juice-shop:latest)", "reasoner": args.llm,
        "budget_requests": args.budget_requests, "seconds": round(elapsed, 1), "requests": res.stats["requests"],
        "recall": f"{found}/{len(GROUND_TRUTH)}", "ground_truth": dict(hits),
        "findings": [f"{f.severity.name} {f.confidence.name} {f.title} @ {f.url} {f.parameter or ''}" for f in res.findings],
        "unmatched_medium_plus": [f"{f.title} @ {f.url}" for f in unmatched],
        "trace": [t.to_dict() for t in res.trace], "facts": res.facts,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
