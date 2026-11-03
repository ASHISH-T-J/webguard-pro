"""Registry of active per-injection-point checks (name -> coroutine(ctx, point))."""

from webguard.detection.checks import advanced, client_side, hunting, server_side, sqli, xss

POINT_CHECKS = {
    "sqli": sqli.run,
    "nosqli": advanced.nosqli,
    "xss": xss.run,
    "ssti": server_side.ssti,
    "lfi": server_side.lfi,
    "cmdi": server_side.cmdi,
    "ssrf": server_side.ssrf,
    "redirect": client_side.open_redirect,
    "crlf": client_side.crlf,
    "anomaly": hunting.anomaly_fuzz,
}
