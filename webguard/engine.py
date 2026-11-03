"""Scan engine: the assessment agent run exhaustively with the deterministic local reasoner.

``webguard scan`` runs every applicable test (no budget, no LLM); ``webguard assess`` runs the
same methodology with budget-aware, reasoner-driven prioritisation. One code path, two modes.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx

from webguard.ai.reasoner import LocalReasoner
from webguard.assessment.agent import AssessmentAgent, AssessmentResult, injection_points
from webguard.config import ScanConfig
from webguard.models import Finding, Host
from webguard.scope import Scope
from webguard.signatures import SignatureDB

ScanResult = AssessmentResult
__all__ = ["ScanEngine", "ScanResult", "injection_points"]


class ScanEngine:
    def __init__(self, config: ScanConfig, scope: Scope, sigdb: SignatureDB | None = None,
                 transport: httpx.AsyncBaseTransport | None = None,
                 on_finding: Callable[[Finding], None] | None = None,
                 on_status: Callable[[str], None] | None = None) -> None:
        self.agent = AssessmentAgent(config, scope, LocalReasoner(exhaustive=True), sigdb, transport,
                                     on_finding=on_finding, on_status=on_status)

    async def scan(self, target: str, extra_urls: list[str] = (), hosts: list[Host] | None = None) -> ScanResult:
        return await self.agent.run(target, list(extra_urls), hosts)
