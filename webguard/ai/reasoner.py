"""Reasoning engines that analyse the assessment state and decide the next actions.

The agent (``webguard.assessment.agent``) proposes *candidate actions* - concrete, pre-defined,
scope-enforced tests such as "inject sqli,lfi into GET /view?file" or "verify finding #3".
A reasoner chooses and orders them, explains why (the reasoning trace in the report), and
writes the narrative summary. Reasoners can never invent actions: anything they return that
is not in the candidate list is discarded, and all traffic still passes the scope guard.

Engines:

* ``LocalReasoner``   - built-in, deterministic. Expected-value ranking from NLP parameter /
                        page classification priors, knowledge-base facts and action cost.
* ``ClaudeReasoner``  - Anthropic Claude via the official ``anthropic`` SDK (optional extra).
* ``OllamaReasoner``  - any local model served by Ollama (``/api/chat`` with JSON schema output),
                        for fully offline / air-gapped engagements.

LLM engines fall back to the local reasoner on any error, timeout, refusal or invalid output.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field

import httpx

from webguard.models import Finding
from webguard.nlp import summarize

log = logging.getLogger("webguard.ai")

SYSTEM_PROMPT = """You are the planning component of WebGuard, an automated web application security \
assessment tool used by professional penetration testers and bug bounty hunters on targets they are \
authorised to test. The tool follows the OWASP Web Security Testing Guide.

At each step you receive (1) a JSON summary of what is known about the target - technologies, WAF, page \
types, parameters with their inferred meaning, findings so far, request budget - and (2) a list of \
candidate actions. Every candidate is a pre-built, non-destructive test with its own scope enforcement.

Choose the candidates to run next, most valuable first, the way an experienced tester would: test the \
most likely hypothesis for each input first (e.g. file-like parameters for path traversal, URL-like \
parameters for SSRF/open redirect, login endpoints for authentication bypass), favour attack surface \
that has not been covered yet, follow up on leads from earlier observations, avoid spending budget on \
low-value repetition, and slow down when a WAF or rate limiting is observed. Only use ids from the \
candidate list. Explain your reasoning briefly in "thought"."""

DECISION_SCHEMA = {
    "type": "object",
    "properties": {
        "thought": {"type": "string"},
        "selected": {"type": "array", "items": {"type": "string"}},
        "hypotheses": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["thought", "selected", "hypotheses"],
    "additionalProperties": False,
}

NARRATIVE_SCHEMA = {
    "type": "object",
    "properties": {
        "executive_summary": {"type": "string"},
        "key_risks": {"type": "array", "items": {"type": "string"}},
        "next_steps": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["executive_summary", "key_risks", "next_steps"],
    "additionalProperties": False,
}


@dataclass
class Candidate:
    id: str
    action: str
    target: str
    phase: str
    rationale: str
    priority: float  # local expected-value estimate (higher first)
    cost: int  # estimated requests

    def brief(self) -> dict:
        return {"id": self.id, "action": self.action, "target": self.target, "why": self.rationale,
                "prior": round(self.priority, 2), "cost": self.cost}


@dataclass
class Decision:
    thought: str
    selected: list[str]
    hypotheses: list[str] = field(default_factory=list)
    engine: str = "local"


class LocalReasoner:
    name = "local"

    def __init__(self, exhaustive: bool = False) -> None:
        self.exhaustive = exhaustive

    async def decide(self, phase: str, state: dict, candidates: list[Candidate], limit: int) -> Decision:
        if state.get("budgeted"):
            ranked = self._budgeted_rank(candidates)
        else:
            ranked = sorted(candidates, key=lambda c: (-c.priority, c.cost, c.id))
        chosen = ranked if self.exhaustive else ranked[:limit]
        if not chosen:
            return Decision("Nothing left to test in this phase.", [])
        top = chosen[:3]
        basis = "expected value per request (budgeted)" if state.get("budgeted") else "likelihood x impact"
        thought = (f"{phase}: {len(candidates)} candidate test(s). Prioritising by {basis}. "
                   + " ".join(f"[{c.action} {c.target}] {c.rationale}." for c in top))
        if len(chosen) > 3:
            thought += f" (+{len(chosen) - 3} more)"
        hyps = [c.rationale for c in top]
        return Decision(thought, [c.id for c in chosen], hyps)

    @staticmethod
    def _budgeted_rank(candidates: list[Candidate], decay: float = 0.6) -> list[Candidate]:
        """Greedy ranking for limited budgets: value per request, with diminishing returns per action type
        (the 5th CORS probe is worth much less than the first exposure probe)."""
        remaining = list(candidates)
        taken: dict[str, int] = {}
        ranked = []
        while remaining:
            best = max(remaining, key=lambda c: (c.priority * decay ** taken.get(c.action, 0) / max(1, c.cost) ** 0.5,
                                                 c.id))
            ranked.append(best)
            remaining.remove(best)
            taken[best.action] = taken.get(best.action, 0) + 1
        return ranked

    async def narrate(self, target: str, findings: list[Finding], chains: list[dict], coverage: dict) -> dict:
        return {"executive_summary": summarize.executive_summary(target, findings, chains, coverage),
                "key_risks": summarize.technical_summary(findings)[:8],
                "next_steps": _next_steps(findings, chains)}


def _next_steps(findings: list[Finding], chains: list[dict]) -> list[str]:
    steps = []
    if any(f.confidence.name == "TENTATIVE" for f in findings):
        steps.append("Manually verify tentative findings and anomaly leads (see reproduction commands).")
    if chains:
        steps.append(f"Demonstrate the highest-impact attack chain: {chains[0]['title']}.")
    if any(f.check in ("sqli", "auth", "nosqli") for f in findings):
        steps.append("Confirm injection impact with a dedicated tool (sqlmap commands are included in the report).")
    if any(f.check == "idor" for f in findings):
        steps.append("Re-test object access with two separate user accounts to confirm IDOR.")
    steps.append("Re-run the assessment after fixes to confirm remediation (webguard db new / fixed findings).")
    return steps


class _LLMReasoner(LocalReasoner):
    """Shared prompt building, validation and fallback for LLM engines."""

    name = "llm"
    max_candidates = 60

    def __init__(self) -> None:
        super().__init__(exhaustive=False)
        self.calls = 0
        self.failures = 0

    async def _complete(self, system: str, user: str, schema: dict) -> dict:
        raise NotImplementedError

    async def decide(self, phase: str, state: dict, candidates: list[Candidate], limit: int) -> Decision:
        fallback = await super().decide(phase, state, candidates, limit)
        if not candidates:
            return fallback
        shortlist = sorted(candidates, key=lambda c: -c.priority)[: self.max_candidates]
        user = json.dumps({
            "phase": phase,
            "select_at_most": limit,
            "state": state,
            "candidates": [c.brief() for c in shortlist],
        }, default=str)
        try:
            self.calls += 1
            data = await self._complete(SYSTEM_PROMPT, user, DECISION_SCHEMA)
            valid = {c.id for c in shortlist}
            selected = [i for i in data.get("selected", []) if i in valid][:limit]
            if not selected:
                raise ValueError("no valid candidate ids returned")
            return Decision(str(data.get("thought", ""))[:2000], selected,
                            [str(h)[:300] for h in data.get("hypotheses", [])][:10], engine=self.name)
        except Exception as exc:
            self.failures += 1
            log.warning("%s reasoner failed (%s); using local reasoner for this step", self.name, exc)
            fallback.thought = f"[{self.name} unavailable: {type(exc).__name__}] " + fallback.thought
            return fallback

    async def narrate(self, target: str, findings: list[Finding], chains: list[dict], coverage: dict) -> dict:
        local = await super().narrate(target, findings, chains, coverage)
        facts = {
            "target": target,
            "findings": [{"title": f.title, "severity": f.severity.name, "confidence": f.confidence.name,
                          "url": f.url, "parameter": f.parameter, "evidence": f.evidence[:300]}
                         for f in sorted(findings, key=lambda f: -f.severity)[:60]],
            "attack_chains": chains, "wstg_coverage": coverage, "draft_summary": local["executive_summary"],
        }
        system = ("You write the narrative sections of a professional web application penetration test report "
                  "for an authorised engagement. Be accurate and concise: only state what the findings support, "
                  "explain business impact in plain language for executives, and give prioritised next steps.")
        try:
            data = await self._complete(system, json.dumps(facts, default=str), NARRATIVE_SCHEMA)
            if data.get("executive_summary"):
                return {k: data.get(k) or local[k] for k in local}
        except Exception as exc:
            log.warning("%s narrative failed (%s); using local summary", self.name, exc)
        return local


class ClaudeReasoner(_LLMReasoner):
    """Claude via the official Anthropic SDK (``pip install anthropic``; credentials from the environment)."""

    name = "claude"

    def __init__(self, model: str = "claude-opus-5-5", effort: str = "high") -> None:
        super().__init__()
        import anthropic  # optional dependency

        self._anthropic = anthropic
        self.client = anthropic.AsyncAnthropic()
        self.model = model
        self.effort = effort

    async def _complete(self, system: str, user: str, schema: dict) -> dict:
        response = await self.client.beta.messages.create(
            model=self.model,
            max_tokens=16000,
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",  # re-run server-side on another model if a safety classifier declines
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config={"effort": self.effort, "format": {"type": "json_schema", "schema": schema}},
        )
        if response.stop_reason == "refusal":
            raise RuntimeError(f"model declined ({getattr(response.stop_details, 'category', None)})")
        if response.stop_reason == "max_tokens":
            raise RuntimeError("response truncated (max_tokens)")
        text = next((b.text for b in response.content if b.type == "text"), "")
        return json.loads(text)


class OllamaReasoner(_LLMReasoner):
    """Local model served by Ollama (e.g. ``ollama run qwen2.5:7b``) - fully offline."""

    name = "ollama"
    max_candidates = 30  # small local models do better with shorter prompts

    def __init__(self, model: str = "qwen2.5:7b", base_url: str | None = None, timeout: float = 180.0) -> None:
        super().__init__()
        self.model = model
        self.base_url = (base_url or os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434").rstrip("/")
        self.timeout = timeout

    async def _complete(self, system: str, user: str, schema: dict) -> dict:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            r = await client.post(f"{self.base_url}/api/chat", json={
                "model": self.model, "stream": False, "format": schema,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "options": {"temperature": 0},
            })
            r.raise_for_status()
            return json.loads(r.json()["message"]["content"])


def make_reasoner(spec: str | None, model: str | None = None, effort: str = "high") -> LocalReasoner:
    """'local' (default) | 'claude' | 'ollama' (optionally 'ollama:<model>')."""
    if not spec or spec == "local":
        return LocalReasoner()
    kind, _, inline_model = spec.partition(":")
    if kind in ("claude", "anthropic"):
        return ClaudeReasoner(model=model or inline_model or "claude-opus-5-5", effort=effort)
    if kind == "ollama":
        return OllamaReasoner(model=model or inline_model or "qwen2.5:7b")
    raise ValueError(f"unknown reasoner {spec!r} (use local, claude, or ollama[:model])")
