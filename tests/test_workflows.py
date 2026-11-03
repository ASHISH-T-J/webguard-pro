"""Hunt / attack-surface workflows with public recon sources stubbed (offline, deterministic)."""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

import pytest
from vulnapp import VulnServer

from webguard.config import ScanConfig
from webguard.db import Database
from webguard.models import Host, Severity
from webguard.recon import active, passive
from webguard.scope import Scope
from webguard.workflows import hunt as hunt_mod
from webguard.workflows.redteam import attack_mapping, attack_surface, prioritise


@pytest.fixture()
def server(monkeypatch):
    with VulnServer() as s:
        name = urlsplit(s.url).netloc  # "127.0.0.1:PORT" acts as the "domain"

        async def subs(domain, proxy=None, use_tools=True):
            return {"stub": {name}}

        async def history(domain, proxy=None, use_tools=True):
            return {f"{s.url}/view?file=x.txt", f"{s.url}/backup.sql"}

        async def resolve_many(hosts, concurrency=50):
            return {h: ["127.0.0.1"] for h in hosts}

        monkeypatch.setattr(passive, "enumerate_subdomains", subs)
        monkeypatch.setattr(passive, "historical_urls", history)
        monkeypatch.setattr(active, "resolve_many", resolve_many)
        yield s, name


def test_hunt_pipeline_and_continuous_diffing(server, tmp_path):
    s, name = server
    cfg = ScanConfig(rate_limit=1000, timing_checks=False, model_path=tmp_path / "m.json",
                     checks=("lfi", "xss", "exposure"))
    db = Database(tmp_path / "w.db")
    scope = Scope(include=[name])
    res = asyncio.run(hunt_mod.hunt(name, cfg, scope, db, tmp_path / "out", ["json", "md"], use_nuclei=False,
                                    use_tools=False, status=lambda m: None))
    checks = {f.check for f in res.findings}
    assert {"lfi", "xss", "exposure"} <= checks
    assert res.new_findings and len(res.reports) == 2
    assert res.ranking and res.ranking[0]["url"] == s.url
    assert db.assets(name, "endpoint") and db.assets(name, "param")
    # second run: nothing new
    res2 = asyncio.run(hunt_mod.hunt(name, cfg, scope, db, tmp_path / "out", ["json"], use_nuclei=False,
                                     use_tools=False, status=lambda m: None))
    assert res2.new_findings == []


def test_attack_surface_ports_and_attack_mapping(server, tmp_path, monkeypatch):
    s, name = server
    port = urlsplit(s.url).port
    real_scan = active.port_scan

    async def fake_port_scan(host, ports=None, timeout=2.0, concurrency=200):
        return await real_scan("127.0.0.1", [port, 1])  # real connect scan, limited to known ports

    monkeypatch.setattr(active, "port_scan", fake_port_scan)
    cfg = ScanConfig(rate_limit=1000, model_path=tmp_path / "m.json")
    db = Database(tmp_path / "w.db")
    res = asyncio.run(attack_surface(name, cfg, Scope(include=[name]), db, use_nmap=False, use_tools=False,
                                     status=lambda m: None))
    assert res.ports[name] == [port]
    assert res.recon.hosts and res.ranking
    for f in res.findings:
        assert attack_mapping(f)


def test_prioritise_ranks_juicy_hosts_first():
    hosts = [Host("https://www.example.com", 200, title="Welcome", waf=["Cloudflare"]),
             Host("https://jenkins-dev.example.com", 200, title="Dashboard [Jenkins]", technologies=["Jenkins 2.1"])]
    ranked = prioritise(hosts, {}, [])
    assert ranked[0]["url"] == "https://jenkins-dev.example.com"
    assert "interesting hostname" in ranked[0]["reasons"]


def test_exposed_service_findings():
    fs = active.exposed_service_findings("h.test", [443, 6379, 2375])
    assert {f.title.split(" port")[0] for f in fs} == {"Redis", "Docker API (unauthenticated)"}
    assert max(f.severity for f in fs) == Severity.CRITICAL


def test_hunt_scans_subdomains_in_parallel(tmp_path, monkeypatch):
    with VulnServer() as a, VulnServer() as b:
        names = [urlsplit(a.url).netloc, urlsplit(b.url).netloc]

        async def subs(domain, proxy=None, use_tools=True):
            return {"stub": set(names)}

        async def history(domain, proxy=None, use_tools=True):
            return set()

        async def resolve_many(hosts, concurrency=50):
            return {h: ["127.0.0.1"] for h in hosts}

        monkeypatch.setattr(passive, "enumerate_subdomains", subs)
        monkeypatch.setattr(passive, "historical_urls", history)
        monkeypatch.setattr(active, "resolve_many", resolve_many)
        cfg = ScanConfig(rate_limit=1000, timing_checks=False, model_path=tmp_path / "m.json",
                         checks=("lfi", "xss", "exposure"), browser=False)
        res = asyncio.run(hunt_mod.hunt(names[0], cfg, Scope(include=names), Database(tmp_path / "w.db"),
                                        tmp_path / "out", ["json"], use_nuclei=False, use_tools=False,
                                        parallel_hosts=2, screenshots=False, status=lambda m: None))
    assert len(res.host_results) == 2
    hosts_with_lfi = {urlsplit(f.url).netloc for f in res.findings if f.check == "lfi"}
    assert hosts_with_lfi == set(names)
