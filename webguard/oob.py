"""Out-of-band (OOB) interaction detection with a dynamically spawned interaction server.

Blind vulnerabilities (the server fetches a URL or resolves a host but shows nothing in the response)
are confirmed by giving every test its own unique callback host/URL and watching for interactions:

    test -> payload with unique id -> target makes a DNS / HTTP request -> poll -> correlate id -> finding

Providers (``--oob``):

* ``auto`` (default when ``--oob`` is given without a value): public interactsh server, falling back to
  a local listener if registration fails
* ``interactsh[:server]``: an interactsh server (public ``oast.*`` or self-hosted, ``--oob-token`` for auth).
  Interactions are encrypted for this session (RSA-OAEP + AES-CFB); requires ``cryptography``
* ``local[:ip[:port]]``: an HTTP listener spawned on this machine for the duration of the scan (labs,
  internal networks: the target must be able to reach ``ip:port``)
* ``<domain>``: your own Collaborator / interactsh domain; payloads are recorded for manual correlation
  (no polling)

Only *interactions caused by our unique ids* are reported. The payload ids are random and single-use.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import random
import socket
import string
import time
import uuid
from dataclasses import dataclass, field

import httpx

log = logging.getLogger("webguard.oob")
PUBLIC_SERVERS = ("oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me")
_ALPHA = string.ascii_lowercase + string.digits


def _rand(n: int) -> str:
    return "".join(random.choices(_ALPHA, k=n))


@dataclass
class Interaction:
    protocol: str  # dns / http / smtp / ...
    unique_id: str
    remote: str = ""
    timestamp: str = ""
    raw: str = ""


@dataclass
class Payload:
    """One single-use callback: ``host`` for DNS-style payloads, ``url`` for HTTP-style payloads."""

    id: str
    host: str
    url: str
    label: dict = field(default_factory=dict)  # what test sent it (check, url, parameter, payload)
    created: float = field(default_factory=time.time)


class Provider:
    name = "none"
    polls = False

    def __init__(self) -> None:
        self.payloads: dict[str, Payload] = {}

    async def start(self) -> None: ...

    async def close(self) -> None: ...

    def new_payload(self, label: dict) -> Payload:
        raise NotImplementedError

    async def poll(self) -> list[Interaction]:
        return []

    async def correlate(self) -> list[tuple[Payload, Interaction]]:
        """Interactions matched to the payload (and therefore the test) that caused them."""
        out = []
        for it in await self.poll():
            p = self.match(it)
            if p is not None:
                out.append((p, it))
        return out

    def match(self, it: Interaction) -> Payload | None:
        uid = it.unique_id.lower()
        return self.payloads.get(uid) or next((p for k, p in self.payloads.items() if k in uid), None)

    def describe(self) -> str:
        return self.name


# ----------------------------------------------------------------------------- static domain (manual)

class StaticDomain(Provider):
    """User-supplied Collaborator/interactsh domain: payloads recorded for manual correlation."""

    name = "static"

    def __init__(self, domain: str) -> None:
        super().__init__()
        self.domain = domain.strip(".")

    def new_payload(self, label: dict) -> Payload:
        pid = "wg" + _rand(10)
        p = Payload(pid, f"{pid}.{self.domain}", f"http://{pid}.{self.domain}/", label)
        self.payloads[pid] = p
        return p

    def describe(self) -> str:
        return f"{self.domain} (manual correlation)"


# ----------------------------------------------------------------------------- local listener

class LocalListener(Provider):
    """HTTP interaction listener spawned for the duration of the scan."""

    name = "local"
    polls = True

    def __init__(self, advertise: str | None = None, port: int = 0, bind: str = "0.0.0.0") -> None:
        super().__init__()
        self.bind, self.port, self.advertise = bind, port, advertise
        self._server: asyncio.base_events.Server | None = None
        self._hits: list[Interaction] = []

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.bind, self.port)
        self.port = self._server.sockets[0].getsockname()[1]
        if not self.advertise:
            self.advertise = _local_ip()
        log.info("OOB listener on %s:%s (advertised as %s)", self.bind, self.port, self.advertise)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.read(8192), 5)
            text = head.decode("latin-1", "replace")
            line = text.split("\r\n", 1)[0]
            parts = line.split(" ")
            path = parts[1] if len(parts) > 1 else ""
            peer = writer.get_extra_info("peername")
            self._hits.append(Interaction("http", path.strip("/").split("/")[0].split("?")[0].lower(),
                                          peer[0] if peer else "", time.strftime("%Y-%m-%dT%H:%M:%S"), text[:2000]))
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await writer.drain()
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            writer.close()

    def new_payload(self, label: dict) -> Payload:
        pid = "wg" + _rand(12)
        p = Payload(pid, self.advertise or "127.0.0.1", f"http://{self.advertise}:{self.port}/{pid}", label)
        self.payloads[pid] = p
        return p

    async def poll(self) -> list[Interaction]:
        hits, self._hits = self._hits, []
        return hits

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    def describe(self) -> str:
        return f"local listener http://{self.advertise}:{self.port}/"


def _local_ip() -> str:
    """Primary outbound interface address (no packets are sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # TEST-NET address: only selects a route
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


# ----------------------------------------------------------------------------- interactsh

class Interactsh(Provider):
    """Client for the interactsh protocol (register -> poll -> decrypt -> deregister)."""

    name = "interactsh"
    polls = True
    CORRELATION_LEN, NONCE_LEN = 20, 13

    def __init__(self, server: str | None = None, token: str | None = None, proxy: str | None = None,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        super().__init__()
        self.servers = [server] if server else list(PUBLIC_SERVERS)
        self.server = ""
        self.token = token
        self.correlation = _rand(self.CORRELATION_LEN)
        self.secret = str(uuid.uuid4())
        self._http = httpx.AsyncClient(timeout=15, proxy=proxy, transport=transport,
                                       headers={"Authorization": token} if token else None)
        self._key = None

    async def start(self) -> None:
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
        except ImportError as exc:
            raise RuntimeError("interactsh needs the 'cryptography' package: pip install 'webguard-pro[tls]'") from exc
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = self._key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)
        body = {"public-key": base64.b64encode(pem).decode(), "secret-key": self.secret,
                "correlation-id": self.correlation}
        errors = []
        for server in random.sample(self.servers, len(self.servers)):
            try:
                r = await self._http.post(f"https://{server}/register", json=body)
                if r.status_code == 200:
                    self.server = server
                    return
                errors.append(f"{server}: HTTP {r.status_code}")
            except httpx.HTTPError as exc:
                errors.append(f"{server}: {type(exc).__name__}")
        raise RuntimeError("interactsh registration failed (" + "; ".join(errors) + ")")

    def new_payload(self, label: dict) -> Payload:
        nonce = _rand(self.NONCE_LEN)
        uid = self.correlation + nonce
        host = f"{uid}.{self.server}"
        p = Payload(uid, host, f"http://{host}/", label)
        self.payloads[uid] = p
        return p

    def _decrypt(self, aes_key_b64: str, item: str) -> dict:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        key = self._key.decrypt(base64.b64decode(aes_key_b64),
                                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        blob = base64.b64decode(item)
        try:  # interactsh uses AES-CFB; newer cryptography releases moved CFB to the "decrepit" module
            from cryptography.hazmat.decrepit.ciphers.modes import CFB
        except ImportError:
            CFB = modes.CFB
        dec = Cipher(algorithms.AES(key), CFB(blob[:16])).decryptor()
        return json.loads((dec.update(blob[16:]) + dec.finalize()).decode("utf-8", "replace"))

    async def poll(self) -> list[Interaction]:
        if not self.server:
            return []
        try:
            r = await self._http.get(f"https://{self.server}/poll",
                                     params={"id": self.correlation, "secret": self.secret})
            data = r.json() if r.status_code == 200 else {}
        except (httpx.HTTPError, ValueError) as exc:
            log.debug("interactsh poll failed: %s", exc)
            return []
        out = []
        for item in data.get("data") or []:
            try:
                d = self._decrypt(data["aes_key"], item)
            except Exception as exc:  # corrupted / foreign entry
                log.debug("interactsh decrypt failed: %s", exc)
                continue
            out.append(Interaction(d.get("protocol", "?"), (d.get("unique-id") or d.get("full-id") or "").lower(),
                                   d.get("remote-address", ""), d.get("timestamp", ""), (d.get("raw-request") or "")[:2000]))
        return out

    async def close(self) -> None:
        if self.server:
            try:
                await self._http.post(f"https://{self.server}/deregister",
                                      json={"correlation-id": self.correlation, "secret-key": self.secret})
            except httpx.HTTPError:
                pass
        await self._http.aclose()

    def describe(self) -> str:
        return f"interactsh {self.server}"


# ----------------------------------------------------------------------------- factory

async def spawn(spec: str | None, token: str | None = None, proxy: str | None = None,
                transport: httpx.AsyncBaseTransport | None = None) -> Provider | None:
    """Create and start the provider described by ``--oob``. Returns None when OOB is off."""
    if not spec or spec in ("off", "none"):
        return None
    kind, _, rest = spec.partition(":")
    if kind in ("auto", "interactsh"):
        try:
            p: Provider = Interactsh(rest or None, token, proxy, transport)
            await p.start()
            return p
        except Exception as exc:
            if kind == "interactsh":
                raise
            log.warning("OOB: %s - falling back to a local listener", exc)
            kind, rest = "local", ""
    if kind == "local":
        ip, _, port = rest.partition(":")
        p = LocalListener(ip or None, int(port) if port else 0)
        await p.start()
        return p
    return StaticDomain(spec)
