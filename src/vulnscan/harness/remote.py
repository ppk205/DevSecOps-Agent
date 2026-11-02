"""Token-protected HTTP relay for a host; all gate authority stays in Python."""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import secrets
import socket
import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from sse_starlette.sse import EventSourceResponse

from vulnscan.providers.credentials import redact, redact_value

from .host import MAX_LINE_BYTES, PROTOCOL, SessionHost


def issue_token() -> str:
    return secrets.token_urlsafe(32)


def remote_url(port: int, token: str) -> str:
    return f"http://127.0.0.1:{port}/app/remote#t={token}"


def _json(value: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(redact_value(value), status_code=status)


def _same_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    if not origin:
        return True
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    return parsed.scheme == request.url.scheme and parsed.netloc == request.url.netloc


def _equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def create_remote_app(host: SessionHost, token: str, spa_dir: Path | None) -> FastAPI:
    """State GET bootstraps csrf_token even before login (401 until authenticated)."""
    from .rpc import RPCController

    closing = threading.Event()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        closing.set()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.clock = time.monotonic
    app.state.issued_at = app.state.clock()
    app.state.login_token = token
    app.state.used = False
    app.state.stop = closing
    login_lock = threading.Lock()
    # Only hashes would suffice, but these random cookies live solely in this
    # process and are never emitted in events, logs or response JSON.
    clients: dict[str, str] = {}
    controller = RPCController(lambda event: None, host)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError) -> Response:
        return _json({"ok": False, "error": "invalid request parameters"}, 422)

    def authenticated(request: Request) -> str | None:
        cookie = request.cookies.get("devsec_remote", "")
        return cookie if cookie in clients else None

    @app.middleware("http")
    async def protection(request: Request, call_next: Any) -> Response:
        csrf = request.cookies.get("csrf_token") or secrets.token_urlsafe(32)
        request.state.csrf_token = csrf
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            supplied = request.headers.get("X-CSRF-Token", "")
            if not _same_origin(request) or not supplied or not _equal(supplied, csrf):
                return _json({"ok": False, "error": "Invalid CSRF token"}, 403)
            cookie = authenticated(request)
            if cookie and not _equal(csrf, clients[cookie]):
                return _json({"ok": False, "error": "Invalid CSRF token"}, 403)
        response: Response = await call_next(request)
        response.set_cookie(
            "csrf_token",
            csrf,
            httponly=False,
            samesite="strict",
            path="/",
            secure=request.url.scheme == "https",
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    async def body(request: Request) -> dict[str, Any] | None:
        chunks = bytearray()
        async for chunk in request.stream():
            if len(chunks) + len(chunk) > MAX_LINE_BYTES:
                return None
            chunks.extend(chunk)
        try:
            value = json.loads(chunks)
        except (ValueError, UnicodeError):
            return None
        return value if isinstance(value, dict) else None

    @app.post("/api/remote/login")
    async def login(request: Request) -> Response:
        value = await body(request)
        supplied = value.get("token") if value else None
        with login_lock:
            if (
                app.state.used
                or app.state.clock() - app.state.issued_at >= 600
                or not isinstance(supplied, str)
                or not _equal(supplied, token)
            ):
                return _json({"ok": False, "error": "login token expired or already used"}, 401)
            app.state.used = True
            cookie = secrets.token_urlsafe(32)
            clients[cookie] = request.state.csrf_token
        response = _json({"ok": True, "csrf_token": request.state.csrf_token})
        response.set_cookie(
            "devsec_remote",
            cookie,
            httponly=True,
            samesite="strict",
            path="/",
            secure=request.url.scheme == "https",
        )
        return response

    @app.get("/api/remote/state")
    async def state(request: Request) -> Response:
        if authenticated(request) is None:
            return _json(
                {"ok": False, "error": "login required", "csrf_token": request.state.csrf_token},
                401,
            )
        return _json({**host.state(), "csrf_token": request.state.csrf_token})

    @app.post("/api/remote/messages")
    async def messages(request: Request) -> Response:
        cookie = authenticated(request)
        if cookie is None:
            return _json({"ok": False, "error": "login required"}, 401)
        value = await body(request)
        if value is None:
            return _json({"ok": False, "error": "invalid or oversized JSON object"}, 400)
        value.setdefault("protocol", PROTOCOL)
        try:
            detach = host.attach(cookie, "web")
        except ValueError:
            return _json({"ok": False, "error": "host is closed"}, 409)
        try:
            # Commands may touch disk or start a server. Keep the event loop
            # available to drain SSE while this relay dispatches them.
            result = await asyncio.to_thread(controller.handle, value, cookie)
            return _json(result)
        finally:
            detach()

    @app.get("/api/remote/events")
    async def events(request: Request, after: int = 0) -> Response:
        cookie = authenticated(request)
        if cookie is None:
            return _json({"ok": False, "error": "login required"}, 401)
        if not _same_origin(request):
            return _json({"ok": False, "error": "invalid origin"}, 403)
        try:
            cursor = max(0, after, int(request.headers.get("last-event-id", "0")))
        except ValueError:
            return _json({"ok": False, "error": "invalid event cursor"}, 400)

        async def stream() -> AsyncIterator[dict[str, str]]:
            nonlocal cursor
            loop = asyncio.get_running_loop()
            changed = asyncio.Event()

            def wake(event: dict[str, Any]) -> None:
                if not loop.is_closed():
                    loop.call_soon_threadsafe(changed.set)

            unsubscribe = host.subscribe(wake)
            detach = host.attach(cookie, "web") if not host.closed else lambda: None
            try:
                while True:
                    # Subscribe before reading, clear before replay: publication
                    # racing either edge is replayed or wakes the next read.
                    changed.clear()
                    for event in host.events_after(cursor):
                        cursor = event["seq"]
                        yield {"id": str(cursor), "data": json.dumps(redact_value(event))}
                    if host.closed or closing.is_set() or await request.is_disconnected():
                        break
                    try:
                        await asyncio.wait_for(changed.wait(), timeout=1)
                    except TimeoutError:
                        pass
            finally:
                unsubscribe()
                detach()

        return EventSourceResponse(stream(), ping=15)

    if spa_dir is not None and spa_dir.is_dir():
        root = spa_dir.resolve()

        @app.get("/app/{full_path:path}")
        async def spa(full_path: str) -> Response:
            candidate = (root / full_path).resolve()
            if not candidate.is_relative_to(root) or ".." in Path(full_path).parts:
                return _json({"error": "not found"}, 404)
            if candidate.is_file():
                return FileResponse(candidate)
            index = root / "index.html"
            if index.is_file():
                return FileResponse(index, media_type="text/html")
            return _json({"error": "web UI is not built"}, 404)

    return app


def default_spa_dir() -> Path | None:
    for directory in (
        Path(__file__).resolve().parents[1] / "web/static/app",
        Path(__file__).resolve().parents[3] / "web-ui/dist",
    ):
        if (directory / "index.html").is_file():
            return directory
    return None


def _is_loopback(bind: str) -> bool:
    try:
        return ipaddress.ip_address(bind).is_loopback
    except ValueError:
        return bind.lower() == "localhost"


class RemoteServer:
    """Bind a local relay with readiness notification; no provider is started."""

    def __init__(
        self,
        host: SessionHost,
        *,
        bind: str = "127.0.0.1",
        port: int = 0,
        allow_lan: bool = False,
        spa_dir: Path | None = None,
    ) -> None:
        if not _is_loopback(bind) and not allow_lan:
            raise ValueError("non-loopback binding requires --remote-allow-lan")
        self.host, self.bind, self.port = host, bind, port
        self.token = issue_token()
        self.app = create_remote_app(host, self.token, spa_dir or default_spa_dir())
        self._thread: threading.Thread | None = None
        self._socket: socket.socket | None = None
        self._server: uvicorn.Server | None = None
        self.url = ""

    def start(self) -> None:
        ready = threading.Event()

        class Server(uvicorn.Server):
            async def startup(self, sockets: list[socket.socket] | None = None) -> None:
                await super().startup(sockets)
                ready.set()

        sock = socket.socket(
            socket.AF_INET6 if ":" in self.bind else socket.AF_INET, socket.SOCK_STREAM
        )
        try:
            sock.bind((self.bind, self.port))
            sock.listen(128)
            self.port = sock.getsockname()[1]
            self._socket = sock
            config = uvicorn.Config(self.app, log_level="warning", access_log=False)
            server = Server(config)
            self._server = server

            def run() -> None:
                try:
                    server.run(sockets=[sock])
                finally:
                    ready.set()

            self._thread = threading.Thread(target=run, daemon=True)
            self._thread.start()
            if not ready.wait(10) or not server.started:
                raise RuntimeError("remote server did not start")
            self.url = remote_url(self.port, self.token)
        except BaseException:
            self.close()
            sock.close()
            raise

    def close(self) -> None:
        self.app.state.stop.set()
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)
        if self._socket is not None:
            self._socket.close()

    def wait(self, timeout: float | None = None) -> None:
        """Keep a headless CLI alive until shutdown or its KeyboardInterrupt."""
        if self._thread is not None:
            self._thread.join(timeout=timeout)


def run_headless(
    *,
    target: Path,
    model: str | None = None,
    provider: str | None = None,
    mode: str = "ask",
    budget: float = 50.0,
    resume: Path | None = None,
    sessions_dir: Path = Path(".devsec/sessions"),
    laya_config: Path = Path("config/laya.json"),
    port: int = 0,
    remote_host: str = "127.0.0.1",
    remote_allow_lan: bool = False,
) -> int:
    """CLI entry: serve HTTP before G0, wait for a client, and stop on Ctrl+C."""
    from .rpc import build_host

    if not _is_loopback(remote_host) and not remote_allow_lan:
        print("non-loopback binding requires --remote-allow-lan")
        return 2
    if not _is_loopback(remote_host):
        print("Warning: remote control is accessible on the LAN; keep the login link private.")
    host: SessionHost | None = None
    server: RemoteServer | None = None

    def emit(event: dict[str, Any]) -> None:
        if event.get("type") == "error":
            print(redact(str(event.get("message", "session error"))))

    try:
        options: dict[str, Any] = {
            "target": str(target),
            "model": model,
            "mode": mode,
            "budget": budget,
            "sessions_dir": str(sessions_dir),
            "laya_config": str(laya_config),
        }
        if provider is not None:
            options["provider"] = provider
        if resume is not None:
            options["resume"] = str(resume)
        host = build_host(options, emit)
        server = RemoteServer(host, bind=remote_host, port=port, allow_lan=remote_allow_lan)
        server.start()
        print(server.url, flush=True)
        # No synthetic TUI attachment. The HTTP stream owns human presence,
        # so even local auto mode waits if nobody has connected yet.
        host.enable_pending()
        host.start()
        server.wait()
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as exc:  # noqa: BLE001 - CLI reports failures without a traceback
        print(redact(f"remote unavailable: {exc}"))
        return 2
    finally:
        if server is not None:
            server.close()
        if host is not None:
            host.close()
