"""FastAPI app for the xentry V1 web flow."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse
from starlette.responses import Response

from xentry.broker import BrokerError
from xentry.bundle import build_bundle
from xentry.db import connect, init_db
from xentry.extract import ArtifactText, ExtractorError, extract
from xentry.fetch import FetchError, bundle_sha256, fetch
from xentry.jobstore import (
    get_job,
    list_artifacts,
    list_jobs,
    list_steps,
    list_validations,
    now,
    request_cancel,
)
from xentry.runner import JobRunner
from xentry.security import constant_time_equal, new_token
from xentry.targets import by_cve, by_poc_url

ROOT = Path(__file__).resolve().parents[3]
TEMPLATES = ROOT / "src" / "xentry" / "web" / "templates"
STATIC = ROOT / "src" / "xentry" / "web" / "static"


class LinkCheckRequest(BaseModel):
    cve_url: str
    poc_url: str


class JobCreateRequest(BaseModel):
    cve_url: str
    poc_url: str
    check_id: str


DEFAULT_ALLOWED_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "testserver"})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _allowed_hosts(extra: str | None = None) -> frozenset[str]:
    configured = extra if extra is not None else os.environ.get("XENTRY_ALLOWED_HOSTS", "")
    hosts = {host.strip().lower() for host in configured.split(",") if host.strip()}
    return DEFAULT_ALLOWED_HOSTS | hosts


def _request_host(request: Request) -> str:
    return (request.url.hostname or "").lower()


def _origin_matches_authority(origin: str, request: Request) -> bool:
    if not origin or origin == "null":
        return False
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    try:
        origin_port = parsed.port
        request_port = request.url.port
    except ValueError:
        return False
    if origin_port is None:
        origin_port = 443 if parsed.scheme == "https" else 80
    if request_port is None:
        request_port = 443 if request.url.scheme == "https" else 80
    return parsed.hostname.lower() == _request_host(request) and origin_port == request_port


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        {"error": {"code": code, "message": message}},
        status_code=status,
    )


def _token_path(data_dir: Path) -> Path:
    path = data_dir / "instance" / "token"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(new_token(), encoding="utf-8")
        path.chmod(0o600)
    return path


def _raw_poc_url(target: Any) -> str:
    repo = target.poc.repository.removeprefix("https://github.com/")
    return f"https://raw.githubusercontent.com/{repo}/{target.poc.commit}/README.md"


def _link_check(cve_url: str, poc_url: str) -> dict[str, Any]:
    target_hint = by_poc_url(poc_url)
    cve = fetch(cve_url)
    poc = fetch(_raw_poc_url(target_hint) if target_hint is not None else poc_url)
    facts = extract(
        [
            ArtifactText("cve", cve.sha256, cve.text),
            ArtifactText("poc", poc.sha256, poc.text),
        ]
    )
    target = by_cve(facts.cve_id)
    if target is None:
        raise HTTPException(status_code=422, detail="unsupported target")
    normalized = poc_url.rstrip("/").removesuffix(".git")
    expected = target.poc.repository.rstrip("/").removesuffix(".git")
    if normalized != expected:
        raise HTTPException(status_code=422, detail="PoC does not match the target pin")
    bundle = bundle_sha256([cve, poc])
    check_id = uuid.uuid4().hex
    now_dt = datetime.now(UTC)
    return {
        "check_id": check_id,
        "cve_id": facts.cve_id,
        "target_id": target.target_id,
        "bundle_sha256": bundle,
        "created_at": now_dt.isoformat(),
        "expires_at": (now_dt + timedelta(minutes=30)).isoformat(),
        "plan": {
            "target_id": target.target_id,
            "cve_id": facts.cve_id,
            "base_image_id": target.base_image_id,
            "attacker_profile_id": target.attacker_profile_id,
            "network_profile_id": target.network_profile_id,
            "target_ports": list(target.target_ports),
            "nonce_path": target.nonce.path,
            "nonce_owner": target.nonce.owner,
            "nonce_mode": target.nonce.mode,
            "probe_step_id": target.probe_step_id,
            "poc_commit": target.poc.commit,
            "setup_sha256": target.setup_sha256,
        },
    }


def build_app(
    *,
    data_dir: Path,
    db_path: Path,
    broker_socket: Path,
    runner: JobRunner | None = None,
    allowed_hosts: str | None = None,
) -> FastAPI:
    hosts = _allowed_hosts(allowed_hosts)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        conn = init_db(db_path)
        conn.close()
        app.state.token = _token_path(data_dir).read_text(encoding="utf-8").strip()
        app.state.runner = runner or JobRunner(
            db_path=db_path,
            data_dir=data_dir,
            broker_socket=broker_socket,
            job_deadline_s=float(os.environ.get("XENTRY_JOB_DEADLINE_S", "7200")),
            target_deadlines={
                "php2shell": float(os.environ.get("XENTRY_JOB_TIMEOUT_PHP", "5400")),
                "gitlab": float(os.environ.get("XENTRY_JOB_TIMEOUT_GITLAB", "7200")),
                "dirtyfrag": float(os.environ.get("XENTRY_JOB_TIMEOUT_DIRTYFRAG", "5400")),
            },
        )
        app.state.runner.start()
        yield
        app.state.runner.stop()

    app = FastAPI(title="xentry", lifespan=lifespan)
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    templates = Jinja2Templates(directory=str(TEMPLATES))

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.method not in SAFE_METHODS:
            host = _request_host(request)
            if not host or host not in hosts:
                return _error(403, "host_invalid", "Host header is not allowed")
            origin = request.headers.get("origin")
            if origin is not None and not _origin_matches_authority(origin, request):
                return _error(403, "origin_invalid", "Origin does not match this host")

            token = getattr(request.app.state, "token", "")
            cookie = request.cookies.get("xentry_token", "")
            header = request.headers.get("x-xentry-csrf", "")
            if not token or not cookie:
                return _error(401, "token_missing", "missing token cookie")
            if not constant_time_equal(cookie, token):
                return _error(401, "token_invalid", "invalid token cookie")
            if not header or not constant_time_equal(header, token):
                return _error(403, "csrf_invalid", "missing or invalid CSRF header")

            media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if media_type != "application/json":
                return _error(400, "validation", "JSON content type required")
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def db() -> sqlite3.Connection:
        return connect(db_path)

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        conn = db()
        try:
            jobs = list_jobs(conn)
        finally:
            conn.close()
        response = templates.TemplateResponse(
            request,
            "index.html",
            {"jobs": jobs, "csrf": app.state.token},
        )
        if request.cookies.get("xentry_token") != app.state.token:
            response.set_cookie(
                "xentry_token",
                app.state.token,
                httponly=True,
                samesite="strict",
            )
        return response

    @app.get("/jobs/{job_id}", response_class=HTMLResponse)
    def job_page(request: Request, job_id: str) -> HTMLResponse:
        conn = db()
        try:
            job = get_job(conn, job_id)
            steps = list_steps(conn, job_id)
            validations = list_validations(conn, job_id)
            artifacts = list_artifacts(conn, job_id)
        finally:
            conn.close()
        if job is None:
            raise HTTPException(status_code=404, detail="unknown job")
        response = templates.TemplateResponse(
            request,
            "job.html",
            {
                "job": job,
                "steps": steps,
                "validations": validations,
                "artifacts": artifacts,
                "csrf": app.state.token,
            },
        )
        if request.cookies.get("xentry_token") != app.state.token:
            response.set_cookie(
                "xentry_token",
                app.state.token,
                httponly=True,
                samesite="strict",
            )
        return response

    @app.post("/api/links/check")
    def link_check(payload: LinkCheckRequest) -> dict[str, Any]:
        try:
            plan = _link_check(payload.cve_url, payload.poc_url)
        except FetchError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ExtractorError as exc:
            raise HTTPException(status_code=422, detail=exc.code) from exc
        conn = db()
        try:
            conn.execute(
                "INSERT INTO link_checks(check_id, cve_url, poc_url, cve_id, target_id, "
                "bundle_sha256, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?)",
                (
                    plan["check_id"],
                    payload.cve_url,
                    payload.poc_url,
                    plan["cve_id"],
                    plan["target_id"],
                    plan["bundle_sha256"],
                    plan["created_at"],
                    plan["expires_at"],
                ),
            )
            conn.commit()
        finally:
            conn.close()
        return plan

    @app.post("/api/jobs")
    def create_job_api(payload: JobCreateRequest) -> dict[str, Any]:
        conn = db()
        try:
            row = conn.execute(
                "SELECT * FROM link_checks WHERE check_id=?", (payload.check_id,)
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="unknown check")
            if row["used_at"] is not None:
                raise HTTPException(status_code=409, detail="check already used")
            timestamp = now()
            if row["expires_at"] < timestamp:
                raise HTTPException(status_code=409, detail="check expired")
            if row["cve_url"] != payload.cve_url or row["poc_url"] != payload.poc_url:
                raise HTTPException(status_code=409, detail="check URL mismatch")
            claimed = conn.execute(
                "UPDATE link_checks SET used_at=? WHERE check_id=? AND used_at IS NULL "
                "AND expires_at >= ?",
                (timestamp, payload.check_id, timestamp),
            )
            if claimed.rowcount != 1:
                raise HTTPException(status_code=409, detail="check already used")
            conn.commit()
            try:
                job_id = app.state.runner.submit(
                    payload.cve_url,
                    payload.poc_url,
                    check_id=payload.check_id,
                    bundle_sha256=str(row["bundle_sha256"]),
                )
            except BrokerError as exc:
                conn.execute(
                    "UPDATE link_checks SET used_at=NULL WHERE check_id=?",
                    (payload.check_id,),
                )
                conn.commit()
                status = 503 if exc.code == "broker_unavailable" else 409
                raise HTTPException(status_code=status, detail=exc.code) from exc
        finally:
            conn.close()
        return {"job_id": job_id, "state": "queued"}

    @app.get("/api/jobs")
    def jobs_api() -> dict[str, Any]:
        conn = db()
        try:
            return {"items": list_jobs(conn)}
        finally:
            conn.close()

    @app.get("/api/jobs/{job_id}")
    def job_api(job_id: str) -> dict[str, Any]:
        conn = db()
        try:
            job = get_job(conn, job_id)
            if job is None:
                raise HTTPException(status_code=404, detail="unknown job")
            return {
                "job": job,
                "steps": list_steps(conn, job_id),
                "validations": list_validations(conn, job_id),
            }
        finally:
            conn.close()

    @app.get("/api/jobs/{job_id}/steps")
    def steps_api(job_id: str) -> dict[str, Any]:
        conn = db()
        try:
            if get_job(conn, job_id) is None:
                raise HTTPException(status_code=404, detail="unknown job")
            return {"items": list_steps(conn, job_id)}
        finally:
            conn.close()

    @app.get("/api/jobs/{job_id}/validations")
    def validations_api(job_id: str) -> dict[str, Any]:
        conn = db()
        try:
            if get_job(conn, job_id) is None:
                raise HTTPException(status_code=404, detail="unknown job")
            return {"items": list_validations(conn, job_id)}
        finally:
            conn.close()

    @app.get("/api/jobs/{job_id}/evidence/{artifact_id}")
    def evidence_api(job_id: str, artifact_id: str) -> FileResponse:
        conn = db()
        try:
            row = conn.execute(
                "SELECT path, sha256 FROM artifacts WHERE id=? AND job_id=?",
                (artifact_id, job_id),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            raise HTTPException(status_code=404, detail="unknown artifact")
        path = Path(str(row["path"]))
        if not path.is_file():
            raise HTTPException(status_code=404, detail="artifact file missing")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != str(row["sha256"]):
            raise HTTPException(status_code=409, detail="artifact hash mismatch")
        return FileResponse(path, media_type="application/octet-stream", filename=path.name)

    @app.post("/api/jobs/{job_id}/cancel")
    def cancel_api(job_id: str) -> dict[str, Any]:
        conn = db()
        try:
            row = conn.execute(
                "SELECT outcome FROM jobs WHERE id=?", (job_id,)
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="unknown job")
            if row["outcome"] is not None:
                raise HTTPException(status_code=409, detail="job already finished")
            request_cancel(conn, job_id)
        finally:
            conn.close()
        return {"cancelled": True, "job_id": job_id}

    @app.get("/api/jobs/{job_id}/events")
    async def events_api(job_id: str) -> EventSourceResponse:
        conn = connect(db_path)
        try:
            exists = get_job(conn, job_id) is not None
        finally:
            conn.close()
        if not exists:
            raise HTTPException(status_code=404, detail="unknown job")

        async def stream() -> AsyncIterator[dict[str, str]]:
            last = ""
            while True:
                conn = connect(db_path)
                try:
                    job = get_job(conn, job_id)
                    steps = list_steps(conn, job_id)
                finally:
                    conn.close()
                payload = json.dumps(
                    {"job": job, "steps": steps},
                    sort_keys=True,
                    default=str,
                )
                if payload != last:
                    last = payload
                    yield {"event": "state", "data": payload}
                if job is None or job.get("outcome") is not None:
                    break
                await asyncio.sleep(1)

        return EventSourceResponse(stream())

    @app.get("/api/jobs/{job_id}/bundle")
    def bundle_api(job_id: str) -> JSONResponse:
        conn = db()
        try:
            try:
                bundle = build_bundle(conn, job_id)
            except KeyError as exc:
                raise HTTPException(status_code=404, detail="unknown job") from exc
        finally:
            conn.close()
        return JSONResponse(
            bundle,
            headers={
                "Content-Disposition": f'attachment; filename="xentry-{job_id}-bundle.json"'
            },
        )

    @app.post("/api/preflight")
    def preflight() -> dict[str, Any]:
        images = Path(
            os.environ.get("XENTRY_IMAGES_MANIFEST", ROOT / "var" / "images" / "build-results.json")
        )
        artifacts = Path(
            os.environ.get(
                "XENTRY_ARTIFACT_MANIFEST", ROOT / "var" / "artifacts" / "manifest.json"
            )
        )
        checks = {
            "broker_socket": broker_socket.exists(),
            "database": db_path.exists(),
            "images": images.exists(),
            "artifacts": artifacts.exists(),
        }
        return {"checks": checks, "ok": all(checks.values())}

    @app.get("/api/system")
    def system() -> dict[str, Any]:
        return {
            "version": "0.1.0",
            "broker_socket": str(broker_socket),
            "broker_available": broker_socket.exists(),
            "database": str(db_path),
        }

    return app


app = build_app(
    data_dir=Path(os.environ.get("XENTRY_DATA_DIR", ROOT / "var" / "instance")),
    db_path=Path(os.environ.get("XENTRY_DB_PATH", ROOT / "var" / "instance" / "xentry.db")),
    broker_socket=Path(os.environ.get("XENTRY_BROKER_SOCKET", "/run/xentry/broker.sock")),
)
