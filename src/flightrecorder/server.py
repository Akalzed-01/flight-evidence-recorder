import html
import re
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from .capsule import CapsuleError, CapsuleReader, inspect_capsule


def render_report_html(report: dict) -> str:
    def esc(value) -> str:
        return html.escape(str(value if value is not None else "—"))

    events = report.get("events", [])
    streams = report.get("streams", {})
    timeline = "".join(
        f"<tr><td>{esc(event.get('seq'))}</td><td>{esc(event.get('type'))}</td>"
        f"<td><code>{esc(event.get('data'))}</code></td></tr>"
        for event in events
    )
    process = report.get("process", {})
    git = report.get("git", {})
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Evidence capsule</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#172033;background:#f6f8fb}}
main,section{{background:white;border:1px solid #dbe2ee;border-radius:14px;padding:1rem;margin:1rem 0}}
.badge{{display:inline-block;padding:.25rem .6rem;border-radius:999px;background:#e8eefc;margin-right:.4rem;font-size:.9rem}}
pre,code{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f4f8;padding:.75rem;border-radius:8px}}
table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;border-bottom:1px solid #e6eaf0;padding:.5rem;vertical-align:top}}
.warning{{border-left:4px solid #c47f00;padding-left:.75rem}}
</style></head><body><main>
<h1>Evidence capsule</h1>
<p><span class="badge">{esc(report.get('read_state'))}</span><span class="badge">replay: {esc(report.get('replay_state'))}</span><span class="badge">LOOPBACK · READ-ONLY</span></p>
<p><strong>Attempt preserved.</strong> No process is started by this page. Hashes indicate internal consistency, not origin authenticity.</p>
</main>
<section><h2>Summary</h2><p>Original exit code: <strong>{esc(process.get('returncode'))}</strong></p>
<p>Duration: {esc(process.get('duration_s'))} s · Redactions before persistence: {esc(report.get('redactions', 0))}</p>
<p>Git before: {esc(git.get('before'))}<br>Git after: {esc(git.get('after'))}</p></section>
<section><h2>Timeline</h2><table><thead><tr><th>Seq</th><th>Event</th><th>Data</th></tr></thead><tbody>{timeline}</tbody></table></section>
<section><h2>stdout</h2><pre>{esc(streams.get('stdout',''))}</pre><h2>stderr</h2><pre>{esc(streams.get('stderr',''))}</pre></section>
<section><h2>Limitations</h2><ul>{''.join(f'<li>{esc(item)}</li>' for item in report.get('limitations', []))}</ul></section>
</body></html>"""


def serve_capsule(
    path: Path,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    access_token: str | None = None,
    on_ready: Callable[[tuple[str, int]], None] | None = None,
) -> None:
    if host != "127.0.0.1":
        raise ValueError("serve is loopback-only in v1")
    report = inspect_capsule(path)
    if report.get("read_state") == "invalid":
        raise CapsuleError(report.get("error", "invalid capsule"))
    payload = render_report_html(report).encode("utf-8")
    access_token = access_token or secrets.token_urlsafe(32)
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", access_token):
        raise ValueError("access_token must be a high-entropy URL-safe token")
    route = f"/{access_token}/"

    class Handler(BaseHTTPRequestHandler):
        def _send(self, body: bytes, include_body: bool) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if include_body:
                self.wfile.write(body)

        def do_GET(self) -> None:
            if urlsplit(self.path).path != route:
                self.send_error(404)
                return
            self._send(payload, True)

        def do_HEAD(self) -> None:
            if urlsplit(self.path).path != route:
                self.send_error(404)
                return
            self._send(payload, False)

        def do_POST(self) -> None:
            self.send_error(405, "read-only server")

        do_PUT = do_POST
        do_PATCH = do_POST
        do_DELETE = do_POST

        def log_message(self, format: str, *args) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    if on_ready:
        on_ready(server.server_address)
    try:
        server.serve_forever()
    finally:
        server.server_close()
