from __future__ import annotations

import argparse
import json
import platform
import subprocess
import tempfile
import threading
import urllib.request
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class PlatformFixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _send(self, status: int, body: bytes, content_type: str, *, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _authenticated(self) -> bool:
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        return jar.get("adverscope_platform_session") is not None

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/login":
            body = b"""<!doctype html><html><body><form method='post' action='/login'><input id='username' name='username'><input id='password' name='password' type='password'><button id='login-submit' type='submit'>Login</button></form></body></html>"""
            self._send(200, body, "text/html; charset=utf-8")
            return
        if self.path == "/chat":
            if not self._authenticated():
                self._send(302, b"", "text/plain", headers={"Location": "/login"})
                return
            body = b"""<!doctype html><html><body><textarea id='message'></textarea><button id='send'>Send</button><pre id='response'></pre><script>document.querySelector('#send').onclick=async()=>{const response=await fetch('/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:document.querySelector('#message').value})});const data=await response.json();document.querySelector('#response').textContent=data.response;};</script></body></html>"""
            self._send(200, body, "text/html; charset=utf-8")
            return
        self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        length = max(0, min(100_000, int(self.headers.get("Content-Length", "0"))))
        body = self.rfile.read(length)
        if self.path == "/login":
            self._send(302, b"", "text/plain", headers={
                "Location": "/chat",
                "Set-Cookie": "adverscope_platform_session=qualified; Max-Age=3600; HttpOnly; SameSite=Strict; Path=/",
            })
            return
        if self.path == "/api/chat" and self._authenticated():
            try:
                request = json.loads(body.decode("utf-8"))
                message = str(request.get("message") or "")
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send(400, b'{"error":"invalid"}', "application/json")
                return
            response = json.dumps({"response": f"qualified: {message}"}).encode("utf-8")
            self._send(200, response, "application/json")
            return
        if self.path == "/api/echo":
            self._send(200, body, "application/json")
            return
        self._send(401, b'{"error":"authentication required"}', "application/json")


def qualify(output_directory: Path, browser_executable: str = "") -> dict[str, object]:
    output_directory.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), PlatformFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        api_payload = b'{"message":"api-platform-qualified"}'
        request = urllib.request.Request(
            f"{base_url}/api/echo",
            data=api_payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            api_ok = response.status == 200 and response.read() == api_payload
        with tempfile.TemporaryDirectory(prefix="adverscope-platform-profile-") as profile_directory:
            process = subprocess.run(
                ["node", str(ROOT / "browser" / "platform-smoke.mjs")],
                input=json.dumps({
                    "base_url": base_url,
                    "output_directory": str(output_directory),
                    "profile_directory": profile_directory,
                    "browser_executable": browser_executable,
                }),
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        if process.returncode != 0:
            raise RuntimeError(f"browser platform qualification failed: {process.stderr.strip()[:1000]}")
        browser = json.loads(process.stdout)
        result: dict[str, object] = {
            "schema_version": "1.0",
            "platform": platform.platform(),
            "python": platform.python_version(),
            "api_target": "pass" if api_ok else "fail",
            "browser_capture": "pass" if all(item["bytes"] > 0 for item in browser["screenshots"]) else "fail",
            "screenshots": "pass" if len(browser["screenshots"]) == 4 else "fail",
            "persistent_session": "pass" if browser["persistent_session"] else "fail",
            "login_workflow": "pass" if browser["login_completed"] else "fail",
            "browser": browser,
        }
        result["ok"] = all(result[key] == "pass" for key in ("api_target", "browser_capture", "screenshots", "persistent_session", "login_workflow"))
        (output_directory / "platform-qualification.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return result
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description="Qualify AdverScope API and browser workflows on the current platform")
    parser.add_argument("--output", default="")
    parser.add_argument("--browser-executable", default="")
    args = parser.parse_args()
    if args.output:
        result = qualify(Path(args.output).expanduser().resolve(), args.browser_executable)
    else:
        with tempfile.TemporaryDirectory(prefix="adverscope-platform-") as directory:
            result = qualify(Path(directory), args.browser_executable)
    print(json.dumps({key: value for key, value in result.items() if key != "browser"}, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
