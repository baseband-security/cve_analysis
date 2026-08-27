#!/usr/bin/env python3
"""Serve the artifact explorer and generated JSON without external dependencies."""

from __future__ import annotations

import argparse
import json
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit


class ArtifactHandler(SimpleHTTPRequestHandler):
    web_root: Path
    data_root: Path

    def translate_path(self, path: str) -> str:
        request_path = unquote(urlsplit(path).path)
        if request_path in {"", "/"}:
            return str(self.web_root / "index.html")
        if request_path.startswith("/data/"):
            root = self.data_root
            relative = request_path.removeprefix("/data/")
        else:
            root = self.web_root
            relative = request_path.lstrip("/")
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            return str(root / "__not_found__")
        return str(candidate)

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if urlsplit(self.path).path == "/api/health":
            payload = json.dumps({"status": "ok", "data_dir": str(self.data_root)}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        super().do_GET()

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()


def main() -> None:
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--data-dir", type=Path, default=Path("outputs"))
    args = parser.parse_args()

    web_root = (root / "web").resolve()
    data_root = args.data_dir.resolve()
    required = data_root / "baseband_memory_cves.json"
    if not required.is_file():
        raise SystemExit(f"missing generated dataset: {required}")

    handler = type(
        "ConfiguredArtifactHandler",
        (ArtifactHandler,),
        {"web_root": web_root, "data_root": data_root},
    )
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"Baseband Memory Safety Bugs Overview: http://{args.host}:{args.port}", flush=True)
    print(f"Generated data: {data_root}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
