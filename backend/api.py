"""
ScamHunt 2.0 — REST API & Integration Gateway
==============================================
Zero-dependency HTTP REST API exposing the core AI/ML heuristic engine,
case management, and Section 65B legal evidence stamping services.

Endpoints:
  GET  /api/health       - Health status and engine capabilities
  POST /api/analyze      - Analyze message text, URLs, UPI IDs, or phone numbers
  GET  /api/cases        - List local incident cases
  POST /api/cases        - Create or update an incident case
  POST /api/export       - Generate Section 65B tamper-proof legal dossier

Usage:
  python api.py
  python api.py --port 8000
"""

import sys
import json
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import engine
import case_manager
import evidence_export

PORT = 8000

class ScamHuntAPIHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(204)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "" or path == "/api" or path == "/api/health":
            response = {
                "status": "healthy",
                "service": "ScamHunt Threat Defense Suite API",
                "version": "2.0",
                "offline_engine": True,
                "section_65b_supported": True,
                "endpoints": [
                    "GET  /api/health",
                    "POST /api/analyze",
                    "GET  /api/cases",
                    "POST /api/cases",
                    "POST /api/export"
                ]
            }
            self._set_headers(200)
            self.wfile.write(json.dumps(response, indent=2).encode("utf-8"))

        elif path == "/api/cases":
            cases = case_manager.list_cases()
            self._set_headers(200)
            self.wfile.write(json.dumps({"cases": cases, "count": len(cases)}, indent=2).encode("utf-8"))

        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Endpoint not found", "path": path}).encode("utf-8"))

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        try:
            body = json.loads(post_data.decode("utf-8")) if post_data else {}
        except Exception:
            body = {}

        if path == "/api/analyze":
            text = body.get("text", "")
            if not text and "url" in body:
                text = body["url"]

            if not text:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": "Missing 'text' or 'url' in request body"}).encode("utf-8"))
                return

            result = engine.analyze(text)
            self._set_headers(200)
            self.wfile.write(json.dumps(result, indent=2).encode("utf-8"))

        elif path == "/api/cases":
            case_id = body.get("case_id")
            title = body.get("title", "Digital Fraud Incident")
            notes = body.get("notes", "")
            indicators = body.get("indicators", [])
            case = case_manager.create_or_update_case(case_id=case_id, title=title, notes=notes, indicators=indicators)
            self._set_headers(201)
            self.wfile.write(json.dumps({"case": case}, indent=2).encode("utf-8"))

        elif path == "/api/export":
            case_data = body.get("case", {})
            dossier_text = evidence_export.generate_text_report(case_data)
            self._set_headers(200)
            self.wfile.write(json.dumps({
                "status": "success",
                "format": "Section 65B Compliant Text Dossier",
                "dossier": dossier_text
            }, indent=2).encode("utf-8"))

        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Endpoint not found", "path": path}).encode("utf-8"))

def run_server(port=PORT):
    server_address = ("", port)
    httpd = HTTPServer(server_address, ScamHuntAPIHandler)
    print("=" * 65)
    print("  SCAMHUNT 2.0 — THREAT DEFENSE & AI ENGINE REST API")
    print("=" * 65)
    print(f"  > API Server running on : http://localhost:{port}")
    print(f"  > Health Check Endpoint : http://localhost:{port}/api/health")
    print(f"  > Threat Scan Endpoint  : http://localhost:{port}/api/analyze")
    print("=" * 65)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nAPI Server stopped.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ScamHunt REST API Server")
    parser.add_argument("--port", type=int, default=PORT, help="Port to listen on (default 8000)")
    args = parser.parse_args()
    run_server(args.port)
