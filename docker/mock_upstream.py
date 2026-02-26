from http.server import HTTPServer, BaseHTTPRequestHandler
import json


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        body = json.dumps(
            {
                "path": self.path,
                "method": "GET",
                "headers": dict(self.headers),
                "message": "Hello from mock upstream",
            }
        )
        self.wfile.write(body.encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body_in = self.rfile.read(length).decode() if length else ""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        body = json.dumps(
            {
                "path": self.path,
                "method": "POST",
                "headers": dict(self.headers),
                "body": body_in,
                "message": "Hello from mock upstream",
            }
        )
        self.wfile.write(body.encode())

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_GET

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()


HTTPServer(("0.0.0.0", 3000), Handler).serve_forever()
