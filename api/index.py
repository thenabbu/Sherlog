from http.server import BaseHTTPRequestHandler
import json

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Sherlog - SOC Assessment Tool</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        a { color: #0066cc; }
    </style>
</head>
<body>
    <h1>Sherlog - SOC Assessment Tool</h1>
    <p>API endpoint: <a href="/api/health">/api/health</a></p>
</body>
</html>"""
        self.wfile.write(html.encode())
    
    def do_POST(self):
        self.do_GET()

if __name__ == "__main__":
    handler
