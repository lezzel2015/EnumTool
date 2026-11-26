#tests/test_banner_grab_integration.py

import socketserver
import threading
from fingerprint import banner_grab


class BannerHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"220 TestServer 1.0\r\n")


def test_banner_grab_integration():
    with socketserver.TCPServer(("127.0.0.1", 0), BannerHandler) as server:
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()

        result = banner_grab("127.0.0.1", [port], timeout=1, threads=1)

        server.shutdown()
        thread.join()

    assert "127.0.0.1" in result
    assert port in result["127.0.0.1"]
    entry = result["127.0.0.1"][port]
    assert entry["banner"].startswith("220 TestServer")
    assert entry["status"] == "OK"


class HttpVirtualHostHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.server.received_host = None
        self.rfile.readline()
        self.server.received_host = self.rfile.readline().decode().strip()
        self.wfile.write(
            b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )


def test_banner_grab_probes_http_virtual_host_on_nonstandard_port():
    with socketserver.TCPServer(("127.0.0.1", 0), HttpVirtualHostHandler) as server:
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        result = banner_grab(
            "127.0.0.1", [port], timeout=1, threads=1, http_host="geo.example.test"
        )

        server.shutdown()
        thread.join()

    entry = result["127.0.0.1"][port]
    assert server.received_host == "Host: geo.example.test"
    assert entry["detected_service"] == "http"
    assert entry["product"] == "nginx"


