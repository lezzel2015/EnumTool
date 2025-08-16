#tests/test_banner_grab_integration.py

import socketserver
import threading
from fingerprint import banner_grab


class TestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"220 TestServer 1.0\r\n")


def test_banner_grab_integration():
    with socketserver.TCPServer(("127.0.0.1", 0), TestHandler) as server:
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

