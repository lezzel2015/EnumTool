# tests/test_http_headers_contract.py

import fingerprint.http_headers as hh

def test_http_headers_shape(monkeypatch):
    def fake_get_http_headers(ip, port, timeout=3, use_https=None, insecure_tls=False):
        return {"Server": "nginx/1.25", "X-Powered-By": "PHP/8"}
    monkeypatch.setattr(hh, "get_http_headers", fake_get_http_headers)

    res = hh.http_headers("127.0.0.1", [80], timeout=0.2, use_https=None, insecure_tls=True)
    assert res["127.0.0.1"][80]["status"] == "OPEN"
    assert "headers" in res["127.0.0.1"][80]

