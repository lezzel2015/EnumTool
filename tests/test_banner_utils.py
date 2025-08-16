#tests/test_banner_utils.py

from fingerprint.banner_grab import clean_banner, extract_version


def test_clean_banner():
    raw = "SSH-2.0-OpenSSH_7.9p1\r\nDebian\t"
    assert clean_banner(raw) == "SSH-2.0-OpenSSH_7.9p1 Debian"


def test_extract_version_ssh():
    version, product, proto = extract_version("SSH-2.0-OpenSSH_7.9p1 Debian")
    assert version == "7.9p1"
    assert product == "OpenSSH"
    assert proto == "ssh"


def test_extract_version_http():
    version, product, proto = extract_version("Server: Apache 2.4.41")
    assert version == "2.4.41"
    assert product == "Apache"
    assert proto == "http"


def test_extract_version_ftp():
    version, product, proto = extract_version("220 ProFTPD 1.3.5e Server")
    assert version == "1.3.5e"
    assert product == "ProFTPD"
    assert proto == "ftp"

