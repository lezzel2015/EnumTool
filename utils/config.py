# utils/config.py
# Fichero con constantes que no tienen que ver con services o ports

BANNER_PATTERNS = [
     # SSH: ejemplo "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2"
    (r"^SSH-(?P<proto>[\d\.]+)-(?P<product>[A-Za-z\-_]+)_(?P<version>[\w\.\-]+)", "ssh"),
    # SMTP: ejemplo "220 mail.example.com ESMTP Postfix 3.4.13"
    (r"^220[ -].*?SMTP.*?(?P<product>[A-Za-z0-9\-\._]+)/?(?P<version>[\w\.\-]+)?", "smtp"),
    # HTTP Server header
    (r"Server:\s*(?P<product>[\w\-/]+)\s*(?P<version>[\w\.\-]+)?", "http"),
    # HTTP X-Powered-By header
    (r"X-Powered-By:\s*(?P<product>[\w\-/]+)\s*(?P<version>[\w\.\-]+)?", "http"),
    # FTP: ejemplo "220 ProFTPD 1.3.5e Server"
    (r"^220.*?(?P<product>ProFTPD|vsftpd|FileZilla)\s*(?P<version>[\w\.\-]+)?", "ftp"),
]

PAYLOADS = {
    21: b"USER anonymous\r\n",                      # FTP
    23: b"\r\n",                                    # Telnet
    25: b"EHLO enumtool.local\r\n",                 # SMTP
    80: b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",  # HTTP
    110: b"USER test\r\n",                          # POP3
    143: b"a001 CAPABILITY\r\n",                    # IMAP
    443: b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", # HTTPS (TLS)
    993: b"\r\n",                                   # IMAPS
    995: b"\r\n",                                   # POP3S
}

