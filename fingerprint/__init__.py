# fingerprint package
from .banner_grab import grab_banner, banner_grab, clean_banner, extract_version
from .http_headers import http_headers
from .os_detection import os_detection

__all__ = [
    "grab_banner",
    "banner_grab",
    "clean_banner",
    "extract_version",
    "http_headers",   # módulo, no función
    "os_detection",
]

