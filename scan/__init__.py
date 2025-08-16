# scan package

from . import tcp_connect
from .syn_scan import syn_scan
from .ack_scan import ack_scan

# Alias opcional para la función (compatibilidad)
from .tcp_connect import tcp_connect as tcp_connect_fn

__all__ = ["tcp_connect", "tcp_connect_fn", "syn_scan", "ack_scan"]

