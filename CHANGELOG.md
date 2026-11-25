# Changelog

Cambios relevantes de EnumTool. La primera versión publicada es **0.1.0**.

## 0.1.0 — 2026-11-25

### Añadido
- Expansión de objetivos IPv4 desde direcciones, rangos, CIDR y listas; elimina duplicados y aplica un límite configurable.
- Validación de límites numéricos de la CLI y mensajes claros para errores al expandir objetivos.
- Pruebas de regresión para discovery, clasificación de escaneos, fingerprinting, límites de objetivos y argumentos de CLI.
- CI en Python 3.10, 3.11 y 3.12.

### Mejorado
- Discovery ICMP valida la respuesta y su dirección de origen.
- TCP Connect clasifica conexiones abiertas, cerradas y filtradas/desconocidas usando conexiones TCP del sistema.
- SYN y ACK scan clasifican las respuestas TCP e ICMP.
- Banner Grab intenta obtener banners solo en puertos confirmados como abiertos.
- HTTP Headers permite seleccionar HTTP/HTTPS y controlar la validación TLS.
- Los resúmenes conservan los resultados y la evidencia de fingerprinting.

### Verificación
- Suite automatizada: 85 pruebas aprobadas.
- GitHub Actions: pruebas aprobadas en Python 3.10, 3.11 y 3.12.
- Prueba manual en laboratorio VirtualBox: ARP, ICMP, TCP abierto/cerrado, cabeceras HTTP y banner de servicio.

Publicado con la etiqueta `v0.1.0` el 2026-11-25.
