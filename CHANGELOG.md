# Changelog

Cambios relevantes de EnumTool. La primera versión publicada es **0.1.0**.

## 0.2.0 — 2026-11-27

### Mejorado
- Las pruebas HTTP permiten definir `Host` y SNI con `--http-host`, también en puertos no estándar.
- Banner Grab puede enviar una petición HTTP explícita a un puerto abierto cuando se indica `--http-host`.
- Los resultados distinguen el protocolo/producto detectado del nombre asignado al puerto en la tabla local.
- La detección de sistema operativo identifica la fuente de sus indicios y evita presentar el score o un banner como probabilidad concluyente.
- Los resúmenes de escaneo separan estados filtrados, no respuesta TCP, no filtrados, desconocidos y errores.
- Los timeouts conservan el estado `FILTERED` para mantener la clasificación compatible, pero indican explícitamente que no hubo respuesta.
- HTTP Headers muestra y conserva la línea de estado HTTP para facilitar la comparación con Banner Grab y otras herramientas.

### Verificación
- Suite local: 90 pruebas aprobadas en la rama de estabilización incorporada por el PR #6.
- GitHub Actions: pruebas aprobadas en Python 3.10, 3.11 y 3.12 para el PR #6.
- Pruebas manuales controladas: detección de hosts, escaneo TCP, cabeceras HTTP y banner grab; prueba de virtual host HTTP en puertos estándar y no estándar.
- Comparación de puertos abiertos con Nmap en una máquina de laboratorio autorizada.

### Mejorado
- Las pruebas HTTP permiten definir `Host` y SNI con `--http-host`, también en puertos no estándar.
- Banner Grab puede enviar una petición HTTP explícita a un puerto abierto cuando se indica `--http-host`.
- Los resultados distinguen el protocolo/producto detectado del nombre asignado al puerto en la tabla local.
- La detección de sistema operativo identifica la fuente de sus indicios y evita presentar el score o un banner como probabilidad concluyente.
- Los resúmenes de escaneo separan estados filtrados, no respuesta TCP, no filtrados, desconocidos y errores.
- Los timeouts conservan el estado `FILTERED` para mantener la clasificación compatible, pero indican explícitamente que no hubo respuesta.
- HTTP Headers muestra y conserva la línea de estado HTTP para facilitar la comparación con Banner Grab y otras herramientas.

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

