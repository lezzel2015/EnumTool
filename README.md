# EnumTool

Herramienta de enumeración y escaneo para redes internas orientada a labores de pentesting.
Permite descubrir hosts, escanear puertos y realizar fingerprinting de servicios mediante
módulos independientes.

## Instalación

```bash
  pip install -r requirements.txt
```

## Uso básico

python3 EnumTool.py [acción] [opciones]

## Modos y Técnicas

- discovery: ARP, TCP, UDP, ICMP
- scan: TCP, SYN, ACK
- fingerprint: Banner grab, OS detection, HTTP headers

## 🎛️ Acciones y opciones de EnumTool

### 1. 🔹Acciones (mutuamente excluyentes)

| Flag  | Categoría   | Técnica        | Módulo                             |
|-------|-------------|----------------|------------------------------------|
| `-dA` | Discovery   | `arp_ping`     | `discovery/arp_ping.py`            |
| `-dI` | Discovery   | `icmp_ping`    | `discovery/icmp_ping.py`           |
| `-dT` | Discovery   | `tcp_ping`     | `discovery/tcp_ping.py`            |
| `-dU` | Discovery   | `udp_ping`     | `discovery/udp_ping.py`            |
| `-sT` | Scan        | `tcp_connect`  | `scan/tcp_connect.py`              |
| `-sS` | Scan        | `syn_scan`     | `scan/syn_scan.py`                 |
| `-sA` | Scan        | `ack_scan`     | `scan/ack_scan.py`                 |
| `-B`  | Fingerprint | `banner_grab`  | `fingerprint/banner_grab.py`       |
| `-V`  | Fingerprint | `os_detection` | `fingerprint/os_detection_plus.py` |
| `-H`  | Fingerprint | `http_headers` | `fingerprint/http_headers.py`      |

---

### 2. 🟩 Parámetros Comunes

| Flag                | Opciones            | Descripción                                        |
|---------------------|---------------------|----------------------------------------------------|
| `-i`, `--interface` |                     | Interfaz de red (obligatorio con `-dA`)            |
| `-t`, `--target`    |                     | IP, rango o red objetivo                           |
| `-p`, `--port`      |                     | Puerto/s destino (e.g. `22,80`, `20-25`)           |
| `--port-all`        |                     | Escanear todos los puertos TCP (1-65535)           |
| `--top N`           |                     | Escanear los N puertos TCP más frecuentes (N≤1000) |
| `--profile`         | {web,windows,linux} | perfiles de puertos predefinidos                   |
| `--timeout`         |                     | Tiempo de espera por paquete (defecto 0.5s)        |
| `--threads`         |                     | Hilos concurrentes (defecto 5, recomendado ≤10)    |
| `-S`, `--sumary`    |                     | Mostrar resumen final de la ejecución              |
| `--format`          | {text,json}         | formato del resumen (texto o json)                 |
| `--output FICHERO`  |                     | Volcar el resumen a un archivo ("append")            |


---

### 3. 🟨 Parámetros Especiales `-H` (HTTP Header Analysis)

| Flag           | Description                                                                                  |
|----------------|----------------------------------------------------------------------------------------------|
| `--http`       | Forzar HTTP (no TLS) en todos los puertos escaneados en opción -H                            |
| `--https`      | Forzar HTTPS (TLS) en todos los puertos escaneados en opción -H                              |
| *(none)*       | Auto detección de protocolo basado en número de puerto (80 → HTTP, 443 → HTTPS) en opción -H |
| --insecure-tls | deshabilitar la validación TLS en opción -B                                                  |

---

### Ejemplos de uso

```bash
  sudo python3 EnumTool.py -dA -i eth0 -t 192.168.1.0/24
  sudo python3 EnumTool.py -sT -t 192.168.1.10-15 -p 22,80,443
  sudo python3 EnumTool.py -sS -t 10.0.0.5 --top 100
  sudo python3 EnumTool.py -B -t 10.0.0.5 -p 80,443 --insecure-tls
  sudo python3 EnumTool.py -H -t 10.0.0.5 --https
  sudo python3 EnumTool.py -V -t 10.0.0.5 -p 80,443 --summary --format json --output resultados.log
```


### ⚠️ Avisos

- `--interface` es **obligatorio solo para `-dA`**.
- `--target` es obligatorio para **todas las técnicas**.
- Los flag de acción (e.g. `-sT`, `-B`) son **mútuamente exclusivos**.
- Para evitar fallos de Scapy al usar muchos hilos se recomienda `--threads ≤ 10`.
- Algunas técnicas requieren privilegios de root (ARP, ICMP, UDP ping, SYN y ACK scan).

