# EnumTool

Herramienta de enumeración y escaneo para redes internas orientada a labores de pentesting.
Permite descubrir hosts, escanear puertos y realizar fingerprinting de servicios mediante
módulos independientes.

## Instalación

```bash
pip install -r requirements.txt
```

## Uso básico

```bash
python3 EnumTool.py [acción] [opciones]
```

### Acciones disponibles

- `-dA`  : discovery **ARP ping**
- `-dI`  : discovery **ICMP ping**
- `-dT`  : discovery **TCP ping**
- `-dU`  : discovery **UDP ping**
- `-sT`  : scan **TCP connect**
- `-sS`  : scan **SYN scan**
- `-sA`  : scan **ACK scan**
- `-B`   : fingerprint **banner grabbing**
- `-V`   : fingerprint **detección de sistema operativo**
- `-H`   : fingerprint **cabeceras HTTP/HTTPS**

### Opciones comunes

- `-i`, `--interface`  interfaz de red (obligatoria con `-dA`)
- `-t`, `--target`     IP, rango o red objetivo
- `-p`, `--port`       puertos destino (`22,80,443` o `20-25`)
- `--port-all`         escanear todos los puertos TCP (1-65535)
- `--top N`            escanear los N puertos TCP más frecuentes (N≤1000)
- `--profile {web,windows,linux}`  perfiles de puertos predefinidos
- `--timeout`          tiempo de espera por paquete (defecto 0.5s)
- `--threads`          hilos concurrentes (defecto 5, recomendado ≤10)
- `-S`, `--summary`    mostrar resumen final de la ejecución
- `--format {text,json}`  formato del resumen (`text` o `json`)
- `--output FICH`      volcar el resumen a un archivo (append)
- `--https` / `--http` forzar protocolo al usar `-H`
- `--insecure-tls`     deshabilitar la validación TLS en `-B`

### Ejemplos

```bash
sudo python3 EnumTool.py -dA -i eth0 -t 192.168.1.0/24
sudo python3 EnumTool.py -sT -t 192.168.1.10 -p 22,80,443
sudo python3 EnumTool.py -sS -t 10.0.0.5 --top 100
sudo python3 EnumTool.py -B -t 10.0.0.5 -p 80,443 --insecure-tls
sudo python3 EnumTool.py -H -t 10.0.0.5 --https
sudo python3 EnumTool.py -V -t 10.0.0.5 -p 80,443 --summary --format json --output resultados.log
```

## Avisos

- Los flags de acción son mutuamente excluyentes; sólo se puede usar uno por ejecución.
- Algunas técnicas requieren privilegios de root (ARP, ICMP, UDP ping, SYN y ACK scan).
- Para evitar fallos de Scapy al usar muchos hilos se recomienda `--threads` ≤ 10.

