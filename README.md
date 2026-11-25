# 🔍 NetSecScanner4Kali

> Escáner de red local y auditoría de seguridad para Linux

[![Python](https://img.shields.io/badge/Python-3.6%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange?logo=linux&logoColor=white)](https://www.linux.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Root required](https://img.shields.io/badge/Root-required-red?logo=linux)](https://en.wikipedia.org/wiki/Superuser)

Herramienta de línea de comandos para descubrir dispositivos en tu red local, auditar la seguridad de tu propio equipo, detectar puertos peligrosos expuestos y actuar sobre ellos — todo sin dependencias externas de Python.

---

## ✨ ¿Qué puede hacer?

### 🛡️ Auditoría de seguridad del equipo local
- Lista todos los **puertos TCP/UDP en escucha** con el proceso y PID que los controla.
- Clasifica la exposición de cada puerto: `LOCAL` (solo tu máquina) o `EXPUESTO` (toda la red puede conectarse).
- Detecta servicios peligrosos expuestos: **Telnet, FTP, Redis, MongoDB, Docker API, MySQL, PostgreSQL, RDP, VNC**...
- Analiza `/etc/ssh/sshd_config` y avisa de configuraciones débiles:
  - `PermitRootLogin yes` → acceso root directo por SSH.
  - `PasswordAuthentication yes` → vulnerable a fuerza bruta.
  - `PermitEmptyPasswords yes` → cuentas sin contraseña permitidas.
- Comprueba si tienes **firewall activo** (`ufw`, `firewalld`, `nftables`, `iptables`).
- Calcula una **puntuación de seguridad** del 0 al 100 con un resumen de hallazgos por severidad.
- Ofrece **acciones directas** cuando detecta un riesgo: bloquear con firewall, parar el servicio o matar el proceso.

### 🌐 Escáner de red local
- Descubrimiento de dispositivos activos con **`arp-scan`** (rápido) y respaldo automático a **`nmap -sn`**.
- Muestra IP, MAC, hostname, fabricante y sistema operativo estimado.
- **Escaneo paralelo** de múltiples equipos a la vez (mucho más rápido que el escaneo secuencial).
- Parseo fiable de Nmap mediante **XML nativo** (`-oX -`): puerto, protocolo, producto, versión y salida de scripts NSE.
- **5 perfiles de escaneo** adaptados a cada necesidad (ver tabla abajo).
- Detecta servicios peligrosos en la red y lanza alertas con severidad.
- Muestra información completa de tu red: gateway, SSID, DNS, IP pública, país e ISP.

### 💾 Exportación de informes
- Informe legible en **`.txt`** con marca de tiempo.
- Informe estructurado en **`.json`** listo para integraciones y futuras visualizaciones.

---

## 🚀 Perfiles de escaneo de red

| Perfil | Qué escanea | Velocidad |
|---|---|---|
| `inventory` | Solo descubre dispositivos, sin escanear puertos | ⚡⚡⚡ Instantáneo |
| `basic` | Top 100 puertos + SO estimado | ⚡⚡ Rápido |
| `security` | Top 1000 puertos + alertas de seguridad + NSE | ⚡ Moderado |
| `deep` | **Todos** los puertos (`-p-`) + scripts NSE + SO | 🐢 Lento pero completo |
| `custom` | Los puertos que tú elijas (ej. `22,80,443,3306`) | Variable |

---

## 🎯 Modos de uso

### Menú interactivo
```bash
sudo python3 network_scanner.py
```
```
========================================================================
        NETWORK_SCANNER — RED LOCAL Y AUDITORÍA DE SEGURIDAD
========================================================================

[1] Auditoría de seguridad de ESTE equipo (puertos, SSH, firewall)
[2] Escaneo de red — Básico (Top 100 puertos + SO)
[3] Escaneo de red — Profundo (todos los puertos + NSE)
[4] Escaneo de red — Seguridad / Puertos personalizados
[5] Auditoría COMPLETA (Este equipo + Red local)
[6] Solo inventario de dispositivos (sin escanear puertos)
[7] Cambiar interfaz / definir objetivo manual
[8] Salir
```

### CLI directo (automatizable con `cron`)
```bash
# Auditar puertos y seguridad de tu propio equipo
sudo python3 network_scanner.py --local

# Auditar con verificación cruzada (Nmap confirma qué puertos son visibles desde la red)
sudo python3 network_scanner.py --local --cross-check

# Escaneo básico de la red
sudo python3 network_scanner.py --mode basic

# Auditoría completa: tu equipo + red local → exporta TXT y JSON
sudo python3 network_scanner.py --full --out-txt informe.txt --out-json informe.json

# Escanear puertos concretos en una subred específica
sudo python3 network_scanner.py --mode custom --target 192.168.1.0/24 --ports 22,80,443,3306

# Inventario rápido sin root (sin escaneo de puertos)
sudo python3 network_scanner.py --mode inventory --iface eth0
```

---

## 📊 Ejemplo de salida — Auditoría local

```
========================================================================
        AUDITORÍA DE PUERTOS ACTIVOS Y SEGURIDAD DEL EQUIPO
========================================================================

[+] Puntuación de seguridad: 42/100
[+] Firewall:                Sin firewall activo
[+] SSH activo:              Sí
[+] Puertos expuestos (LAN): 3
[+] Hallazgos:               CRÍTICO: 2 | ALTO: 2 | MEDIO: 1 | INFO: 1

[+] Puertos en escucha detectados (5):

PROTO   DIRECCIÓN                PUERTO   EXPOSICIÓN      PROCESO (PID)
--------------------------------------------------------------------------------
tcp     0.0.0.0                  22       EXPOSED_ALL     sshd (912)
tcp     0.0.0.0                  6379     EXPOSED_ALL     redis-server (1400)
tcp     0.0.0.0                  3306     EXPOSED_ALL     mysqld (1800)
tcp     127.0.0.1                5432     LOCAL           postgres (2100)
udp     127.0.0.53               53       LOCAL           systemd-resolve (400)

[+] Diagnóstico y recomendaciones:

  [CRÍTICO] (Puerto Expuesto) Redis (6379/tcp) expuesto en 0.0.0.0
      Detalle:       redis-server (PID 1400) acepta conexiones de red.
      Recomendación: Redis expuesto fuera de localhost suele carecer de cifrado/autenticación.

  [CRÍTICO] (SSH) PermitRootLogin activado
      Detalle:       SSH permite iniciar sesión directamente como usuario root.
      Recomendación: Cambia a `PermitRootLogin no` en /etc/ssh/sshd_config y reinicia sshd.

  [ALTO] (SSH) PasswordAuthentication activado
      Detalle:       SSH acepta autenticación por contraseña (vulnerable a fuerza bruta).
      Recomendación: Usa claves SSH y fija `PasswordAuthentication no`.

  [ALTO] (Firewall) Sin firewall activo con puertos expuestos
      Detalle:       3 socket(s) escuchando fuera de localhost sin firewall activo.
      Recomendación: Activa ufw: `sudo ufw enable`

¿Qué quieres hacer con Redis (6379)?
  [1] Bloquear con UFW (ufw deny 6379)
  [2] Parar el servicio (systemctl stop redis)
  [3] Solo ver la recomendación
  [4] Ignorar
```

---

## 📋 Requisitos

**Sistema operativo:** Linux (cualquier distribución: Kali, Ubuntu, Debian, Fedora, Arch, etc.)

**Python:** 3.6 o superior — solo biblioteca estándar (`subprocess`, `xml.etree`, `concurrent.futures`, `ipaddress`, `argparse`...). **Sin `pip install` necesario.**

**Permisos:** root (`sudo`) para escaneos completos.

### Herramientas externas

| Herramienta | Función | Obligatoria |
|---|---|---|
| `nmap` | Escaneo de puertos, SO y servicios | ✅ Para escaneo de red |
| `ss` | Listar puertos activos del equipo | ✅ Para auditoría local |
| `ip` | Detectar interfaces y rutas | ✅ Siempre |
| `arp-scan` | Descubrimiento rápido de dispositivos | ⚡ Recomendada |
| `iwgetid` | Obtener SSID (si es WiFi) | 🔵 Opcional |
| `nmcli` | Fabricante de la MAC de tu interfaz | 🔵 Opcional |
| `whois` | País e ISP de la IP pública | 🔵 Opcional |
| `curl` / `dig` | Obtener IP pública | 🔵 Opcional |
| `ufw` / `iptables` | Leer estado del firewall | 🔵 Opcional |

> Las herramientas opcionales degradan limpiamente: si no están, el scanner sigue funcionando sin ellas.

---

## 🔧 Instalación de dependencias

### Debian / Ubuntu / Kali
```bash
sudo apt update && sudo apt install -y \
  nmap arp-scan iproute2 wireless-tools \
  whois curl dnsutils network-manager ufw
```

### Arch / Manjaro
```bash
sudo pacman -S nmap arp-scan iproute2 wireless_tools whois curl
```

### Fedora / RHEL
```bash
sudo dnf install -y nmap arp-scan iproute wireless-tools whois curl
```

---

## 📁 Estructura del proyecto

```
network_scanner/
├── network_scanner.py      # Punto de entrada: menú interactivo + CLI
└── scanner/
    ├── __init__.py
    ├── utils.py            # Ejecución de comandos, cálculo CIDR, check de herramientas
    ├── network_info.py     # Interfaces, gateway, DNS, SSID, IP pública, WHOIS
    ├── discovery.py        # Descubrimiento de dispositivos (arp-scan + nmap -sn XML)
    ├── port_scanner.py     # Escaneo Nmap XML paralelo, 5 perfiles, alertas de red
    ├── local_audit.py      # Auditoría local: puertos, SSH, firewall, scoring
    └── exporter.py         # Exportación a .txt y .json con timestamp
```

---

## 🗺️ Roadmap

- [x] Escáner de red con dos niveles (básico / profundo)
- [x] Arquitectura modular
- [x] Parseo XML de Nmap (puertos y versiones completos)
- [x] Escaneo paralelo de dispositivos
- [x] Auditoría de seguridad del equipo local
- [x] Análisis de SSH (`sshd_config`)
- [x] Detección de firewall
- [x] Puntuación de seguridad 0-100
- [x] CLI con `argparse` (automatizable con `cron`)
- [x] Exportación TXT y JSON
- [ ] Acciones correctivas desde el menú (bloquear/parar servicios peligrosos)
- [ ] Monitor de red / detección de intrusos (baseline + diff)
- [ ] Más chequeos locales: usuarios con sudo, conexiones establecidas
- [ ] Toolkit de red: ping, traceroute, Wake-on-LAN, banner grabbing
- [ ] Informe HTML visual autogenerado
- [ ] Interfaz TUI en terminal o dashboard web local
- [ ] Contenedor Docker para usar en cualquier SO

---

## ⚠️ Aviso legal

Esta herramienta está diseñada para uso en **redes propias o con autorización explícita**. Escanear redes ajenas sin permiso puede ser ilegal en tu país. Úsala de forma responsable.

---

## 📄 Licencia

MIT © [Paukkita](https://github.com/Paukkita/NetSecScanner4Kali)
