<div align="center">
# 🔍 NetSecScanner4Kali
**Escáner de red local y auditoría de seguridad para Linux**
[![Python](https://img.shields.io/badge/Python-3.6%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange?logo=linux&logoColor=white)](https://www.linux.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Root required](https://img.shields.io/badge/Root-required-red?logo=linux)](https://en.wikipedia.org/wiki/Superuser)
Herramienta de línea de comandos para descubrir dispositivos en tu red local, auditar la seguridad de tu propio equipo, detectar puertos peligrosos expuestos y actuar sobre ellos — todo sin dependencias externas de Python.
</div>
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
