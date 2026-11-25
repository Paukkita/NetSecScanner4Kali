# -*- coding: utf-8 -*-
"""Auditoría de seguridad del equipo local: puertos activos, procesos, SSH y firewall."""

import glob
import os
import re
import shutil
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

from .utils import run_cmd

# Base de conocimiento de servicios locales sensibles
SENSITIVE_LOCAL_SERVICES: Dict[int, Tuple[str, str, str]] = {
    21: ("ALTO", "FTP", "Protocolo sin cifrar; sustitúyelo por SFTP/SSH."),
    22: ("INFO", "SSH", "Verifica endurecimiento en /etc/ssh/sshd_config y firewall."),
    23: ("CRÍTICO", "Telnet", "Servicio obsoleto sin cifrado; deshabilítalo de inmediato."),
    25: ("MEDIO", "SMTP", "Comprueba si el servidor de correo necesita escuchar fuera de localhost."),
    53: ("BAJO", "DNS", "Si no actúas como servidor DNS para la red, limita la escucha a 127.0.0.1."),
    80: ("MEDIO", "HTTP", "Tráfico web sin cifrar; usa HTTPS o limita a localhost si es de desarrollo."),
    111: ("MEDIO", "rpcbind", "Servicio RPC innecesario en equipos de escritorio; desactívalo si no usas NFS."),
    139: ("MEDIO", "NetBIOS/SMB", "Compartición de archivos expuesta; restringe por firewall a la LAN confiable."),
    445: ("MEDIO", "SMB", "Revisa permisos de recursos compartidos y desactiva SMBv1."),
    2375: ("CRÍTICO", "Docker API (sin TLS)", "Permite ejecución remota como root sin autenticación; cierra el socket TCP."),
    3306: ("ALTO", "MySQL/MariaDB", "Base de datos accesible por red; usa bind-address = 127.0.0.1 si es local."),
    3389: ("ALTO", "RDP", "Escritorio remoto expuesto; protégelo con VPN, firewall y contraseñas fuertes."),
    5432: ("ALTO", "PostgreSQL", "Base de datos accesible por red; limita listen_addresses a localhost si es local."),
    5900: ("ALTO", "VNC", "Acceso gráfico remoto; encapsúlalo por túnel SSH o restringe por firewall."),
    6379: ("CRÍTICO", "Redis", "Redis expuesto fuera de localhost suele carecer de cifrado/autenticación."),
    8080: ("MEDIO", "HTTP-Alt / Proxy", "Revisa qué panel o app web está escuchando en todas las interfaces."),
    27017: ("CRÍTICO", "MongoDB", "Base de datos expuesta en red; restringe bindIp a 127.0.0.1."),
}

SEVERITY_PENALTY: Dict[str, int] = {
    "CRÍTICO": 25,
    "ALTO": 15,
    "MEDIO": 7,
    "BAJO": 2,
    "INFO": 0,
}


def _split_host_port(address: str) -> Tuple[str, Optional[int]]:
    """Separa dirección y puerto en formatos de ss/netstat (IPv4, IPv6, *, %iface)."""
    addr = address.strip()
    if ":" not in addr:
        return addr, None

    if addr.startswith("["):
        # [::]:22 o [::1%lo]:53
        match = re.match(r"^\[([^\]]+)\]:(\d+|\*)$", addr)
        if match:
            host = match.group(1).split("%", 1)[0]
            port_str = match.group(2)
            return host, int(port_str) if port_str.isdigit() else None

    host_part, port_part = addr.rsplit(":", 1)
    host_clean = host_part.split("%", 1)[0]
    port_num = int(port_part) if port_part.isdigit() else None
    return host_clean, port_num


def classify_exposure(host: str) -> str:
    """Clasifica si una dirección de escucha es solo local o expuesta."""
    h = host.strip().lower()
    if h in ("127.0.0.1", "::1", "localhost") or h.startswith("127."):
        return "LOCAL"
    if h in ("0.0.0.0", "::", "*", ""):
        return "EXPOSED_ALL"
    return "EXPOSED_IFACE"


def parse_ss_output(output: str) -> List[Dict[str, Any]]:
    """Parsea la salida de `ss -tulnp` en registros estructurados."""
    entries: List[Dict[str, Any]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("Netid") or line.startswith("State"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue

        proto = parts[0].lower()
        state = parts[1].upper()
        local_raw = parts[4]
        host, port = _split_host_port(local_raw)
        if port is None:
            continue

        proc_name = "Desconocido"
        pid = ""
        users_match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
        if users_match:
            proc_name = users_match.group(1)
            pid = users_match.group(2)

        entries.append(
            {
                "proto": proto,
                "state": state,
                "address": host,
                "port": port,
                "exposure": classify_exposure(host),
                "process": proc_name,
                "pid": pid,
            }
        )

    return _deduplicate_ports(entries)


def parse_netstat_output(output: str) -> List[Dict[str, Any]]:
    """Parsea la salida de `netstat -tulnp` como respaldo cuando no hay `ss`."""
    entries: List[Dict[str, Any]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("Active") or line.startswith("Proto"):
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        proto = parts[0].lower()
        if not (proto.startswith("tcp") or proto.startswith("udp")):
            continue

        local_raw = parts[3]
        host, port = _split_host_port(local_raw)
        if port is None:
            continue

        state = parts[5].upper() if proto.startswith("tcp") else "UNCONN"
        pid_prog = parts[-1] if "/" in parts[-1] else "-"
        pid, proc_name = ("", "Desconocido")
        if "/" in pid_prog:
            pid, proc_name = pid_prog.split("/", 1)

        entries.append(
            {
                "proto": proto,
                "state": state,
                "address": host,
                "port": port,
                "exposure": classify_exposure(host),
                "process": proc_name,
                "pid": pid,
            }
        )

    return _deduplicate_ports(entries)


def _deduplicate_ports(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Elimina duplicados exactos y ordena por puerto y protocolo."""
    seen = set()
    unique: List[Dict[str, Any]] = []
    for item in entries:
        key = (item["proto"], item["address"], item["port"], item["process"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    unique.sort(key=lambda x: (x["port"], x["proto"], x["address"]))
    return unique


def get_listening_ports() -> Tuple[List[Dict[str, Any]], str]:
    """Obtiene los puertos en escucha del equipo usando `ss` o `netstat`."""
    if shutil.which("ss"):
        out, _, rc = run_cmd(["ss", "-tulnp"], timeout=10)
        if rc == 0 and out:
            return parse_ss_output(out), "ss"

    if shutil.which("netstat"):
        out, _, rc = run_cmd(["netstat", "-tulnp"], timeout=10)
        if rc == 0 and out:
            return parse_netstat_output(out), "netstat"

    return [], "unavailable"


def parse_firewall_status(
    ufw_out: str = "",
    firewalld_out: str = "",
    nft_out: str = "",
    iptables_out: str = "",
) -> Dict[str, Any]:
    """Analiza salidas de firewall de Linux y devuelve estado unificado."""
    if ufw_out:
        low = ufw_out.lower()
        if "status: active" in low:
            return {
                "active": True,
                "backend": "ufw",
                "summary": "UFW activo",
                "details": ufw_out,
            }
        if "status: inactive" in low:
            return {
                "active": False,
                "backend": "ufw",
                "summary": "UFW instalado pero INACTIVO",
                "details": ufw_out,
            }

    if firewalld_out:
        if "running" in firewalld_out.lower():
            return {
                "active": True,
                "backend": "firewalld",
                "summary": "firewalld activo",
                "details": firewalld_out,
            }

    if nft_out and ("chain " in nft_out or "hook input" in nft_out):
        return {
            "active": True,
            "backend": "nftables",
            "summary": "nftables con reglas configuradas",
            "details": "\n".join(nft_out.splitlines()[:25]),
        }

    if iptables_out:
        has_accept_policy = "Chain INPUT (policy ACCEPT)" in iptables_out
        rule_lines = [
            ln for ln in iptables_out.splitlines()
            if ln.strip() and not ln.startswith("Chain ") and not ln.startswith("target ")
        ]
        if not has_accept_policy or rule_lines:
            return {
                "active": True,
                "backend": "iptables",
                "summary": f"iptables activo ({len(rule_lines)} regla(s) en INPUT)",
                "details": iptables_out,
            }
        return {
            "active": False,
            "backend": "iptables",
            "summary": "iptables sin reglas restrictivas (policy ACCEPT)",
            "details": iptables_out,
        }

    return {
        "active": False,
        "backend": "none",
        "summary": "No se detectó ningún firewall activo",
        "details": "",
    }


def check_firewall() -> Dict[str, Any]:
    """Consulta el estado real del firewall del sistema."""
    ufw_out = ""
    if shutil.which("ufw"):
        out, _, rc = run_cmd(["ufw", "status", "verbose"], timeout=5)
        if rc == 0:
            ufw_out = out

    fw_out = ""
    if not ufw_out and shutil.which("firewall-cmd"):
        out, _, rc = run_cmd(["firewall-cmd", "--state"], timeout=5)
        if rc == 0:
            fw_out = out

    nft_out = ""
    if not ufw_out and not fw_out and shutil.which("nft"):
        out, _, rc = run_cmd(["nft", "list", "ruleset"], timeout=5)
        if rc == 0:
            nft_out = out

    ipt_out = ""
    if not ufw_out and not fw_out and not nft_out and shutil.which("iptables"):
        out, _, rc = run_cmd(["iptables", "-L", "INPUT", "-n"], timeout=5)
        if rc == 0:
            ipt_out = out

    return parse_firewall_status(
        ufw_out=ufw_out,
        firewalld_out=fw_out,
        nft_out=nft_out,
        iptables_out=ipt_out,
    )


def parse_sshd_config(content: str) -> Dict[str, Any]:
    """
    Parsea el contenido efectivo de sshd_config (primera ocurrencia prevalece en OpenSSH)
    y genera hallazgos concretos de endurecimiento.
    """
    directives: Dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        key = parts[0].lower()
        value = parts[1].strip()
        # En sshd_config, el primer valor encontrado para una directiva es el efectivo
        if key not in directives:
            directives[key] = value

    findings: List[Dict[str, str]] = []

    permit_root = directives.get("permitrootlogin", "prohibit-password").lower()
    if permit_root == "yes":
        findings.append(
            {
                "severity": "CRÍTICO",
                "category": "SSH",
                "title": "PermitRootLogin activado",
                "detail": "SSH permite iniciar sesión directamente como usuario root.",
                "recommendation": "Cambia a `PermitRootLogin no` en /etc/ssh/sshd_config y reinicia sshd.",
            }
        )
    elif permit_root != "no":
        findings.append(
            {
                "severity": "BAJO",
                "category": "SSH",
                "title": f"PermitRootLogin en '{permit_root}'",
                "detail": "Aunque no permite contraseña, root sigue pudiendo acceder por clave si existe.",
                "recommendation": "Si no lo necesitas, fija `PermitRootLogin no`.",
            }
        )

    pass_auth = directives.get("passwordauthentication", "yes").lower()
    if pass_auth == "yes":
        findings.append(
            {
                "severity": "ALTO",
                "category": "SSH",
                "title": "PasswordAuthentication activado",
                "detail": "SSH acepta autenticación por contraseña (vulnerable a fuerza bruta si está expuesto).",
                "recommendation": "Usa claves SSH (`ssh-copy-id`) y fija `PasswordAuthentication no`.",
            }
        )

    empty_pw = directives.get("permitemptypasswords", "no").lower()
    if empty_pw == "yes":
        findings.append(
            {
                "severity": "CRÍTICO",
                "category": "SSH",
                "title": "PermitEmptyPasswords activado",
                "detail": "SSH permite cuentas sin contraseña.",
                "recommendation": "Fija inmediatamente `PermitEmptyPasswords no`.",
            }
        )

    x11 = directives.get("x11forwarding", "no").lower()
    if x11 == "yes":
        findings.append(
            {
                "severity": "BAJO",
                "category": "SSH",
                "title": "X11Forwarding activado",
                "detail": "Reenvío gráfico X11 habilitado sin necesidad en la mayoría de servidores.",
                "recommendation": "Si no ejecutas apps gráficas remotas, pon `X11Forwarding no`.",
            }
        )

    ssh_port = directives.get("port", "22")
    if ssh_port == "22":
        findings.append(
            {
                "severity": "INFO",
                "category": "SSH",
                "title": "SSH en puerto estándar (22)",
                "detail": "Es normal, pero recibe más escaneos automáticos si se expone al exterior.",
                "recommendation": "Mantén firewall/fail2ban activos o restringe IPs permitidas.",
            }
        )

    return {"directives": directives, "findings": findings}


def audit_ssh_config(sshd_config_path: str = "/etc/ssh/sshd_config") -> Dict[str, Any]:
    """Lee /etc/ssh/sshd_config (y drop-ins .d/*.conf si existen) y lo audita."""
    if not os.path.isfile(sshd_config_path):
        return {
            "found": False,
            "path": sshd_config_path,
            "directives": {},
            "findings": [],
        }

    chunks: List[str] = []
    dropin_dir = "/etc/ssh/sshd_config.d"
    if os.path.isdir(dropin_dir):
        for conf_file in sorted(glob.glob(os.path.join(dropin_dir, "*.conf"))):
            try:
                with open(conf_file, "r", encoding="utf-8", errors="ignore") as fh:
                    chunks.append(fh.read())
            except OSError:
                pass

    try:
        with open(sshd_config_path, "r", encoding="utf-8", errors="ignore") as fh:
            chunks.append(fh.read())
    except OSError as exc:
        return {
            "found": True,
            "path": sshd_config_path,
            "error": str(exc),
            "directives": {},
            "findings": [],
        }

    parsed = parse_sshd_config("\n".join(chunks))
    return {
        "found": True,
        "path": sshd_config_path,
        "directives": parsed["directives"],
        "findings": parsed["findings"],
    }


def cross_check_local_ports(local_ip: str, ports: List[Dict[str, Any]]) -> Dict[int, str]:
    """
    Comprueba con Nmap contra la IP local qué puertos TCP expuestos son alcanzables desde la LAN.
    """
    if not local_ip or not shutil.which("nmap"):
        return {}

    exposed_tcp = sorted(
        {
            p["port"]
            for p in ports
            if p["proto"].startswith("tcp") and p["exposure"] != "LOCAL"
        }
    )
    if not exposed_tcp:
        return {}

    port_list = ",".join(str(p) for p in exposed_tcp)
    out, _, rc = run_cmd(["nmap", "-sT", "-Pn", "-p", port_list, "-oX", "-", local_ip], timeout=30)
    if rc != 0 or not out:
        return {}

    status_map: Dict[int, str] = {}
    try:
        root = ET.fromstring(out)
        for port_el in root.findall(".//port"):
            port_id = int(port_el.get("portid", "0"))
            state_el = port_el.find("state")
            if state_el is not None and port_id:
                status_map[port_id] = state_el.get("state", "unknown")
    except ET.ParseError:
        return {}
    return status_map


def run_local_audit(
    local_ip: Optional[str] = None,
    cross_check: bool = False,
    sshd_config_path: str = "/etc/ssh/sshd_config",
) -> Dict[str, Any]:
    """
    Ejecuta la auditoría completa del equipo local:
    - Puertos activos y procesos/PID
    - Estado del firewall
    - Análisis de SSH si está activo o configurado
    - Evaluación de riesgo y puntuación 0-100
    """
    ports, source = get_listening_ports()
    firewall = check_firewall()
    findings: List[Dict[str, str]] = []

    exposed_ports = [p for p in ports if p["exposure"] != "LOCAL"]
    ssh_listening = False
    ssh_exposed = False

    for entry in ports:
        port = entry["port"]
        proc = entry["process"]
        exposure = entry["exposure"]
        is_exposed = exposure != "LOCAL"

        if port == 22 or "sshd" in proc.lower():
            ssh_listening = True
            if is_exposed:
                ssh_exposed = True

        if port in SENSITIVE_LOCAL_SERVICES:
            base_sev, svc_label, rec = SENSITIVE_LOCAL_SERVICES[port]
            if not is_exposed and base_sev != "INFO":
                findings.append(
                    {
                        "severity": "INFO",
                        "category": "Puerto Local",
                        "title": f"{svc_label} ({port}/{entry['proto']}) solo en localhost",
                        "detail": f"Proceso '{proc}' escucha únicamente en {entry['address']}.",
                        "recommendation": "Buena práctica: no está expuesto a la red.",
                    }
                )
            elif is_exposed and base_sev != "INFO":
                findings.append(
                    {
                        "severity": base_sev,
                        "category": "Puerto Expuesto",
                        "title": f"{svc_label} ({port}/{entry['proto']}) expuesto ({entry['address']})",
                        "detail": f"Proceso '{proc}' (PID {entry['pid'] or '?'}) acepta conexiones de red.",
                        "recommendation": rec,
                    }
                )
        elif exposure == "EXPOSED_ALL":
            findings.append(
                {
                    "severity": "BAJO",
                    "category": "Puerto Expuesto",
                    "title": f"Puerto {port}/{entry['proto']} escuchando en todas las interfaces",
                    "detail": f"Proceso '{proc}' (PID {entry['pid'] or '?'}) escucha en {entry['address']}.",
                    "recommendation": "Verifica si este servicio necesita aceptar tráfico externo.",
                }
            )

    ssh_audit: Dict[str, Any] = {"found": False, "directives": {}, "findings": []}
    if ssh_listening or os.path.isfile(sshd_config_path):
        ssh_audit = audit_ssh_config(sshd_config_path)
        for item in ssh_audit.get("findings", []):
            # Si SSH no está escuchando fuera de localhost, reducimos el ruido
            copied = dict(item)
            if not ssh_listening and copied["severity"] in ("ALTO", "CRÍTICO"):
                copied["severity"] = "INFO"
                copied["detail"] += " (Nota: sshd no está escuchando actualmente)."
            elif ssh_listening and not ssh_exposed and copied["severity"] == "ALTO":
                copied["severity"] = "MEDIO"
            findings.append(copied)

    if exposed_ports and not firewall.get("active"):
        findings.append(
            {
                "severity": "ALTO",
                "category": "Firewall",
                "title": "Sin firewall activo con puertos expuestos",
                "detail": f"Hay {len(exposed_ports)} socket(s) escuchando fuera de localhost sin firewall activo ({firewall['summary']}).",
                "recommendation": "Activa un firewall (ej: `sudo ufw enable` tras permitir solo los puertos necesarios).",
            }
        )

    cross_map: Dict[int, str] = {}
    if cross_check and local_ip:
        cross_map = cross_check_local_ports(local_ip, ports)
        for p_num, p_state in cross_map.items():
            if p_state == "open":
                findings.append(
                    {
                        "severity": "INFO",
                        "category": "Verificación Red",
                        "title": f"Puerto {p_num}/tcp alcanzable desde la IP de red ({local_ip})",
                        "detail": "Nmap confirmó que el puerto responde desde la interfaz de red.",
                        "recommendation": "Si solo debería usarse en este equipo, bloquéalo en el firewall.",
                    }
                )

    severity_counts = {"CRÍTICO": 0, "ALTO": 0, "MEDIO": 0, "BAJO": 0, "INFO": 0}
    penalty = 0
    for f in findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        penalty += SEVERITY_PENALTY.get(sev, 0)

    score = max(0, 100 - penalty)

    return {
        "source": source,
        "listening_ports": ports,
        "exposed_count": len(exposed_ports),
        "firewall": firewall,
        "ssh_listening": ssh_listening,
        "ssh_audit": ssh_audit,
        "cross_check": cross_map,
        "findings": findings,
        "severity_counts": severity_counts,
        "score": score,
    }
