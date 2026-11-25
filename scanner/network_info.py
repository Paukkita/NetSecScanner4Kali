# -*- coding: utf-8 -*-
"""Obtención de interfaces, datos de red local, DNS e información pública."""

import re
import shutil
from typing import Any, Dict, List, Optional, Tuple

from .utils import calculate_cidr, run_cmd


def default_iface() -> Optional[str]:
    """Devuelve la interfaz asociada a la ruta por defecto."""
    out, _, rc = run_cmd(["ip", "route", "show", "default"])
    if rc != 0:
        return None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] == "default" and "dev" in parts:
            dev_idx = parts.index("dev")
            if dev_idx + 1 < len(parts):
                return parts[dev_idx + 1]
    return None


def net_info(iface: str) -> Tuple[Optional[str], Optional[str]]:
    """Devuelve (ip, red_cidr) para una interfaz IPv4."""
    out, _, rc = run_cmd(["ip", "-4", "addr", "show", iface])
    if rc != 0:
        return None, None
    for line in out.splitlines():
        match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if match:
            ip = match.group(1)
            prefix = int(match.group(2))
            return ip, calculate_cidr(ip, prefix)
    return None, None


def list_interfaces() -> List[Dict[str, str]]:
    """
    Lista todas las interfaces IPv4 activas (excluyendo loopback)
    junto con su IP, red CIDR y si es la ruta por defecto.
    """
    out, _, rc = run_cmd(["ip", "-4", "-o", "addr", "show"])
    if rc != 0 or not out:
        return []

    def_if = default_iface()
    interfaces: List[Dict[str, str]] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        iface = parts[1]
        if iface == "lo":
            continue
        match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if not match:
            continue
        ip = match.group(1)
        prefix = int(match.group(2))
        cidr = calculate_cidr(ip, prefix) or f"{ip}/{prefix}"
        interfaces.append(
            {
                "iface": iface,
                "ip": ip,
                "net": cidr,
                "is_default": "sí" if iface == def_if else "no",
            }
        )
    return interfaces


def get_dns_servers(resolv_path: str = "/etc/resolv.conf") -> List[str]:
    """Lee los servidores DNS configurados en /etc/resolv.conf."""
    servers: List[str] = []
    try:
        with open(resolv_path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] not in servers:
                        servers.append(parts[1])
    except OSError:
        pass
    return servers


def parse_whois_info(whois_out: str) -> Tuple[str, str]:
    """Extrae país e ISP de una salida WHOIS."""
    country = "No disponible"
    isp = "No disponible"

    country_match = re.search(r"country:\s*([A-Z]{2})", whois_out, re.IGNORECASE)
    if country_match:
        country = country_match.group(1).upper()

    for pattern in (r"org-name:\s*(.+)", r"orgname:\s*(.+)", r"descr:\s*(.+)", r"netname:\s*(.+)"):
        match = re.search(pattern, whois_out, re.IGNORECASE)
        if match:
            isp = match.group(1).strip()
            break

    return country, isp


def get_public_info() -> Dict[str, str]:
    """Obtiene IP pública, país e ISP usando curl/dig y whois (si están disponibles)."""
    info = {
        "public_ip": "No disponible",
        "country": "No disponible",
        "isp": "No disponible",
    }

    public_ip = ""
    if shutil.which("curl"):
        out, _, rc = run_cmd(["curl", "-s", "--max-time", "4", "https://ifconfig.me"], 5)
        if rc == 0 and re.match(r"^\d+\.\d+\.\d+\.\d+$", out):
            public_ip = out

    if not public_ip and shutil.which("dig"):
        out, _, rc = run_cmd(
            ["dig", "+short", "myip.opendns.com", "@resolver1.opendns.com"], 5
        )
        if rc == 0 and out:
            candidate = out.splitlines()[0].strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", candidate):
                public_ip = candidate

    if not public_ip:
        return info

    info["public_ip"] = public_ip
    if shutil.which("whois"):
        whois_out, _, rc2 = run_cmd(["whois", public_ip], 10)
        if rc2 == 0 and whois_out:
            country, isp = parse_whois_info(whois_out)
            info["country"] = country
            info["isp"] = isp

    return info


def get_network_details(
    iface: str,
    ip: Optional[str] = None,
    net: Optional[str] = None,
    fetch_public: bool = True,
) -> Dict[str, Any]:
    """Reúne los datos completos de red local y pública para la interfaz dada."""
    if ip is None or net is None:
        detected_ip, detected_net = net_info(iface)
        ip = ip or detected_ip
        net = net or detected_net

    details: Dict[str, Any] = {
        "interfaz": iface,
        "ip_local": ip or "No disponible",
        "red": net or "No disponible",
        "gateway": "No disponible",
        "ssid": "No disponible (no WiFi)",
        "mac_iface": "No disponible",
        "vendor_iface": "Desconocido",
        "dns_servers": get_dns_servers(),
        "public_ip": "Omitido" if not fetch_public else "No disponible",
        "country": "Omitido" if not fetch_public else "No disponible",
        "isp": "Omitido" if not fetch_public else "No disponible",
    }

    # Gateway
    out, _, rc = run_cmd(["ip", "route", "show", "default"])
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "default" and parts[1] == "via":
                details["gateway"] = parts[2]
                break

    # SSID WiFi (herramienta opcional)
    if shutil.which("iwgetid"):
        ssid_out, _, rc = run_cmd(["iwgetid", iface, "-r"])
        if rc == 0 and ssid_out:
            details["ssid"] = ssid_out

    # MAC de la interfaz
    link_out, _, rc = run_cmd(["ip", "link", "show", iface])
    if rc == 0:
        match = re.search(r"link/ether\s+([0-9a-fA-F:]+)", link_out)
        if match:
            details["mac_iface"] = match.group(1)

    # Fabricante vía nmcli (herramienta opcional)
    if shutil.which("nmcli"):
        nm_out, _, rc = run_cmd(
            ["nmcli", "-t", "-f", "GENERAL.HWADDR,GENERAL.VENDOR", "device", "show", iface]
        )
        if rc == 0:
            for line in nm_out.splitlines():
                if "GENERAL.VENDOR" in line and ":" in line:
                    vendor = line.split(":", 1)[1].strip()
                    if vendor and vendor != "--":
                        details["vendor_iface"] = vendor
                    break

    if fetch_public:
        details.update(get_public_info())

    return details
