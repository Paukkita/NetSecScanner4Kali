# -*- coding: utf-8 -*-
"""Utilidades comunes: ejecución de comandos, cálculo CIDR y comprobación de entorno."""

from datetime import datetime
import ipaddress
import os
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple


def run_cmd(command: List[str], timeout: int = 10) -> Tuple[str, str, int]:
    """
    Ejecuta un comando del sistema con timeout.
    Devuelve (stdout, stderr, returncode). Si falla o expira, returncode es -1.
    """
    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        return proc.stdout.strip(), proc.stderr.strip(), proc.returncode
    except (subprocess.SubprocessError, OSError):
        return "", "", -1


def clear_screen() -> None:
    """Limpia la terminal de forma compatible con Linux/Windows."""
    os.system("cls" if os.name == "nt" else "clear")


def print_banner(title_text: str, width: int = 72) -> None:
    """Imprime un encabezado centrado."""
    print("\n" + "=" * width)
    print(title_text.center(width))
    print("=" * width + "\n")


def timestamp_slug() -> str:
    """Devuelve una marca de tiempo apta para nombres de archivo."""
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def is_root() -> bool:
    """Comprueba si el proceso corre con privilegios de root (en POSIX)."""
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    return geteuid() == 0


def calculate_cidr(ip: str, prefix: int) -> Optional[str]:
    """Calcula la red en formato CIDR dada una IP y un prefijo."""
    try:
        iface = ipaddress.IPv4Interface(f"{ip}/{prefix}")
        return str(iface.network)
    except ValueError:
        return None


def check_tools() -> Dict[str, Dict[str, bool]]:
    """
    Comprueba qué herramientas externas están disponibles.
    Distingue entre herramientas recomendadas/imprescindibles según el modo.
    """
    tools = [
        "nmap",
        "ip",
        "ss",
        "netstat",
        "arp-scan",
        "iwgetid",
        "nmcli",
        "whois",
        "curl",
        "dig",
        "ufw",
        "firewall-cmd",
        "nft",
        "iptables",
    ]
    available = {tool: (shutil.which(tool) is not None) for tool in tools}
    return {
        "available": available,
        "can_network_scan": available["nmap"],
        "can_local_audit": available["ss"] or available["netstat"],
    }
