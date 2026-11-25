# -*- coding: utf-8 -*-
"""Descubrimiento de dispositivos activos mediante arp-scan y Nmap XML."""

import ipaddress
import re
import shutil
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from .utils import run_cmd


def _ip_sort_key(ip_str: str) -> tuple:
    """Clave de ordenación numérica para direcciones IPv4/IPv6."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return (addr.version, int(addr))
    except ValueError:
        return (99, ip_str)


def parse_arp_scan(output: str) -> List[Dict[str, Any]]:
    """Extrae dispositivos de la salida estándar de arp-scan."""
    devices: List[Dict[str, Any]] = []
    for line in output.splitlines():
        match = re.search(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s+(.*)$", line.strip())
        if not match:
            continue
        vendor = match.group(3).strip()
        if not vendor or "(Unknown" in vendor:
            vendor = "Desconocido"
        devices.append(
            {
                "ip": match.group(1),
                "mac": match.group(2).upper(),
                "fab": vendor,
                "hostname": "",
                "source": "arp-scan",
            }
        )
    return devices


def parse_nmap_discovery_xml(xml_text: str) -> List[Dict[str, Any]]:
    """Extrae dispositivos, MAC, fabricante y hostname desde nmap -sn -oX -."""
    devices: List[Dict[str, Any]] = []
    if not xml_text.strip():
        return devices
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return devices

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        ip_addr = ""
        mac_addr = ""
        vendor = "Desconocido"

        for addr in host.findall("address"):
            addr_type = addr.get("addrtype", "")
            if addr_type in ("ipv4", "ipv6") and not ip_addr:
                ip_addr = addr.get("addr", "")
            elif addr_type == "mac":
                mac_addr = addr.get("addr", "").upper()
                if addr.get("vendor"):
                    vendor = addr.get("vendor", "Desconocido")

        if not ip_addr:
            continue

        hostname = ""
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None and hn.get("name"):
                hostname = hn.get("name", "")

        devices.append(
            {
                "ip": ip_addr,
                "mac": mac_addr,
                "fab": vendor,
                "hostname": hostname,
                "source": "nmap-sn",
            }
        )
    return devices


def discover_devices(iface: Optional[str], target: str) -> List[Dict[str, Any]]:
    """
    Descubre dispositivos activos en un objetivo (CIDR, IP o rango).
    Usa arp-scan en subredes locales si está disponible y completa/respalda con nmap -sn -oX -.
    """
    by_ip: Dict[str, Dict[str, Any]] = {}

    is_cidr_or_local = "/" in target
    if iface and is_cidr_or_local and shutil.which("arp-scan"):
        out, _, rc = run_cmd(["arp-scan", "--interface", iface, target], timeout=20)
        if rc == 0 and out:
            for dev in parse_arp_scan(out):
                by_ip[dev["ip"]] = dev

    # Usar nmap -sn XML como respaldo o para enriquecer hostnames/objetivos no locales
    if len(by_ip) < 2 or not by_ip:
        cmd = ["nmap", "-sn", "-oX", "-"]
        if iface:
            cmd.extend(["-e", iface])
        cmd.append(target)
        out, _, rc = run_cmd(cmd, timeout=45)
        if rc == 0 and out:
            for dev in parse_nmap_discovery_xml(out):
                existing = by_ip.get(dev["ip"])
                if existing:
                    if not existing.get("hostname") and dev.get("hostname"):
                        existing["hostname"] = dev["hostname"]
                    if not existing.get("mac") and dev.get("mac"):
                        existing["mac"] = dev["mac"]
                    if existing.get("fab") == "Desconocido" and dev.get("fab") != "Desconocido":
                        existing["fab"] = dev["fab"]
                else:
                    by_ip[dev["ip"]] = dev

    devices = list(by_ip.values())
    devices.sort(key=lambda d: _ip_sort_key(d["ip"]))
    return devices
