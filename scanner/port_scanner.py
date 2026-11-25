# -*- coding: utf-8 -*-
"""Escaneo de puertos, servicios, SO y alertas de red con Nmap XML y concurrencia."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET
from typing import Any, Callable, Dict, List, Optional, Tuple

from .utils import run_cmd

# Puertos cuyo servicio suele implicar riesgo si está abierto en la LAN sin protección
RISKY_NETWORK_PORTS: Dict[int, Tuple[str, str]] = {
    21: ("ALTO", "FTP sin cifrar (credenciales en texto plano)"),
    23: ("CRÍTICO", "Telnet sin cifrar (sustituir por SSH)"),
    69: ("MEDIO", "TFTP sin autenticación"),
    139: ("MEDIO", "NetBIOS/SMB expuesto"),
    445: ("MEDIO", "SMB expuesto (revisar SMBv1/firmado)"),
    512: ("CRÍTICO", "rexec heredado inseguro"),
    513: ("CRÍTICO", "rlogin heredado inseguro"),
    514: ("CRÍTICO", "rsh heredado inseguro"),
    1433: ("ALTO", "SQL Server expuesto en red"),
    2375: ("CRÍTICO", "Docker API sin TLS (control remoto total)"),
    3306: ("MEDIO", "MySQL/MariaDB expuesto en red"),
    3389: ("ALTO", "RDP expuesto (objetivo habitual de ataques)"),
    5432: ("MEDIO", "PostgreSQL expuesto en red"),
    5900: ("ALTO", "VNC expuesto (a menudo sin cifrado fuerte)"),
    6379: ("CRÍTICO", "Redis expuesto en red (a menudo sin contraseña)"),
    27017: ("CRÍTICO", "MongoDB expuesto en red"),
}


def build_nmap_args(
    ip: str, profile: str = "basic", custom_ports: Optional[str] = None
) -> Tuple[List[str], int]:
    """Construye los argumentos de Nmap XML (-oX -) y el timeout recomendado según perfil."""
    base = ["nmap", "-oX", "-", "--open", "-T4"]
    if profile == "basic":
        return base + ["-O", "-sV", "--top-ports", "100", ip], 60
    if profile == "deep":
        return base + ["-O", "-sV", "-sC", "-p-", "--min-rate", "1000", ip], 300
    if profile == "security":
        return base + ["-O", "-sV", "-sC", "--top-ports", "1000", ip], 150
    if profile == "custom":
        ports = custom_ports.strip() if custom_ports else "22,80,443"
        return base + ["-sV", "-sC", "-p", ports, ip], 90
    raise ValueError(f"Perfil de escaneo desconocido: {profile}")


def parse_nmap_xml(xml_text: str) -> Dict[str, Any]:
    """
    Parsea la salida XML de Nmap para un host.
    Devuelve SO estimado, hostnames, lista detallada de puertos y alertas de seguridad.
    """
    result: Dict[str, Any] = {
        "so": "No determinado",
        "os_accuracy": "",
        "hostnames": [],
        "ports": [],
        "security_alerts": [],
        "error": None,
    }
    if not xml_text.strip():
        result["error"] = "Salida XML vacía"
        return result

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        result["error"] = f"Error parseando XML de Nmap: {exc}"
        return result

    host = root.find("host")
    if host is None:
        return result

    # Hostnames
    hostnames_el = host.find("hostnames")
    if hostnames_el is not None:
        for hn in hostnames_el.findall("hostname"):
            name = hn.get("name")
            if name and name not in result["hostnames"]:
                result["hostnames"].append(name)

    # Sistema operativo
    os_el = host.find("os")
    if os_el is not None:
        best_match = os_el.find("osmatch")
        if best_match is not None and best_match.get("name"):
            result["so"] = best_match.get("name", "No determinado")
            result["os_accuracy"] = best_match.get("accuracy", "")

    # Puertos y servicios
    ports_el = host.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if state != "open":
                continue

            port_num = int(port_el.get("portid", "0"))
            proto = port_el.get("protocol", "tcp")

            svc_el = port_el.find("service")
            svc_name = svc_el.get("name", "desconocido") if svc_el is not None else "desconocido"
            product = svc_el.get("product", "") if svc_el is not None else ""
            version = svc_el.get("version", "") if svc_el is not None else ""
            extrainfo = svc_el.get("extrainfo", "") if svc_el is not None else ""

            version_parts = [p for p in (product, version, extrainfo) if p]
            version_str = " ".join(version_parts)
            summary = f"{port_num}/{proto} {svc_name}"
            if version_str:
                summary += f" ({version_str})"

            scripts: List[Dict[str, str]] = []
            for script_el in port_el.findall("script"):
                sid = script_el.get("id", "")
                sout = (script_el.get("output") or "").strip()
                if sid:
                    scripts.append({"id": sid, "output": sout})

            result["ports"].append(
                {
                    "port": port_num,
                    "protocol": proto,
                    "state": state,
                    "service": svc_name,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "summary": summary,
                    "scripts": scripts,
                }
            )

            if port_num in RISKY_NETWORK_PORTS:
                sev, reason = RISKY_NETWORK_PORTS[port_num]
                result["security_alerts"].append(
                    {
                        "severity": sev,
                        "port": port_num,
                        "protocol": proto,
                        "service": svc_name,
                        "reason": reason,
                    }
                )

    return result


def scan_host(
    ip: str, profile: str = "basic", custom_ports: Optional[str] = None
) -> Dict[str, Any]:
    """Ejecuta Nmap XML sobre una IP y devuelve el resultado estructurado."""
    args, timeout = build_nmap_args(ip, profile=profile, custom_ports=custom_ports)
    out, err, rc = run_cmd(args, timeout=timeout)
    if rc != 0 or not out:
        return {
            "so": "Fallo",
            "os_accuracy": "",
            "hostnames": [],
            "ports": [],
            "security_alerts": [],
            "error": err or f"Nmap terminó con código {rc}",
        }
    return parse_nmap_xml(out)


def scan_hosts_parallel(
    devices: List[Dict[str, Any]],
    profile: str = "basic",
    custom_ports: Optional[str] = None,
    max_workers: int = 5,
    progress_callback: Optional[Callable[[int, int, Dict[str, Any]], None]] = None,
) -> List[Dict[str, Any]]:
    """
    Escanea una lista de dispositivos en paralelo (excepto en modo 'inventory')
    conservando el orden original de la lista.
    """
    if profile == "inventory":
        enriched = []
        for dev in devices:
            item = dict(dev)
            item.setdefault("so", "No escaneado (solo inventario)")
            item.setdefault("ports", [])
            item.setdefault("security_alerts", [])
            item["services_text"] = "No escaneado"
            enriched.append(item)
        return enriched

    total = len(devices)
    results_by_idx: Dict[int, Dict[str, Any]] = {}
    workers = max(1, min(max_workers, total or 1))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(scan_host, dev["ip"], profile, custom_ports): idx
            for idx, dev in enumerate(devices)
        }
        completed = 0
        for future in as_completed(future_map):
            idx = future_map[future]
            dev = dict(devices[idx])
            try:
                scan_data = future.result()
            except Exception as exc:  # pragma: no cover - defensivo
                scan_data = {
                    "so": "Error",
                    "ports": [],
                    "security_alerts": [],
                    "hostnames": [],
                    "error": str(exc),
                }

            dev["so"] = scan_data.get("so", "No determinado")
            dev["os_accuracy"] = scan_data.get("os_accuracy", "")
            if not dev.get("hostname") and scan_data.get("hostnames"):
                dev["hostname"] = scan_data["hostnames"][0]
            dev["ports"] = scan_data.get("ports", [])
            dev["security_alerts"] = scan_data.get("security_alerts", [])
            dev["scan_error"] = scan_data.get("error")
            dev["services_text"] = (
                ", ".join(p["summary"] for p in dev["ports"])
                if dev["ports"]
                else ("Error" if dev["scan_error"] else "Ninguno")
            )

            results_by_idx[idx] = dev
            completed += 1
            if progress_callback:
                progress_callback(completed, total, dev)

    return [results_by_idx[i] for i in range(total)]
