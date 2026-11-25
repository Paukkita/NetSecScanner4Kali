# -*- coding: utf-8 -*-
"""Exportación de informes de red y auditoría local en formatos TXT y JSON."""

from datetime import datetime
import json
from typing import Any, Dict, List, Optional


def _format_txt_network(lines: List[str], info: Dict[str, Any], devices: List[Dict[str, Any]]) -> None:
    """Añade al informe de texto la sección de información de red y dispositivos."""
    lines.append("[ INFORMACIÓN DE RED ]")
    lines.append(f"Interfaz:            {info.get('interfaz', 'N/A')}")
    lines.append(f"IP Local:            {info.get('ip_local', 'N/A')}")
    lines.append(f"Red (CIDR):          {info.get('red', 'N/A')}")
    lines.append(f"Gateway:             {info.get('gateway', 'N/A')}")
    lines.append(f"SSID:                {info.get('ssid', 'N/A')}")
    lines.append(f"Servidores DNS:      {', '.join(info.get('dns_servers', [])) or 'N/A'}")
    lines.append(f"IP Pública:          {info.get('public_ip', 'N/A')}")
    lines.append(f"País:                {info.get('country', 'N/A')}")
    lines.append(f"Proveedor (ISP):     {info.get('isp', 'N/A')}")
    lines.append(f"MAC Interfaz:        {info.get('mac_iface', 'N/A')}")
    lines.append(f"Fabricante Interfaz: {info.get('vendor_iface', 'N/A')}")
    lines.append("")

    lines.append(f"[ DISPOSITIVOS EN LA RED ({len(devices)}) ]")
    if not devices:
        lines.append("No se encontraron dispositivos.")
        lines.append("")
        return

    lines.append("-" * 105)
    lines.append(f"{'IP':<16} {'MAC':<18} {'HOSTNAME':<22} {'FABRICANTE':<20} {'SO'}")
    lines.append("-" * 105)
    for dev in devices:
        lines.append(
            f"{dev.get('ip', ''):<16} "
            f"{(dev.get('mac') or '-'):<18} "
            f"{(dev.get('hostname') or '-')[:21]:<22} "
            f"{(dev.get('fab') or 'Desconocido')[:19]:<20} "
            f"{dev.get('so', 'No determinado')}"
        )
        ports = dev.get("ports", [])
        if ports:
            for port in ports:
                lines.append(f"    -> {port.get('summary', '')}")
                for scr in port.get("scripts", []):
                    out_one_line = scr.get("output", "").replace("\n", " | ")
                    lines.append(f"       [{scr.get('id')}] {out_one_line[:140]}")
        elif dev.get("services_text") and dev.get("services_text") != "Ninguno":
            lines.append(f"    -> Servicios: {dev['services_text']}")

        for alert in dev.get("security_alerts", []):
            lines.append(
                f"    [!] ALERTA [{alert['severity']}] {alert['port']}/{alert['protocol']}: {alert['reason']}"
            )
    lines.append("")


def _format_txt_local_audit(lines: List[str], audit: Dict[str, Any]) -> None:
    """Añade al informe de texto la sección de auditoría local del equipo."""
    lines.append("[ AUDITORÍA DE SEGURIDAD DEL EQUIPO LOCAL ]")
    lines.append(f"Puntuación estimada: {audit.get('score', 0)}/100")
    fw = audit.get("firewall", {})
    lines.append(f"Firewall:            {fw.get('summary', 'Desconocido')}")
    lines.append(f"Fuente de sockets:   {audit.get('source', 'N/A')}")
    counts = audit.get("severity_counts", {})
    lines.append(
        "Resumen hallazgos:   "
        + ", ".join(f"{k}: {v}" for k, v in counts.items())
    )
    lines.append("")

    ports = audit.get("listening_ports", [])
    lines.append(f"Puertos locales en escucha ({len(ports)}):")
    lines.append("-" * 92)
    lines.append(f"{'PROTO':<7} {'DIRECCIÓN':<24} {'PUERTO':<8} {'EXPOSICIÓN':<15} {'PROCESO (PID)'}")
    lines.append("-" * 92)
    for p in ports:
        proc = p.get("process", "Desconocido")
        pid = p.get("pid", "")
        proc_str = f"{proc} ({pid})" if pid else proc
        lines.append(
            f"{p.get('proto', ''):<7} "
            f"{p.get('address', ''):<24} "
            f"{str(p.get('port', '')):<8} "
            f"{p.get('exposure', ''):<15} "
            f"{proc_str}"
        )
    lines.append("")

    findings = audit.get("findings", [])
    lines.append(f"Hallazgos y recomendaciones ({len(findings)}):")
    if not findings:
        lines.append("Sin hallazgos relevantes.")
    else:
        for idx, item in enumerate(findings, start=1):
            lines.append(
                f"  {idx}. [{item.get('severity', 'INFO')}] ({item.get('category', '')}) {item.get('title', '')}"
            )
            lines.append(f"     Detalle:        {item.get('detail', '')}")
            lines.append(f"     Recomendación:  {item.get('recommendation', '')}")
    lines.append("")


def export_txt(
    filepath: str,
    network_info: Optional[Dict[str, Any]] = None,
    devices: Optional[List[Dict[str, Any]]] = None,
    local_audit: Optional[Dict[str, Any]] = None,
) -> None:
    """Guarda un informe completo legible en archivo .txt."""
    lines: List[str] = [
        "=" * 78,
        "              INFORME DE ESCÁNER DE RED Y SEGURIDAD LOCAL",
        f"              Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 78,
        "",
    ]

    if local_audit is not None:
        _format_txt_local_audit(lines, local_audit)

    if network_info is not None or devices is not None:
        _format_txt_network(lines, network_info or {}, devices or [])

    lines.append("=" * 78)
    lines.append("FIN DEL INFORME")

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def export_json(
    filepath: str,
    network_info: Optional[Dict[str, Any]] = None,
    devices: Optional[List[Dict[str, Any]]] = None,
    local_audit: Optional[Dict[str, Any]] = None,
    mode: str = "custom",
) -> None:
    """Guarda los resultados estructurados en JSON (útil para integraciones o futura UI)."""
    payload: Dict[str, Any] = {
        "metadata": {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "mode": mode,
        },
        "local_audit": local_audit,
        "network_info": network_info,
        "devices": devices or [],
    }
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
