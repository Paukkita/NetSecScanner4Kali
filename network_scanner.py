#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
network_scanner: Escáner de red local y auditoría de seguridad del equipo.

Soporta ejecución por menú interactivo o mediante argumentos CLI (--help).
Usa únicamente la biblioteca estándar de Python + utilidades del sistema Linux.
"""

import argparse
import signal
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from scanner.discovery import discover_devices
from scanner.exporter import export_json, export_txt
from scanner.local_audit import run_local_audit
from scanner.network_info import (
    default_iface,
    get_network_details,
    list_interfaces,
    net_info,
)
from scanner.port_scanner import scan_hosts_parallel
from scanner.utils import (
    check_tools,
    clear_screen,
    is_root,
    print_banner,
    timestamp_slug,
)

PROFILE_TITLES = {
    "inventory": "INVENTARIO RÁPIDO DE RED (SIN ESCANEO DE PUERTOS)",
    "basic": "ANÁLISIS BÁSICO DE RED (TOP 100 PUERTOS + SO)",
    "deep": "ANÁLISIS PROFUNDO DE RED (TODOS LOS PUERTOS + NSE)",
    "security": "ANÁLISIS DE SEGURIDAD EN RED (TOP 1000 + ALERTAS)",
    "custom": "ANÁLISIS DE PUERTOS PERSONALIZADO",
}


def _signal_handler(sig: int, frame: Any) -> None:
    print("\n[!] Interrupción recibida. Saliendo limpiamente...")
    sys.exit(0)


def print_network_summary(details: Dict[str, Any], target: str) -> None:
    """Muestra en pantalla la configuración de red detectada."""
    print(f"[+] Interfaz:       {details.get('interfaz')} ({details.get('ip_local')})")
    print(f"[+] Objetivo/Red:   {target}")
    print(f"[+] Gateway:        {details.get('gateway', 'No disponible')}")
    print(f"[+] SSID:           {details.get('ssid', 'No disponible')}")
    dns = details.get("dns_servers") or []
    print(f"[+] DNS:            {', '.join(dns) if dns else 'No disponible'}")
    print(f"[+] IP Pública:     {details.get('public_ip', 'No disponible')}")
    print(f"[+] País / ISP:     {details.get('country', 'No disponible')} / {details.get('isp', 'No disponible')}")
    print(f"[+] MAC Interfaz:   {details.get('mac_iface', 'No disponible')} ({details.get('vendor_iface', 'Desconocido')})")
    print()


def print_devices_results(devices: List[Dict[str, Any]], profile: str) -> None:
    """Muestra la tabla de dispositivos descubiertos y sus puertos/alertas."""
    if not devices:
        print("[!] No se encontraron dispositivos activos.")
        return

    print(f"\n[+] {len(devices)} dispositivo(s) analizado(s):\n")
    header = f"{'IP':<16} {'MAC':<18} {'HOSTNAME':<22} {'FABRICANTE':<18} {'SO'}"
    print(header)
    print("-" * 100)
    for dev in devices:
        print(
            f"{dev.get('ip', ''):<16} "
            f"{(dev.get('mac') or '-'):<18} "
            f"{(dev.get('hostname') or '-')[:21]:<22} "
            f"{(dev.get('fab') or 'Desconocido')[:17]:<18} "
            f"{dev.get('so', 'No determinado')[:28]}"
        )
        if profile != "inventory":
            ports = dev.get("ports", [])
            if ports:
                for p in ports:
                    print(f"    -> {p['summary']}")
            else:
                print(f"    -> Puertos abiertos: {dev.get('services_text', 'Ninguno')}")
        for alert in dev.get("security_alerts", []):
            print(
                f"    [!] [{alert['severity']}] {alert['port']}/{alert['protocol']}: {alert['reason']}"
            )


def print_local_audit_results(audit: Dict[str, Any]) -> None:
    """Muestra los resultados de la auditoría de puertos y seguridad del equipo local."""
    print_banner("AUDITORÍA DE PUERTOS ACTIVOS Y SEGURIDAD DEL EQUIPO")

    fw = audit.get("firewall", {})
    counts = audit.get("severity_counts", {})
    print(f"[+] Puntuación de seguridad: {audit.get('score', 0)}/100")
    print(f"[+] Firewall:                {fw.get('summary', 'Desconocido')}")
    print(f"[+] SSH activo:              {'Sí' if audit.get('ssh_listening') else 'No'}")
    print(f"[+] Puertos expuestos (LAN): {audit.get('exposed_count', 0)}")
    print(
        "[+] Hallazgos:               "
        + " | ".join(f"{k}: {v}" for k, v in counts.items())
    )

    ports = audit.get("listening_ports", [])
    print(f"\n[+] Puertos en escucha detectados ({len(ports)}, fuente: {audit.get('source')}):\n")
    if ports:
        print(f"{'PROTO':<7} {'DIRECCIÓN':<22} {'PUERTO':<8} {'EXPOSICIÓN':<15} {'PROCESO (PID)'}")
        print("-" * 80)
        for p in ports:
            proc_txt = f"{p['process']} ({p['pid']})" if p.get("pid") else p.get("process", "-")
            print(
                f"{p['proto']:<7} {p['address']:<22} {str(p['port']):<8} "
                f"{p['exposure']:<15} {proc_txt}"
            )
    else:
        print("    [!] No se pudieron listar puertos activos (revisa si tienes `ss` o `netstat`).")

    cross = audit.get("cross_check") or {}
    if cross:
        print("\n[+] Verificación cruzada Nmap contra IP local:")
        for port_num, state in sorted(cross.items()):
            print(f"    - Puerto {port_num}/tcp -> {state}")

    findings = audit.get("findings", [])
    print(f"\n[+] Diagnóstico y recomendaciones ({len(findings)}):")
    if not findings:
        print("    [OK] No se detectaron riesgos destacables.")
    else:
        for item in findings:
            print(f"\n  [{item['severity']}] ({item['category']}) {item['title']}")
            print(f"      Detalle:       {item['detail']}")
            print(f"      Recomendación: {item['recommendation']}")


def run_network_scan(
    profile: str,
    iface: Optional[str] = None,
    target: Optional[str] = None,
    custom_ports: Optional[str] = None,
    fetch_public: bool = True,
    workers: int = 5,
) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    """Ejecuta descubrimiento + escaneo de red y devuelve (details, devices)."""
    print_banner(PROFILE_TITLES.get(profile, "ANÁLISIS DE RED"))

    selected_iface = iface or default_iface()
    if not selected_iface and not target:
        print("[!] No se encontró una interfaz con ruta por defecto ni objetivo manual.")
        return None, []

    ip_local, net_cidr = (None, None)
    if selected_iface:
        ip_local, net_cidr = net_info(selected_iface)

    scan_target = target or net_cidr
    if not scan_target:
        print(f"[!] La interfaz {selected_iface} no tiene IP IPv4 asignada.")
        return None, []

    details = (
        get_network_details(selected_iface, ip=ip_local, net=net_cidr, fetch_public=fetch_public)
        if selected_iface
        else {"interfaz": "Manual", "ip_local": "N/A", "red": scan_target}
    )
    print_network_summary(details, scan_target)

    print(f"[*] Descubriendo dispositivos activos en {scan_target}...")
    devices = discover_devices(selected_iface, scan_target)
    if not devices:
        print("[!] No se encontraron dispositivos activos.")
        return details, []

    print(f"[+] {len(devices)} dispositivo(s) encontrado(s).")
    if profile != "inventory":
        print(f"[*] Escaneando puertos/SO en paralelo ({workers} hilos)...")

    def _on_progress(done: int, total: int, dev: Dict[str, Any]) -> None:
        print(f"    [{done}/{total}] {dev['ip']} -> {len(dev.get('ports', []))} puerto(s) abierto(s)")

    results = scan_hosts_parallel(
        devices,
        profile=profile,
        custom_ports=custom_ports,
        max_workers=workers,
        progress_callback=_on_progress if profile != "inventory" else None,
    )
    print_devices_results(results, profile)
    return details, results


def prompt_export(
    network_info: Optional[Dict[str, Any]] = None,
    devices: Optional[List[Dict[str, Any]]] = None,
    local_audit: Optional[Dict[str, Any]] = None,
    mode: str = "interactive",
) -> None:
    """Pregunta en modo interactivo si guardar resultados en TXT y/o JSON."""
    if not devices and not local_audit:
        return
    resp = input("\n¿Guardar resultados? [n] No / [t] TXT / [j] JSON / [a] Ambos (N): ").strip().lower()
    if not resp or resp == "n":
        return

    slug = timestamp_slug()
    if resp in ("t", "txt", "s", "si", "a", "ambos"):
        txt_name = f"informe_red_{slug}.txt"
        export_txt(txt_name, network_info=network_info, devices=devices, local_audit=local_audit)
        print(f"[+] Informe TXT guardado en: {txt_name}")
    if resp in ("j", "json", "a", "ambos"):
        json_name = f"informe_red_{slug}.json"
        export_json(
            json_name,
            network_info=network_info,
            devices=devices,
            local_audit=local_audit,
            mode=mode,
        )
        print(f"[+] Informe JSON guardado en: {json_name}")


def select_interface_interactive(current_iface: Optional[str], current_target: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Permite al usuario elegir otra interfaz o fijar un objetivo CIDR/IP manual."""
    ifaces = list_interfaces()
    print("\nInterfaces IPv4 disponibles:")
    if not ifaces:
        print("  (No se detectaron interfaces)")
    else:
        for idx, item in enumerate(ifaces, start=1):
            print(
                f"  [{idx}] {item['iface']:<10} IP: {item['ip']:<16} "
                f"Red: {item['net']:<18} (Por defecto: {item['is_default']})"
            )

    chosen_iface = current_iface
    sel = input("\nElige número de interfaz (ENTER para mantener actual): ").strip()
    if sel.isdigit() and 1 <= int(sel) <= len(ifaces):
        chosen_iface = ifaces[int(sel) - 1]["iface"]

    manual = input("Objetivo manual IP/rango/CIDR (ENTER para usar la red de la interfaz): ").strip()
    chosen_target = manual if manual else None
    return chosen_iface, chosen_target


def interactive_menu(tools_status: Dict[str, Any]) -> None:
    """Menú interactivo principal."""
    selected_iface = default_iface()
    manual_target: Optional[str] = None

    while True:
        clear_screen()
        print("=" * 72)
        print("        NETWORK_SCANNER — RED LOCAL Y AUDITORÍA DE SEGURIDAD")
        print("=" * 72)
        print(f"\nInterfaz activa: {selected_iface or 'No disponible'}")
        print(f"Objetivo actual: {manual_target or 'Subred automática de la interfaz'}")

        avail = tools_status["available"]
        missing_opt = [
            t for t in ("arp-scan", "iwgetid", "nmcli", "whois", "curl", "dig") if not avail.get(t)
        ]
        if missing_opt:
            print(f"Herramientas opcionales no presentes: {', '.join(missing_opt)}")

        print("\n[1] Auditoría de seguridad de ESTE equipo (puertos activos, procesos, SSH, firewall)")
        print("[2] Escaneo de red — Básico (descubrimiento + Top 100 puertos + SO)")
        print("[3] Escaneo de red — Profundo (todos los puertos + scripts NSE + SO)")
        print("[4] Escaneo de red — Seguridad / Puertos personalizados")
        print("[5] Auditoría COMPLETA (Este equipo + Escaneo de seguridad en red)")
        print("[6] Solo inventario de dispositivos (sin escanear puertos)")
        print("[7] Cambiar interfaz / definir objetivo manual (IP o CIDR)")
        print("[8] Salir")

        op = input("\nOpción: ").strip()

        if op == "1":
            clear_screen()
            ip_local, _ = net_info(selected_iface) if selected_iface else (None, None)
            cc = False
            if ip_local and avail.get("nmap"):
                cc_in = input("¿Verificar con Nmap qué puertos son visibles desde tu IP de red? (s/N): ").strip().lower()
                cc = cc_in in ("s", "si")
            audit = run_local_audit(local_ip=ip_local, cross_check=cc)
            print_local_audit_results(audit)
            prompt_export(local_audit=audit, mode="local_audit")
            input("\nPulsa ENTER para continuar...")

        elif op in ("2", "3", "4", "6"):
            if not tools_status["can_network_scan"]:
                print("\n[!] Falta `nmap` para realizar escaneos de red.")
                time.sleep(2)
                continue
            clear_screen()
            if op == "2":
                profile, custom_ports = "basic", None
            elif op == "3":
                profile, custom_ports = "deep", None
            elif op == "6":
                profile, custom_ports = "inventory", None
            else:
                sub = input("Elige [1] Perfil Seguridad (Top 1000 + alertas) o [2] Puertos manuales: ").strip()
                if sub == "2":
                    profile = "custom"
                    custom_ports = input("Puertos separados por coma (ej. 22,80,443,3306): ").strip() or "22,80,443"
                else:
                    profile, custom_ports = "security", None

            details, devs = run_network_scan(
                profile=profile,
                iface=selected_iface,
                target=manual_target,
                custom_ports=custom_ports,
            )
            prompt_export(network_info=details, devices=devs, mode=profile)
            input("\nPulsa ENTER para continuar...")

        elif op == "5":
            clear_screen()
            ip_local, _ = net_info(selected_iface) if selected_iface else (None, None)
            audit = run_local_audit(local_ip=ip_local, cross_check=bool(ip_local and avail.get("nmap")))
            print_local_audit_results(audit)

            details, devs = (None, [])
            if tools_status["can_network_scan"]:
                details, devs = run_network_scan(
                    profile="security",
                    iface=selected_iface,
                    target=manual_target,
                )
            else:
                print("\n[!] `nmap` no está instalado; se omite el escaneo de red.")

            prompt_export(network_info=details, devices=devs, local_audit=audit, mode="full")
            input("\nPulsa ENTER para continuar...")

        elif op == "7":
            selected_iface, manual_target = select_interface_interactive(selected_iface, manual_target)

        elif op == "8":
            print("\n[+] Saliendo...")
            break
        else:
            print("\n[!] Opción inválida.")
            time.sleep(1)


def parse_cli_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Define los argumentos de línea de comandos."""
    parser = argparse.ArgumentParser(
        description="Escáner de red local y auditoría de seguridad del equipo."
    )
    parser.add_argument(
        "--local", "-l", action="store_true",
        help="Ejecuta la auditoría de puertos activos y seguridad del equipo local.",
    )
    parser.add_argument(
        "--full", action="store_true",
        help="Ejecuta auditoría local + escaneo de seguridad de la red.",
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["inventory", "basic", "deep", "security", "custom"],
        help="Modo de escaneo de red (si se omite y no se usa --local/--full, abre el menú).",
    )
    parser.add_argument("--iface", "-i", help="Interfaz de red a utilizar (ej. eth0, wlan0).")
    parser.add_argument("--target", "-t", help="Objetivo manual: IP, rango o CIDR (ej. 192.168.1.0/24).")
    parser.add_argument("--ports", "-p", help="Puertos para --mode custom (ej. 22,80,443).")
    parser.add_argument("--workers", "-w", type=int, default=5, help="Hilos paralelos para Nmap (defecto: 5).")
    parser.add_argument("--no-public", action="store_true", help="Omitir consulta de IP pública/WHOIS.")
    parser.add_argument(
        "--cross-check", action="store_true",
        help="Verifica con Nmap qué puertos locales son accesibles en la IP de red.",
    )
    parser.add_argument("--out-txt", help="Ruta para guardar el informe en formato TXT.")
    parser.add_argument("--out-json", help="Ruta para guardar el informe en formato JSON.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    signal.signal(signal.SIGINT, _signal_handler)
    args = parse_cli_args(argv)
    tools_status = check_tools()

    is_cli_mode = any([args.local, args.full, args.mode is not None])

    if not is_root():
        if args.local and not args.full and not args.mode:
            print("[!] Aviso: sin root, `ss` puede no mostrar algunos nombres de proceso/PID y algunos firewalls.")
        else:
            print("[!] Ejecuta como root para escaneos completos: sudo python3 network_scanner.py")
            if not is_cli_mode:
                sys.exit(1)

    if not is_cli_mode:
        interactive_menu(tools_status)
        return

    local_audit_data = None
    network_details = None
    devices_data: List[Dict[str, Any]] = []

    selected_iface = args.iface or default_iface()
    ip_local, _ = net_info(selected_iface) if selected_iface else (None, None)

    if args.local or args.full:
        local_audit_data = run_local_audit(
            local_ip=ip_local,
            cross_check=args.cross_check or args.full,
        )
        print_local_audit_results(local_audit_data)

    scan_mode = args.mode or ("security" if args.full else None)
    if scan_mode:
        if not tools_status["can_network_scan"]:
            print("[!] Error: falta `nmap` para el escaneo de red.")
            sys.exit(1)
        network_details, devices_data = run_network_scan(
            profile=scan_mode,
            iface=selected_iface,
            target=args.target,
            custom_ports=args.ports,
            fetch_public=not args.no_public,
            workers=args.workers,
        )

    if args.out_txt:
        export_txt(
            args.out_txt,
            network_info=network_details,
            devices=devices_data,
            local_audit=local_audit_data,
        )
        print(f"\n[+] Informe TXT guardado en: {args.out_txt}")

    if args.out_json:
        export_json(
            args.out_json,
            network_info=network_details,
            devices=devices_data,
            local_audit=local_audit_data,
            mode="full" if args.full else (scan_mode or "local"),
        )
        print(f"[+] Informe JSON guardado en: {args.out_json}")


if __name__ == "__main__":
    main()
