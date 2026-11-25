# -*- coding: utf-8 -*-
"""Tests unitarios para parsers, auditoría local, escáner Nmap XML y exportación."""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from scanner.discovery import parse_arp_scan, parse_nmap_discovery_xml
from scanner.exporter import export_json, export_txt
from scanner.local_audit import (
    classify_exposure,
    parse_firewall_status,
    parse_netstat_output,
    parse_ss_output,
    parse_sshd_config,
    run_local_audit,
)
from scanner.network_info import parse_whois_info
from scanner.port_scanner import build_nmap_args, parse_nmap_xml
from scanner.utils import calculate_cidr


class TestUtilsAndNetworkInfo(unittest.TestCase):
    def test_calculate_cidr(self):
        self.assertEqual(calculate_cidr("192.168.1.45", 24), "192.168.1.0/24")
        self.assertEqual(calculate_cidr("10.0.5.12", 16), "10.0.0.0/16")
        self.assertIsNone(calculate_cidr("999.999.1.1", 24))

    def test_parse_whois_info(self):
        sample = """
        netname: TELEFONICA-DATA
        country: es
        org-name: Telefonica de Espana SAU
        """
        country, isp = parse_whois_info(sample)
        self.assertEqual(country, "ES")
        self.assertEqual(isp, "Telefonica de Espana SAU")


class TestDiscoveryAndPortScanner(unittest.TestCase):
    def test_parse_arp_scan(self):
        out = (
            "Interface: eth0, type: EN10MB\n"
            "192.168.1.1\taa:bb:cc:dd:ee:ff\tTP-Link Technologies\n"
            "192.168.1.50\t11:22:33:44:55:66\t(Unknown: locally administered)\n"
        )
        devs = parse_arp_scan(out)
        self.assertEqual(len(devs), 2)
        self.assertEqual(devs[0]["mac"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(devs[1]["fab"], "Desconocido")

    def test_parse_nmap_discovery_xml(self):
        xml_sample = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Raspberry Pi"/>
            <hostnames><hostname name="nas.local" type="PTR"/></hostnames>
          </host>
        </nmaprun>"""
        devs = parse_nmap_discovery_xml(xml_sample)
        self.assertEqual(len(devs), 1)
        self.assertEqual(devs[0]["hostname"], "nas.local")
        self.assertEqual(devs[0]["fab"], "Raspberry Pi")

    def test_parse_nmap_xml_ports_and_alerts(self):
        xml_sample = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <hostnames><hostname name="server.lan"/></hostnames>
            <os><osmatch name="Linux 5.15" accuracy="98"/></os>
            <ports>
              <port protocol="tcp" portid="22">
                <state state="open"/>
                <service name="ssh" product="OpenSSH" version="8.9p1"/>
              </port>
              <port protocol="tcp" portid="23">
                <state state="open"/>
                <service name="telnet"/>
              </port>
              <port protocol="tcp" portid="443">
                <state state="closed"/>
                <service name="https"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""
        parsed = parse_nmap_xml(xml_sample)
        self.assertEqual(parsed["so"], "Linux 5.15")
        self.assertEqual(len(parsed["ports"]), 2)
        self.assertEqual(parsed["ports"][0]["summary"], "22/tcp ssh (OpenSSH 8.9p1)")
        self.assertEqual(parsed["ports"][1]["summary"], "23/tcp telnet")
        self.assertEqual(len(parsed["security_alerts"]), 1)
        self.assertEqual(parsed["security_alerts"][0]["severity"], "CRÍTICO")

    def test_build_nmap_args(self):
        args, timeout = build_nmap_args("192.168.1.1", profile="custom", custom_ports="22,443")
        self.assertIn("-oX", args)
        self.assertIn("22,443", args)
        self.assertEqual(timeout, 90)


class TestLocalAudit(unittest.TestCase):
    def test_classify_exposure(self):
        self.assertEqual(classify_exposure("127.0.0.1"), "LOCAL")
        self.assertEqual(classify_exposure("::1"), "LOCAL")
        self.assertEqual(classify_exposure("0.0.0.0"), "EXPOSED_ALL")
        self.assertEqual(classify_exposure("::"), "EXPOSED_ALL")
        self.assertEqual(classify_exposure("192.168.1.25"), "EXPOSED_IFACE")

    def test_parse_ss_output(self):
        sample = """Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=912,fd=3))
tcp   LISTEN 0      50     127.0.0.1:3306     0.0.0.0:*    users:(("mariadbd",pid=1100,fd=20))
tcp   LISTEN 0      128    [::]:8080          [::]:*       users:(("python3",pid=2200,fd=4))
udp   UNCONN 0      0      127.0.0.53%lo:53   0.0.0.0:*    users:(("systemd-resolve",pid=400,fd=12))
"""
        ports = parse_ss_output(sample)
        self.assertEqual(len(ports), 4)
        p22 = next(p for p in ports if p["port"] == 22)
        self.assertEqual(p22["exposure"], "EXPOSED_ALL")
        self.assertEqual(p22["process"], "sshd")
        self.assertEqual(p22["pid"], "912")

        p3306 = next(p for p in ports if p["port"] == 3306)
        self.assertEqual(p3306["exposure"], "LOCAL")

        p8080 = next(p for p in ports if p["port"] == 8080)
        self.assertEqual(p8080["address"], "::")
        self.assertEqual(p8080["exposure"], "EXPOSED_ALL")

    def test_parse_netstat_output(self):
        sample = """Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      888/sshd
udp        0      0 127.0.0.1:53            0.0.0.0:*                           500/dnsmasq
"""
        ports = parse_netstat_output(sample)
        self.assertEqual(len(ports), 2)
        self.assertEqual(ports[0]["process"], "sshd")
        self.assertEqual(ports[0]["pid"], "888")

    def test_parse_sshd_config(self):
        cfg = """
        # Comentario
        Port 22
        PermitRootLogin yes
        PasswordAuthentication yes
        PermitEmptyPasswords no
        X11Forwarding yes
        """
        res = parse_sshd_config(cfg)
        titles = [f["title"] for f in res["findings"]]
        self.assertIn("PermitRootLogin activado", titles)
        self.assertIn("PasswordAuthentication activado", titles)
        self.assertIn("X11Forwarding activado", titles)

    def test_parse_firewall_status(self):
        self.assertTrue(parse_firewall_status(ufw_out="Status: active")["active"])
        self.assertFalse(parse_firewall_status(ufw_out="Status: inactive")["active"])
        self.assertFalse(
            parse_firewall_status(iptables_out="Chain INPUT (policy ACCEPT)\ntarget prot opt source destination")["active"]
        )

    def test_run_local_audit_integration(self):
        mock_ports = [
            {
                "proto": "tcp",
                "state": "LISTEN",
                "address": "0.0.0.0",
                "port": 22,
                "exposure": "EXPOSED_ALL",
                "process": "sshd",
                "pid": "912",
            },
            {
                "proto": "tcp",
                "state": "LISTEN",
                "address": "0.0.0.0",
                "port": 6379,
                "exposure": "EXPOSED_ALL",
                "process": "redis-server",
                "pid": "1400",
            },
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            sshd_file = os.path.join(tmpdir, "sshd_config")
            with open(sshd_file, "w", encoding="utf-8") as fh:
                fh.write("PermitRootLogin yes\nPasswordAuthentication yes\n")

            with patch("scanner.local_audit.get_listening_ports", return_value=(mock_ports, "ss")), \
                 patch("scanner.local_audit.check_firewall", return_value={"active": False, "backend": "none", "summary": "Sin firewall", "details": ""}):
                audit = run_local_audit(local_ip="192.168.1.15", cross_check=False, sshd_config_path=sshd_file)

        self.assertTrue(audit["ssh_listening"])
        self.assertGreaterEqual(audit["severity_counts"]["CRÍTICO"], 2)  # Redis + PermitRootLogin
        self.assertGreaterEqual(audit["severity_counts"]["ALTO"], 2)     # PasswordAuth + No firewall
        self.assertLess(audit["score"], 50)


class TestExporter(unittest.TestCase):
    def test_export_txt_and_json(self):
        net_info_data = {
            "interfaz": "eth0",
            "ip_local": "192.168.1.15",
            "red": "192.168.1.0/24",
            "gateway": "192.168.1.1",
            "ssid": "No disponible (no WiFi)",
            "dns_servers": ["1.1.1.1"],
            "public_ip": "1.2.3.4",
            "country": "ES",
            "isp": "ISP Test",
            "mac_iface": "AA:BB:CC:DD:EE:FF",
            "vendor_iface": "Intel",
        }
        devices = [
            {
                "ip": "192.168.1.1",
                "mac": "11:22:33:44:55:66",
                "hostname": "router.lan",
                "fab": "TP-Link",
                "so": "Linux 4.x",
                "ports": [{"summary": "80/tcp http", "scripts": []}],
                "security_alerts": [],
            }
        ]
        audit = {
            "score": 85,
            "source": "ss",
            "firewall": {"active": True, "summary": "UFW activo"},
            "severity_counts": {"CRÍTICO": 0, "ALTO": 0, "MEDIO": 1, "BAJO": 0, "INFO": 1},
            "listening_ports": [
                {"proto": "tcp", "address": "127.0.0.1", "port": 5432, "exposure": "LOCAL", "process": "postgres", "pid": "100"}
            ],
            "findings": [
                {"severity": "INFO", "category": "Puerto Local", "title": "PostgreSQL local", "detail": "Solo localhost", "recommendation": "OK"}
            ],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            txt_path = os.path.join(tmpdir, "out.txt")
            json_path = os.path.join(tmpdir, "out.json")
            export_txt(txt_path, network_info=net_info_data, devices=devices, local_audit=audit)
            export_json(json_path, network_info=net_info_data, devices=devices, local_audit=audit, mode="full")

            with open(txt_path, "r", encoding="utf-8") as fh:
                txt_content = fh.read()
            self.assertIn("Interfaz:            eth0", txt_content)
            self.assertIn("Red (CIDR):          192.168.1.0/24", txt_content)
            self.assertIn("80/tcp http", txt_content)
            self.assertIn("Puntuación estimada: 85/100", txt_content)

            with open(json_path, "r", encoding="utf-8") as fh:
                parsed_json = json.load(fh)
            self.assertEqual(parsed_json["metadata"]["mode"], "full")
            self.assertEqual(parsed_json["local_audit"]["score"], 85)
            self.assertEqual(len(parsed_json["devices"]), 1)


if __name__ == "__main__":
    unittest.main()
