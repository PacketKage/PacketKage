"""Host profiling — builds per-IP profiles with roles, services, and behavior.

Profile shape (Module H):
    192.168.1.25  →  role: "Web server", services: 22/SSH 80/HTTP 443/HTTPS,
                     bytes in/out, protocols, contacted peers, hostname (via DNS PTR/CNAME/SNI).
"""
from __future__ import annotations

from collections import Counter

from app.core.models import ParsedCapture
from app.services.flow_builder import is_private_ip

# service inference by port
PORT_SERVICES = {
    22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "SMTP", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "OracleDB",
    3306: "MySQL", 3389: "RDP", 4444: "Metasploit", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt", 25565: "Minecraft",
}

ROLE_SIGNALS = {
    "DNS server": {53},
    "Web server": {80, 443, 8080, 8443},
    "Mail server": {25, 110, 143, 465, 587, 993, 995},
    "Database server": {1433, 1521, 3306, 5432, 6379},
    "File server": {445, 139},
    "Remote access server": {3389, 5900},
    "SSH server": {22},
}


class _HostAccumulator:
    def __init__(self, ip: str) -> None:
        self.ip = ip
        self.mac: str | None = None
        self.first_seen: float | None = None
        self.last_seen: float | None = None
        self.packets_sent = 0
        self.packets_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.protocols: Counter = Counter()
        # services exposed: someone connected TO this host on this port
        self._service_ports: dict[tuple[str, int], int] = {}
        # peers contacted: this host initiated to (ip, port)
        self._contacted: dict[tuple[str, int, str], dict] = {}
        self.hostname_hints: set[str] = set()

    def observe(self, pkt, sent: bool) -> None:
        ts = pkt.timestamp
        self.first_seen = ts if self.first_seen is None else min(self.first_seen, ts)
        self.last_seen = ts if self.last_seen is None else max(self.last_seen, ts)
        if sent:
            self.packets_sent += 1
            self.bytes_sent += pkt.length
        else:
            self.packets_received += 1
            self.bytes_received += pkt.length
        if pkt.protocol:
            self.protocols[pkt.protocol] += 1
        if sent and pkt.metadata.get("eth.src"):
            self.mac = pkt.metadata["eth.src"]
        elif not sent and pkt.metadata.get("eth.dst"):
            self.mac = self.mac or pkt.metadata["eth.dst"]

    def record_flow(self, flow: dict, as_source: bool) -> None:
        if as_source:
            port = flow["destination_port"]
            key = (flow["destination_ip"], port)
            self._contacted.setdefault(
                key + (flow["application_protocol"] or flow["transport_protocol"],),
                {
                    "ip": flow["destination_ip"],
                    "port": port,
                    "app_protocol": flow["application_protocol"] or flow["transport_protocol"],
                    "packets": 0,
                    "bytes": 0,
                },
            )
            entry = self._contacted[
                (flow["destination_ip"], port, flow["application_protocol"] or flow["transport_protocol"])
            ]
            entry["packets"] += flow["packets"]
            entry["bytes"] += flow["bytes"]
        else:
            port = flow["destination_port"]  # service port others connect to on us
            self._service_ports[(flow["source_ip"], port)] = (
                self._service_ports.get((flow["source_ip"], port), 0) + flow["packets"]
            )

    def note_hostname(self, name: str) -> None:
        if name:
            self.hostname_hints.add(name.rstrip("."))

    @property
    def services(self) -> list[dict]:
        by_port: Counter = Counter()
        for (_src_ip, port), packets in self._service_ports.items():
            by_port[port] += packets
        return [
            {
                "port": port,
                "service": PORT_SERVICES.get(port, "unknown"),
                "transport": "TCP/UDP",
                "packets": packets,
            }
            for port, packets in by_port.most_common()
        ]

    @property
    def contacted(self) -> list[dict]:
        return sorted(self._contacted.values(), key=lambda c: -c["bytes"])

    @property
    def role(self) -> str | None:
        exposed = {s["port"] for s in self.services if s["service"] != "unknown"}
        if not exposed:
            return None
        best, best_score = None, 0
        for role, ports in ROLE_SIGNALS.items():
            score = len(exposed & ports)
            if score > best_score:
                best, best_score = role, score
        return best

    @property
    def behavior_summary(self) -> dict:
        return {
            "dominant_protocol": self.protocols.most_common(1)[0][0] if self.protocols else None,
            "protocol_distribution": dict(self.protocols.most_common()),
            "unique_peers": len({c["ip"] for c in self.contacted}),
            "services_exposed": len(self.services),
            "connections_initiated": len(self.contacted),
        }


class HostProfiler:
    def build_profiles(self, parsed: ParsedCapture, flows: list[dict]) -> list[dict]:
        hosts: dict[str, _HostAccumulator] = {}

        def acc(ip: str) -> _HostAccumulator:
            if ip not in hosts:
                hosts[ip] = _HostAccumulator(ip)
            return hosts[ip]

        for pkt in parsed.packets:
            if not pkt.source_ip or not pkt.destination_ip:
                continue
            src, dst = acc(pkt.source_ip), acc(pkt.destination_ip)
            src.observe(pkt, sent=True)
            dst.observe(pkt, sent=False)

        # flows → services + contacted peers (direction-aware)
        for flow in flows:
            if not flow["source_ip"] or not flow["destination_ip"]:
                continue
            acc(flow["source_ip"]).record_flow(flow, as_source=True)
            acc(flow["destination_ip"]).record_flow(flow, as_source=False)

        # hostname resolution: DNS CNAME answers + reverse hints + TLS SNI (client → sni)
        for txn in _dns_transactions(parsed):
            for answer in txn.get("response_ips", []):
                if answer in hosts:
                    hosts[answer].note_hostname(txn["query_name"])
            # reverse: query that matches an IP literal (x.x.x.x.in-addr.arpa)
        for pkt in parsed.packets:
            sni = pkt.metadata.get("tls.sni")
            if sni and pkt.source_ip in hosts:
                hosts[pkt.source_ip].note_hostname(sni)  # client visited sni — peer hint
            # DHCP hostname: the client announcing its own name
            dhcp_host = pkt.metadata.get("dhcp.hostname")
            if dhcp_host and pkt.source_ip in hosts:
                hosts[pkt.source_ip].note_hostname(dhcp_host)
            # SMTP/FTP banners carry the server's own hostname
            for banner_key in ("smtp.banner", "ftp.banner"):
                banner = pkt.metadata.get(banner_key)
                if banner and pkt.source_ip in hosts:
                    # "220 mail.example.com ESMTP ..." → take first token after code
                    try:
                        parts = banner.split()
                        if len(parts) >= 2 and not parts[1].startswith("("):
                            hosts[pkt.source_ip].note_hostname(parts[1])
                    except Exception:
                        pass

        results = []
        for ip, a in hosts.items():
            results.append(
                {
                    "ip": ip,
                    "mac": a.mac,
                    "hostname": (sorted(a.hostname_hints)[0] if a.hostname_hints else None),
                    "is_internal": is_private_ip(ip),
                    "first_seen": a.first_seen,
                    "last_seen": a.last_seen,
                    "packets_sent": a.packets_sent,
                    "packets_received": a.packets_received,
                    "bytes_sent": a.bytes_sent,
                    "bytes_received": a.bytes_received,
                    "protocols": dict(a.protocols),
                    "services": a.services,
                    "contacted": a.contacted,
                    "role": a.role,
                    "behavior_summary": a.behavior_summary,
                }
            )
        results.sort(key=lambda h: -(h["bytes_sent"] + h["bytes_received"]))
        return results


def _dns_transactions(parsed: ParsedCapture) -> list[dict]:
    from app.services.protocol_extractor import extract_dns

    return extract_dns(parsed)
