"""TSharkParser — optional enhanced parser (direct tshark integration, no PyShark)."""

from __future__ import annotations

import shutil
import subprocess
from typing import Any

from app.core.models import NormalizedPacket, ParsedCapture
from app.parsers.base import PacketParser, ParserError
from app.parsers.scapy_parser import TCP_FLAG_NAMES


class TSharkParser(PacketParser):
    name = "tshark"

    def __init__(self, tshark_path: str = "tshark") -> None:
        self._tshark_path = tshark_path

    def available(self) -> bool:
        return shutil.which(self._tshark_path) is not None

    def parse_file(self, path: str, progress_cb=None) -> ParsedCapture:
        if not self.available():
            raise ParserError("tshark not found on this system")
        fields = ",".join(
            [
                "frame.number",
                "frame.time_epoch",
                "frame.len",
                "frame.protocols",
                "ip.src",
                "ip.dst",
                "ipv6.src",
                "ipv6.dst",
                "tcp.srcport",
                "tcp.dstport",
                "tcp.flags",
                "udp.srcport",
                "udp.dstport",
                "dns.qry.name",
                "dns.flags.response",
                "dns.flags.rcode",
                "http.host",
                "http.request.method",
                "http.response.code",
                "tls.handshake.extensions_server_name",
                "tls.record.version",
                "quic.long.packet_type",
                "bootp.option.hostname",
                "bootp.type",
                "ssh.protocol",
                "smtp.req_command",
                "ftp.request.command",
            ]
        )
        # -e must precede each field with -T fields
        cmd = [self._tshark_path, "-r", path, "-T", "fields", "-E", "separator=|", "-E", "occurrence=f"]
        for f in fields.split(","):
            cmd += ["-e", f]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired as exc:
            raise ParserError("tshark timed out after 600s") from exc
        if proc.returncode != 0:
            raise ParserError(f"tshark failed: {proc.stderr.strip()[:500]}")

        capture = ParsedCapture(filename=path.split("/")[-1], parser_used=self.name)
        lines = proc.stdout.splitlines()
        total = len(lines)
        for index, line in enumerate(lines):
            normalized = self._normalize_line(line, index)
            if normalized is not None:
                capture.packets.append(normalized)
            if progress_cb and index % 500 == 0:
                progress_cb(index, total, "parsing")
        if progress_cb:
            progress_cb(total, total, "parsing")
        return capture

    def _normalize_line(self, line: str, index: int) -> NormalizedPacket | None:
        parts = line.split("|")
        if not parts or not parts[0]:
            return None

        def g(i: int) -> str | None:
            return parts[i] if i < len(parts) and parts[i] else None

        def gi(i: int) -> int | None:
            v = g(i)
            if v is None:
                return None
            try:
                return int(v)
            except ValueError:
                return None

        timestamp = float(g(1) or 0)
        length = gi(2) or 0
        protocols_stack = g(3) or ""
        src = g(4) or g(6)
        dst = g(5) or g(7)
        sport, dport = gi(9), gi(10)
        tcp_flags_hex = g(11)
        if tcp_flags_hex is None:
            udp_src, udp_dst = gi(12), gi(13)
            sport, dport = sport or udp_src, dport or udp_dst
        dns_query = g(14)
        dns_is_response = g(15)
        dns_rcode = g(16)
        http_host = g(17)
        http_method = g(18)
        http_status = g(19)
        tls_sni = g(20)
        tls_version = g(21)
        quic_type = g(22)
        dhcp_hostname = g(23)
        bootp_type = g(24)
        ssh_proto = g(25)
        smtp_cmd = g(26)
        ftp_cmd = g(27)

        transport = "TCP" if tcp_flags_hex is not None else ("UDP" if g(12) is not None else None)
        protocol = None
        metadata: dict[str, Any] = {}
        flags: list[str] = []

        if dns_query or dns_is_response is not None:
            protocol = "DNS"
            if dns_query:
                metadata["dns.query"] = dns_query
            if dns_is_response is not None:
                metadata["dns.is_response"] = dns_is_response == "1"
            if dns_rcode is not None:
                metadata["dns.rcode"] = int(dns_rcode)
        elif tls_sni or tls_version:
            protocol = "TLS"
            if tls_sni:
                metadata["tls.sni"] = tls_sni
            if tls_version:
                metadata["tls.record_version"] = tls_version
        elif http_host or http_method or http_status:
            protocol = "HTTP"
            if http_host:
                metadata["http.host"] = http_host
            if http_method:
                metadata["http.method"] = http_method
            if http_status:
                metadata["http.status"] = int(http_status)
        elif quic_type is not None or (transport == "UDP" and (dport == 443 or sport == 443)):
            protocol = "QUIC"
        elif dhcp_hostname is not None or bootp_type is not None:
            protocol = "DHCP"
            if dhcp_hostname:
                metadata["dhcp.hostname"] = dhcp_hostname
            if bootp_type is not None:
                metadata["dhcp.message_type"] = bootp_type
        elif ssh_proto:
            protocol = "SSH"
            metadata["ssh.banner"] = ssh_proto
        elif smtp_cmd:
            protocol = "SMTP"
        elif ftp_cmd:
            protocol = "FTP"

        if tcp_flags_hex:
            try:
                value = int(tcp_flags_hex, 16)
                flags = [n for b, n in TCP_FLAG_NAMES if value & b]
            except ValueError:
                flags = []

        if protocol is None:
            protocol = transport or (protocols_stack.split(":")[-1] if protocols_stack else "RAW")

        return NormalizedPacket(
            timestamp=timestamp,
            source_ip=src,
            destination_ip=dst,
            protocol=protocol,
            transport=transport,
            source_port=sport,
            destination_port=dport,
            length=length,
            flags=flags,
            metadata=metadata,
            packet_reference=index,
        )
