"""ScapyParser — default, guaranteed to work without Wireshark/TShark."""
from __future__ import annotations

import os
from typing import Any

from scapy.all import PcapReader
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.layers.tls.record import TLS  # may be absent in minimal installs

from app.core.models import NormalizedPacket, ParsedCapture
from app.parsers.base import PacketParser, ParserError

# Shared TCP flag bit→name table (scapy and tshark both emit bit flags)
TCP_FLAG_NAMES = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
]

# Common application protocols by port (first pass heuristic; deep dissection in Step 3)
WELL_KNOWN_PORTS: dict[int, str] = {
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    123: "NTP",
    445: "SMB",
    3389: "RDP",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    4444: "C2-PORT",
}

# UDP-only protocol labels (port heuristic)
UDP_PORT_PROTOCOLS: dict[int, str] = {
    443: "QUIC",  # UDP 443 is the QUIC/HTTP3 transport
    67: "DHCP",  # server
    68: "DHCP",  # client
    5353: "mDNS",
    1900: "SSDP",
    547: "DHCPv6",
    546: "DHCPv6",
    88: "Kerberos",
}

# TLS record version bytes → label (from record header, not ClientHello offer)
TLS_RECORD_VERSIONS = {
    b"\x03\x01": "TLS 1.0",
    b"\x03\x02": "TLS 1.1",
    b"\x03\x03": "TLS 1.2",
    b"\x03\x04": "TLS 1.3",
}


class ScapyParser(PacketParser):
    name = "scapy"

    def available(self) -> bool:
        try:
            import scapy  # noqa: F401

            return True
        except ImportError:
            return False

    def parse_file(self, path: str, progress_cb=None) -> ParsedCapture:
        if not self.available():
            raise ParserError("scapy is not installed")
        try:
            return self._parse_with_reader(path, progress_cb)
        except ParserError:
            raise
        except Exception as exc:  # scapy raises a wide variety of errors
            raise ParserError(f"scapy failed to parse {path}: {exc}") from exc

    def _parse_with_reader(self, path: str, progress_cb=None) -> ParsedCapture:
        capture = ParsedCapture(filename=path.split("/")[-1], parser_used=self.name)
        try:
            reader = PcapReader(path)
            capture.link_type = getattr(reader, "linktype", None)
        except Exception as exc:
            raise ParserError(f"cannot open {path}: {exc}") from exc

        with reader:
            total_hint = self._estimate_total(path)
            for index, pkt in enumerate(reader):
                normalized = self.normalize_packet(pkt, index)
                if normalized is not None:
                    capture.packets.append(normalized)
                if progress_cb and total_hint and index % 500 == 0:
                    progress_cb(index, total_hint, "parsing")
        if progress_cb:
            progress_cb(len(capture.packets), len(capture.packets), "parsing")
        return capture

    @staticmethod
    def _estimate_total(path: str) -> int:
        """Cheap packet-count estimate from file size (avoids a second full read)."""
        try:
            size = os.path.getsize(path)
        except OSError:
            return 0
        if size <= 0:
            return 0
        # pcaps average ~200-1000 bytes/packet on real captures;
        # 400 is a good middle ground that only affects progress display granularity.
        return max(1, size // 400)

    @staticmethod
    def normalize_packet(pkt: Any, index: int) -> NormalizedPacket | None:
        """Convert a Scapy packet to a NormalizedPacket (the ONLY bridge point)."""
        timestamp = float(pkt.time)
        length = int(getattr(pkt, "len", len(pkt)))

        if IPv6 in pkt:
            ip6 = pkt[IPv6]
            src, dst = ip6.src, ip6.dst
            transport = None
            sport = dport = None
            flags: list[str] = []
            app_protocol = None
            metadata: dict[str, Any] = {}

            if Ether in pkt:
                metadata["eth.src"] = pkt[Ether].src
                metadata["eth.dst"] = pkt[Ether].dst
            metadata["ipv6.hop_limit"] = int(ip6.hlim)
            if ip6.fl:
                metadata["ipv6.flow_label"] = int(ip6.fl)

            if TCP in pkt:
                transport = "TCP"
                tcp = pkt[TCP]
                sport, dport = int(tcp.sport), int(tcp.dport)
                flags = ScapyParser._tcp_flags(int(tcp.flags))
                metadata["seq"] = int(tcp.seq)
                metadata["win"] = int(tcp.window)
                app_protocol = ScapyParser._guess_app_protocol(sport, dport, pkt)
            elif UDP in pkt:
                transport = "UDP"
                udp = pkt[UDP]
                sport, dport = int(udp.sport), int(udp.dport)
                app_protocol = (
                    "QUIC" if dport == 443 or sport == 443
                    else ScapyParser._guess_app_protocol(sport, dport, pkt)
                )
            elif pkt.haslayer(ICMP):
                transport = "ICMP"

            protocol = app_protocol or transport or "IPv6"
            ScapyParser._extract_hints(pkt, metadata)
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

        if IP in pkt:
            ip_layer = pkt[IP]
            src, dst = ip_layer.src, ip_layer.dst
            transport = None
            sport = dport = None
            flags = []
            app_protocol = None
            metadata = {}

            if Ether in pkt:
                metadata["eth.src"] = pkt[Ether].src
                metadata["eth.dst"] = pkt[Ether].dst

            if TCP in pkt:
                transport = "TCP"
                tcp = pkt[TCP]
                sport, dport = int(tcp.sport), int(tcp.dport)
                flags = ScapyParser._tcp_flags(int(tcp.flags))
                metadata["seq"] = int(tcp.seq)
                metadata["win"] = int(tcp.window)
                app_protocol = ScapyParser._guess_app_protocol(sport, dport, pkt)
            elif UDP in pkt:
                transport = "UDP"
                udp = pkt[UDP]
                sport, dport = int(udp.sport), int(udp.dport)
                app_protocol = (
                    "QUIC" if dport == 443 or sport == 443
                    else ScapyParser._guess_app_protocol(sport, dport, pkt)
                )
            elif ICMP in pkt:
                transport = "ICMP"
                icmp = pkt[ICMP]
                metadata["icmp_type"] = int(icmp.type)
                metadata["icmp_code"] = int(icmp.code)

            protocol = app_protocol or transport or "IP"
            ScapyParser._extract_hints(pkt, metadata)
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

        if ARP in pkt:
            arp = pkt[ARP]
            return NormalizedPacket(
                timestamp=timestamp,
                protocol="ARP",
                length=length,
                metadata={
                    "arp.opcode": int(arp.op),
                    "arp.src_ip": arp.psrc,
                    "arp.dst_ip": arp.pdst,
                    "arp.src_mac": arp.hwsrc,
                    "arp.dst_mac": arp.hwdst,
                },
                packet_reference=index,
            )

        if Ether in pkt:
            eth = pkt[Ether]
            return NormalizedPacket(
                timestamp=timestamp,
                protocol=f"ETH-{eth.type}",
                length=length,
                metadata={"eth.src": eth.src, "eth.dst": eth.dst},
                packet_reference=index,
            )

        return NormalizedPacket(
            timestamp=timestamp, protocol="RAW", length=length, packet_reference=index
        )

    @staticmethod
    def _tcp_flags(value: int) -> list[str]:
        return [name for bit, name in TCP_FLAG_NAMES if value & bit]

    @staticmethod
    def _guess_app_protocol(sport: int, dport: int, pkt: Any) -> str | None:
        if DNS in pkt:
            return "DNS"
        if HTTPRequest in pkt or HTTPResponse in pkt:
            return "HTTP"
        if TLS in pkt:
            return "TLS"
        # UDP service ports (DHCP/mDNS/SSDP/QUIC transport labels)
        if pkt.haslayer("UDP"):
            if dport in UDP_PORT_PROTOCOLS:
                return UDP_PORT_PROTOCOLS[dport]
            if sport in UDP_PORT_PROTOCOLS and dport not in (53,):
                return UDP_PORT_PROTOCOLS[sport]
        return WELL_KNOWN_PORTS.get(dport) or WELL_KNOWN_PORTS.get(sport)

    @staticmethod
    def _extract_hints(pkt: Any, metadata: dict[str, Any]) -> None:
        """Extract protocol hints for later stages (hosts, protocols, timeline)."""
        if DNS in pkt:
            dns = pkt[DNS]
            metadata["dns.is_response"] = bool(int(dns.qr))
            metadata["dns.id"] = int(dns.id)
            if int(dns.qr) == 0 and dns.qd:
                qd = dns.qd[0] if isinstance(dns.qd, list) else dns.qd
                qname = qd.qname
                metadata["dns.query"] = (
                    str(qname, "utf-8", "replace") if isinstance(qname, bytes) else str(qname)
                )
                metadata["dns.qtype"] = int(qd.qtype)
            if int(dns.qr) == 1:
                metadata["dns.rcode"] = int(dns.rcode)
                answers = []
                an = dns.an
                if an is not None:
                    an_list = an if isinstance(an, list) else [an]
                    for rr in an_list:
                        rdata = getattr(rr, "rdata", None)
                        if rdata is not None and rr.type in (1, 5, 28):  # A, CNAME, AAAA
                            answers.append(str(rdata))
                        if rr.type == 5 and rdata:  # CNAME → hostname hint
                            metadata["dns.cname"] = str(rdata)
                metadata["dns.answers"] = answers
        if HTTPRequest in pkt:
            http = pkt[HTTPRequest]
            def _s(v) -> str:
                return str(v, "utf-8", "replace") if isinstance(v, bytes) else str(v)
            metadata["http.method"] = _s(http.Method)
            metadata["http.host"] = _s(http.Host)
            metadata["http.path"] = _s(http.Path)
            ua = http.User_Agent
            if ua:
                metadata["http.user_agent"] = _s(ua)
        if HTTPResponse in pkt:
            http = pkt[HTTPResponse]
            status = http.Status_Code
            metadata["http.status"] = int(status) if status else None
            server = http.Server
            if server:
                metadata["http.server"] = (
                    str(server, "utf-8", "replace") if isinstance(server, bytes) else str(server)
                )
        # TLS SNI: parse ClientHello record if scapy TLS layers are present
        if TLS in pkt and pkt[TLS].type == 22:  # handshake
            sni = ScapyParser._try_extract_sni(bytes(pkt[TLS]))
            if sni:
                metadata["tls.sni"] = sni
        # Raw TLS over 443 without scapy dissection — detect via payload sniffing
        if TLS not in pkt and pkt.haslayer("TCP"):
            try:
                payload = bytes(pkt["TCP"].payload)
                if payload[:1] == b"\x16" and len(payload) > 5:
                    sni = ScapyParser._try_extract_sni(payload)
                    if sni:
                        metadata["tls.sni"] = sni
                    # record-layer version (bytes 1-2 of the TLS record header)
                    version = TLS_RECORD_VERSIONS.get(payload[1:3])
                    if version:
                        metadata["tls.record_version"] = version
            except Exception:
                pass

        # ---- Plain-text protocol banners (server greeting strings) ----
        if pkt.haslayer("TCP") and not pkt.haslayer("HTTP"):
            try:
                payload = bytes(pkt["TCP"].payload)
                if payload and (b"\r\n" in payload or b"\n" in payload):
                    banner = payload.split(b"\r\n")[0][:120]
                    text = banner.decode("utf-8", "replace")
                    # SSH: "SSH-2.0-OpenSSH_9.6" etc.
                    if text.startswith("SSH-"):
                        metadata["ssh.banner"] = text
                    # SMTP: "220 mail.example.com ESMTP Postfix"
                    elif text.startswith("220") and ("SMTP" in text or "ESMTP" in text):
                        metadata["smtp.banner"] = text
                    # FTP: "220 ftp.example.com FTP server ready" / "220-..."
                    elif text.startswith("220-") or "FTP" in text[:40]:
                        metadata["ftp.banner"] = text
            except Exception:
                pass

        # ---- DHCP: message type + hostname option via BOOTP layer ----
        if pkt.haslayer("BOOTP"):
            try:
                from scapy.layers.dhcp import BOOTP
                from scapy.layers.dhcp import DHCP as ScapyDHCP

                bootp = pkt[BOOTP]
                if ScapyDHCP in pkt:
                    for opt in pkt[ScapyDHCP].options:
                        if isinstance(opt, tuple) and len(opt) >= 2:
                            name, value = opt[0], opt[1]
                            if name == "message-type":
                                # 1=DISCOVER 2=OFFER 3=REQUEST 5=ACK
                                dhcp_types = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE"}
                                metadata["dhcp.message_type"] = dhcp_types.get(int(value), str(value))
                            elif name == "hostname":
                                metadata["dhcp.hostname"] = (
                                    value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
                                )
                if bootp.yiaddr and str(bootp.yiaddr) != "0.0.0.0":
                    metadata["dhcp.assigned_ip"] = str(bootp.yiaddr)
            except Exception:
                pass

    @staticmethod
    def _try_extract_sni(data: bytes) -> str | None:
        """Best-effort ClientHello SNI extraction (handshake record bytes)."""
        try:
            # record header (5) + handshake header (4); skip if session-id/extensions parse fails
            i = 5 + 4
            if len(data) <= i:
                return None
            i += 2 + 32  # version + random
            session_len = data[i]
            i += 1 + session_len
            cipher_len = int.from_bytes(data[i : i + 2], "big")
            i += 2 + cipher_len
            comp_len = data[i]
            i += 1 + comp_len
            ext_len = int.from_bytes(data[i : i + 2], "big")
            i += 2
            end = i + ext_len
            while i + 4 <= min(end, len(data)):
                etype = int.from_bytes(data[i : i + 2], "big")
                elen = int.from_bytes(data[i + 2 : i + 4], "big")
                body = data[i + 4 : i + 4 + elen]
                if etype == 0 and len(body) >= 5 and body[2] == 0:  # server_name extension
                    nlen = int.from_bytes(body[3:5], "big")
                    return body[5 : 5 + nlen].decode("utf-8", "replace")
                i += 4 + elen
        except Exception:
            return None
        return None
