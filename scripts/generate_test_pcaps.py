#!/usr/bin/env python3
"""Deterministic synthetic PCAP generator for PacketKage.

Every scenario is reproducible: fixed seeds, fixed timestamps, fixed hosts.
Output PCAPs are byte-stable given the same Scapy version.

Usage:
    python scripts/generate_test_pcaps.py --out test-data/synthetic
"""
from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

from scapy.all import ARP, IP, TCP, UDP, Ether, IPv6, wrpcap
from scapy.layers.dhcp import BOOTP
from scapy.layers.dhcp import DHCP as ScapyDHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR

BASE_TS = 1717252200.0

HOSTS = {
    "workstation": "192.168.1.42",
    "web_server": "192.168.1.25",
    "dns_server": "192.168.1.1",
    "file_server": "192.168.1.10",
    "dc_server": "192.168.1.5",
    "hr_host": "192.168.1.60",
    "it_host": "192.168.1.61",
    "ext_web": "93.184.216.34",
    "ext_api": "140.82.121.6",
    "suspicious": "185.234.72.19",
    "cdn": "151.101.1.69",
    # IPv6 hosts
    "v6_ws": "fd00::42",
    "v6_ext": "2606:4700:4700::1111",
    "v6_dns": "fd00::1",
}

MAC_LOCAL = "aa:bb:cc:dd:ee:01"
MAC_REMOTE = "aa:bb:cc:dd:ee:02"
MAC_ATTACKER = "aa:bb:cc:dd:ee:99"  # ARP spoofer's NIC


def _eth(src_ip: str) -> Ether:
    """Ether header with deterministic MACs (local nets get MAC_LOCAL, others MAC_REMOTE)."""
    mac = MAC_LOCAL if src_ip.startswith("192.168.") else MAC_REMOTE
    return Ether(src=mac, dst=MAC_REMOTE if mac == MAC_LOCAL else MAC_LOCAL)


_ip_id_counter = iter(range(1, 65535))


def _ip(src: str, dst: str) -> IP:
    return IP(src=src, dst=dst, id=next(_ip_id_counter))


def dns_query(ts: float, src: str, dst: str, name: str, txid: int) -> Ether:
    return _eth(src) / _ip(src, dst) / UDP(sport=33333, dport=53) / DNS(
        id=txid, qr=0, qd=DNSQR(qname=name)
    )


def dns_response(ts: float, src: str, dst: str, name: str, txid: int, rcode: int = 0) -> Ether:
    return _eth(src) / _ip(src, dst) / UDP(sport=53, dport=33333) / DNS(
        id=txid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name),
        an=DNSRR(rrname=name, ttl=60, rdata="1.2.3.4") if rcode == 0 else None,
    )


def tcp_syn(ts: float, src: str, dst: str, sport: int, dport: int, seq: int = 1000) -> Ether:
    pkt = _eth(src) / _ip(src, dst) / TCP(sport=sport, dport=dport, flags="S", seq=seq)
    pkt.time = ts
    return pkt


def tcp_synack(ts: float, src: str, dst: str, sport: int, dport: int, seq: int = 2000, ack: int = 1001) -> Ether:
    pkt = _eth(src) / _ip(src, dst) / TCP(sport=sport, dport=dport, flags="SA", seq=seq, ack=ack)
    pkt.time = ts
    return pkt


def tcp_ack(ts: float, src: str, dst: str, sport: int, dport: int, seq: int, ack: int, payload: bytes = b"") -> Ether:
    pkt = _eth(src) / _ip(src, dst) / TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=ack) / payload
    pkt.time = ts
    return pkt


def tcp_rst(ts: float, src: str, dst: str, sport: int, dport: int) -> Ether:
    pkt = _eth(src) / _ip(src, dst) / TCP(sport=sport, dport=dport, flags="R", seq=3000)
    pkt.time = ts
    return pkt


def http_req(ts: float, src: str, dst: str, sport: int, host: str, path: str = "/", ua: str = "Mozilla/5.0 (X11; Linux x86_64)", seq: int = 1000) -> Ether:
    payload = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: */*\r\n\r\n".encode()
    pkt = _eth(src) / _ip(src, dst) / TCP(sport=sport, dport=80, flags="PA", seq=seq) / payload
    pkt.time = ts
    return pkt


def http_resp(ts: float, src: str, dst: str, sport: int, status: int = 200, seq: int = 2000, body: bytes = b"<html>ok</html>") -> Ether:
    payload = f"HTTP/1.1 {status} {'OK' if status==200 else 'ERROR'}\r\nServer: nginx/1.24\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body
    pkt = _eth(src) / _ip(src, dst) / TCP(sport=80, dport=sport, flags="PA", seq=seq) / payload
    pkt.time = ts
    return pkt


def _tls_client_hello(server_name: str) -> bytes:
    """Deterministic TLS ClientHello with SNI extension (minimal, spec-shaped)."""
    import struct
    name = server_name.encode()
    sni_body = struct.pack(">HBH", len(name) + 3, 0, len(name)) + name
    ext = struct.pack(">HH", 0, len(sni_body)) + sni_body
    ch_body = b"\x03\x01" + b"\x41" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + struct.pack(">H", len(ext)) + ext
    hs = b"\x01" + struct.pack(">I", len(ch_body))[1:] + ch_body  # handshake header
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs  # TLS record


def tls_clienthello(ts: float, src: str, dst: str, sport: int, dport: int, server_name: str, seq: int = 1000) -> Ether:
    pkt = _eth(src) / _ip(src, dst) / TCP(sport=sport, dport=dport, flags="PA", seq=seq) / _tls_client_hello(server_name)
    pkt.time = ts
    return pkt


def tls_server_hello(ts: float, src: str, dst: str, sport: int, dport: int, seq: int = 2000) -> Ether:
    pkt = _eth(src) / _ip(src, dst) / TCP(sport=dport, dport=sport, flags="PA", seq=seq) / b"\x16\x03\x03\x00\x02\x02\x00"
    pkt.time = ts
    return pkt


def _set_times(packets, start_ts: float, interval: float) -> list:
    for i, pkt in enumerate(packets):
        pkt.time = start_ts + i * interval
    return packets


def scenario_normal_traffic() -> list:
    """Benign browsing: DNS + plain HTTP + HTTPS/TLS to a handful of common domains."""
    pkts = []
    ws, dns_srv, ext = HOSTS["workstation"], HOSTS["dns_server"], HOSTS["ext_web"]
    for i, domain in enumerate(["example.com", "github.com", "wikipedia.org"]):
        ts = BASE_TS + i * 20
        dns_sport = 33400 + i

        pkt_q = _eth(ws) / _ip(ws, dns_srv) / UDP(sport=dns_sport, dport=53) / DNS(id=1000 + i, qr=0, qd=DNSQR(qname=domain))
        pkt_r = _eth(dns_srv) / _ip(dns_srv, ws) / UDP(sport=53, dport=dns_sport) / DNS(id=1000 + i, qr=1, rd=1, ra=1, an=DNSRR(rrname=domain, ttl=60, rdata="93.184.216.34"))
        pkt_q.time = ts
        pkt_r.time = ts + 0.02
        pkts += [pkt_q, pkt_r]
        if i < 2:

            http_sport = 52000 + i
            pkts.append(http_req(ts + 0.05, ws, ext, http_sport, domain, ua="Mozilla/5.0 (X11; Linux x86_64) PacketKageTest/1.0"))
            pkts.append(http_resp(ts + 0.06, ext, ws, http_sport, status=200 if i == 0 else 404, body=(b"<html>hello</html>" if i == 0 else b"not found")))
        else:
            tls_sport = 53000 + i
            pkts.append(tls_clienthello(ts + 0.05, ws, ext, tls_sport, 443, domain))
            pkts.append(tls_server_hello(ts + 0.06, ext, ws, tls_sport, 443))
    pkts.sort(key=lambda p: float(p.time))
    return pkts


def scenario_port_scan() -> list:
    """SYN scan: one host probing many ports on a single target."""
    pkts = []
    attacker, target = HOSTS["workstation"], HOSTS["web_server"]
    for port in range(20, 120):
        pkts.append(tcp_syn(BASE_TS + port * 0.01, attacker, target, 40000, port))
    return _set_times(pkts, BASE_TS, 0.01)


def scenario_dns_tunneling() -> list:
    """DNS tunneling indicators: many long TXT-ish queries to one suspect domain."""
    pkts = []
    ws, dns_srv = HOSTS["workstation"], HOSTS["dns_server"]
    rng = random.Random(42)
    for i in range(64):
        sport = 33400 + (i % 8)
        label = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=40))
        name = f"{label}.tunnel.example.net"
        pkt_q = _eth(ws) / _ip(ws, dns_srv) / UDP(sport=sport, dport=53) / DNS(id=2000 + i, qr=0, qd=DNSQR(qname=name))
        pkt_r = _eth(dns_srv) / _ip(dns_srv, ws) / UDP(sport=53, dport=sport) / DNS(id=2000 + i, qr=1, rcode=3, qd=DNSQR(qname=name))
        pkt_q.time = BASE_TS + i * 0.5
        pkt_r.time = BASE_TS + i * 0.5 + 0.1
        pkts.append(pkt_q)
        pkts.append(pkt_r)
    return pkts


def scenario_c2_beacon() -> list:
    """Periodic beaconing: regular-interval connections to a rare destination on 4444."""
    pkts = []
    ws, c2 = HOSTS["workstation"], HOSTS["suspicious"]
    for i in range(40):
        ts = BASE_TS + i * 30.0  # exactly every 30s — beacon pattern
        # each beacon is its own connection: unique source port per cycle
        sport = 44440 + i
        pkts.append(tcp_syn(ts, ws, c2, sport, 4444, seq=5000))
        pkts.append(tcp_synack(ts + 0.05, c2, ws, 4444, sport, seq=6000, ack=5001))
        pkts.append(tcp_ack(ts + 0.06, ws, c2, sport, 4444, seq=5001, ack=6001, payload=b"\x00\x01beacon"))
    pkts.sort(key=lambda p: float(p.time))
    return pkts


def scenario_tcp_problems() -> list:
    """TCP issues: handshake, retransmitted SYN, reset, refused connection, failures."""
    pkts = []
    ws, ext = HOSTS["workstation"], HOSTS["ext_web"]
    # 1) established flow with a data retransmission (seq goes backwards)
    pkts.append(tcp_syn(BASE_TS, ws, ext, 51000, 80, seq=1000))
    pkts.append(tcp_synack(BASE_TS + 1.0, ext, ws, 80, 51000, seq=2000, ack=1001))
    pkts.append(tcp_ack(BASE_TS + 1.1, ws, ext, 51000, 80, seq=1001, ack=2001, payload=b"DATA-1" * 20))
    pkts.append(tcp_ack(BASE_TS + 1.2, ws, ext, 51000, 80, seq=1121, ack=2001, payload=b"DATA-2" * 20))
    pkts.append(tcp_ack(BASE_TS + 1.3, ws, ext, 51000, 80, seq=1001, ack=2001, payload=b"DATA-1" * 20))  # retransmission
    # 2) SYN retransmission then success
    pkts.append(tcp_syn(BASE_TS + 5, ws, ext, 51001, 80, seq=3000))
    pkts.append(tcp_syn(BASE_TS + 6, ws, ext, 51001, 80, seq=3000))  # SYN retransmit
    pkts.append(tcp_synack(BASE_TS + 7, ext, ws, 80, 51001, seq=4000, ack=3001))
    # 3) reset flow (refused)
    pkts.append(tcp_syn(BASE_TS + 10, ws, ext, 51002, 8080, seq=5000))
    pkts.append(tcp_rst(BASE_TS + 10.1, ext, ws, 8080, 51002))
    # 4) failed connections (SYN, no answer)
    for i in range(5):
        pkts.append(tcp_syn(BASE_TS + 20 + i, ws, ext, 51003 + i, 81, seq=7000 + i))
    pkts.sort(key=lambda p: float(p.time))
    return pkts


def scenario_arp_spoofing() -> list:
    """ARP spoofing: attacker MAC claims the gateway IP; gratuitous ARP announces."""
    pkts = []
    gw_ip = HOSTS["dns_server"]  # 192.168.1.1 — the gateway
    victim = HOSTS["workstation"]
    victim_mac = MAC_LOCAL
    attacker_mac = MAC_ATTACKER
    gw_mac = "aa:bb:cc:dd:ee:03"

    # normal ARP resolution: victim asks who-has gateway, gateway replies (layer 2 only)
    t = BASE_TS
    pkts.append(Ether(src=victim_mac, dst="ff:ff:ff:ff:ff:ff", type=0x0806) / ARP(op=1, hwsrc=victim_mac, psrc=victim, pdst=gw_ip))
    pkts[-1].time = t
    pkts.append(Ether(src=gw_mac, dst=victim_mac, type=0x0806) / ARP(op=2, hwsrc=gw_mac, psrc=gw_ip, hwdst=victim_mac, pdst=victim))
    pkts[-1].time = t + 0.05

    # attacker poisons: gratuitous ARP announcing gateway IP with ATTACKER MAC (x5)
    for i in range(5):
        ts = BASE_TS + 10 + i * 2
        pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff", type=0x0806) / ARP(op=2, hwsrc=attacker_mac, psrc=gw_ip, pdst=gw_ip)
        pkt.time = ts
        pkts.append(pkt)
    # legit gateway re-announces (conflict visible: same IP, two MACs)
    pkt = Ether(src=gw_mac, dst="ff:ff:ff:ff:ff:ff", type=0x0806) / ARP(op=2, hwsrc=gw_mac, psrc=gw_ip, pdst=gw_ip)
    pkt.time = BASE_TS + 25
    pkts.append(pkt)
    pkts.sort(key=lambda p: float(p.time))
    return pkts


def scenario_lateral_movement() -> list:
    """Compromised host touching many internal hosts on SSH/SMB/RDP."""
    pkts = []
    attacker = HOSTS["workstation"]
    targets = [HOSTS["web_server"], HOSTS["file_server"], HOSTS["dc_server"], HOSTS["hr_host"], HOSTS["it_host"]]
    ports = [22, 445, 3389, 22, 5985]
    for i, (target, dport) in enumerate(zip(targets, ports, strict=False)):
        ts = BASE_TS + i * 30
        sport = 46000 + i
        pkts.append(tcp_syn(ts, attacker, target, sport, dport, seq=9000 + i))
        pkts.append(tcp_synack(ts + 0.1, target, attacker, dport, sport, seq=9100 + i, ack=9001 + i))
    pkts.sort(key=lambda p: float(p.time))
    return pkts


def scenario_data_exfiltration() -> list:
    """Large outbound transfer to an unrare (never-DNS-resolved) external host."""
    pkts = []
    ws = HOSTS["workstation"]
    dest = "203.0.113.66"  # external, never resolved via DNS in this capture
    # a few normal DNS queries for cover (resolving popular hosts)
    for i, domain in enumerate(["example.com"]):
        ts = BASE_TS + i * 5
        sport = 33500 + i
        pkts.append(dns_query(ts, ws, HOSTS["dns_server"], domain, 3000 + i))
        pkts.append(dns_response(ts + 0.02, HOSTS["dns_server"], ws, domain, 3000 + i))
    # big transfer: 400 packets x ~1400 bytes ≈ 560KB to dest in 20s, one long flow
    sport = 47000
    chunk = b"E" * 1400
    pkts.append(tcp_syn(BASE_TS + 10, ws, dest, sport, 8443, seq=10000))
    pkts.append(tcp_synack(BASE_TS + 10.05, dest, ws, 8443, sport, seq=20000, ack=10001))
    for i in range(400):
        ts = BASE_TS + 10.1 + i * 0.05
        pkts.append(tcp_ack(ts, ws, dest, sport, 8443, seq=10001 + i * 1400, ack=20001, payload=chunk))
    pkts.sort(key=lambda p: float(p.time))
    return pkts


def scenario_low_slow_beacon() -> list:
    """Low-and-slow C2: 4 check-ins at regular 5-minute intervals on 443."""
    pkts = []
    ws, c2 = HOSTS["workstation"], "198.51.100.77"
    for i in range(4):
        ts = BASE_TS + i * 300.0  # every 300s (5 min), 3 intervals, jitter ~0
        sport = 48000 + i
        pkts.append(tcp_syn(ts, ws, c2, sport, 443, seq=11000 + i))
        pkts.append(tcp_synack(ts + 0.05, c2, ws, 443, sport, seq=12000 + i, ack=11001 + i))
        pkts.append(tcp_ack(ts + 0.06, ws, c2, sport, 443, seq=11001 + i, ack=12001 + i, payload=b"\x00\x00keepalive"))
    pkts.sort(key=lambda p: float(p.time))
    return pkts


def scenario_dga_domains() -> list:
    """DGA malware: many high-entropy NXDOMAIN lookups + real domains as baseline."""
    pkts = []
    ws, dns_srv = HOSTS["workstation"], HOSTS["dns_server"]
    rng = random.Random(1337)
    # 5 real domains first (baseline traffic, all readable)
    for i, domain in enumerate(["example.com", "wikipedia.org", "github.com", "cloudflare.com", "debian.org"]):
        ts = BASE_TS + i
        pkts.append(dns_query(ts, ws, dns_srv, domain, 4000 + i))
        pkts.append(dns_response(ts + 0.02, dns_srv, ws, domain, 4000 + i))
    # 20 DGA lookups: consonant-heavy random labels, most NXDOMAIN
    tld = ["com", "net", "xyz", "top", "info"]
    for i in range(20):
        ts = BASE_TS + 10 + i * 2
        label = "".join(rng.choices("bcdfghjklmnpqrstvwxz", k=12)) + "".join(rng.choices("aeiou", k=1)) + "zxq"
        name = f"{label}.{tld[i % len(tld)]}"
        pkts.append(dns_query(ts, ws, dns_srv, name, 4100 + i))
        rcode = 3 if i % 4 != 3 else 0  # most fail; one in four resolves (rotating DGA)
        pkts.append(dns_response(ts + 0.03, dns_srv, ws, name, 4100 + i, rcode=rcode))
    pkts.sort(key=lambda p: float(p.time))
    return pkts


def scenario_ipv6_traffic() -> list:
    """IPv6: DNS + HTTP + ping over v6 (unique-local ↔ global addresses)."""
    pkts = []
    ws, dns_srv, ext = HOSTS["v6_ws"], HOSTS["v6_dns"], HOSTS["v6_ext"]
    mac = MAC_LOCAL
    # v6 DNS (query + response)
    q = Ether(src=mac, dst=MAC_REMOTE) / IPv6(src=ws, dst=dns_srv) / UDP(sport=34500, dport=53) / DNS(id=5000, qr=0, qd=DNSQR(qname="example.org", qtype="AAAA"))
    q.time = BASE_TS
    # response with AAAA answer: build via scapy's own AAAA field encoder
    rr = DNSRR(rrname="example.org", ttl=60, type=28, rdata="2606:4700:4700::1111")  # AAAA
    r = Ether(src=MAC_REMOTE, dst=mac) / IPv6(src=dns_srv, dst=ws) / UDP(sport=53, dport=34500) / DNS(id=5000, qr=1, ra=1, an=rr)
    r.time = BASE_TS + 0.02
    pkts += [q, r]
    # v6 TCP HTTP (request + response)
    req = Ether(src=mac, dst=MAC_REMOTE) / IPv6(src=ws, dst=ext) / TCP(sport=54600, dport=80, flags="PA", seq=1) / (
        b"GET / HTTP/1.1\r\nHost: example.org\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    )
    req.time = BASE_TS + 0.1
    resp = Ether(src=MAC_REMOTE, dst=mac) / IPv6(src=ext, dst=ws) / TCP(sport=80, dport=54600, flags="PA", seq=1) / (
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
    )
    resp.time = BASE_TS + 0.12
    pkts += [req, resp]
    # v6 ICMPv6 echo request + reply
    from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest
    e1 = Ether(src=mac, dst=MAC_REMOTE) / IPv6(src=ws, dst=ext) / ICMPv6EchoRequest()
    e1.time = BASE_TS + 1
    e2 = Ether(src=MAC_REMOTE, dst=mac) / IPv6(src=ext, dst=ws) / ICMPv6EchoReply()
    e2.time = BASE_TS + 1.05
    pkts += [e1, e2]
    pkts.sort(key=lambda p: float(p.time))
    return pkts


def scenario_quic_traffic() -> list:
    """QUIC/HTTP3: UDP 443 initial + handshake-looking long-header packets."""
    pkts = []
    ws, cdn = HOSTS["workstation"], HOSTS["cdn"]
    # long-header QUIC initial (0x18xx first byte, random-looking payload)
    import random as _r
    rng = _r.Random(7)
    for i in range(4):
        ts = BASE_TS + i * 0.1
        hdr = bytes([0x18 + (i % 3)]) + rng.randbytes(8)
        pkt = _eth(ws) / _ip(ws, cdn) / UDP(sport=55000 + i * 0, dport=443) / (hdr + rng.randbytes(64))
        pkt.time = ts
        pkts.append(pkt)
    # server responses
    for i in range(2):
        ts = BASE_TS + 0.5 + i * 0.1
        hdr = bytes([0x40 + i]) + rng.randbytes(8)
        pkt = _eth(cdn) / _ip(cdn, ws) / UDP(sport=443, dport=55000) / (hdr + rng.randbytes(64))
        pkt.time = ts
        pkts.append(pkt)
    pkts.sort(key=lambda p: float(p.time))
    return pkts


def scenario_protocol_banners() -> list:
    """SSH/SMTP/FTP server banners — plaintext greeting strings."""
    pkts = []
    ws = HOSTS["workstation"]
    mail_srv, ssh_srv, ftp_srv = "93.184.216.50", "93.184.216.51", "93.184.216.52"

    def banner_flow(dst: str, dport: int, banner: bytes, sport: int):
        out = []
        out.append(tcp_syn(BASE_TS + dport * 0.01, ws, dst, sport, dport, seq=1))
        out.append(tcp_synack(BASE_TS + dport * 0.01 + 0.05, dst, ws, dport, sport, seq=2, ack=2))
        srv = _eth(dst) / _ip(dst, ws) / TCP(sport=dport, dport=sport, flags="PA", seq=2) / banner
        srv.time = BASE_TS + dport * 0.01 + 0.1
        out.append(srv)
        ack = _eth(ws) / _ip(ws, dst) / TCP(sport=sport, dport=dport, flags="A", seq=2, ack=2 + len(banner))
        ack.time = BASE_TS + dport * 0.01 + 0.15
        out.append(ack)
        return out

    pkts += banner_flow(ssh_srv, 22, b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu1\r\n", 55100)
    pkts += banner_flow(mail_srv, 25, b"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n", 55101)
    pkts += banner_flow(ftp_srv, 21, b"220 ftp.example.com FTP server (vsftpd 3.0.5) ready\r\n", 55102)
    pkts.sort(key=lambda p: float(p.time))
    return pkts


def scenario_dhcp_lease() -> list:
    """DHCP DORA: DISCOVER → OFFER → REQUEST → ACK with hostname option."""
    pkts = []
    client, server = HOSTS["workstation"], HOSTS["dns_server"]

    def dhcp(ts: float, src: str, dst: str, sport: int, dport: int, msg_type: int, yiaddr: str = "0.0.0.0", hostname: bytes | None = None):
        opts = [("message-type", msg_type), "end"]
        if hostname:
            opts = [("message-type", msg_type), ("hostname", hostname), "end"]
        pkt = _eth(src) / _ip(src, dst) / UDP(sport=sport, dport=dport) / BOOTP(
            op=1 if msg_type in (1, 3) else 2,
            chaddr=bytes.fromhex("020304050607" + "00" * 10),
            yiaddr=yiaddr,
            xid=0x1234,
        ) / ScapyDHCP(options=opts)
        pkt.time = ts
        return pkt

    pkts.append(dhcp(BASE_TS, client, "255.255.255.255", 68, 67, 1, hostname=b"ws-laptop-01"))
    pkts.append(dhcp(BASE_TS + 1, server, client, 67, 68, 2, yiaddr="192.168.1.99"))
    pkts.append(dhcp(BASE_TS + 2, client, "255.255.255.255", 68, 67, 3, hostname=b"ws-laptop-01"))
    pkts.append(dhcp(BASE_TS + 3, server, client, 67, 68, 5, yiaddr="192.168.1.99"))
    pkts.sort(key=lambda p: float(p.time))
    return pkts


def scenario_large_graph() -> list:
    """Scale test: many hosts, domains and flows to exercise the graph's large-capture tiers.

    ~50 hosts, ~120 domains (most leaf-only DGA-style), ~400 flows — produces
    500+ graph nodes so the scale tier (auto-collapse, selective labels,
    draft layout) can be verified end-to-end.
    """
    pkts = []
    ws, dns_srv = HOSTS["workstation"], HOSTS["dns_server"]
    rng = random.Random(4242)

    # 60 extra internal hosts + 30 external servers (using 10.x ranges for variety)
    internal = [f"192.168.1.{100 + i}" for i in range(60)]
    external = [f"203.0.113.{10 + i}" for i in range(30)]

    # each internal host browses to a few real domains (DNS + HTTP flows)
    real_domains = ["example.com", "github.com", "wikipedia.org", "cloudflare.com", "debian.org"]
    for i, host in enumerate(internal):
        for j in range(3):
            ts = BASE_TS + i * 3 + j * 0.5
            domain = real_domains[(i + j) % len(real_domains)]
            pkts.append(dns_query(ts, host, dns_srv, domain, 5000 + i * 10 + j))
            pkts.append(dns_response(ts + 0.02, dns_srv, host, domain, 5000 + i * 10 + j))
            ext = external[(i + j) % len(external)]
            sport = 40000 + (i * 3 + j) % 20000
            pkts.append(http_req(ts + 0.05, host, ext, sport, domain))
            pkts.append(http_resp(ts + 0.06, ext, host, sport))

    # hub traffic: file server talks to every internal host (star topology)
    fs = HOSTS["file_server"]
    for i, host in enumerate(internal):
        pkts.append(tcp_syn(BASE_TS + 200 + i * 0.2, fs, host, 20000 + i, 445))
        pkts.append(tcp_synack(BASE_TS + 200.1 + i * 0.2, host, fs, 445, 20000 + i))

    # 100 leaf-only DGA domains from one infected host (degree-1 nodes, mostly NXDOMAIN)
    tld = ["com", "net", "xyz", "top", "info"]
    for i in range(100):
        ts = BASE_TS + 300 + i * 0.5
        label = "".join(rng.choices("bcdfghjklmnpqrstvwxz", k=12)) + "".join(rng.choices("aeiou", k=1)) + "zxq"
        name = f"{label}.{tld[i % len(tld)]}"
        pkts.append(dns_query(ts, ws, dns_srv, name, 7000 + i))
        rcode = 3 if i % 4 != 3 else 0
        pkts.append(dns_response(ts + 0.03, dns_srv, ws, name, 7000 + i, rcode=rcode))

    # a few resolved DGA domains get TLS sessions (non-leaf domain nodes)
    for i in range(0, 100, 12):
        label = "".join(rng.choices("bcdfghjklmnpqrstvwxz", k=12)) + "zxq"
        name = f"{label}.com"
        pkts.append(tls_clienthello(BASE_TS + 400 + i * 0.1, ws, external[i % len(external)], 30000 + i, 443, name))
        pkts.append(tls_server_hello(BASE_TS + 400.05 + i * 0.1, external[i % len(external)], ws, 30000 + i, 443))

    pkts.sort(key=lambda p: float(p.time))
    return pkts


SCENARIOS = {
    "normal_traffic.pcap": scenario_normal_traffic,
    "port_scan.pcap": scenario_port_scan,
    "dns_tunneling.pcap": scenario_dns_tunneling,
    "c2_beacon.pcap": scenario_c2_beacon,
    "tcp_problems.pcap": scenario_tcp_problems,
    "arp_spoofing.pcap": scenario_arp_spoofing,
    "lateral_movement.pcap": scenario_lateral_movement,
    "data_exfiltration.pcap": scenario_data_exfiltration,
    "low_slow_beacon.pcap": scenario_low_slow_beacon,
    "dga_domains.pcap": scenario_dga_domains,
    "ipv6_traffic.pcap": scenario_ipv6_traffic,
    "quic_traffic.pcap": scenario_quic_traffic,
    "protocol_banners.pcap": scenario_protocol_banners,
    "dhcp_lease.pcap": scenario_dhcp_lease,
    "large_graph.pcap": scenario_large_graph,
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="test-data/synthetic", help="output directory")
    ap.add_argument("--only", default=None, help="generate only a named scenario")
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    for name, builder in SCENARIOS.items():
        if args.only and args.only not in name:
            continue
        packets = builder()
        path = out_dir / name
        wrpcap(str(path), packets)
        print(f"  wrote {path} ({len(packets)} packets)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
