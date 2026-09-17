"""Suspicion Engine — deterministic, explainable behavioral detection (Module D).

Every alert must be explainable:
    rule name + severity + score + weighted reasons + evidence + related flows.

No ML. No black boxes. Every score traces back to observable network facts.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from math import log2

from app.core.models import ParsedCapture
from app.services.flow_builder import is_private_ip

# Suspicious ports commonly associated with malware/tooling
SUSPICIOUS_PORTS = {
    4444: "Metasploit default handler",
    1337: "elite/leet convention",
    31337: "Back Orifice",
    6667: "IRC (often C2)",
    6660: "IRC (often C2)",
    5555: "ADB / common backdoor",
    8888: "common C2 / proxy",
    9999: "common C2 channel",
    1234: "common trojan port",
}


@dataclass
class RuleResult:
    rule_name: str
    title: str
    severity: str
    score: int
    reasons: list[dict] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    related_flow_ids: list[str] = field(default_factory=list)
    related_packet_refs: list[int] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_name": self.rule_name,
            "title": self.title,
            "severity": self.severity,
            "score": self.score,
            "reasons": self.reasons,
            "evidence": self.evidence,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "related_flow_ids": self.related_flow_ids,
            "related_packet_refs": self.related_packet_refs,
            "explanation": self.explanation,
        }


def _reason(reason: str, detail: str, weight: int) -> dict:
    return {"reason": reason, "detail": detail, "weight": weight}


def _clamp(score: int) -> int:
    return max(0, min(100, score))


def _severity_for(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


# ---------------- Rules ----------------


def rule_port_scan(flows: list[dict]) -> list[RuleResult]:
    """One source probing many distinct ports on one destination."""
    scans: dict[tuple, dict] = defaultdict(lambda: {"ports": set(), "flows": [], "first": None, "last": None})
    for f in flows:
        if f["transport_protocol"] != "TCP" or not f["failed"]:
            continue
        key = (f["source_ip"], f["destination_ip"])
        s = scans[key]
        s["ports"].add(f["destination_port"])
        s["flows"].append(f)
        s["first"] = f["first_seen"] if s["first"] is None else min(s["first"], f["first_seen"])
        s["last"] = f["last_seen"] if s["last"] is None else max(s["last"], f["last_seen"])

    results = []
    for (src, dst), s in scans.items():
        n_ports = len(s["ports"])
        if n_ports < 10:
            continue
        duration = max(0.001, (s["last"] or 0) - (s["first"] or 0))
        rate = n_ports / duration
        score = _clamp(35 + min(n_ports, 100) * 0.4 + min(rate, 50) * 0.5)
        reasons = [
            _reason("Distinct ports probed", f"{n_ports} unique ports on {dst}", 30),
            _reason("Failed connections", f"{len(s['flows'])} unanswered SYN attempts", 20),
            _reason("Scan rate", f"{rate:.0f} ports/second", 20),
        ]
        if dst and is_private_ip(dst):
            reasons.append(_reason("Internal target", f"target {dst} is an internal host", 10))
        results.append(
            RuleResult(
                rule_name="port_scan",
                title=f"Port scan: {src} → {dst} ({n_ports} ports)",
                severity=_severity_for(int(score)),
                score=int(score),
                reasons=reasons,
                evidence={
                    "ports_probed": sorted(s["ports"]),
                    "flow_count": len(s["flows"]),
                    "duration_seconds": round(duration, 2),
                    "ports_per_second": round(rate, 1),
                },
                source_ip=src,
                destination_ip=dst,
                related_flow_ids=[f["_alert_flow_id"] for f in s["flows"][:50]],
                explanation=(
                    f"Host {src} attempted connections to {n_ports} distinct ports on {dst} "
                    f"within {duration:.1f}s with no responses — consistent with a SYN port scan."
                ),
            )
        )
    return results


def rule_beaconing(flows: list[dict]) -> list[RuleResult]:
    """Regular-interval (periodic) connections to the same destination."""
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for f in flows:
        if f["transport_protocol"] != "TCP":
            continue
        groups[(f["source_ip"], f["destination_ip"], f["destination_port"])].append(f)

    results = []
    for (src, dst, dport), group in groups.items():
        if len(group) < 5:
            continue
        times = sorted(f["first_seen"] for f in group)
        intervals = [b - a for a, b in zip(times, times[1:], strict=False)]
        if not intervals:
            continue
        mean = sum(intervals) / len(intervals)
        variance = sum((i - mean) ** 2 for i in intervals) / len(intervals)
        std = variance**0.5
        # periodic = low jitter relative to interval
        if mean <= 0 or std / mean > 0.1:
            continue

        reasons = [
            _reason("Periodic connection pattern", f"{len(times)} connections at ~{mean:.1f}s intervals", 40),
            _reason("Low jitter", f"interval std-dev {std:.2f}s (machine-like regularity)", 25),
            _reason("Repeated destination", f"{dst}:{dport} contacted {len(group)} times", 20),
        ]
        score = _clamp(60 + min(len(group), 40) * 0.5 + 10)  # periodicity alone is strong

        suspicious_port = SUSPICIOUS_PORTS.get(dport)
        if suspicious_port:
            reasons.append(_reason("Suspicious port", f"port {dport} ({suspicious_port})", 10))
            score = _clamp(score + 10)

        results.append(
            RuleResult(
                rule_name="beaconing",
                title=f"Beaconing: {src} → {dst}:{dport} every {mean:.0f}s",
                severity=_severity_for(int(score)),
                score=int(score),
                reasons=reasons,
                evidence={
                    "intervals": [round(i, 3) for i in intervals[:50]],
                    "mean_interval": round(mean, 3),
                    "jitter": round(std, 3),
                    "jitter_ratio": round(std / mean, 4),
                    "connection_count": len(group),
                },
                source_ip=src,
                destination_ip=dst,
                destination_port=dport,
                related_flow_ids=[f["_alert_flow_id"] for f in group[:50]],
                explanation=(
                    f"Host {src} connected to {dst}:{dport} {len(times)} times with machine-precise "
                    f"~{mean:.0f}s intervals (jitter {std:.2f}s). Periodic beacons like this are a "
                    f"hallmark of C2 check-ins or scheduled implants."
                ),
            )
        )
    return results


def rule_dns_tunneling(parsed: ParsedCapture, dns_txns: list[dict]) -> list[RuleResult]:
    """DNS tunneling indicators: long encoded labels + high NXDOMAIN to one domain."""
    by_client: dict[str, dict] = defaultdict(
        lambda: {"queries": [], "max_label": 0, "nxdomain": 0, "unique_subdomains": set()}
    )
    for t in dns_txns:
        if not t["query_name"]:
            continue
        client = t["client_ip"]
        name = t["query_name"].rstrip(".")
        by_client[client]["queries"].append(t)
        labels = name.split(".")
        longest = max(len(label) for label in labels)
        by_client[client]["max_label"] = max(by_client[client]["max_label"], longest)
        # count unique subdomains under the same parent domain
        if len(labels) >= 3:
            parent = ".".join(labels[-3:])
            by_client[client]["unique_subdomains"].add((parent, labels[0]))
        if t["rcode"] == 3:
            by_client[client]["nxdomain"] += 1

    results = []
    for client, d in by_client.items():
        n_queries = len(d["queries"])
        unique_sub = len(d["unique_subdomains"])
        reasons = []
        score = 0
        if d["max_label"] >= 30:
            reasons.append(_reason("Long encoded labels", f"longest DNS label: {d['max_label']} chars", 35))
            score += 35
        if unique_sub >= 10:
            reasons.append(
                _reason("High subdomain entropy", f"{unique_sub} unique subdomains under one parent", 30)
            )
            score += 30
        if d["nxdomain"] >= 10:
            reasons.append(
                _reason("High NXDOMAIN rate", f"{d['nxdomain']}/{n_queries} queries returned NXDOMAIN", 15)
            )
            score += 15
        if not reasons:
            continue
        # representative query for evidence
        sample = max(d["queries"], key=lambda t: len(t["query_name"]))
        results.append(
            RuleResult(
                rule_name="dns_tunneling",
                title=f"DNS tunneling indicators from {client}",
                severity=_severity_for(_clamp(score)),
                score=_clamp(score),
                reasons=reasons,
                evidence={
                    "query_count": n_queries,
                    "longest_label_chars": d["max_label"],
                    "unique_subdomains": unique_sub,
                    "nxdomain_count": d["nxdomain"],
                    "sample_query": sample["query_name"][:120],
                },
                source_ip=client,
                destination_ip=sample.get("server_ip"),
                related_packet_refs=[t["packet_ref"] for t in d["queries"][:50]],
                explanation=(
                    f"Host {client} sent {n_queries} DNS queries with encoded-looking labels "
                    f"(longest {d['max_label']} chars) across {unique_sub} unique subdomains — "
                    f"a pattern consistent with DNS tunneling (data exfiltration over DNS)."
                ),
            )
        )
    return results


def rule_nxdomain_burst(dns_txns: list[dict]) -> list[RuleResult]:
    """Excessive NXDOMAIN responses — typo-squat probing, DGA behavior, or scanning."""
    by_client: Counter = Counter()
    total_by_client: Counter = Counter()
    samples: dict[str, list[str]] = defaultdict(list)
    for t in dns_txns:
        if not t["client_ip"]:
            continue
        total_by_client[t["client_ip"]] += 1
        if t["rcode"] == 3:
            by_client[t["client_ip"]] += 1
            if len(samples[t["client_ip"]]) < 10:
                samples[t["client_ip"]].append(t["query_name"][:80])

    results = []
    for client, nx in by_client.items():
        total = total_by_client[client]
        rate = nx / total if total else 0
        if nx < 10:
            continue
        reasons = [
            _reason("High NXDOMAIN volume", f"{nx} failed lookups out of {total}", 30),
            _reason("NXDOMAIN rate", f"{rate * 100:.0f}% of queries fail", 20),
        ]
        score = _clamp(nx * 1.5 + rate * 20)
        results.append(
            RuleResult(
                rule_name="nxdomain_burst",
                title=f"Excessive NXDOMAIN from {client} ({nx} failed lookups)",
                severity=_severity_for(int(score)),
                score=int(score),
                reasons=reasons,
                evidence={
                    "nxdomain_count": nx,
                    "total_queries": total,
                    "rate": round(rate, 3),
                    "sample_domains": samples[client],
                },
                source_ip=client,
                explanation=(
                    f"Host {client} generated {nx} NXDOMAIN responses ({rate * 100:.0f}% of its DNS "
                    f"traffic). Bursts of failed lookups can indicate DGA malware, typo-squat "
                    f"probing, or DNS reconnaissance."
                ),
            )
        )
    return results


def rule_suspicious_port(flows: list[dict]) -> list[RuleResult]:
    """Connections to ports commonly used by malware/tooling."""
    results = []
    seen: set[tuple] = set()
    for f in flows:
        port = f["destination_port"]
        if port not in SUSPICIOUS_PORTS:
            continue
        key = (f["source_ip"], f["destination_ip"], port)
        if key in seen:
            continue
        seen.add(key)
        reasons = [_reason("Known malware-associated port", f"port {port} ({SUSPICIOUS_PORTS[port]})", 40)]
        if is_private_ip(f["source_ip"]) and not is_private_ip(f["destination_ip"]):
            reasons.append(_reason("Outbound to external host", f"{f['destination_ip']} is external", 15))
        score = _clamp(45 + (15 if len(reasons) > 1 else 0) + min(f["packets"], 20))
        results.append(
            RuleResult(
                rule_name="suspicious_port",
                title=f"Suspicious port: {f['source_ip']} → {f['destination_ip']}:{port}",
                severity=_severity_for(int(score)),
                score=int(score),
                reasons=reasons,
                evidence={
                    "port": port,
                    "association": SUSPICIOUS_PORTS[port],
                    "packets": f["packets"],
                    "bytes": f["bytes"],
                },
                source_ip=f["source_ip"],
                destination_ip=f["destination_ip"],
                destination_port=port,
                related_flow_ids=[f["_alert_flow_id"]],
                explanation=(
                    f"Host {f['source_ip']} communicated with {f['destination_ip']} on port {port}, "
                    f"commonly associated with {SUSPICIOUS_PORTS[port]}."
                ),
            )
        )
    return results


def rule_excessive_failures(flows: list[dict]) -> list[RuleResult]:
    """Many failed connections to a single destination (not a scan — spread over time/ports)."""
    by_dest: dict[tuple, dict] = defaultdict(lambda: {"failed": 0, "flows": [], "ports": set()})
    for f in flows:
        if not f["failed"]:
            continue
        key = (f["source_ip"], f["destination_ip"])
        by_dest[key]["failed"] += 1
        by_dest[key]["flows"].append(f)
        by_dest[key]["ports"].add(f["destination_port"])

    results = []
    for (src, dst), d in by_dest.items():
        # scans are caught by rule_port_scan; only flag small-port-set failures
        if len(d["ports"]) >= 10:
            continue
        if d["failed"] < 5:
            continue
        score = _clamp(30 + d["failed"] * 5)
        results.append(
            RuleResult(
                rule_name="excessive_connection_failures",
                title=f"Connection failures: {src} → {dst} ({d['failed']} attempts)",
                severity=_severity_for(int(score)),
                score=int(score),
                reasons=[
                    _reason("Repeated failures", f"{d['failed']} failed connections", 30),
                    _reason("Limited port set", f"only {len(d['ports'])} ports involved", 10),
                    _reason("No successful handshake", "no SYN-ACK observed", 15),
                ],
                evidence={"failed_count": d["failed"], "ports": sorted(d["ports"])},
                source_ip=src,
                destination_ip=dst,
                related_flow_ids=[f["_alert_flow_id"] for f in d["flows"][:20]],
                explanation=(
                    f"Host {src} attempted {d['failed']} connections to {dst} on ports "
                    f"{sorted(d['ports'])} without any completing — service outage, blocked "
                    f"firewall rule, or dead destination."
                ),
            )
        )
    return results


def rule_connection_without_dns(flows: list[dict], dns_txns: list[dict]) -> list[RuleResult]:
    """Outbound connections to IPs with no prior DNS resolution (hardcoded C2)."""
    resolved: set[str] = set()
    for t in dns_txns:
        for ip in t.get("response_ips", []):
            resolved.add(ip)

    results = []
    by_dest: dict[tuple, list[dict]] = defaultdict(list)
    for f in flows:
        if f["transport_protocol"] != "TCP":
            continue
        if not (is_private_ip(f["source_ip"]) and not is_private_ip(f["destination_ip"])):
            continue
        if f["destination_ip"] in resolved:
            continue
        if f["destination_port"] == 80:  # plain HTTP often uses IP directly; skip noise
            continue
        by_dest[(f["source_ip"], f["destination_ip"], f["destination_port"])].append(f)

    for (src, dst, dport), group in by_dest.items():
        total_bytes = sum(f["bytes"] for f in group)
        reasons = [
            _reason("No DNS resolution observed", f"{dst} was never resolved by any DNS query", 35),
            _reason("Direct IP connection", f"connection to {dst}:{dport} bypassing DNS", 25),
        ]
        if total_bytes > 10_000:
            reasons.append(_reason("Meaningful data volume", f"{total_bytes} bytes exchanged", 10))
        score = _clamp(50 + min(len(group), 20) + (10 if total_bytes > 10_000 else 0))
        results.append(
            RuleResult(
                rule_name="connection_without_dns",
                title=f"Direct IP connection: {src} → {dst}:{dport} (no DNS)",
                severity=_severity_for(int(score)),
                score=int(score),
                reasons=reasons,
                evidence={"connections": len(group), "bytes": total_bytes, "destination": f"{dst}:{dport}"},
                source_ip=src,
                destination_ip=dst,
                destination_port=dport,
                related_flow_ids=[f["_alert_flow_id"] for f in group[:20]],
                explanation=(
                    f"Host {src} connected to {dst}:{dport} without any DNS lookup resolving it "
                    f"in this capture. Hardcoded destinations are common in malware config."
                ),
            )
        )
    return results


def rule_high_outbound_volume(flows: list[dict]) -> list[RuleResult]:
    """A single host sending an unusually large share of total outbound bytes."""
    internal_flows = [
        f for f in flows if is_private_ip(f["source_ip"]) and not is_private_ip(f["destination_ip"])
    ]
    if not internal_flows:
        return []
    total_bytes = sum(f["bytes"] for f in internal_flows)
    if total_bytes < 50_000:  # capture too small to judge
        return []
    by_host: dict[str, int] = defaultdict(int)
    for f in internal_flows:
        by_host[f["source_ip"]] += f["bytes"]

    results = []
    for host, bytes_ in by_host.items():
        share = bytes_ / total_bytes
        if share < 0.7 or bytes_ < 20_000:  # dominant host with meaningful volume
            continue
        results.append(
            RuleResult(
                rule_name="high_outbound_volume",
                title=f"High outbound volume from {host} ({bytes_} bytes)",
                severity=_severity_for(55),
                score=55,
                reasons=[
                    _reason("Dominant outbound traffic", f"{share * 100:.0f}% of all outbound bytes", 30),
                    _reason("Large data volume", f"{bytes_} bytes sent externally", 20),
                ],
                evidence={
                    "bytes": bytes_,
                    "share_of_outbound": round(share, 3),
                    "total_outbound": total_bytes,
                },
                source_ip=host,
                explanation=(
                    f"Host {host} accounts for {share * 100:.0f}% of outbound traffic "
                    f"({bytes_} bytes) — possible data exfiltration or backup activity."
                ),
            )
        )
    return results


# ---------------- Phase 2 rules ----------------

# Ports whose internal-to-internal use suggests credential theft / remote control
LATERAL_MOVE_PORTS = {22: "SSH", 445: "SMB", 3389: "RDP", 5985: "WinRM", 5986: "WinRM-TLS", 5900: "VNC"}

# UA fingerprints commonly seen in tooling/malware (deterministic substring matches)
SUSPICIOUS_UA_PATTERNS = [
    (r"(?i)sqlmap", "sqlmap injection tool"),
    (r"(?i)nikto", "Nikto web scanner"),
    (r"(?i)masscan", "masscan scanner"),
    (r"(?i)nmap scripting engine", "Nmap NSE"),
    (r"(?i)^python-requests", "generic python script"),
    (r"(?i)^curl/", "scripted curl"),
    (r"(?i)^wget$", "wget (no UA customizing)"),
    (r"(?i)metasploit", "Metasploit"),
    (r"(?i)^go-http-client", "Go malware default client"),
    (r"(?i)mimikatz", "Mimikatz"),
    (r"(?i)^backdoor", "named backdoor client"),
    (r"(?i)^python-urllib", "python urllib script"),
]


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in counts.values())


def rule_arp_spoofing(parsed: ParsedCapture) -> list[RuleResult]:
    """One IP claimed by multiple MACs, or gratuitous ARP announcements.

    ARP data is parsed in the ScapyParser (arp.* metadata) — this rule finally uses it.
    """
    # ip -> set of MACs claiming it (from ARP requests/replies)
    ip_to_macs: dict[str, set[str]] = defaultdict(set)
    # (ip, mac) -> packet refs + timestamps for evidence
    claims: dict[tuple, dict] = defaultdict(lambda: {"refs": [], "times": []})
    gratuitous = 0
    gratuitous_refs: list[int] = []

    for pkt in parsed.packets:
        md = pkt.metadata
        src_ip, dst_ip = md.get("arp.src_ip"), md.get("arp.dst_ip")
        src_mac = md.get("arp.src_mac")
        if not (src_ip and src_mac):
            continue
        ip_to_macs[src_ip].add(src_mac)
        key = (src_ip, src_mac)
        claims[key]["refs"].append(pkt.packet_reference)
        claims[key]["times"].append(pkt.timestamp)
        # gratuitous announce: ARP request/reply telling the sender's own mapping
        if dst_ip == src_ip:
            gratuitous += 1
            if len(gratuitous_refs) < 20:
                gratuitous_refs.append(pkt.packet_reference)

    results = []
    for ip, macs in ip_to_macs.items():
        if len(macs) < 2:
            continue
        reasons = [
            _reason(
                "IP claimed by multiple MACs",
                f"{ip} announced by {len(macs)} MACs: {', '.join(sorted(macs))}",
                45,
            ),
        ]
        score = 70
        if gratuitous > 0:
            reasons.append(
                _reason(
                    "Gratuitous ARP announcements", f"{gratuitous} ARP packets announcing own mapping", 15
                )
            )
            score = _clamp(score + 10)
        all_refs = []
        for mac in sorted(macs):
            all_refs.extend(claims[(ip, mac)]["refs"][:10])
        results.append(
            RuleResult(
                rule_name="arp_spoofing",
                title=f"ARP conflict: {ip} claimed by {len(macs)} MACs",
                severity=_severity_for(score),
                score=int(score),
                reasons=reasons,
                evidence={
                    "ip": ip,
                    "macs": sorted(macs),
                    "gratuitous_arp_count": gratuitous,
                    "mac_claim_evidence": {
                        mac: {"packets": len(claims[(ip, mac)]["refs"])} for mac in sorted(macs)
                    },
                },
                source_ip=ip,
                related_packet_refs=all_refs[:20],
                explanation=(
                    f"IP address {ip} was claimed by {len(macs)} different MAC addresses in ARP "
                    f"traffic — classic ARP-spoofing / man-in-the-middle signature (attacker "
                    f"poisons the gateway mapping)."
                ),
            )
        )
    return results


def rule_lateral_movement(flows: list[dict]) -> list[RuleResult]:
    """Internal host fanning out to many other internal hosts on admin ports."""
    by_src: dict[str, dict] = defaultdict(lambda: {"targets": {}, "flows": []})
    for f in flows:
        if f["destination_port"] not in LATERAL_MOVE_PORTS:
            continue
        if not (is_private_ip(f["source_ip"]) and is_private_ip(f["destination_ip"])):
            continue
        s = by_src[f["source_ip"]]
        s["targets"].setdefault(f["destination_ip"], {"ports": set(), "successful": 0, "failed": 0})
        t = s["targets"][f["destination_ip"]]
        t["ports"].add(f["destination_port"])
        t["successful" if not f["failed"] else "failed"] += 1
        s["flows"].append(f)

    results = []
    for src, s in by_src.items():
        n_targets = len(s["targets"])
        if n_targets < 3:
            continue
        admin_ports = sorted({p for t in s["targets"].values() for p in t["ports"]})
        successful_targets = sum(1 for t in s["targets"].values() if t["successful"] > 0)
        reasons = [
            _reason("Internal fan-out", f"{src} touched {n_targets} internal hosts", 35),
            _reason(
                "Admin/administrative ports",
                f"ports {admin_ports} ({', '.join(LATERAL_MOVE_PORTS.get(p, str(p)) for p in admin_ports[:4])})",
                30,
            ),
        ]
        score = 40 + min(n_targets, 10) * 4
        if successful_targets >= 2:
            reasons.append(
                _reason(
                    "Successful connections", f"{successful_targets} targets answered — access achieved", 20
                )
            )
            score += 15
        results.append(
            RuleResult(
                rule_name="lateral_movement",
                title=f"Lateral movement: {src} → {n_targets} internal hosts (admin ports)",
                severity=_severity_for(_clamp(score)),
                score=int(_clamp(score)),
                reasons=reasons,
                evidence={
                    "target_count": n_targets,
                    "targets": {
                        ip: {
                            "ports": sorted(t["ports"]),
                            "successful": t["successful"],
                            "failed": t["failed"],
                        }
                        for ip, t in list(s["targets"].items())[:20]
                    },
                    "ports_used": admin_ports,
                },
                source_ip=src,
                related_flow_ids=[f["_alert_flow_id"] for f in s["flows"][:50]],
                explanation=(
                    f"Internal host {src} connected to {n_targets} other internal hosts on "
                    f"administrative ports {admin_ports}. This internal fan-out pattern is "
                    f"characteristic of post-compromise lateral movement."
                ),
            )
        )
    return results


def rule_dga_domains(dns_txns: list[dict]) -> list[RuleResult]:
    """Algorithmically-generated domains: high entropy + no dictionary structure.

    Compares each client's domains against the capture's own baseline entropy.
    """
    # capture-wide baseline: median entropy of second-level domains, computed over
    # READABLE domains only (dictionary words) so DGAs can't skew their own baseline
    all_domains = [t["query_name"].rstrip(".") for t in dns_txns if t.get("query_name")]
    if len(all_domains) < 10:
        return []

    def _sld(name: str) -> str:
        labels = name.split(".")
        return labels[0] if len(labels) == 1 else labels[-2]

    def _readable(name: str) -> bool:
        """Heuristic: readable SLDs have vowels breaking up consonant runs."""
        return (
            max(
                (len(m.group()) for m in re.finditer(r"[bcdfghjklmnpqrstvwxz]{4,}", name.lower())),
                default=0,
            )
            < 4
        )

    baseline_pool = sorted(_shannon_entropy(_sld(d)) for d in all_domains if _readable(d))
    if len(baseline_pool) < 5:
        return []  # not enough readable traffic to establish a baseline
    baseline = baseline_pool[len(baseline_pool) // 2]

    by_client: dict[str, dict] = defaultdict(lambda: {"domains": [], "high_entropy": [], "nx": 0})
    for t in dns_txns:
        name = (t.get("query_name") or "").rstrip(".")
        if not name:
            continue
        c = by_client[t["client_ip"]]
        c["domains"].append(name)
        e = _shannon_entropy(_sld(name))
        # DGA markers: high entropy vs baseline AND long AND no vowels-rhythm (consonant runs)
        consonant_run = max(
            (len(m.group()) for m in re.finditer(r"[bcdfghjklmnpqrstvwxz]{4,}", name.lower())), default=0
        )
        if e > max(3.2, baseline + 0.6) and len(_sld(name)) >= 8 and consonant_run >= 4:
            c["high_entropy"].append((name, round(e, 2)))
        if t.get("rcode") == 3:
            c["nx"] += 1

    results = []
    for client, d in by_client.items():
        n_hi = len(d["high_entropy"])
        if n_hi < 5:
            continue
        reasons = [
            _reason(
                "High-entropy domains",
                f"{n_hi} domains with entropy well above baseline ({baseline:.2f})",
                40,
            ),
            _reason("Dictionary-less labels", "long consonant runs, no readable words", 20),
        ]
        score = 45 + min(n_hi, 20) * 2
        if d["nx"] >= 5:
            reasons.append(
                _reason(
                    "Many NXDOMAIN replies",
                    f"{d['nx']} domains failed to resolve (typical of DGA rotation)",
                    20,
                )
            )
            score += 10
        results.append(
            RuleResult(
                rule_name="dga_domain",
                title=f"DGA-like domains from {client} ({n_hi} algorithmic names)",
                severity=_severity_for(int(_clamp(score))),
                score=int(_clamp(score)),
                reasons=reasons,
                evidence={
                    "high_entropy_domains": [n for n, _ in d["high_entropy"][:20]],
                    "count": n_hi,
                    "baseline_entropy": round(baseline, 2),
                    "sample_entropies": [e for _, e in d["high_entropy"][:10]],
                    "nxdomain_count": d["nx"],
                },
                source_ip=client,
                related_packet_refs=[
                    t["packet_ref"] for t in dns_txns if t["client_ip"] == client and t.get("query_name")
                ][:50],
                explanation=(
                    f"Host {client} looked up {n_hi} high-entropy, dictionary-less domains "
                    f"(capture baseline entropy {baseline:.2f}). Domains like these are usually "
                    f"generated by malware DGAs to evade static blocklists."
                ),
            )
        )
    return results


def rule_data_exfiltration(flows: list[dict], dns_txns: list[dict]) -> list[RuleResult]:
    """Large outbound transfer to a rare destination (first contact + big volume)."""
    # which external IPs ever got DNS-resolved (known/popular destinations)
    resolved: set[str] = set()
    for t in dns_txns:
        for ip in t.get("response_ips", []):
            resolved.add(ip)

    by_dest: dict[tuple, dict] = defaultdict(lambda: {"flows": [], "bytes": 0})
    for f in flows:
        if not (is_private_ip(f["source_ip"]) and not is_private_ip(f["destination_ip"])):
            continue
        key = (f["source_ip"], f["destination_ip"])
        by_dest[key]["flows"].append(f)
        by_dest[key]["bytes"] += f["bytes"]

    # capture-wide baseline: median per-destination external volume
    vols = sorted(d["bytes"] for d in by_dest.values())
    if not vols:
        return []
    baseline = vols[len(vols) // 2]

    results = []
    for (src, dst), d in by_dest.items():
        bytes_ = d["bytes"]
        if bytes_ < 100_000:  # too small to call exfiltration in synthetic data
            continue
        reasons = []
        score = 0
        if baseline > 0 and bytes_ > baseline * 20:
            reasons.append(
                _reason(
                    "Volume far above baseline", f"{bytes_} bytes vs median {baseline} per destination", 35
                )
            )
            score += 35
        if dst not in resolved:
            reasons.append(
                _reason("First-contact destination", f"{dst} never resolved via DNS in this capture", 25)
            )
            score += 25
        duration = max(f["last_seen"] - f["first_seen"] for f in d["flows"])
        if duration < 30:
            reasons.append(_reason("Short transfer window", f"{bytes_} bytes moved in {duration:.0f}s", 15))
            score += 15
        if not reasons:
            continue
        results.append(
            RuleResult(
                rule_name="data_exfiltration",
                title=f"Possible exfiltration: {src} → {dst} ({bytes_} bytes)",
                severity=_severity_for(int(_clamp(score + 20))),
                score=int(_clamp(score + 20)),
                reasons=reasons,
                evidence={
                    "bytes": bytes_,
                    "baseline_bytes": baseline,
                    "duration_seconds": round(duration, 1),
                    "destination_resolved_via_dns": dst in resolved,
                    "flow_count": len(d["flows"]),
                },
                source_ip=src,
                destination_ip=dst,
                related_flow_ids=[f["_alert_flow_id"] for f in d["flows"][:20]],
                explanation=(
                    f"Host {src} transferred {bytes_} bytes to external host {dst} "
                    f"({'which was never resolved via DNS — first contact' if dst not in resolved else 'in a short window'}) "
                    f"— consistent with data exfiltration."
                ),
            )
        )
    return results


def rule_low_slow_beaconing(flows: list[dict]) -> list[RuleResult]:
    """Long-interval periodic connections (hours-like beacons disguised as keepalives).

    rule_beaconing requires >=5 connections with <=10% jitter; this rule covers
    small connection counts and larger, still-regular intervals.
    """
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for f in flows:
        if f["transport_protocol"] != "TCP":
            continue
        groups[(f["source_ip"], f["destination_ip"], f["destination_port"])].append(f)

    results = []
    for (src, dst, dport), group in groups.items():
        if len(group) < 3:  # fewer than beaconing's 5 — low-and-slow needs fewer
            continue
        times = sorted(f["first_seen"] for f in group)
        intervals = [b - a for a, b in zip(times, times[1:], strict=False)]
        mean = sum(intervals) / len(intervals)
        if mean < 60:  # rule_beaconing territory (< 60s); here we want long intervals
            continue
        variance = sum((i - mean) ** 2 for i in intervals) / len(intervals)
        std = variance**0.5
        if mean <= 0 or std / mean > 0.2:  # allow more jitter than fast beaconing
            continue

        reasons = [
            _reason(
                "Long-interval periodicity", f"{len(times)} connections at ~{mean / 60:.0f}min intervals", 40
            ),
            _reason("Low and slow cadence", "few, spread-out check-ins designed to evade rate alerts", 25),
            _reason("Repeated destination", f"{dst}:{dport} contacted {len(group)} times", 20),
        ]
        score = _clamp(55 + min(len(group), 10) * 2)
        results.append(
            RuleResult(
                rule_name="low_slow_beaconing",
                title=f"Low-and-slow beacon: {src} → {dst}:{dport} every {mean / 60:.0f}min",
                severity=_severity_for(int(score)),
                score=int(score),
                reasons=reasons,
                evidence={
                    "intervals": [round(i, 1) for i in intervals[:20]],
                    "mean_interval": round(mean, 1),
                    "jitter_ratio": round(std / mean, 3),
                    "connection_count": len(group),
                },
                source_ip=src,
                destination_ip=dst,
                destination_port=dport,
                related_flow_ids=[f["_alert_flow_id"] for f in group[:20]],
                explanation=(
                    f"Host {src} checked in with {dst}:{dport} {len(group)} times at regular "
                    f"~{mean / 60:.0f}-minute intervals — low-and-slow C2 cadence that evades "
                    f"short-window rate-based detection."
                ),
            )
        )
    return results


def rule_suspicious_user_agent(http_txns: list[dict]) -> list[RuleResult]:
    """HTTP requests with tool/malware user-agent fingerprints."""
    hits: dict[str, list[dict]] = defaultdict(list)
    for t in http_txns:
        ua = t.get("user_agent")
        if not ua:
            continue
        for pattern, label in SUSPICIOUS_UA_PATTERNS:
            if re.search(pattern, ua):
                hits[label].append(t)
                break

    results = []
    for label, txns in hits.items():
        ua_sample = txns[0].get("user_agent", "")[:80]
        score = _clamp(40 + min(len(txns), 20))
        results.append(
            RuleResult(
                rule_name="suspicious_user_agent",
                title=f"Suspicious user agent: {label} ({len(txns)} requests)",
                severity=_severity_for(score),
                score=int(score),
                reasons=[
                    _reason(
                        "Tool/malware UA fingerprint", f"{len(txns)} requests with UA matching {label}", 40
                    ),
                    _reason("Sample UA", f'"{ua_sample}"', 15),
                ],
                evidence={
                    "matched_label": label,
                    "request_count": len(txns),
                    "sample_user_agent": ua_sample,
                    "hosts": list({t.get("host") for t in txns if t.get("host")})[:10],
                },
                source_ip=txns[0].get("client_ip"),
                destination_ip=txns[0].get("server_ip"),
                related_packet_refs=[t["packet_ref"] for t in txns[:20]],
                explanation=(
                    f"{len(txns)} HTTP requests carried a user agent matching {label} — "
                    f'"{ua_sample}". Legitimate browsers rarely send these fingerprints.'
                ),
            )
        )
    return results


# ---------------- Engine ----------------


def correlate_alerts(alerts: list[dict]) -> list[dict]:
    """Group related alerts into incidents (same source host + overlapping time).

    Correlation is deterministic: same source_ip alerts within a 10-minute window
    merge into one incident with a synthesized story.
    """
    if not alerts:
        return []
    WINDOW = 600  # seconds between alerts to chain into one incident
    by_source: dict[str, list[dict]] = defaultdict(list)
    for a in alerts:
        src = a.get("source_ip")
        if not src or a.get("severity") == "info":
            continue
        by_source[src].append(a)

    incidents: list[dict] = []
    for src, src_alerts in by_source.items():
        src_alerts.sort(key=lambda a: a.get("timestamp") or 0)
        chain: list[dict] = [src_alerts[0]]
        for a in src_alerts[1:]:
            prev = chain[-1]
            if (a.get("timestamp") or 0) - (prev.get("timestamp") or 0) <= WINDOW:
                chain.append(a)
            else:
                incidents.append(_build_incident(src, chain))
                chain = [a]
        incidents.append(_build_incident(src, chain))

    incidents.sort(key=lambda i: -i["max_score"])
    return incidents


def _build_incident(source_ip: str, alerts: list[dict]) -> dict:
    rules = sorted({a["rule_name"] for a in alerts})
    max_score = max(a["score"] for a in alerts)
    by_sev: Counter = Counter(a["severity"] for a in alerts)
    top_sev = next(
        (s for s in ("critical", "high", "medium", "low", "info") if by_sev.get(s)),
        "info",
    )
    ts_min = min((a.get("timestamp") or 0) for a in alerts)
    ts_max = max((a.get("timestamp") or 0) for a in alerts)
    return {
        "source_ip": source_ip,
        "rule_names": rules,
        "alert_count": len(alerts),
        "max_score": max_score,
        "severity": top_sev,
        "first_seen": ts_min,
        "last_seen": ts_max,
        "alert_ids": [a.get("id") for a in alerts if a.get("id")],
        "title": f"Incident on {source_ip}: {' + '.join(rules)}",
        "story": (
            f"Host {source_ip} triggered {len(alerts)} alert(s) ({', '.join(rules)}) "
            f"over {ts_max - ts_min:.0f}s — correlated activity suggests a single campaign "
            f"rather than isolated events."
        ),
    }


class SuspicionEngine:
    """Runs all deterministic rules over a capture's normalized artifacts."""

    def run(
        self,
        parsed: ParsedCapture,
        flows: list[dict],
        dns_txns: list[dict],
        id_by_flow: dict[int, str] | None = None,
        http_txns: list[dict] | None = None,
    ) -> list[dict]:
        """id_by_flow: optional mapping to REAL persisted flow ids (by object identity)."""
        # tag each flow dict with its persisted id so rules can cross-reference
        for i, f in enumerate(flows):
            f["_alert_flow_id"] = (id_by_flow.get(id(f)) if id_by_flow else None) or f"flowidx-{i}"

        results: list[RuleResult] = []
        results += rule_port_scan(flows)
        results += rule_beaconing(flows)
        results += rule_dns_tunneling(parsed, dns_txns)
        results += rule_nxdomain_burst(dns_txns)
        results += rule_suspicious_port(flows)
        results += rule_excessive_failures(flows)
        results += rule_connection_without_dns(flows, dns_txns)
        results += rule_high_outbound_volume(flows)
        # Phase 2 rules
        results += rule_arp_spoofing(parsed)
        results += rule_lateral_movement(flows)
        results += rule_dga_domains(dns_txns)
        results += rule_data_exfiltration(flows, dns_txns)
        results += rule_low_slow_beaconing(flows)
        if http_txns is not None:
            results += rule_suspicious_user_agent(http_txns)

        alert_dicts = []
        for r in results:
            d = r.to_dict()
            first_flow = next((f for f in flows if f["_alert_flow_id"] in (r.related_flow_ids or [])), None)
            d["timestamp"] = (
                first_flow["first_seen"] if first_flow else (dns_txns[0]["timestamp"] if dns_txns else None)
            )
            alert_dicts.append(d)
        alert_dicts.sort(key=lambda a: -a["score"])
        return alert_dicts

    @staticmethod
    def augment_hosts(host_dicts: list[dict], alert_dicts: list[dict]) -> None:
        """Attach alert counts to host profiles (suspicious behaviors per host)."""
        by_host: Counter = Counter()
        by_host_high: Counter = Counter()
        for a in alert_dicts:
            if a.get("source_ip"):
                by_host[a["source_ip"]] += 1
                if a["severity"] in ("high", "critical"):
                    by_host_high[a["source_ip"]] += 1
        for h in host_dicts:
            h["behavior_summary"] = dict(h.get("behavior_summary") or {})
            h["behavior_summary"]["alert_count"] = by_host.get(h["ip"], 0)
            h["behavior_summary"]["high_severity_alert_count"] = by_host_high.get(h["ip"], 0)
