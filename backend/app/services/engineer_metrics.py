"""Network Engineering Mode metrics (Module G).

Network health rather than security: throughput, reliability, latency,
top talkers, protocol distribution, and engineering-grade anomaly flags
(packet loss indicators, reset storms, DNS degradation, MTU issues).
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from app.core.models import ParsedCapture

BYTES_PER_SEC_WARN = 1_000_000  # 1 MB/s
DNS_LATENCY_WARN = 0.5  # 500 ms
RETRANS_RATIO_WARN = 0.05  # 5% of packets
RESET_RATIO_WARN = 0.1  # 10% of TCP flows


def compute_engineer_metrics(
    parsed: ParsedCapture,
    flows: list[dict],
    dns_txns: list[dict],
    bucket_count: int = 40,
) -> dict[str, Any]:
    packets = parsed.packets
    if not packets:
        return {"error": "no packets"}

    t0 = packets[0].timestamp
    t_end = packets[-1].timestamp
    duration = max(t_end - t0, 1e-6)
    total_bytes = sum(p.length for p in packets)

    # ---- time series buckets ----
    bucket_len = duration / bucket_count
    ts_pps: list[dict] = []
    ts_bandwidth: list[dict] = []
    counts = [0] * bucket_count
    byte_counts = [0] * bucket_count
    for p in packets:
        idx = min(int((p.timestamp - t0) / bucket_len), bucket_count - 1)
        counts[idx] += 1
        byte_counts[idx] += p.length

    for i in range(bucket_count):
        t = t0 + i * bucket_len
        ts_pps.append({"t": round(t - t0, 2), "pps": round(counts[i] / max(bucket_len, 1e-6), 1)})
        ts_bandwidth.append(
            {"t": round(t - t0, 2), "bps": round(byte_counts[i] * 8 / max(bucket_len, 1e-6), 0)}
        )

    # ---- protocol distribution ----
    proto_counts = Counter(p.protocol or "unknown" for p in packets)
    transport_counts = Counter(p.transport or "other" for p in packets if p.transport)

    # ---- TCP health ----
    tcp_flows = [f for f in flows if f["transport_protocol"] == "TCP"]
    total_retrans = sum(f["retransmissions"] for f in flows)
    total_resets = sum(f["resets"] for f in flows)
    failed_flows = [f for f in flows if f["failed"]]
    syn_retrans = sum(f["syn_retransmissions"] for f in flows)

    # retransmission ratio relative to TCP data packets
    tcp_packets = sum(f["packets"] for f in tcp_flows)
    retrans_ratio = (total_retrans / tcp_packets) if tcp_packets else 0
    reset_ratio = (total_resets / len(tcp_flows)) if tcp_flows else 0
    failure_ratio = (len(failed_flows) / len(flows)) if flows else 0

    # ---- DNS latency ----
    latencies = [t["latency"] for t in dns_txns if t.get("latency") is not None]
    nx_rate = (
        sum(1 for t in dns_txns if t.get("rcode") == 3) / len(dns_txns) if dns_txns else 0
    )
    dns_stats = {
        "transactions": len(dns_txns),
        "avg_latency_ms": round(sum(latencies) / len(latencies) * 1000, 1) if latencies else None,
        "max_latency_ms": round(max(latencies) * 1000, 1) if latencies else None,
        "p95_latency_ms": round(sorted(latencies)[min(int(len(latencies) * 0.95), len(latencies) - 1)] * 1000, 1)
        if latencies
        else None,
        "nxdomain_rate": round(nx_rate, 3),
    }

    # ---- top talkers ----
    sent_bytes: Counter = Counter()
    recv_bytes: Counter = Counter()
    sent_pkts: Counter = Counter()
    for p in packets:
        if p.source_ip:
            sent_bytes[p.source_ip] += p.length
            sent_pkts[p.source_ip] += 1
        if p.destination_ip:
            recv_bytes[p.destination_ip] += p.length
    top_talkers = [
        {
            "ip": ip,
            "sent_bytes": sent_bytes[ip],
            "received_bytes": recv_bytes[ip],
            "packets": sent_pkts[ip],
        }
        for ip, _ in sent_bytes.most_common(10)
    ]

    # ---- MTU indicators ----
    mtu_sizes = [p.length for p in packets]
    max_packet = max(mtu_sizes) if mtu_sizes else 0
    mtu_issues = sum(1 for p in packets if 1480 < p.length <= 1500)

    # ---- health verdict / issues ----
    issues: list[dict] = []

    if retrans_ratio > RETRANS_RATIO_WARN:
        issues.append({
            "issue": "retransmissions",
            "severity": "high" if retrans_ratio > 0.15 else "medium",
            "detail": f"{total_retrans} retransmissions ({retrans_ratio * 100:.1f}% of TCP packets) — possible packet loss or congestion",
        })
    if syn_retrans > 0:
        issues.append({
            "issue": "syn_retransmissions",
            "severity": "low",
            "detail": f"{syn_retrans} SYN retransmissions — slow or dropping handshakes",
        })
    if reset_ratio > RESET_RATIO_WARN:
        issues.append({
            "issue": "tcp_resets",
            "severity": "medium" if reset_ratio > 0.3 else "low",
            "detail": f"{total_resets} resets across {len(tcp_flows)} TCP flows ({reset_ratio * 100:.0f}%) — aborted connections",
        })
    if failure_ratio > 0.5 and len(failed_flows) > 5:
        issues.append({
            "issue": "connection_failures",
            "severity": "high" if failure_ratio > 0.7 else "medium",
            "detail": f"{len(failed_flows)}/{len(flows)} connections never completed — unreachable service, firewall drops, or scan traffic",
        })
    if dns_stats["avg_latency_ms"] and dns_stats["avg_latency_ms"] > DNS_LATENCY_WARN * 1000:
        issues.append({
            "issue": "dns_latency",
            "severity": "medium",
            "detail": f"average DNS latency {dns_stats['avg_latency_ms']} ms exceeds {DNS_LATENCY_WARN * 1000:.0f} ms",
        })
    if nx_rate > 0.3 and len(dns_txns) > 10:
        issues.append({
            "issue": "dns_nxdomain",
            "severity": "medium",
            "detail": f"{nx_rate * 100:.0f}% of DNS queries return NXDOMAIN — misconfigured resolver or stale records",
        })
    if mtu_issues > 0:
        issues.append({
            "issue": "mtu_boundary",
            "severity": "low",
            "detail": f"{mtu_issues} packets at {max_packet} bytes near MTU boundary — check for fragmentation/Path-MTU issues",
        })
    bandwidth_bps = total_bytes * 8 / duration
    if bandwidth_bps > BYTES_PER_SEC_WARN * 8:
        issues.append({
            "issue": "high_bandwidth",
            "severity": "info",
            "detail": f"sustained {bandwidth_bps / 1e6:.1f} Mbps throughput",
        })

    # asymmetric routing: many one-way flows without reverse traffic
    one_way = sum(
        1 for f in flows if f["packets_reverse"] == 0 and f["transport_protocol"] == "TCP"
    )
    if one_way > 5 and len(tcp_flows) > 10 and one_way / len(tcp_flows) > 0.5:
        issues.append({
            "issue": "asymmetric_routing",
            "severity": "medium",
            "detail": f"{one_way}/{len(tcp_flows)} TCP flows have no return traffic — asymmetric routing or capture point misses one direction",
        })

    return {
        "capture_duration_s": round(duration, 3),
        "total_packets": len(packets),
        "total_bytes": total_bytes,
        "avg_pps": round(len(packets) / duration, 1),
        "peak_pps": max(round(c / max(bucket_len, 1e-6), 1) for c in counts),
        "avg_bandwidth_bps": round(bandwidth_bps, 0),
        "peak_bandwidth_bps": max(b * 8 / max(bucket_len, 1e-6) for b in byte_counts),
        "protocol_distribution": dict(proto_counts.most_common()),
        "transport_distribution": dict(transport_counts.most_common()),
        "tcp": {
            "flows": len(tcp_flows),
            "retransmissions": total_retrans,
            "retransmission_ratio": round(retrans_ratio, 4),
            "syn_retransmissions": syn_retrans,
            "resets": total_resets,
            "reset_ratio": round(reset_ratio, 4),
            "failed_flows": len(failed_flows),
            "failure_ratio": round(failure_ratio, 4),
            "one_way_flows": one_way,
        },
        "dns": dns_stats,
        "top_talkers": top_talkers,
        "max_packet_size": max_packet,
        "mtu_boundary_packets": mtu_issues,
        "timeseries": {"pps": ts_pps, "bandwidth": ts_bandwidth},
        "issues": issues,
        "health": "degraded" if any(i["severity"] == "high" for i in issues)
        else ("warning" if issues else "healthy"),
    }
