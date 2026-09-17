"""Protocol extraction — DNS transactions, HTTP transactions, TLS sessions.

Turns per-packet metadata hints into paired transactions:
- DNS: query ↔ response matching by DNS txid + client, with latency + rcode
- HTTP: request ↔ response matching by (client, server, server_port) in time order
- TLS: sessions grouped by flow (SNI recorded when ClientHello observed)
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from app.core.models import ParsedCapture


def extract_dns(parsed: ParsedCapture) -> list[dict]:
    """Pair DNS queries with responses; unpaired queries become open transactions."""
    pending: dict[tuple, dict] = {}
    results: list[dict] = []

    for pkt in parsed.packets:
        md = pkt.metadata
        if "dns.query" not in md and "dns.is_response" not in md:
            continue
        if not md.get("dns.is_response"):
            key = (pkt.source_ip, pkt.destination_ip, md.get("dns.id"))
            pending[key] = {
                "transaction_id": md.get("dns.id", 0),
                "client_ip": pkt.source_ip,
                "server_ip": pkt.destination_ip,
                "query_name": md.get("dns.query", ""),
                "query_type": str(md.get("dns.qtype", "")),
                "response_ips": [],
                "is_response": False,
                "rcode": None,
                "latency": None,
                "timestamp": pkt.timestamp,
                "packet_ref": pkt.packet_reference,
            }
        else:
            key = (pkt.destination_ip, pkt.source_ip, md.get("dns.id"))
            txn = pending.pop(key, None)
            if txn is None:
                # response without query (capture started mid-stream)
                txn = {
                    "transaction_id": md.get("dns.id", 0),
                    "client_ip": pkt.destination_ip,
                    "server_ip": pkt.source_ip,
                    "query_name": md.get("dns.query", ""),
                    "query_type": "",
                    "response_ips": md.get("dns.answers", []),
                    "is_response": True,
                    "rcode": md.get("dns.rcode"),
                    "latency": None,
                    "timestamp": pkt.timestamp,
                    "packet_ref": pkt.packet_reference,
                }
            else:
                txn.update(
                    is_response=True,
                    rcode=md.get("dns.rcode"),
                    response_ips=md.get("dns.answers", []),
                    latency=round(pkt.timestamp - txn["timestamp"], 6),
                )
            results.append(txn)

    # unanswered queries
    results.extend(pending.values())
    results.sort(key=lambda t: t["timestamp"])
    return results


def extract_http(parsed: ParsedCapture) -> list[dict]:
    """Pair HTTP requests with the next response on the same (client, server, port)."""
    open_requests: dict[tuple, dict] = {}
    results: list[dict] = []

    for pkt in parsed.packets:
        md = pkt.metadata
        if "http.method" in md:
            key = (pkt.source_ip, pkt.destination_ip, pkt.destination_port)
            open_requests[key] = {
                "client_ip": pkt.source_ip,
                "server_ip": pkt.destination_ip,
                "server_port": pkt.destination_port or 80,
                "method": md.get("http.method"),
                "host": md.get("http.host"),
                "path": md.get("http.path"),
                "user_agent": md.get("http.user_agent"),
                "status_code": None,
                "request_len": pkt.length,
                "response_len": 0,
                "timestamp": pkt.timestamp,
                "packet_ref": pkt.packet_reference,
            }
        elif "http.status" in md:
            key = (pkt.destination_ip, pkt.source_ip, pkt.source_port)
            req = open_requests.pop(key, None)
            if req is None:
                req = {
                    "client_ip": pkt.destination_ip,
                    "server_ip": pkt.source_ip,
                    "server_port": pkt.source_port or 80,
                    "method": None,
                    "host": None,
                    "path": None,
                    "user_agent": None,
                    "status_code": md.get("http.status"),
                    "request_len": 0,
                    "response_len": pkt.length,
                    "timestamp": pkt.timestamp,
                    "packet_ref": pkt.packet_reference,
                }
            else:
                req["status_code"] = md.get("http.status")
                req["response_len"] = pkt.length
            results.append(req)

    results.extend(open_requests.values())
    results.sort(key=lambda t: t["timestamp"])
    return results


def extract_tls(parsed: ParsedCapture, flows: list[dict] | None = None) -> list[dict]:
    """Group TLS traffic into sessions by flow; attach SNI from ClientHello hints."""
    sessions: dict[tuple, dict] = {}

    # map packet refs -> flow for TLS-labeled packets
    flow_by_ref: dict[int, dict] = {}
    if flows:
        for f in flows:
            if f.get("application_protocol") == "TLS" or f.get("destination_port") in (443, 8443):
                for ref in f.get("packet_refs", []):
                    flow_by_ref[ref] = f

    for pkt in parsed.packets:
        is_tls = pkt.protocol == "TLS" or (pkt.transport == "TCP" and pkt.destination_port in (443, 8443))
        if not is_tls:
            continue
        if flows:
            flow = flow_by_ref.get(pkt.packet_reference)
            if flow is None:
                continue
            key = (flow["source_ip"], flow["source_port"], flow["destination_ip"], flow["destination_port"])
        else:
            key = (pkt.source_ip, pkt.source_port, pkt.destination_ip, pkt.destination_port)
        s = sessions.get(key)
        if s is None:
            s = {
                "client_ip": key[0],
                "server_ip": key[2],
                "server_port": key[3],
                "sni": pkt.metadata.get("tls.sni"),
                "version": pkt.metadata.get("tls.record_version"),
                "bytes": 0,
                "packets": 0,
                "first_seen": pkt.timestamp,
                "last_seen": pkt.timestamp,
                "packet_refs": [],
            }
            sessions[key] = s
        s["packets"] += 1
        s["bytes"] += pkt.length
        s["last_seen"] = max(s["last_seen"], pkt.timestamp)
        s["packet_refs"].append(pkt.packet_reference)
        if pkt.metadata.get("tls.sni") and not s["sni"]:
            s["sni"] = pkt.metadata["tls.sni"]
        # prefer the first observed record version (initial ClientHello)
        if not s["version"] and pkt.metadata.get("tls.record_version"):
            s["version"] = pkt.metadata["tls.record_version"]

    results = sorted(sessions.values(), key=lambda s: s["first_seen"])
    return results


def protocol_statistics(parsed) -> dict[str, Any]:
    """Protocol-centric stats: 'what is this protocol doing?' summaries.

    Accepts a ParsedCapture or any object with a `.packets` iterable
    (e.g. a lightweight wrapper over persisted packets).
    """
    dns = extract_dns(parsed)
    http = extract_http(parsed)

    nxdomain = [t for t in dns if t["rcode"] == 3]
    unique_domains = {t["query_name"].rstrip(".") for t in dns if t["query_name"]}

    dns_stats = {
        "transactions": len(dns),
        "unique_domains": len(unique_domains),
        "nxdomain_count": len(nxdomain),
        "nxdomain_rate": round(len(nxdomain) / len(dns), 3) if dns else 0,
        "avg_latency": round(
            sum(t["latency"] for t in dns if t["latency"] is not None)
            / max(1, sum(1 for t in dns if t["latency"] is not None)),
            4,
        )
        if any(t["latency"] is not None for t in dns)
        else None,
        "top_domains": _top([t["query_name"].rstrip(".") for t in dns if t["query_name"]], 10),
        "nxdomain_domains": _top([t["query_name"].rstrip(".") for t in nxdomain], 10),
        "longest_queries": sorted(
            ({t["query_name"] for t in dns if t["query_name"]}),
            key=len,
            reverse=True,
        )[:10],
    }

    statuses = defaultdict(int)
    methods = defaultdict(int)
    hosts = defaultdict(int)
    user_agents = defaultdict(int)
    for t in http:
        if t["status_code"]:
            statuses[t["status_code"]] += 1
        if t["method"]:
            methods[t["method"]] += 1
        if t["host"]:
            hosts[t["host"]] += 1
        if t["user_agent"]:
            user_agents[t["user_agent"]] += 1

    http_stats = {
        "transactions": len(http),
        "status_codes": dict(statuses),
        "methods": dict(methods),
        "top_hosts": _top(list(hosts), 10, weight=list(hosts.values())),
        "user_agents": dict(user_agents),
        "total_request_bytes": sum(t["request_len"] for t in http),
        "total_response_bytes": sum(t["response_len"] for t in http),
    }

    return {"dns": dns_stats, "http": http_stats}


def _top(items: list, n: int, weight: list | None = None) -> list[dict]:
    from collections import Counter

    c = Counter(items)
    return [{"value": k, "count": v} for k, v in c.most_common(n)]
