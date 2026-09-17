"""Timeline + Graph builders (Module C/E/F).

Timeline: chronological behavioral events derived from reconstructed artifacts —
NOT raw packets. Events answer "what happened" and each links to evidence
(flow/alert/packet) for drill-down.

Graph: Cytoscape-shaped elements (nodes/edges) describing network relationships:
hosts, domains, services; DNS / TCP / TLS / HTTP edges.
"""

from __future__ import annotations

from app.core.models import ParsedCapture
from app.services.flow_builder import is_private_ip


def build_timeline(
    parsed: ParsedCapture,
    flows: list[dict],
    dns_txns: list[dict],
    http_txns: list[dict],
    tls_sessions: list[dict],
    alert_dicts: list[dict],
    flow_id_map: dict | None = None,
    alert_id_map: dict | None = None,
) -> list[dict]:
    """Build chronological behavioral events from analysis artifacts."""
    events: list[dict] = []

    # DNS events (paired transactions emit query event + response event)
    for t in dns_txns:
        name = (t.get("query_name") or "").rstrip(".")
        events.append(
            {
                "event_type": "dns_query",
                "label": f"DNS query: {name}",
                "timestamp": t["timestamp"],
                "source_ip": t["client_ip"],
                "destination_ip": t["server_ip"],
                "protocol": "DNS",
                "domain": name,
                "detail": {"qtype": t.get("query_type"), "txid": t.get("transaction_id")},
                "packet_ref": t.get("packet_ref"),
            }
        )
        if t.get("is_response"):
            answers = ", ".join(t.get("response_ips") or [])
            answer_txt = answers if answers else ("NXDOMAIN" if t.get("rcode") == 3 else "no answer")
            events.append(
                {
                    "event_type": "dns_response",
                    "label": f"DNS response: {name} → {answer_txt}",
                    "timestamp": t["timestamp"] + (t.get("latency") or 0),
                    "source_ip": t["server_ip"],
                    "destination_ip": t["client_ip"],
                    "protocol": "DNS",
                    "domain": name,
                    "detail": {
                        "rcode": t.get("rcode"),
                        "answers": t.get("response_ips", []),
                        "latency": t.get("latency"),
                        "txid": t.get("transaction_id"),
                    },
                }
            )

    # Connection events (from flows) — TCP and UDP both, typed accordingly
    for f in flows:
        fid = (flow_id_map or {}).get(id(f), f.get("_alert_flow_id"))
        label_proto = f.get("application_protocol") or f["transport_protocol"]
        if f.get("failed"):
            events.append(
                {
                    "event_type": "flow_failed",
                    "label": f"Connection failed: {f['source_ip']} → {f['destination_ip']}:{f['destination_port']}",
                    "timestamp": f["first_seen"],
                    "source_ip": f["source_ip"],
                    "destination_ip": f["destination_ip"],
                    "destination_port": f["destination_port"],
                    "protocol": label_proto,
                    "severity": "medium",
                    "detail": {"reason": "no SYN-ACK", "transport": f["transport_protocol"]},
                    "related_flow_id": fid,
                }
            )
            continue

        if f["transport_protocol"] == "UDP":
            events.append(
                {
                    "event_type": "udp_session",
                    "label": f"UDP session: {f['source_ip']}:{f['source_port']} → {f['destination_ip']}:{f['destination_port']}",
                    "timestamp": f["first_seen"],
                    "source_ip": f["source_ip"],
                    "destination_ip": f["destination_ip"],
                    "destination_port": f["destination_port"],
                    "protocol": label_proto,
                    "detail": {
                        "bytes": f["bytes"],
                        "packets": f["packets"],
                        "duration": f["duration"],
                    },
                    "related_flow_id": fid,
                }
            )
            continue

        ev_type = "tcp_connect"
        label = (
            f"Connection: {f['source_ip']}:{f['source_port']} → {f['destination_ip']}:{f['destination_port']}"
        )
        severity = None
        if f.get("tcp_state") == "reset":
            ev_type = "tcp_reset"
            label = f"TCP reset: {f['source_ip']} ⇄ {f['destination_ip']}:{f['destination_port']}"
            severity = "medium"
        events.append(
            {
                "event_type": ev_type,
                "label": label,
                "timestamp": f["first_seen"],
                "source_ip": f["source_ip"],
                "destination_ip": f["destination_ip"],
                "destination_port": f["destination_port"],
                "protocol": label_proto,
                "severity": severity,
                "detail": {
                    "bytes": f["bytes"],
                    "packets": f["packets"],
                    "duration": f["duration"],
                    "tcp_state": f.get("tcp_state"),
                    "retransmissions": f.get("retransmissions", 0),
                },
                "related_flow_id": fid,
            }
        )
        if f.get("resets", 0) > 0 and f.get("tcp_state") != "reset":
            events.append(
                {
                    "event_type": "tcp_reset",
                    "label": f"TCP reset during: {f['source_ip']} ⇄ {f['destination_ip']}:{f['destination_port']}",
                    "timestamp": f["last_seen"],
                    "source_ip": f["destination_ip"],
                    "destination_ip": f["source_ip"],
                    "destination_port": f["destination_port"],
                    "protocol": label_proto,
                    "severity": "medium",
                    "detail": {"resets": f["resets"]},
                    "related_flow_id": fid,
                }
            )

    # HTTP events
    for t in http_txns:
        events.append(
            {
                "event_type": "http_request",
                "label": f"HTTP {t.get('method') or '?'} {(t.get('host') or '')}{(t.get('path') or '')} → {t.get('status_code') or '…'}",
                "timestamp": t["timestamp"],
                "source_ip": t["client_ip"],
                "destination_ip": t["server_ip"],
                "destination_port": t["server_port"],
                "protocol": "HTTP",
                "domain": t.get("host"),
                "severity": "high" if (t.get("status_code") or 0) >= 400 else None,
                "detail": {
                    "method": t.get("method"),
                    "host": t.get("host"),
                    "path": t.get("path"),
                    "status": t.get("status_code"),
                    "user_agent": t.get("user_agent"),
                },
                "packet_ref": t.get("packet_ref"),
            }
        )

    # TLS events
    for s in tls_sessions:
        events.append(
            {
                "event_type": "tls_handshake",
                "label": f"TLS session: {s['client_ip']} → {s['sni'] or s['server_ip']}",
                "timestamp": s["first_seen"],
                "source_ip": s["client_ip"],
                "destination_ip": s["server_ip"],
                "destination_port": s["server_port"],
                "protocol": "TLS",
                "domain": s.get("sni"),
                "detail": {"sni": s.get("sni"), "bytes": s["bytes"], "packets": s["packets"]},
            }
        )

    # Alert events
    for a in alert_dicts:
        events.append(
            {
                "event_type": "alert",
                "label": f"ALERT [{a['severity'].upper()}]: {a['title']}",
                "timestamp": a.get("timestamp") or (events[-1]["timestamp"] if events else 0),
                "source_ip": a.get("source_ip"),
                "destination_ip": a.get("destination_ip"),
                "destination_port": a.get("destination_port"),
                "protocol": None,
                "severity": a["severity"],
                "detail": {
                    "rule": a["rule_name"],
                    "score": a["score"],
                    "reasons": [r["reason"] for r in a["reasons"]],
                },
                "related_alert_id": (alert_id_map or {}).get(id(a), a.get("id")),
            }
        )

    events.sort(key=lambda e: e["timestamp"])
    return events


def build_graph(
    flows: list[dict],
    dns_txns: list[dict],
    tls_sessions: list[dict],
    host_dicts: list[dict],
    flow_id_map: dict | None = None,
) -> dict:
    """Build Cytoscape.js elements for the network relationship graph (Module C)."""
    nodes: dict[str, dict] = {}
    edges: dict[tuple, dict] = {}

    def add_node(node_id: str, ntype: str, label: str, **props) -> None:
        if node_id not in nodes:
            nodes[node_id] = {
                "data": {"id": node_id, "type": ntype, "label": label, **props},
            }

    def add_edge(src: str, dst: str, etype: str, **props) -> None:
        key = (src, dst, etype)
        e = edges.get(key)
        if e is None:
            e = {
                "data": {
                    "id": f"{src}->{dst}:{etype}",
                    "source": src,
                    "target": dst,
                    "type": etype,
                    "packets": 0,
                    "bytes": 0,
                    "count": 0,
                    **props,
                }
            }
            edges[key] = e
        e["data"]["count"] += 1

    # host nodes with profile data
    host_by_ip = {h["ip"]: h for h in host_dicts}
    for ip, h in host_by_ip.items():
        add_node(
            ip,
            "host",
            ip,
            role=h.get("role"),
            hostname=h.get("hostname"),
            internal=h.get("is_internal", False),
            bytes_sent=h.get("bytes_sent", 0),
            bytes_received=h.get("bytes_received", 0),
            alert_count=(h.get("behavior_summary") or {}).get("alert_count", 0),
        )

    # flow edges (host <-> host)
    for f in flows:
        add_node(f["source_ip"], "host", f["source_ip"], internal=is_private_ip(f["source_ip"]))
        add_node(
            f["destination_ip"], "host", f["destination_ip"], internal=is_private_ip(f["destination_ip"])
        )
        etype = f.get("application_protocol") or f["transport_protocol"]
        key = (f["source_ip"], f["destination_ip"], etype)
        e = edges.get(key)
        if e is None:
            e = {
                "data": {
                    "id": f"{f['source_ip']}->{f['destination_ip']}:{etype}",
                    "source": f["source_ip"],
                    "target": f["destination_ip"],
                    "type": etype,
                    "packets": 0,
                    "bytes": 0,
                    "count": 0,
                    "flow_ids": [],
                }
            }
            edges[key] = e
        e["data"]["packets"] += f["packets"]
        e["data"]["bytes"] += f["bytes"]
        e["data"]["count"] += 1
        fid = (flow_id_map or {}).get(id(f), f.get("_alert_flow_id"))
        if fid:
            e["data"]["flow_ids"].append(fid)

    # DNS edges: client -> domain -> server(ip)
    for t in dns_txns:
        name = (t.get("query_name") or "").rstrip(".")
        if not name:
            continue
        client, server = t["client_ip"], t["server_ip"]
        add_node(client, "host", client, internal=is_private_ip(client))
        add_node(name, "domain", name)
        add_node(server, "host", server, internal=is_private_ip(server))
        add_edge(client, name, "DNS")
        for ip in t.get("response_ips", []):
            add_node(ip, "host", ip, internal=is_private_ip(ip))
            add_edge(name, ip, "RESOLVES_TO")

    # TLS: client -> SNI domain -> server
    for s in tls_sessions:
        if s.get("sni"):
            add_node(s["sni"], "domain", s["sni"])
            add_edge(s["client_ip"], s["sni"], "TLS")
            add_edge(s["sni"], s["server_ip"], "RESOLVES_TO")

    # exposed services as port nodes
    for ip, h in host_by_ip.items():
        for svc in (h.get("services") or [])[:15]:  # cap to avoid clutter
            port_id = f"{ip}:{svc['port']}"
            add_node(
                port_id,
                "service",
                f"{svc['service']}/{svc['port']}",
                port=svc["port"],
                service=svc["service"],
                host=ip,
            )
            add_edge(ip, port_id, "EXPOSES")

    return {
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "host_count": sum(1 for n in nodes.values() if n["data"]["type"] == "host"),
            "domain_count": sum(1 for n in nodes.values() if n["data"]["type"] == "domain"),
            "service_count": sum(1 for n in nodes.values() if n["data"]["type"] == "service"),
        },
    }
