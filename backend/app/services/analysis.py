"""Analysis pipeline (Step 1: parse → normalize → persist summary).

Future steps will extend this into:
  parse → flows → protocol extraction → host profiling → behavior → suspicion.
"""
from __future__ import annotations

from collections import Counter
from typing import Callable

from sqlalchemy.orm import Session

from app.core.models import ParsedCapture
from app.db.orm import AnalysisJobModel, CaptureModel
from app.db.orm import utcnow as _utcnow
from app.parsers import resolve_parser
from app.repositories import (
    AlertRepository,
    CaptureRepository,
    DNSRepository,
    FlowRepository,
    HostRepository,
    HTTPRepository,
    JobRepository,
    PacketRepository,
    TimelineRepository,
    TLSRepository,
)
from app.services.flow_builder import FlowBuilder
from app.services.host_profiler import HostProfiler
from app.services.protocol_extractor import extract_dns, extract_http, extract_tls
from app.services.suspicion_engine import SuspicionEngine, correlate_alerts
from app.services.timeline_graph import build_timeline

ProgressCallback = Callable[[int, int, str], None]


def _flow_summary(flow_dicts: list[dict]) -> dict:
    by_transport: Counter = Counter()
    for f in flow_dicts:
        by_transport[f["transport_protocol"]] += 1
    states = Counter(f["tcp_state"] or "-" for f in flow_dicts if f["transport_protocol"] == "TCP")
    return {
        "flow_count": len(flow_dicts),
        "tcp_flows": by_transport.get("TCP", 0),
        "udp_flows": by_transport.get("UDP", 0),
        "failed_flows": sum(1 for f in flow_dicts if f["failed"]),
        "reset_flows": sum(1 for f in flow_dicts if f["resets"] > 0),
        "retransmitting_flows": sum(1 for f in flow_dicts if f["retransmissions"] > 0),
        "tcp_states": dict(states),
        "direction_counts": dict(Counter(f["direction"] for f in flow_dicts)),
    }


class AnalysisService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.captures = CaptureRepository(db)
        self.jobs = JobRepository(db)
        self.flows = FlowRepository(db)
        self.hosts = HostRepository(db)
        self.dns = DNSRepository(db)
        self.http = HTTPRepository(db)
        self.tls = TLSRepository(db)
        self.alerts = AlertRepository(db)
        self.timeline = TimelineRepository(db)
        self.packets = PacketRepository(db)

    def run_full_analysis(
        self,
        capture: CaptureModel,
        job: AnalysisJobModel,
        parser_name: str | None = None,
        file_path: str | None = None,
    ) -> None:
        """Run the full Step-1 pipeline. Updates job + capture rows as it progresses."""
        job = self.jobs.update(job, status="running", stage="parsing", started_at=_utcnow())
        capture = self.captures.update(capture, status="analyzing", analysis_progress=1, error=None)
        try:
            parser = resolve_parser(parser_name)

            def progress_cb(current: int, total: int, stage: str) -> None:
                pct = int(current / total * 90) if total else 0  # parsing = up to 90%
                self.jobs.update(job, progress=pct, stage=f"{stage} ({current}/{total or '?'})")
                self.captures.update(capture, analysis_progress=min(99, max(1, pct)))

            parsed = parser.parse_file(file_path or capture.filename, progress_cb)

            # ---- Packet store (evidence drill-down without re-parsing) ----
            self.jobs.update(job, stage="persisting_packets", progress=91)
            self.packets.delete_for_capture(capture.id)
            self.packets.create_many(capture.id, parsed)

            # ---- Flow reconstruction (Step 2) ----
            self.jobs.update(job, stage="flow_reconstruction", progress=92)
            self.captures.update(capture, analysis_progress=95)
            flow_dicts = FlowBuilder().build_from(parsed)

            # Persist flows FIRST so suspicion engine can reference real flow ids.
            # create_many builds one model per dict, in order — map the DICT
            # objects (what rules/timeline hold) to their persisted model ids.
            # (A previous id(fm)-keyed map never matched: rules look up id() of
            # the flow dicts, not the models, so every alert fell back to
            # "flowidx-N" placeholders and evidence deep links were dead.)
            self.flows.delete_for_capture(capture.id)
            flow_models = self.flows.create_many(capture.id, flow_dicts)
            id_by_flow: dict[int, str] = {
                id(fd): fm.id for fd, fm in zip(flow_dicts, flow_models, strict=True)
            }

            # ---- Protocol extraction + host profiling (Step 3) ----
            self.jobs.update(job, stage="protocol_extraction", progress=96)
            dns_txns = extract_dns(parsed)
            http_txns = extract_http(parsed)
            tls_sessions = extract_tls(parsed, flow_dicts)
            host_dicts = HostProfiler().build_profiles(parsed, flow_dicts)

            # ---- Suspicion engine (Step 4) — flows already have DB ids ----
            self.jobs.update(job, stage="behavioral_analysis", progress=98)
            alert_dicts = SuspicionEngine().run(
                parsed, flow_dicts, dns_txns, id_by_flow, http_txns=http_txns
            )
            SuspicionEngine.augment_hosts(host_dicts, alert_dicts)

            # Persist alerts BEFORE timeline so events reference real alert ids
            self.alerts.delete_for_capture(capture.id)
            if alert_dicts:
                alert_models = self.alerts.create_many(capture.id, alert_dicts)
                alert_id_map = {id(a): m.id for a, m in zip(alert_dicts, alert_models, strict=False)}
            else:
                alert_id_map = {}

            # ---- Timeline (Step 5) ----
            self.jobs.update(job, stage="timeline_construction", progress=99)
            event_dicts = build_timeline(
                parsed, flow_dicts, dns_txns, http_txns, tls_sessions,
                alert_dicts, id_by_flow, alert_id_map,
            )

            self._persist_results(
                capture, parsed, parser.name, None,  # flows persisted above
                dns_txns=dns_txns, http_txns=http_txns, tls_sessions=tls_sessions,
                host_dicts=host_dicts, alert_dicts=alert_dicts,
                flow_dicts_for_summary=flow_dicts, event_dicts=event_dicts,
                alerts_already_persisted=True, alert_id_map=alert_id_map,
            )

            self.jobs.update(
                job,
                status="completed",
                progress=100,
                stage="completed",
                finished_at=_utcnow(),
                result={
                    "packets": len(parsed.packets),
                    "parser": parser.name,
                    "flows": len(flow_dicts),
                    "hosts": len(host_dicts),
                    "dns_transactions": len(dns_txns),
                    "http_transactions": len(http_txns),
                    "tls_sessions": len(tls_sessions),
                    "alerts": len(alert_dicts),
                    "timeline_events": len(event_dicts),
                    "protocols": dict(Counter(p.protocol or "unknown" for p in parsed.packets).most_common(10)),
                },
            )
            self.captures.update(
                capture,
                status="completed",
                analysis_progress=100,
                completed_at=_utcnow(),
                parser_used=parser.name,
            )
        except Exception as exc:
            self.jobs.update(
                job, status="failed", stage="failed", message=str(exc), finished_at=_utcnow()
            )
            self.captures.update(capture, status="failed", error=str(exc))
            raise

    def _persist_results(
        self,
        capture: CaptureModel,
        parsed: ParsedCapture,
        parser_name: str,
        flow_dicts: list[dict] | None = None,
        dns_txns: list[dict] | None = None,
        http_txns: list[dict] | None = None,
        tls_sessions: list[dict] | None = None,
        host_dicts: list[dict] | None = None,
        alert_dicts: list[dict] | None = None,
        flow_dicts_for_summary: list[dict] | None = None,
        event_dicts: list[dict] | None = None,
        alerts_already_persisted: bool = False,
        alert_id_map: dict[int, str] | None = None,
    ) -> None:
        packets = parsed.packets
        timestamps = [p.timestamp for p in packets]
        protocol_counts = Counter(p.protocol or "unknown" for p in packets)
        transport_counts = Counter(p.transport or "other" for p in packets if p.transport)
        src_ips = Counter(p.source_ip for p in packets if p.source_ip)

        # ---- Persist flows (Step 2) — flows may already be persisted by caller ----
        if flow_dicts is not None:
            self.flows.delete_for_capture(capture.id)
            self.flows.create_many(capture.id, flow_dicts)
        if flow_dicts_for_summary is not None:
            flow_dicts = flow_dicts_for_summary  # for the summary block below

        # ---- Persist hosts + protocol transactions (Step 3) ----
        if host_dicts is not None:
            self.hosts.delete_for_capture(capture.id)
            self.hosts.create_many(capture.id, host_dicts)
        if dns_txns is not None:
            self.dns.delete_for_capture(capture.id)
            if dns_txns:
                self.dns.create_many(capture.id, dns_txns)
        if http_txns is not None:
            self.http.delete_for_capture(capture.id)
            if http_txns:
                self.http.create_many(capture.id, http_txns)
        if tls_sessions is not None:
            self.tls.delete_for_capture(capture.id)
            if tls_sessions:
                self.tls.create_many(capture.id, tls_sessions)

        # ---- Persist alerts (Step 4) — caller may have already persisted them ----
        if alert_dicts is not None and not alerts_already_persisted:
            self.alerts.delete_for_capture(capture.id)
            if alert_dicts:
                self.alerts.create_many(capture.id, alert_dicts)

        # ---- Persist timeline events (Step 5) ----
        if event_dicts is not None:
            self.timeline.delete_for_capture(capture.id)
            if event_dicts:
                self.timeline.create_many(capture.id, event_dicts)

        summary = {
            "protocol_counts": dict(protocol_counts.most_common()),
            "transport_counts": dict(transport_counts.most_common()),
            "unique_source_ips": len(src_ips),
            "unique_destination_ips": len(
                {p.destination_ip for p in packets if p.destination_ip}
            ),
            "top_talkers": [
                {"ip": ip, "packets": count}
                for ip, count in src_ips.most_common(10)
            ],
            "warnings": parsed.warnings[:20],
        }
        if flow_dicts is not None:
            summary["flow_summary"] = _flow_summary(flow_dicts)
            summary["top_flows_by_bytes"] = sorted(
                (
                    {
                        "source_ip": f["source_ip"],
                        "destination_ip": f["destination_ip"],
                        "destination_port": f["destination_port"],
                        "transport_protocol": f["transport_protocol"],
                        "bytes": f["bytes"],
                        "packets": f["packets"],
                    }
                    for f in flow_dicts
                ),
                key=lambda f: f["bytes"],
                reverse=True,
            )[:10]
        if host_dicts is not None:
            summary["host_count"] = len(host_dicts)
            summary["internal_host_count"] = sum(1 for h in host_dicts if h["is_internal"])
        if dns_txns is not None:
            summary["dns_summary"] = {
                "transactions": len(dns_txns),
                "unique_domains": len({t["query_name"].rstrip(".") for t in dns_txns if t["query_name"]}),
                "nxdomain_count": sum(1 for t in dns_txns if t["rcode"] == 3),
            }
        if http_txns is not None:
            summary["http_summary"] = {"transactions": len(http_txns)}
        if tls_sessions is not None:
            summary["tls_summary"] = {
                "sessions": len(tls_sessions),
                "unique_sni": len({s["sni"] for s in tls_sessions if s["sni"]}),
            }
        if alert_dicts is not None:
            summary["alert_summary"] = {
                "total": len(alert_dicts),
                "by_severity": {
                    sev: sum(1 for a in alert_dicts if a["severity"] == sev)
                    for sev in ("critical", "high", "medium", "low", "info")
                },
                "by_rule": dict(Counter(a["rule_name"] for a in alert_dicts)),
                "max_score": max((a["score"] for a in alert_dicts), default=0),
            }
            # correlated incidents (Phase 2)
            persisted_alerts = [
                {**a, "id": alert_id_map.get(id(a))} if alert_id_map.get(id(a)) else a
                for a in alert_dicts
            ] if alert_id_map else alert_dicts
            summary["incidents"] = correlate_alerts(persisted_alerts)[:20]
        if event_dicts is not None:
            summary["timeline_summary"] = {
                "total_events": len(event_dicts),
                "by_type": dict(Counter(e["event_type"] for e in event_dicts)),
            }

        self.captures.update(
            capture,
            packet_count=len(packets),
            analyzed_packet_count=len(packets),
            first_packet_ts=min(timestamps) if timestamps else None,
            last_packet_ts=max(timestamps) if timestamps else None,
            start_time=min(timestamps) if timestamps else None,
            end_time=max(timestamps) if timestamps else None,
            link_type=parsed.link_type,
            parser_used=parser_name,
            summary=summary,
        )
