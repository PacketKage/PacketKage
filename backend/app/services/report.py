"""Investigation report generator — self-contained HTML, printable to PDF.

Philosophy: the report must stand alone. A reader with no access to
PacketKage should understand what happened, why we believe it, and where
the evidence is. All styles inline; zero external assets or dependencies.
"""

from __future__ import annotations

import html
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.db.orm import CaptureModel
from app.i18n import translate
from app.i18n.localize import localize_alert, localize_incident
from app.repositories import (
    AlertRepository,
    FlowRepository,
    HostRepository,
    PacketRepository,
    TimelineRepository,
)

SEV_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#0284c7",
    "info": "#64748b",
}

CSS = """
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; color: #0f172a;
         margin: 0; background: #f8fafc; line-height: 1.5; }
  .page { max-width: 900px; margin: 0 auto; padding: 40px 48px 64px; background: #fff; }
  header { border-bottom: 3px solid #0f172a; padding-bottom: 16px; margin-bottom: 24px; }
  h1 { font-size: 26px; margin: 0 0 4px; }
  h2 { font-size: 18px; margin: 32px 0 12px; padding-top: 8px; border-top: 1px solid #e2e8f0; }
  .meta { color: #64748b; font-size: 13px; }
  .meta div { margin: 2px 0; }
  .cards { display: flex; gap: 12px; flex-wrap: wrap; margin: 16px 0; }
  .card { flex: 1 1 120px; border: 1px solid #e2e8f0; border-radius: 8px; padding: 10px 14px; }
  .card .n { font-size: 22px; font-weight: 700; }
  .card .l { font-size: 11px; text-transform: uppercase; letter-spacing: .5px; color: #64748b; }
  .sev { display: inline-block; font-size: 11px; font-weight: 700; color: #fff;
         border-radius: 4px; padding: 1px 8px; margin-right: 6px; }
  .alert { border: 1px solid #e2e8f0; border-left: 4px solid #64748b; border-radius: 8px;
           padding: 14px 18px; margin: 12px 0; page-break-inside: avoid; }
  .alert .title { font-weight: 600; font-size: 15px; }
  .alert .score { float: right; font-weight: 700; color: #475569; }
  .reasons { margin: 8px 0; padding-left: 0; list-style: none; }
  .reasons li { margin: 3px 0; font-size: 13px; }
  .reasons li::before { content: '\\2713  '; color: #16a34a; font-weight: 700; }
  .explanation { font-size: 13px; background: #f1f5f9; border-radius: 6px; padding: 8px 12px; }
  .incident { border: 1px solid #fca5a5; background: #fef2f2; border-radius: 8px;
              padding: 12px 16px; margin: 12px 0; page-break-inside: avoid; }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; margin: 10px 0; }
  th { text-align: left; font-size: 11px; text-transform: uppercase; color: #64748b;
       border-bottom: 1px solid #cbd5e1; padding: 6px 8px; }
  td { border-bottom: 1px solid #f1f5f9; padding: 5px 8px; font-family: ui-monospace, monospace; }
  footer { margin-top: 48px; border-top: 1px solid #e2e8f0; padding-top: 12px;
           color: #94a3b8; font-size: 11px; }
  @media print { .page { padding: 0; } }
"""


def _esc(value) -> str:
    return html.escape(str(value if value is not None else "—"))


def _sev_span(severity: str) -> str:
    color = SEV_COLORS.get(severity, "#64748b")
    return f'<span class="sev" style="background:{color}">{_esc(severity.upper())}</span>'


def _card(label: str, value) -> str:
    return f'<div class="card"><div class="n">{_esc(value)}</div><div class="l">{_esc(label)}</div></div>'


def _label(locale: str, key: str, fallback: str) -> str:
    """Localized chrome label; falls back to the stored-identical English."""
    if locale == "en":
        return fallback
    return translate(locale, key) or fallback


def _localized_alerts(db: Session, capture_id: str, locale: str) -> list[dict]:
    return [localize_alert(a, locale) for a in AlertRepository(db).list_for_capture(capture_id)]


def build_report(db: Session, capture: CaptureModel, locale: str = "en") -> str:
    """Render a full investigation report as one self-contained HTML string."""
    summary = capture.summary or {}
    flow_summary = summary.get("flow_summary", {})
    alert_summary = summary.get("alert_summary", {})
    incidents = [localize_incident(inc, locale) for inc in summary.get("incidents", [])]

    alerts = _localized_alerts(db, capture.id, locale)
    flows = FlowRepository(db).list_for_capture(capture.id)
    hosts = HostRepository(db).list_for_capture(capture.id)
    events = TimelineRepository(db).list_for_capture(capture.id)
    packet_count = PacketRepository(db).count_for_capture(capture.id) or capture.packet_count

    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    duration = ((capture.last_packet_ts or 0) - (capture.first_packet_ts or 0)) or 0

    html_title = translate(locale, "report.html_title", filename=capture.filename) or (
        f"PacketKage Report — {capture.filename}"
    )
    heading = _label(locale, "report.heading", "Network Investigation Report")
    cap_l = _label(locale, "report.capture", "Capture")
    src_l = _label(locale, "report.source", "Source")
    parser_l = _label(locale, "report.parser", "Parser")
    win_l = _label(locale, "report.traffic_window", "Traffic window")
    gen_l = _label(locale, "report.generated", "Generated")
    by_l = _label(locale, "report.generated_by", "by PacketKage")
    overview_l = _label(locale, "report.overview", "Overview")
    packets_l = _label(locale, "report.packets", "Packets")
    flows_l = _label(locale, "report.flows", "Flows")
    hosts_l = _label(locale, "report.hosts", "Hosts")
    alerts_l = _label(locale, "report.alerts", "Alerts")
    incidents_l = _label(locale, "report.incidents_count", "Incidents")
    failed_l = _label(locale, "report.failed_flows", "Failed flows")
    corr_l = _label(locale, "report.correlated_incidents", "Correlated Incidents")
    incident_t_l = _label(locale, "report.incident_title", "Incident")
    maxscore_l = _label(locale, "report.max_score", "max score")
    alert_count_l = _label(locale, "report.alert_count", "alerts")
    alerts_section = _label(locale, "report.alerts_section", f"Alerts ({len(alerts)})")
    no_alerts_l = _label(
        locale, "report.no_alerts", "No alerts were raised for this capture — traffic looks clean."
    )
    analyst_l = _label(locale, "report.analyst_note", "Analyst note:")
    top_flows_l = _label(locale, "report.top_flows", "Top Flows by Volume")
    col_src_l = _label(locale, "report.col_source", "Source")
    col_dst_l = _label(locale, "report.col_destination", "Destination")
    col_proto_l = _label(locale, "report.col_proto", "Proto")
    col_pkts_l = _label(locale, "report.col_packets", "Packets")
    col_bytes_l = _label(locale, "report.col_bytes", "Bytes")
    col_state_l = _label(locale, "report.col_state", "State")
    timeline_l = _label(locale, "report.timeline_highlights", "Timeline Highlights")
    col_time_l = _label(locale, "report.col_time", "Time")
    col_event_l = _label(locale, "report.col_event", "Event")
    col_type_l = _label(locale, "report.col_type", "Type")
    col_sev_l = _label(locale, "report.col_severity", "Severity")
    no_events_l = _label(
        locale, "report.no_events", "No notable events (resets, failures, alerts) in this capture."
    )
    footer_l = _label(
        locale,
        "report.footer",
        "Report generated by PacketKage from packet evidence — every alert traces to "
        "observable network facts. Deterministic, explainable analysis; no ML.",
    )

    # ---------- header ----------
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        f"<title>{_esc(html_title)}</title>",
        f"<style>{CSS}</style></head><body><div class='page'>",
        f"<header><h1>{_esc(heading)}</h1>",
        f"<div class='meta'><div><b>{_esc(cap_l)}:</b> {_esc(capture.filename)}</div>",
        f"<div><b>{_esc(src_l)}:</b> {_esc(capture.source)} · <b>{_esc(parser_l)}:</b> {_esc(capture.parser_used or '—')}</div>",
        f"<div><b>{_esc(win_l)}:</b> {_esc(round(duration, 1))}s of captured traffic · "
        f"<b>{_esc(gen_l)}:</b> {generated} {_esc(by_l)}</div></div></header>",
    ]

    # ---------- overview cards ----------
    parts.append(f"<h2>{_esc(overview_l)}</h2><div class='cards'>")
    parts.append(_card(packets_l, f"{packet_count:,}"))
    parts.append(_card(flows_l, f"{flow_summary.get('flow_count', len(flows)):,}"))
    parts.append(_card(hosts_l, f"{len(hosts):,}"))
    parts.append(_card(alerts_l, alert_summary.get("total", len(alerts))))
    parts.append(_card(incidents_l, len(incidents)))
    parts.append(_card(failed_l, flow_summary.get("failed_flows", 0)))
    parts.append("</div>")

    # ---------- incidents ----------
    if incidents:
        parts.append(f"<h2>{_esc(corr_l)}</h2>")
        for inc in incidents:
            parts.append(
                "<div class='incident'>"
                f"<div><b>{_esc(inc.get('title', incident_t_l))}</b> "
                f"<span class='meta'>{_esc(maxscore_l)} {_esc(inc.get('max_score', 0))} · "
                f"{_esc(inc.get('alert_count', 0))} {_esc(alert_count_l)}</span></div>"
                f"<div style='font-size:13px;margin-top:4px'>{_esc(inc.get('story', ''))}</div>"
                "</div>"
            )

    # ---------- alerts ----------
    parts.append(f"<h2>{_esc(alerts_section)}</h2>")
    if not alerts:
        parts.append(f"<p class='meta'>{_esc(no_alerts_l)}</p>")
    for a in alerts:
        reasons = "".join(
            f"<li><b>{_esc(r.get('reason', ''))}</b> — {_esc(r.get('detail', ''))}</li>"
            for r in (a.get("reasons") or [])
        )
        note_html = (
            f"<div class='explanation'><b>{_esc(analyst_l)}</b> {_esc(a.get('note'))}</div>"
            if a.get("note")
            else ""
        )
        tags_html = (
            " ".join(f"<span class='sev' style='background:#475569'>{_esc(t)}</span>" for t in a["tags"])
            if a.get("tags")
            else ""
        )
        parts.append(
            f"<div class='alert' style='border-left-color:{SEV_COLORS.get(a['severity'], '#64748b')}'>"
            f"<div class='score'>{a['score']}/100</div>"
            f"<div class='title'>{_sev_span(a['severity'])}{_esc(a['title'])} {tags_html}</div>"
            f"<ul class='reasons'>{reasons}</ul>"
            f"<div class='explanation'>{_esc(a.get('explanation') or '')}</div>"
            f"{note_html}</div>"
        )

    # ---------- top flows ----------
    parts.append(f"<h2>{_esc(top_flows_l)}</h2>")
    top_flows = sorted(flows, key=lambda f: f.bytes, reverse=True)[:15]
    if top_flows:
        parts.append(
            f"<table><tr><th>{_esc(col_src_l)}</th><th>{_esc(col_dst_l)}</th><th>{_esc(col_proto_l)}</th>"
            f"<th>{_esc(col_pkts_l)}</th><th>{_esc(col_bytes_l)}</th><th>{_esc(col_state_l)}</th></tr>"
        )
        for f in top_flows:
            state = f.tcp_state or "—"
            parts.append(
                f"<tr><td>{_esc(f.source_ip)}:{f.source_port}</td>"
                f"<td>{_esc(f.destination_ip)}:{f.destination_port}</td>"
                f"<td>{_esc(f.application_protocol or f.transport_protocol)}</td>"
                f"<td>{f.packets:,}</td><td>{f.bytes:,}</td><td>{_esc(state)}</td></tr>"
            )
        parts.append("</table>")

    # ---------- timeline highlights ----------
    highlight_types = {"alert", "tcp_reset", "flow_failed"}
    highlights = [e for e in events if e.event_type in highlight_types][:25]
    parts.append(f"<h2>{_esc(timeline_l)}</h2>")
    if highlights:
        parts.append(
            f"<table><tr><th>{_esc(col_time_l)}</th><th>{_esc(col_event_l)}</th>"
            f"<th>{_esc(col_type_l)}</th><th>{_esc(col_sev_l)}</th></tr>"
        )
        for e in highlights:
            ts = datetime.fromtimestamp(e.timestamp, tz=UTC).strftime("%H:%M:%S")
            parts.append(
                f"<tr><td>{_esc(ts)}</td><td>{_esc(e.label)}</td>"
                f"<td>{_esc(e.event_type)}</td><td>{_esc(e.severity or '—')}</td></tr>"
            )
        parts.append("</table>")
    else:
        parts.append(f"<p class='meta'>{_esc(no_events_l)}</p>")

    parts.append(f"<footer>{_esc(footer_l)}</footer>")
    parts.append("</div></body></html>")
    return "".join(parts)
