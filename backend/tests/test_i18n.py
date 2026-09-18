"""i18n tests: catalog rendering, locale resolution, and API-level French output.

Covers the backend i18n contract:
    - translate() renders {param} placeholders and returns None for missing keys.
    - resolve_locale() honors ?lang= before Accept-Language, and fr* header tags.
    - The alerts/report/case endpoints render French when asked, while the
      default (English) path stays byte-identical to pre-i18n output.
"""

from __future__ import annotations

from tests.test_step1 import _analyze_and_wait, _upload


# ---------------- translate() catalog rendering ----------------


def test_translate_render_french_with_params():
    from app.i18n import translate

    text = translate("fr", "alert.port_scan.title", src="10.0.0.5", dst="10.0.0.9", n_ports=44)
    assert text == "Scan de ports : 10.0.0.5 → 10.0.0.9 (44 ports)"


def test_translate_render_english():
    from app.i18n import translate

    text = translate("en", "report.heading")
    assert text == "Network Investigation Report"


def test_translate_missing_key_returns_none():
    from app.i18n import translate

    assert translate("fr", "alert.nonexistent.title") is None
    assert translate("en", "report.does_not_exist") is None


def test_translate_unsupported_locale_falls_back_to_english():
    from app.i18n import translate

    assert translate("de", "report.heading") == "Network Investigation Report"


def test_translate_missing_param_keeps_placeholder():
    from app.i18n import translate

    # The catalog always supplies the param, so a missing param renders the
    # literal {src} rather than crashing.
    text = translate("fr", "alert.port_scan.reason.distinct_ports.detail", n_ports=5)
    assert "{dst}" in text


def test_catalogs_have_identical_keys():
    """en.json and fr.json must stay in key parity (no missing translations)."""
    import json

    from pathlib import Path

    root = Path(__file__).resolve().parent.parent / "app" / "i18n"
    en = json.loads((root / "en.json").read_text())
    fr = json.loads((root / "fr.json").read_text())
    assert set(fr) == set(en)


# ---------------- resolve_locale / get_locale ----------------


def test_resolve_locale_lang_param_wins():
    from app.i18n import resolve_locale

    assert resolve_locale("fr", "en-US,en;q=0.9") == "fr"
    assert resolve_locale("en", "fr-FR") == "en"
    assert resolve_locale("FR", "de-DE") == "fr"  # case-insensitive


def test_resolve_locale_accept_language_fr_prefix():
    from app.i18n import resolve_locale

    assert resolve_locale(None, "fr-FR,fr;q=0.9") == "fr"
    assert resolve_locale(None, "fr") == "fr"
    assert resolve_locale(None, "en-US,en;q=0.9") == "en"
    assert resolve_locale(None, None) == "en"
    assert resolve_locale(None, "") == "en"


# ---------------- API-level French rendering ----------------


def test_alerts_french_via_accept_language(client):
    capture_id, _ = _analyze_and_alerts(client, "port_scan.pcap")

    en = client.get(f"/api/alerts?capture_id={capture_id}&limit=500")
    fr = client.get(
        f"/api/alerts?capture_id={capture_id}&limit=500",
        headers={"Accept-Language": "fr-FR"},
    )
    assert en.status_code == 200 and fr.status_code == 200

    en_scan = _first(en.json()["items"], "port_scan")
    fr_scan = _first(fr.json()["items"], "port_scan")
    assert en_scan is not None and fr_scan is not None

    # stored English payload passes through untouched
    assert en_scan["title"].startswith("Port scan:")
    # French rendering kicks in via the header
    assert fr_scan["title"].startswith("Scan de ports :")
    assert fr_scan["explanation"] == en_scan["explanation"].replace(
        "attempted connections", "a tenté de se connecter", 1
    ) or "cohérent avec un scan SYN de ports" in fr_scan["explanation"]

    # per-reason headings/details are localized too
    assert all(r["reason"] for r in fr_scan["reasons"])
    assert fr_scan["reasons"][0]["reason"] != en_scan["reasons"][0]["reason"] or len(fr_scan["reasons"]) == 0


def test_alerts_english_when_no_lang_header(client):
    capture_id, alerts = _analyze_and_alerts(client, "c2_beacon.pcap")
    beacons = [a for a in alerts if a["rule_name"] == "beaconing"]
    assert beacons and beacons[0]["title"].startswith("Beaconing")
    assert any("periodic" in r["reason"].lower() for r in beacons[0]["reasons"])


def test_report_french_via_lang_param(client):
    capture_id, _ = _analyze_and_alerts(client, "port_scan.pcap")

    en_report = client.get(f"/api/captures/{capture_id}/report")
    fr_report = client.get(f"/api/captures/{capture_id}/report", params={"lang": "fr"})
    assert en_report.status_code == 200 and fr_report.status_code == 200

    html_en, html_fr = en_report.text, fr_report.text
    assert "Network Investigation Report" in html_en
    assert "Rapport d&#x27;investigation réseau" in html_fr
    assert "Rapport PacketKage — port_scan" in html_fr or "Rapport PacketKage — " in html_fr
    assert "Scan de ports" in html_fr


def test_incident_french_in_case_detail(client):
    # Build a capture + analysis that correlates into incidents, then attach it
    # to a manually-created case (cases are analyst-created, not auto-generated).
    capture_id = _upload(client, "c2_beacon.pcap")
    job = _analyze_and_wait(client, capture_id)
    assert job["status"] == "completed", job

    created = client.post("/api/cases", json={"name": "Beacon", "description": "correlation test"})
    assert created.status_code == 201, created.text
    case_id = created.json()["id"]

    added = client.post(f"/api/cases/{case_id}/captures", json={"capture_id": capture_id})
    assert added.status_code == 200, added.text
    assert added.json()["stats"]["incidents"], "expected correlated incidents on the case"

    en = client.get(f"/api/cases/{case_id}")
    fr = client.get(f"/api/cases/{case_id}", headers={"Accept-Language": "fr"})
    assert en.status_code == 200 and fr.status_code == 200

    en_inc = en.json()["stats"]["incidents"][0]
    fr_inc = fr.json()["stats"]["incidents"][0]
    assert "Incident on" in en_inc["title"]
    assert fr_inc["title"].startswith("Incident sur")


# ---------------- localize_alert_dict unit path ----------------


def test_localize_dict_falls_back_to_stored_english():
    from app.i18n.localize import localize_alert_dict

    alert = {
        "rule_name": "port_scan",
        "title": "Port scan: 10.0.0.5 → 10.0.0.9 (2 ports)",
        "title_key": "alert.port_scan.title",
        "title_params": {"src": "10.0.0.5", "dst": "10.0.0.9", "n_ports": 2},
        "explanation": "EN explanation",
        "explanation_key": "does.not.exist",  # missing key → English fallback
        "reasons": [
            {
                "reason": "EN reason",
                "detail": "EN detail",
                "reason_key": "does.not.exist.reason",
                "detail_key": "does.not.exist.detail",
                "params": {},
                "weight": 10,
            },
            {
                "reason": "Distinct ports probed",
                "detail": "5 unique ports on 10.0.0.9",
                "reason_key": "alert.port_scan.reason.distinct_ports",
                "detail_key": "alert.port_scan.reason.distinct_ports.detail",
                "params": {"n_ports": 5, "dst": "10.0.0.9"},
                "weight": 20,
            },
        ],
    }
    out = localize_alert_dict(alert, "fr")
    assert out["title"] == "Scan de ports : 10.0.0.5 → 10.0.0.9 (2 ports)"
    assert out["explanation"] == "EN explanation"  # key missing → fallback
    assert out["reasons"][0]["reason"] == "EN reason"
    assert out["reasons"][1]["reason"] == "Ports distincts sondés"
    assert out["reasons"][1]["detail"] == "5 ports uniques sur 10.0.0.9"

    # en locale returns the dict untouched
    assert localize_alert_dict(alert, "en") is alert


# ---------------- helpers ----------------


def _analyze_and_alerts(client, pcap: str) -> tuple[str, list]:
    capture_id = _upload(client, pcap)
    job = _analyze_and_wait(client, capture_id)
    assert job["status"] == "completed", job
    resp = client.get(f"/api/alerts?capture_id={capture_id}&limit=500")
    assert resp.status_code == 200
    return capture_id, resp.json()["items"]


def _first(alerts: list, rule_name: str) -> dict | None:
    for a in alerts:
        if a["rule_name"] == rule_name:
            return a
    return None