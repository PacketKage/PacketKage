"""Read-time localization for persisted alerts/incidents (Module D i18n).

Design:
    - suspicion_engine writes English title/reason/detail/explanation AND stable
      message keys + interpolation params (title_key, explanation_key, and per-reason
      reason_key/detail_key/params).
    - At API read time, for `locale == "fr"` we re-render those fields from the
      catalog; a missing catalog key falls back to the stored English string.
    - For `locale == "en"` we return the persisted values untouched (byte-identical
      to pre-i18n output, so existing English-only assertions stay green).
"""

from __future__ import annotations

from app.i18n import translate
from app.schemas.api import AlertOut


def localize_alert(alert, locale: str) -> dict:
    """Produce the AlertOut payload dict, localized when locale != "en"."""
    payload = AlertOut.model_validate(alert).model_dump()
    if locale == "en":
        return payload

    # title
    key = getattr(alert, "title_key", None) or f"alert.{alert.rule_name}.title"
    rendered = translate(locale, key, **(getattr(alert, "title_params", None) or {}))
    if rendered:
        payload["title"] = rendered

    # explanation
    ekey = getattr(alert, "explanation_key", None) or f"alert.{alert.rule_name}.explanation"
    rendered = translate(locale, ekey, **(getattr(alert, "explanation_params", None) or {}))
    if rendered:
        payload["explanation"] = rendered

    # reasons — re-render each from its stored reason_key/detail_key
    localized_reasons = []
    for r in list(alert.reasons or []):
        out = {"reason": r.get("reason", ""), "detail": r.get("detail", ""), "weight": r.get("weight", 0)}
        rk = r.get("reason_key")
        if rk:
            rendered = translate(locale, rk)
            if rendered:
                out["reason"] = rendered
        dk = r.get("detail_key")
        if dk:
            rendered = translate(locale, dk, **(r.get("params") or {}))
            if rendered:
                out["detail"] = rendered
        localized_reasons.append(out)
    payload["reasons"] = localized_reasons
    return payload


def localize_alert_dict(alert: dict, locale: str) -> dict:
    """Localize a pre-built alert dict (unit tests / non-ORM callers).

    Accepts either a dict (from suspicion_engine run) or an ORM model; when given
    a dict the returned payload is the same dict mutated in place.
    """
    if locale == "en":
        return alert
    localized = dict(alert)
    key = localized.get("title_key") or f"alert.{localized.get('rule_name', '')}.title"
    rendered = translate(locale, key, **(localized.get("title_params") or {}))
    if rendered:
        localized["title"] = rendered
    ekey = localized.get("explanation_key") or f"alert.{localized.get('rule_name', '')}.explanation"
    rendered = translate(locale, ekey, **(localized.get("explanation_params") or {}))
    if rendered:
        localized["explanation"] = rendered
    reasons = []
    for r in list(localized.get("reasons") or []):
        out = {"reason": r.get("reason", ""), "detail": r.get("detail", ""), "weight": r.get("weight", 0)}
        rk = r.get("reason_key")
        if rk:
            rendered = translate(locale, rk)
            if rendered:
                out["reason"] = rendered
        dk = r.get("detail_key")
        if dk:
            rendered = translate(locale, dk, **(r.get("params") or {}))
            if rendered:
                out["detail"] = rendered
        reasons.append(out)
    localized["reasons"] = reasons
    return localized


def localize_incident(incident: dict, locale: str) -> dict:
    """Localize an incident dict (title/story) for non-en locales."""
    if locale == "en":
        return incident
    out = dict(incident)
    key = out.get("title_key") or "incident.title"
    rendered = translate(locale, key, **(out.get("title_params") or {}))
    if rendered:
        out["title"] = rendered
    skey = out.get("story_key") or "incident.story"
    rendered = translate(locale, skey, **(out.get("story_params") or {}))
    if rendered:
        out["story"] = rendered
    return out