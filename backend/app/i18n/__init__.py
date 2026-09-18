"""Backend i18n — locale resolution + dictionary-driven string rendering.

The alert content (titles, reason headings, details, explanations) is written to
the database in English at analysis time (so existing captures stay valid). Each
alert ALSO carries stable message keys + params so the serializer can render a
French (or other locale) version at read time, falling back to the stored
English when a key is missing (older captures, unknown rule, etc).

`en.json`/`fr.json` hold the message catalogs. Keys use the same dotted
`rule.site.message` scheme as the frontend dictionaries.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache

from fastapi import Request

_DEFAULT_LOCALE = "en"
_SUPPORTED = {"en", "fr"}
_PARAM_RE = re.compile(r"\{(\w+)\}")


@lru_cache(maxsize=8)
def _catalog(locale: str) -> dict:
    path = os.path.join(os.path.dirname(__file__), f"{locale}.json")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _lookup(catalog: dict, key: str):
    # Catalogs use flat dotted keys ("alert.port_scan.title") — a plain dict get.
    value = catalog.get(key)
    if value is None:
        # Defensive: also support nested dicts if a catalog is ever restructured.
        node = catalog
        for part in key.split("."):
            if not isinstance(node, dict):
                return None
            node = node.get(part)
            if node is None:
                return None
        value = node
    return value


def translate(locale: str, key: str, **params) -> str | None:
    """Render `key` for `locale`, substituting `{name}` placeholders.

    Returns None when the key is missing so callers can fall back to their
    stored English payload instead of leaking a raw key.
    """
    if locale not in _SUPPORTED:
        locale = _DEFAULT_LOCALE
    template = _lookup(_catalog(locale), key)
    if template is None or not isinstance(template, str):
        return None

    def _sub(match: re.Match) -> str:
        name = match.group(1)
        return str(params.get(name, f"{{{name}}}"))

    return _PARAM_RE.sub(_sub, template)


def resolve_locale(lang: str | None, accept_language: str | None) -> str:
    """Resolve "fr" | "en" from an explicit ?lang= query then the header."""
    if lang and lang.strip().lower() in _SUPPORTED:
        return lang.strip().lower()
    header = (accept_language or "").strip()
    if header.lower().startswith("fr"):
        return "fr"
    return _DEFAULT_LOCALE


async def get_locale(request: Request) -> str:
    """FastAPI dependency: resolve the request locale (?lang= then Accept-Language)."""
    lang = request.query_params.get("lang")
    return resolve_locale(lang, request.headers.get("accept-language"))


def is_supported(locale: str) -> bool:
    return locale in _SUPPORTED
