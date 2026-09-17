"""Parser package — registers all built-in parsers."""

from app.parsers.base import PacketParser, ParserError, ParserRegistry, registry, resolve_parser
from app.parsers.scapy_parser import ScapyParser
from app.parsers.tshark_parser import TSharkParser

__all__ = [
    "PacketParser",
    "ParserRegistry",
    "ParserError",
    "registry",
    "resolve_parser",
    "ScapyParser",
    "TSharkParser",
]


def register_default_parsers() -> None:
    if registry.get("scapy") is None:
        registry.register(ScapyParser())
    if registry.get("tshark") is None:
        registry.register(TSharkParser())
