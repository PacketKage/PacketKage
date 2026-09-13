"""Parser abstraction layer.

PCAP / Live Capture
        ↓
    PacketParser (this ABC)
        ↓
  ScapyParser | TSharkParser | <future parsers>
        ↓
PacketKage normalized model (ParsedCapture / NormalizedPacket)

Parser-specific objects (Scapy packets, TShark JSON) NEVER leave this layer.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from app.core.models import ParsedCapture


class ParserError(Exception):
    pass


class PacketParser(ABC):
    """Abstract base for all packet parsers."""

    name: str = "abstract"

    @abstractmethod
    def available(self) -> bool:
        """Return True if this parser can run in the current environment."""

    @abstractmethod
    def parse_file(self, path: str, progress_cb=None) -> ParsedCapture:
        """Parse a PCAP/PCAPNG file into the normalized model.

        progress_cb(current, total, stage) may be called periodically.
        """

    # Future: parse_live(interface, ...) for live capture support.


class ParserRegistry:
    """Registry enabling pluggable parsers without redesigning the app."""

    def __init__(self) -> None:
        self._parsers: dict[str, PacketParser] = {}

    def register(self, parser: PacketParser) -> None:
        self._parsers[parser.name] = parser

    def get(self, name: str) -> PacketParser | None:
        return self._parsers.get(name)

    def available(self) -> dict[str, bool]:
        return {name: p.available() for name, p in self._parsers.items()}

    def default(self) -> PacketParser:
        """Scapy is the guaranteed default; fall back to any available parser."""
        scapy = self._parsers.get("scapy")
        if scapy and scapy.available():
            return scapy
        for parser in self._parsers.values():
            if parser.available():
                return parser
        raise ParserError("No available packet parser (install scapy)")


# Global registry instance
registry = ParserRegistry()


def resolve_parser(requested: str | None) -> PacketParser:
    """Resolve a parser by name, 'auto', or fall back to default."""
    if requested in (None, "", "auto"):
        return registry.default()
    parser = registry.get(requested)
    if parser is None:
        raise ParserError(f"Unknown parser: {requested!r}")
    if not parser.available():
        raise ParserError(
            f"Parser {requested!r} is not available on this system (is tshark installed?)"
        )
    return parser
