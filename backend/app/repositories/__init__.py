"""Repository layer — isolates persistence from business logic."""

from __future__ import annotations

from sqlalchemy import delete, desc, func, select, update
from sqlalchemy.orm import Session

from app.core.database import new_id
from app.db.orm import (
    AlertModel,
    AnalysisJobModel,
    CaptureModel,
    CaseModel,
    DNSTransactionModel,
    FlowModel,
    GraphEdgeModel,
    HostModel,
    HTTPTransactionModel,
    PacketModel,
    TimelineEventModel,
    TLSSessionModel,
    utcnow,
)

# Columns the flows endpoint may sort by (mirrors the API-layer pattern check).
FLOW_SORT_COLUMNS = {"first_seen", "last_seen", "packets", "bytes", "duration"}


class CaptureRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create(self, filename: str, source: str, size_bytes: int) -> CaptureModel:
        capture = CaptureModel(
            id=new_id(),
            filename=filename,
            source=source,
            size_bytes=size_bytes,
            status="created",
        )
        self.db.add(capture)
        self.db.commit()
        self.db.refresh(capture)
        return capture

    def get(self, capture_id: str) -> CaptureModel | None:
        return self.db.get(CaptureModel, capture_id)

    def list(self, limit: int = 100) -> list[CaptureModel]:
        stmt = select(CaptureModel).order_by(desc(CaptureModel.created_at)).limit(limit)
        return list(self.db.scalars(stmt))

    def update(self, capture: CaptureModel, **fields) -> CaptureModel:
        for key, value in fields.items():
            setattr(capture, key, value)
        self.db.commit()
        self.db.refresh(capture)
        return capture

    def claim_for_analysis(self, capture_id: str) -> CaptureModel | None:
        """Atomically transition a capture to 'queued' for analysis.

        Single guarded UPDATE — the WHERE clause makes the check-and-set
        atomic under concurrency, so two simultaneous POST /analyze cannot
        both win (exactly one row update succeeds). Returns the refreshed
        capture on success, None if another analysis already claimed it
        (status 'queued'/'analyzing') or the capture doesn't exist.
        """
        stmt = (
            update(CaptureModel)
            .where(
                CaptureModel.id == capture_id,
                CaptureModel.status.notin_(("queued", "analyzing")),
            )
            .values(status="queued")
        )
        result = self.db.execute(stmt)
        if result.rowcount != 1:
            self.db.rollback()
            return None
        self.db.commit()
        return self.get(capture_id)

    def delete_capture(self, capture_id: str) -> dict:
        """Delete a capture and ALL capture-scoped rows in ONE transaction.

        Runs on a dedicated engine-level connection (engine.begin) so every
        child-table DELETE, the case-membership cleanup and the parent-row
        DELETE commit atomically — a failure anywhere rolls the whole delete
        back and nothing is orphaned. Filesystem cleanup is deliberately NOT
        part of this method: it is the API layer's job, after the commit
        succeeds (a DB rollback must never have deleted the file first).

        Returns {"id", "rows"} where rows counts deleted child rows.
        Raises ValueError if the capture does not exist (the caller maps
        that to a 404 before any deletion happens).
        """
        from app.core.database import engine as _engine

        with _engine.begin() as conn:
            exists = conn.execute(
                select(func.count()).select_from(CaptureModel).where(CaptureModel.id == capture_id)
            ).scalar_one()
            if not exists:
                conn.rollback()
                raise ValueError(capture_id)

            rows = 0
            for model in (
                PacketModel,
                FlowModel,
                HostModel,
                DNSTransactionModel,
                HTTPTransactionModel,
                TLSSessionModel,
                AlertModel,
                TimelineEventModel,
                GraphEdgeModel,
                AnalysisJobModel,
            ):
                result = conn.execute(delete(model).where(model.capture_id == capture_id))
                rows += result.rowcount or 0

            # strip membership from every case that references the capture.
            # JSON columns can't be queried with LIKE portably — read id +
            # capture_ids as plain tuples (Core connection, no ORM loading)
            # and rewrite only the cases that contain the id.
            for case_id_value, case_ids in conn.execute(select(CaseModel.id, CaseModel.capture_ids)).all():
                if case_ids and capture_id in case_ids:
                    conn.execute(
                        update(CaseModel)
                        .where(CaseModel.id == case_id_value)
                        .values(
                            capture_ids=[c for c in case_ids if c != capture_id],
                            updated_at=utcnow(),
                        )
                    )

            conn.execute(delete(CaptureModel).where(CaptureModel.id == capture_id))
        return {"id": capture_id, "rows": rows}


class FlowRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create_many(self, capture_id: str, flow_dicts: list[dict]) -> list[FlowModel]:
        models = [FlowModel(id=new_id(), capture_id=capture_id, **fd) for fd in flow_dicts]
        self.db.add_all(models)
        self.db.commit()
        return models

    def get(self, flow_id: str) -> FlowModel | None:
        return self.db.get(FlowModel, flow_id)

    def list_for_capture(self, capture_id: str) -> list[FlowModel]:
        stmt = select(FlowModel).where(FlowModel.capture_id == capture_id).order_by(FlowModel.first_seen)
        return list(self.db.scalars(stmt))

    def page_for_capture(
        self,
        capture_id: str,
        limit: int = 50,
        offset: int = 0,
        transport: str | None = None,
        direction: str | None = None,
        sort: str = "first_seen",
        order: str = "asc",
    ) -> tuple[list[FlowModel], int]:
        """SQL-level filtered/paginated flows with total count."""
        stmt = select(FlowModel).where(FlowModel.capture_id == capture_id)
        if transport:
            stmt = stmt.where(FlowModel.transport_protocol == transport.upper())
        if direction:
            stmt = stmt.where(FlowModel.direction == direction.lower())

        total = self.db.scalar(select(func.count()).select_from(FlowModel).where(stmt.whereclause))

        # Whitelisted at the API layer (flows.py pattern); getattr is only a
        # belt-and-suspenders fallback so an unknown name can never reach order_by.
        sort_col = getattr(FlowModel, sort if sort in FLOW_SORT_COLUMNS else "first_seen", None)
        if sort_col is None:
            sort_col = FlowModel.first_seen
        order_fn = desc if order == "desc" else lambda c: c.asc()
        stmt = stmt.order_by(order_fn(sort_col)).limit(limit).offset(offset)
        return list(self.db.scalars(stmt)), int(total or 0)

    def delete_for_capture(self, capture_id: str) -> int:
        result = self.db.execute(delete(FlowModel).where(FlowModel.capture_id == capture_id))
        self.db.commit()
        return result.rowcount or 0


class HostRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create_many(self, capture_id: str, host_dicts: list[dict]) -> list[HostModel]:
        models = [HostModel(id=new_id(), capture_id=capture_id, **hd) for hd in host_dicts]
        self.db.add_all(models)
        self.db.commit()
        return models

    def get(self, host_id: str) -> HostModel | None:
        return self.db.get(HostModel, host_id)

    def list_for_capture(self, capture_id: str) -> list[HostModel]:
        stmt = select(HostModel).where(HostModel.capture_id == capture_id)
        return list(self.db.scalars(stmt))

    def delete_for_capture(self, capture_id: str) -> int:
        result = self.db.execute(delete(HostModel).where(HostModel.capture_id == capture_id))
        self.db.commit()
        return result.rowcount or 0


class DNSRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create_many(self, capture_id: str, txns: list[dict]) -> list[DNSTransactionModel]:
        models = [DNSTransactionModel(id=new_id(), capture_id=capture_id, **t) for t in txns]
        self.db.add_all(models)
        self.db.commit()
        return models

    def list_for_capture(self, capture_id: str) -> list[DNSTransactionModel]:
        stmt = (
            select(DNSTransactionModel)
            .where(DNSTransactionModel.capture_id == capture_id)
            .order_by(DNSTransactionModel.timestamp)
        )
        return list(self.db.scalars(stmt))

    def page_for_capture(
        self,
        capture_id: str,
        limit: int = 50,
        offset: int = 0,
        domain: str | None = None,
        rcode: int | None = None,
    ) -> tuple[list[DNSTransactionModel], int]:
        stmt = select(DNSTransactionModel).where(DNSTransactionModel.capture_id == capture_id)
        if domain:
            stmt = stmt.where(DNSTransactionModel.query_name.ilike(f"%{domain}%"))
        if rcode is not None:
            stmt = stmt.where(DNSTransactionModel.rcode == rcode)

        total = self.db.scalar(select(func.count()).select_from(DNSTransactionModel).where(stmt.whereclause))
        stmt = stmt.order_by(DNSTransactionModel.timestamp).limit(limit).offset(offset)
        return list(self.db.scalars(stmt)), int(total or 0)

    def delete_for_capture(self, capture_id: str) -> int:
        result = self.db.execute(
            delete(DNSTransactionModel).where(DNSTransactionModel.capture_id == capture_id)
        )
        self.db.commit()
        return result.rowcount or 0


class HTTPRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create_many(self, capture_id: str, txns: list[dict]) -> list[HTTPTransactionModel]:
        models = [HTTPTransactionModel(id=new_id(), capture_id=capture_id, **t) for t in txns]
        self.db.add_all(models)
        self.db.commit()
        return models

    def list_for_capture(self, capture_id: str) -> list[HTTPTransactionModel]:
        stmt = (
            select(HTTPTransactionModel)
            .where(HTTPTransactionModel.capture_id == capture_id)
            .order_by(HTTPTransactionModel.timestamp)
        )
        return list(self.db.scalars(stmt))

    def page_for_capture(
        self,
        capture_id: str,
        limit: int = 50,
        offset: int = 0,
        host: str | None = None,
        status: int | None = None,
    ) -> tuple[list[HTTPTransactionModel], int]:
        stmt = select(HTTPTransactionModel).where(HTTPTransactionModel.capture_id == capture_id)
        if host:
            stmt = stmt.where(HTTPTransactionModel.host.ilike(f"%{host}%"))
        if status is not None:
            stmt = stmt.where(HTTPTransactionModel.status_code == status)

        total = self.db.scalar(select(func.count()).select_from(HTTPTransactionModel).where(stmt.whereclause))
        stmt = stmt.order_by(HTTPTransactionModel.timestamp).limit(limit).offset(offset)
        return list(self.db.scalars(stmt)), int(total or 0)

    def delete_for_capture(self, capture_id: str) -> int:
        result = self.db.execute(
            delete(HTTPTransactionModel).where(HTTPTransactionModel.capture_id == capture_id)
        )
        self.db.commit()
        return result.rowcount or 0


class TLSRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create_many(self, capture_id: str, sessions: list[dict]) -> list[TLSSessionModel]:
        models = [TLSSessionModel(id=new_id(), capture_id=capture_id, **s) for s in sessions]
        self.db.add_all(models)
        self.db.commit()
        return models

    def list_for_capture(self, capture_id: str) -> list[TLSSessionModel]:
        stmt = (
            select(TLSSessionModel)
            .where(TLSSessionModel.capture_id == capture_id)
            .order_by(TLSSessionModel.first_seen)
        )
        return list(self.db.scalars(stmt))

    def page_for_capture(
        self,
        capture_id: str,
        limit: int = 50,
        offset: int = 0,
        sni: str | None = None,
    ) -> tuple[list[TLSSessionModel], int]:
        stmt = select(TLSSessionModel).where(TLSSessionModel.capture_id == capture_id)
        if sni:
            stmt = stmt.where(TLSSessionModel.sni.ilike(f"%{sni}%"))

        total = self.db.scalar(select(func.count()).select_from(TLSSessionModel).where(stmt.whereclause))
        stmt = stmt.order_by(TLSSessionModel.first_seen).limit(limit).offset(offset)
        return list(self.db.scalars(stmt)), int(total or 0)

    def delete_for_capture(self, capture_id: str) -> int:
        result = self.db.execute(delete(TLSSessionModel).where(TLSSessionModel.capture_id == capture_id))
        self.db.commit()
        return result.rowcount or 0


class AlertRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create_many(self, capture_id: str, alerts: list[dict]) -> list[AlertModel]:
        models = [AlertModel(id=new_id(), capture_id=capture_id, **a) for a in alerts]
        self.db.add_all(models)
        self.db.commit()
        return models

    def get(self, alert_id: str) -> AlertModel | None:
        return self.db.get(AlertModel, alert_id)

    def list_for_capture(self, capture_id: str) -> list[AlertModel]:
        stmt = select(AlertModel).where(AlertModel.capture_id == capture_id).order_by(desc(AlertModel.score))
        return list(self.db.scalars(stmt))

    def page_for_capture(
        self,
        capture_id: str,
        limit: int = 50,
        offset: int = 0,
        severity: str | None = None,
        min_score: int | None = None,
        rule: str | None = None,
    ) -> tuple[list[AlertModel], int]:
        stmt = select(AlertModel).where(AlertModel.capture_id == capture_id)
        if severity:
            stmt = stmt.where(AlertModel.severity == severity.lower())
        if min_score is not None:
            stmt = stmt.where(AlertModel.score >= min_score)
        if rule:
            stmt = stmt.where(AlertModel.rule_name == rule)

        total = self.db.scalar(select(func.count()).select_from(AlertModel).where(stmt.whereclause))
        stmt = stmt.order_by(desc(AlertModel.score), desc(AlertModel.created_at)).limit(limit).offset(offset)
        return list(self.db.scalars(stmt)), int(total or 0)

    def delete_for_capture(self, capture_id: str) -> int:
        result = self.db.execute(delete(AlertModel).where(AlertModel.capture_id == capture_id))
        self.db.commit()
        return result.rowcount or 0

    def count_by_severity(self, capture_ids: list[str]) -> dict[str, int]:
        """Grouped severity counts for one or more captures (one query)."""
        stmt = (
            select(AlertModel.severity, func.count())
            .where(AlertModel.capture_id.in_(capture_ids))
            .group_by(AlertModel.severity)
        )
        return {sev: int(count) for sev, count in self.db.execute(stmt)}

    def set_acknowledged(self, alert_id: str, ack: bool) -> AlertModel | None:
        alert = self.get(alert_id)
        if alert is None:
            return None
        alert.acknowledged = ack
        self.db.commit()
        self.db.refresh(alert)
        return alert

    def update(self, alert: AlertModel, **fields) -> AlertModel:
        for key, value in fields.items():
            setattr(alert, key, value)
        self.db.commit()
        self.db.refresh(alert)
        return alert


class TimelineRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create_many(self, capture_id: str, events: list[dict]) -> list[TimelineEventModel]:
        models = [TimelineEventModel(id=new_id(), capture_id=capture_id, **e) for e in events]
        self.db.add_all(models)
        self.db.commit()
        return models

    def list_for_capture(self, capture_id: str) -> list[TimelineEventModel]:
        stmt = (
            select(TimelineEventModel)
            .where(TimelineEventModel.capture_id == capture_id)
            .order_by(TimelineEventModel.timestamp)
        )
        return list(self.db.scalars(stmt))

    def page_for_capture(
        self,
        capture_id: str,
        limit: int = 200,
        offset: int = 0,
        host: str | None = None,
        protocol: str | None = None,
        event_type: str | None = None,
        severity: str | None = None,
        after: float | None = None,
        before: float | None = None,
    ) -> tuple[list[TimelineEventModel], int]:
        stmt = select(TimelineEventModel).where(TimelineEventModel.capture_id == capture_id)
        if host:
            host_pat = f"%{host}%"
            stmt = stmt.where(
                TimelineEventModel.source_ip.ilike(host_pat)
                | TimelineEventModel.destination_ip.ilike(host_pat)
                | TimelineEventModel.domain.ilike(host_pat)
            )
        if protocol:
            stmt = stmt.where(TimelineEventModel.protocol.ilike(f"%{protocol}%"))
        if event_type:
            stmt = stmt.where(TimelineEventModel.event_type == event_type)
        if severity:
            stmt = stmt.where(TimelineEventModel.severity == severity.lower())
        if after is not None:
            stmt = stmt.where(TimelineEventModel.timestamp >= after)
        if before is not None:
            stmt = stmt.where(TimelineEventModel.timestamp <= before)

        total = self.db.scalar(select(func.count()).select_from(TimelineEventModel).where(stmt.whereclause))
        stmt = stmt.order_by(TimelineEventModel.timestamp).limit(limit).offset(offset)
        return list(self.db.scalars(stmt)), int(total or 0)

    def delete_for_capture(self, capture_id: str) -> int:
        result = self.db.execute(
            delete(TimelineEventModel).where(TimelineEventModel.capture_id == capture_id)
        )
        self.db.commit()
        return result.rowcount or 0

    def ts_range_for_captures(self, capture_ids: list[str]) -> tuple[float | None, float | None]:
        """(min, max) event timestamps across captures via SQL aggregates."""
        if not capture_ids:
            return None, None
        stmt = select(func.min(TimelineEventModel.timestamp), func.max(TimelineEventModel.timestamp)).where(
            TimelineEventModel.capture_id.in_(capture_ids)
        )
        lo, hi = self.db.execute(stmt).one()
        return (float(lo) if lo is not None else None, float(hi) if hi is not None else None)


class JobRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create(self, capture_id: str, job_type: str = "full_analysis") -> AnalysisJobModel:
        job = AnalysisJobModel(id=new_id(), capture_id=capture_id, type=job_type, status="queued")
        self.db.add(job)
        self.db.commit()
        self.db.refresh(job)
        return job

    def get(self, job_id: str) -> AnalysisJobModel | None:
        return self.db.get(AnalysisJobModel, job_id)

    def list_for_capture(self, capture_id: str) -> list[AnalysisJobModel]:
        stmt = (
            select(AnalysisJobModel)
            .where(AnalysisJobModel.capture_id == capture_id)
            .order_by(desc(AnalysisJobModel.created_at))
        )
        return list(self.db.scalars(stmt))

    def update(self, job: AnalysisJobModel, **fields) -> AnalysisJobModel:
        for key, value in fields.items():
            setattr(job, key, value)
        self.db.commit()
        self.db.refresh(job)
        return job

    def running_for_capture(self, capture_id: str) -> AnalysisJobModel | None:
        for job in self.list_for_capture(capture_id):
            if job.status in ("queued", "running"):
                return job
        return None


class PacketRepository:
    """Packet store: normalized packets persisted once at analysis time."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def to_normalized(self, p: PacketModel):
        """Convert a persisted packet back to the normalized dataclass."""
        from app.core.models import NormalizedPacket

        return NormalizedPacket(
            timestamp=p.timestamp,
            source_ip=p.source_ip,
            destination_ip=p.destination_ip,
            protocol=p.protocol,
            transport=p.transport,
            source_port=p.source_port,
            destination_port=p.destination_port,
            length=p.length,
            flags=p.flags or [],
            metadata=p.meta or {},
            packet_reference=p.packet_reference,
        )

    def create_many(self, capture_id: str, parsed) -> int:
        """Batch-insert normalized packets; returns count persisted."""
        BATCH = 5_000
        count = 0
        for start in range(0, len(parsed.packets), BATCH):
            batch = parsed.packets[start : start + BATCH]
            self.db.add_all(
                PacketModel(
                    id=new_id(),
                    capture_id=capture_id,
                    packet_reference=p.packet_reference,
                    timestamp=p.timestamp,
                    source_ip=p.source_ip,
                    destination_ip=p.destination_ip,
                    protocol=p.protocol,
                    transport=p.transport,
                    source_port=p.source_port,
                    destination_port=p.destination_port,
                    length=p.length,
                    flags=p.flags,
                    meta=p.metadata,
                )
                for p in batch
            )
            self.db.commit()
            count += len(batch)
        return count

    def get_by_refs(self, capture_id: str, refs: list[int]) -> list[PacketModel]:
        """Fetch specific packets by their ordinals (flow evidence drill-down)."""
        if not refs:
            return []
        wanted = set(refs)
        stmt = (
            select(PacketModel)
            .where(PacketModel.capture_id == capture_id)
            .where(PacketModel.packet_reference.in_(wanted))
            .order_by(PacketModel.packet_reference)
        )
        return list(self.db.scalars(stmt))

    def iter_for_capture(self, capture_id: str) -> list[PacketModel]:
        """All packets for a capture, ordered by ordinal."""
        stmt = (
            select(PacketModel)
            .where(PacketModel.capture_id == capture_id)
            .order_by(PacketModel.packet_reference)
        )
        return list(self.db.scalars(stmt))

    def count_for_capture(self, capture_id: str) -> int:
        stmt = select(func.count()).select_from(PacketModel).where(PacketModel.capture_id == capture_id)
        return int(self.db.scalar(stmt) or 0)

    def as_parsed_capture(self, capture_id: str):
        """All packets as a ParsedCapture-shaped object (for analysis services)."""
        from app.core.models import ParsedCapture

        parsed = ParsedCapture(filename="")
        parsed.packets = [self.to_normalized(p) for p in self.iter_for_capture(capture_id)]
        return parsed

    def delete_for_capture(self, capture_id: str) -> int:
        result = self.db.execute(delete(PacketModel).where(PacketModel.capture_id == capture_id))
        self.db.commit()
        return result.rowcount or 0


class CaseRepository:
    """Investigation cases — groups of related captures."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create(self, name: str, description: str | None = None) -> CaseModel:
        case = CaseModel(
            id=new_id(),
            name=name,
            description=description,
            capture_ids=[],
            status="open",
        )
        self.db.add(case)
        self.db.commit()
        self.db.refresh(case)
        return case

    def get(self, case_id: str) -> CaseModel | None:
        return self.db.get(CaseModel, case_id)

    def list(self, limit: int = 100) -> list[CaseModel]:
        stmt = select(CaseModel).order_by(desc(CaseModel.created_at)).limit(limit)
        return list(self.db.scalars(stmt))

    def update(self, case: CaseModel, **fields) -> CaseModel:
        for key, value in fields.items():
            setattr(case, key, value)
        case.updated_at = utcnow()
        self.db.commit()
        self.db.refresh(case)
        return case

    def add_capture(self, case: CaseModel, capture_id: str) -> CaseModel:
        ids = list(case.capture_ids or [])
        if capture_id not in ids:
            ids.append(capture_id)
            return self.update(case, capture_ids=ids)
        return case

    def remove_capture(self, case: CaseModel, capture_id: str) -> CaseModel:
        ids = [c for c in (case.capture_ids or []) if c != capture_id]
        return self.update(case, capture_ids=ids)

    def cases_containing(self, capture_id: str) -> list[CaseModel]:
        """Cases whose capture_ids list references the capture."""
        return [case for case in self.list(limit=500) if capture_id in (case.capture_ids or [])]

    def delete(self, case_id: str) -> bool:
        case = self.get(case_id)
        if case is None:
            return False
        self.db.delete(case)
        self.db.commit()
        return True


# Evidence-graph relationship types the repository accepts as filters.
GRAPH_RELATIONSHIPS = {
    "DNS_QUERY",
    "RESOLVES_TO",
    "TLS_SNI",
    "HTTP_HOST",
    "FLOW",
    "EXPOSES",
    "TRIGGERED",
    "TARGETS",
    "GROUPS",
    "INCLUDES",
}
GRAPH_PROVENANCE = {"observed", "correlated", "enriched"}


class GraphEdgeRepository:
    """Evidence-graph edges: SQL-filtered, capped reads + build-time persistence."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create_many(self, capture_id: str, rows: list[GraphEdgeModel]) -> list[GraphEdgeModel]:
        self.db.add_all(rows)
        self.db.commit()
        return rows

    def get(self, edge_id: str) -> GraphEdgeModel | None:
        return self.db.get(GraphEdgeModel, edge_id)

    def delete_for_capture(self, capture_id: str) -> int:
        result = self.db.execute(delete(GraphEdgeModel).where(GraphEdgeModel.capture_id == capture_id))
        self.db.commit()
        return result.rowcount or 0

    def rebuild_for_capture(self, capture_id: str, capture: CaptureModel) -> list[GraphEdgeModel]:
        """Delete existing edges and rebuild the evidence graph for a capture.

        Used when case membership changes (INCLUDES edges) or for manual rebuild.
        """
        self.delete_for_capture(capture_id)
        from app.services.evidence_graph import EvidenceGraphBuilder

        rows = EvidenceGraphBuilder(self.db).build(capture)
        if rows:
            self.db.add_all(rows)
            self.db.commit()
        return rows

    def count_for_capture(self, capture_id: str) -> int:
        return int(
            self.db.scalar(
                select(func.count())
                .select_from(GraphEdgeModel)
                .where(GraphEdgeModel.capture_id == capture_id)
            )
            or 0
        )

    def list_for_capture(
        self,
        capture_id: str,
        *,
        relationships: list[str] | None = None,
        provenance: list[str] | None = None,
        after: float | None = None,
        before: float | None = None,
        with_alerts_only: bool = False,
        node_id: str | None = None,
        max_edges: int = 4000,
    ) -> list[GraphEdgeModel]:
        """Filtered edge read for ONE capture, capped at max_edges rows.

        Time window uses interval overlap: an edge matches when its
        [first_seen, last_seen] intersects [after, before]. All filtering
        happens in SQL so large captures stay bounded.
        """
        stmt = select(GraphEdgeModel).where(GraphEdgeModel.capture_id == capture_id)
        if relationships:
            stmt = stmt.where(GraphEdgeModel.relationship.in_(relationships))
        if provenance:
            stmt = stmt.where(GraphEdgeModel.provenance.in_(provenance))
        if after is not None:
            stmt = stmt.where(GraphEdgeModel.last_seen >= after)
        if before is not None:
            stmt = stmt.where(GraphEdgeModel.first_seen <= before)
        if with_alerts_only:
            stmt = stmt.where(func.json_array_length(GraphEdgeModel.alert_ids) > 0)
        if node_id:
            stmt = stmt.where((GraphEdgeModel.source_id == node_id) | (GraphEdgeModel.target_id == node_id))
        stmt = stmt.order_by(GraphEdgeModel.last_seen.desc(), GraphEdgeModel.source_id).limit(max_edges)
        return list(self.db.scalars(stmt))

    def touching_ids(self, capture_id: str, edges: list[GraphEdgeModel]) -> set[str]:
        """Node ids referenced by the given edges (for capped subgraph assembly)."""
        ids: set[str] = set()
        for e in edges:
            ids.add(e.source_id)
            ids.add(e.target_id)
        return ids
