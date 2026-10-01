"""
Evidence Domain Repository.

Provides database interaction and query execution routines for Evidence entities using Async SQLAlchemy 2.0.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy import select, func, or_, and_, update, desc, asc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.evidence import (
    Evidence,
    EvidenceType,
    EvidenceClassification,
)
from app.domains.evidence.schemas import EvidenceCreate, EvidenceFilterParams, EvidenceSummaryStats


class EvidenceRepository:
    """Repository handling database access for digital forensic Evidence entities."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, evidence_in: EvidenceCreate, collected_by_user_id: Optional[uuid.UUID] = None) -> Evidence:
        """Persist a new Evidence entity with initial chain of custody entry."""
        initial_custody = [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": "EVIDENCE_COLLECTED",
                "actor_id": str(collected_by_user_id) if collected_by_user_id else "SYSTEM",
                "source": evidence_in.source,
                "notes": "Initial collection and intake into AegisAI XDR evidence vault",
            }
        ]

        evidence = Evidence(
            investigation_id=evidence_in.investigation_id,
            incident_id=evidence_in.incident_id,
            name=evidence_in.name,
            evidence_type=evidence_in.evidence_type,
            classification=evidence_in.classification,
            source=evidence_in.source,
            source_hostname=evidence_in.source_hostname,
            source_ip=evidence_in.source_ip,
            collected_by_user_id=collected_by_user_id or evidence_in.collected_by_user_id,
            file_name=evidence_in.file_name,
            file_path=evidence_in.file_path,
            file_size=evidence_in.file_size,
            sha256=evidence_in.sha256,
            md5=evidence_in.md5,
            sha1=evidence_in.sha1,
            mime_type=evidence_in.mime_type,
            process_name=evidence_in.process_name,
            process_id=evidence_in.process_id,
            parent_process_id=evidence_in.parent_process_id,
            registry_key=evidence_in.registry_key,
            network_connection=evidence_in.network_connection,
            url=evidence_in.url,
            domain=evidence_in.domain,
            ip_address=evidence_in.ip_address,
            username=evidence_in.username,
            description=evidence_in.description,
            chain_of_custody=initial_custody,
            integrity_verified=evidence_in.integrity_verified,
            tags=evidence_in.tags,
            evidence_metadata=evidence_in.evidence_metadata,
        )
        self.session.add(evidence)
        await self.session.commit()
        await self.session.refresh(evidence)
        return evidence

    async def get_by_id(self, evidence_id: uuid.UUID, include_deleted: bool = False) -> Optional[Evidence]:
        """Fetch Evidence entity by primary key UUID."""
        stmt = select(Evidence).where(Evidence.id == evidence_id)
        if not include_deleted:
            stmt = stmt.where(Evidence.is_deleted.is_(False))
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_hash(self, hash_value: str, investigation_id: Optional[uuid.UUID] = None) -> Optional[Evidence]:
        """Fetch evidence by hash (SHA256, MD5, or SHA1)."""
        hash_clean = hash_value.strip().lower()
        stmt = select(Evidence).where(
            Evidence.is_deleted.is_(False),
            or_(
                Evidence.sha256 == hash_clean,
                Evidence.md5 == hash_clean,
                Evidence.sha1 == hash_clean,
            ),
        )
        if investigation_id:
            stmt = stmt.where(Evidence.investigation_id == investigation_id)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def list_by_investigation(self, investigation_id: uuid.UUID) -> List[Evidence]:
        """List all evidence belonging to an Investigation."""
        stmt = (
            select(Evidence)
            .where(Evidence.investigation_id == investigation_id, Evidence.is_deleted.is_(False))
            .order_by(Evidence.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def list_filtered(self, params: EvidenceFilterParams) -> Tuple[List[Evidence], int]:
        """List evidence matching query parameters with pagination and dynamic sorting."""
        stmt = select(Evidence).where(Evidence.is_deleted.is_(False))
        count_stmt = select(func.count(Evidence.id)).where(Evidence.is_deleted.is_(False))
        conditions = []

        if params.query:
            pattern = f"%{params.query}%"
            conditions.append(
                or_(
                    Evidence.name.ilike(pattern),
                    Evidence.description.ilike(pattern),
                    Evidence.file_name.ilike(pattern),
                    Evidence.source_hostname.ilike(pattern),
                    Evidence.process_name.ilike(pattern),
                    Evidence.domain.ilike(pattern),
                )
            )

        if params.investigation_id:
            conditions.append(Evidence.investigation_id == params.investigation_id)

        if params.incident_id:
            conditions.append(Evidence.incident_id == params.incident_id)

        if params.evidence_type:
            conditions.append(Evidence.evidence_type == params.evidence_type)

        if params.classification:
            conditions.append(Evidence.classification == params.classification)

        if params.hash_value:
            h_clean = params.hash_value.strip().lower()
            conditions.append(
                or_(
                    Evidence.sha256 == h_clean,
                    Evidence.md5 == h_clean,
                    Evidence.sha1 == h_clean,
                )
            )

        if params.ip_address:
            conditions.append(
                or_(
                    Evidence.source_ip == params.ip_address,
                    Evidence.ip_address == params.ip_address,
                )
            )

        if conditions:
            stmt = stmt.where(and_(*conditions))
            count_stmt = count_stmt.where(and_(*conditions))

        total_result = await self.session.execute(count_stmt)
        total_count = total_result.scalar_one()

        # Dynamic Sorting
        sort_attr = getattr(Evidence, params.sort_by, Evidence.created_at)
        sort_fn = desc if params.sort_order.lower() == "desc" else asc
        stmt = stmt.order_by(sort_fn(sort_attr))

        # Pagination
        offset = (params.page - 1) * params.page_size
        stmt = stmt.offset(offset).limit(params.page_size)

        result = await self.session.execute(stmt)
        evidence_list = list(result.scalars().all())

        return evidence_list, total_count

    async def update(self, evidence: Evidence, update_data: Dict[str, Any]) -> Evidence:
        """Update existing Evidence entity attributes."""
        for field, value in update_data.items():
            if value is not None and hasattr(evidence, field):
                setattr(evidence, field, value)

        self.session.add(evidence)
        await self.session.commit()
        await self.session.refresh(evidence)
        return evidence

    async def add_custody_transfer(
        self, evidence: Evidence, transfer_entry: Dict[str, Any]
    ) -> Evidence:
        """Append a new chain of custody record."""
        current_chain = list(evidence.chain_of_custody)
        current_chain.append(transfer_entry)
        evidence.chain_of_custody = current_chain

        self.session.add(evidence)
        await self.session.commit()
        await self.session.refresh(evidence)
        return evidence

    async def soft_delete(self, evidence_id: uuid.UUID) -> bool:
        """Soft delete an evidence entity."""
        evidence = await self.get_by_id(evidence_id)
        if not evidence:
            return False
        evidence.is_deleted = True
        self.session.add(evidence)
        await self.session.commit()
        return True

    async def count_by_investigation(self, investigation_id: uuid.UUID) -> int:
        """Count active evidence artifacts for an investigation."""
        stmt = select(func.count(Evidence.id)).where(
            Evidence.investigation_id == investigation_id, Evidence.is_deleted.is_(False)
        )
        return (await self.session.execute(stmt)).scalar_one()

    async def get_summary_stats() -> EvidenceSummaryStats:
        """Calculate summary metrics across all evidence artifacts."""
        base_cond = Evidence.is_deleted.is_(False)

        total_stmt = select(func.count(Evidence.id)).where(base_cond)
        total = (await self.session.execute(total_stmt)).scalar_one()

        type_stmt = select(Evidence.evidence_type, func.count(Evidence.id)).where(base_cond).group_by(Evidence.evidence_type)
        type_res = await self.session.execute(type_stmt)
        by_type = {t.value if hasattr(t, 'value') else str(t): count for t, count in type_res.all()}

        class_stmt = select(Evidence.classification, func.count(Evidence.id)).where(base_cond).group_by(Evidence.classification)
        class_res = await self.session.execute(class_stmt)
        by_classification = {c.value if hasattr(c, 'value') else str(c): count for c, count in class_res.all()}

        verified_stmt = select(func.count(Evidence.id)).where(base_cond, Evidence.integrity_verified.is_(True))
        verified_count = (await self.session.execute(verified_stmt)).scalar_one()

        unverified_count = total - verified_count

        return EvidenceSummaryStats(
            total_evidence_count=total,
            by_type=by_type,
            by_classification=by_classification,
            integrity_verified_count=verified_count,
            unverified_count=unverified_count,
        )
