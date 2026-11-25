from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, JSON,
    ForeignKey, Enum as SAEnum, Index
)
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func
from datetime import datetime
import enum
import uuid


Base = declarative_base()


def new_uuid() -> str:
    return str(uuid.uuid4())


# ── Enums ─────────────────────────────────────────────────────────────────────

class HuntStatus(str, enum.Enum):
    PENDING = "pending"
    HYPOTHESIZING = "hypothesizing"
    PLANNING = "planning"
    AWAITING_APPROVAL = "awaiting_approval"
    EXECUTING = "executing"
    ANALYZING = "analyzing"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class HuntVerdict(str, enum.Enum):
    CONFIRMED_THREAT = "confirmed_threat"
    INCONCLUSIVE = "inconclusive"
    NO_FINDING = "no_finding"
    PENDING = "pending"


class EvidenceClassification(str, enum.Enum):
    CONFIRMING = "confirming"
    CONTRADICTING = "contradicting"
    NEUTRAL = "neutral"


class QueryStatus(str, enum.Enum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"


class UserRole(str, enum.Enum):
    ANALYST = "analyst"
    APPROVER = "approver"
    ADMIN = "admin"


class DataSource(str, enum.Enum):
    CROWDSTRIKE = "crowdstrike"
    SENTINELONE = "sentinelone"
    DEFENDER = "defender"
    SPLUNK = "splunk"
    SENTINEL = "sentinel"
    ELASTIC = "elastic"
    MISP = "misp"
    VIRUSTOTAL = "virustotal"
    OPENCTI = "opencti"
    PLAYBOOKS = "playbooks"


# ── Tables ────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=new_uuid)
    email = Column(String, unique=True, nullable=False, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=False)
    role = Column(SAEnum(UserRole), nullable=False, default=UserRole.ANALYST)
    is_active = Column(Boolean, default=True)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    hunt_sessions = relationship("HuntSession", back_populates="analyst", foreign_keys="HuntSession.analyst_id")
    audit_logs = relationship("AuditLog", back_populates="user")


class HuntSession(Base):
    __tablename__ = "hunt_sessions"

    id = Column(String, primary_key=True, default=new_uuid)
    title = Column(String, nullable=False)
    trigger_type = Column(String, nullable=False)  # analyst_request | scheduled | intel_alert
    trigger_context = Column(JSON, nullable=False, default=dict)
    status = Column(SAEnum(HuntStatus), nullable=False, default=HuntStatus.PENDING)
    verdict = Column(SAEnum(HuntVerdict), nullable=False, default=HuntVerdict.PENDING)
    analyst_id = Column(String, ForeignKey("users.id"), nullable=False)
    approver_id = Column(String, ForeignKey("users.id"), nullable=True)
    current_iteration = Column(Integer, default=0)
    max_iterations = Column(Integer, default=5)
    confidence_threshold = Column(Integer, default=70)
    final_confidence = Column(Float, nullable=True)
    celery_task_id = Column(String, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    error_message = Column(Text, nullable=True)

    analyst = relationship("User", back_populates="hunt_sessions", foreign_keys=[analyst_id])
    approver = relationship("User", foreign_keys=[approver_id])
    hypotheses = relationship("Hypothesis", back_populates="hunt_session", order_by="Hypothesis.priority_rank")
    queries = relationship("PlannedQuery", back_populates="hunt_session")
    evidence = relationship("Evidence", back_populates="hunt_session")
    report = relationship("HuntReport", back_populates="hunt_session", uselist=False)
    audit_logs = relationship("AuditLog", back_populates="hunt_session")

    __table_args__ = (
        Index("ix_hunt_sessions_analyst_id", "analyst_id"),
        Index("ix_hunt_sessions_status", "status"),
        Index("ix_hunt_sessions_created_at", "created_at"),
    )


class Hypothesis(Base):
    __tablename__ = "hypotheses"

    id = Column(String, primary_key=True, default=new_uuid)
    hunt_session_id = Column(String, ForeignKey("hunt_sessions.id"), nullable=False)
    description = Column(Text, nullable=False)
    mitre_tactics = Column(JSON, default=list)       # ["TA0001", "TA0002"]
    mitre_techniques = Column(JSON, default=list)    # ["T1059.001", "T1078"]
    priority_rank = Column(Integer, nullable=False)  # 1 = highest
    priority_label = Column(String, nullable=False)  # high | medium | low
    intel_sources = Column(JSON, default=list)
    suggested_data_sources = Column(JSON, default=list)
    initial_query_templates = Column(JSON, default=dict)  # {data_source: query_template}
    iteration = Column(Integer, default=1)
    is_active = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    hunt_session = relationship("HuntSession", back_populates="hypotheses")
    queries = relationship("PlannedQuery", back_populates="hypothesis")


class PlannedQuery(Base):
    __tablename__ = "planned_queries"

    id = Column(String, primary_key=True, default=new_uuid)
    hunt_session_id = Column(String, ForeignKey("hunt_sessions.id"), nullable=False)
    hypothesis_id = Column(String, ForeignKey("hypotheses.id"), nullable=False)
    data_source = Column(SAEnum(DataSource), nullable=False)
    query_language = Column(String, nullable=False)  # KQL | SPL | SQL | YARA | GraphQL
    query_text = Column(Text, nullable=False)
    query_rationale = Column(Text, nullable=False)
    status = Column(SAEnum(QueryStatus), nullable=False, default=QueryStatus.PENDING_APPROVAL)
    approved_by = Column(String, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    rejection_reason = Column(Text, nullable=True)
    modified_query = Column(Text, nullable=True)  # If approver edited before approving
    executed_at = Column(DateTime(timezone=True), nullable=True)
    execution_duration_ms = Column(Integer, nullable=True)
    rows_returned = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    hunt_session = relationship("HuntSession", back_populates="queries")
    hypothesis = relationship("Hypothesis", back_populates="queries")
    approver = relationship("User", foreign_keys=[approved_by])
    evidence = relationship("Evidence", back_populates="query")

    __table_args__ = (
        Index("ix_planned_queries_session_status", "hunt_session_id", "status"),
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(String, primary_key=True, default=new_uuid)
    hunt_session_id = Column(String, ForeignKey("hunt_sessions.id"), nullable=False)
    query_id = Column(String, ForeignKey("planned_queries.id"), nullable=False)
    data_source = Column(SAEnum(DataSource), nullable=False)
    raw_data = Column(JSON, nullable=False)
    summary = Column(Text, nullable=False)
    classification = Column(SAEnum(EvidenceClassification), nullable=False)
    confidence_score = Column(Float, nullable=False)  # 0-100
    confidence_reasoning = Column(Text, nullable=False)
    iocs_extracted = Column(JSON, default=list)  # [{type, value, context}]
    mitre_techniques_observed = Column(JSON, default=list)
    threat_timeline_entries = Column(JSON, default=list)  # [{timestamp, event, actor}]
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    hunt_session = relationship("HuntSession", back_populates="evidence")
    query = relationship("PlannedQuery", back_populates="evidence")


class HuntReport(Base):
    __tablename__ = "hunt_reports"

    id = Column(String, primary_key=True, default=new_uuid)
    hunt_session_id = Column(String, ForeignKey("hunt_sessions.id"), nullable=False, unique=True)
    verdict = Column(SAEnum(HuntVerdict), nullable=False)
    executive_summary = Column(Text, nullable=False)
    hypothesis_summary = Column(JSON, nullable=False)
    evidence_summary = Column(JSON, nullable=False)
    threat_timeline = Column(JSON, default=list)
    ioc_list = Column(JSON, default=list)
    mitre_attack_map = Column(JSON, default=dict)
    analyst_recommendations = Column(JSON, default=list)
    hunt_metadata = Column(JSON, default=dict)
    final_confidence = Column(Float, nullable=False)
    pdf_path = Column(String, nullable=True)
    json_path = Column(String, nullable=True)
    markdown_path = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    hunt_session = relationship("HuntSession", back_populates="report")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=new_uuid)
    hunt_session_id = Column(String, ForeignKey("hunt_sessions.id"), nullable=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    action_type = Column(String, nullable=False, index=True)
    entity_type = Column(String, nullable=True)
    entity_id = Column(String, nullable=True)
    payload_summary = Column(JSON, default=dict)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    outcome = Column(String, nullable=False)  # success | failure
    error_detail = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    user = relationship("User", back_populates="audit_logs")
    hunt_session = relationship("HuntSession", back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_logs_action_created", "action_type", "created_at"),
    )


class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"

    id = Column(String, primary_key=True, default=new_uuid)
    source = Column(String, nullable=False)
    indicator_type = Column(String, nullable=False)  # ip | domain | hash | url | cve
    indicator_value = Column(String, nullable=False)
    context = Column(JSON, default=dict)
    malicious = Column(Boolean, nullable=True)
    confidence = Column(Float, nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_intel_cache_indicator", "indicator_type", "indicator_value"),
    )
