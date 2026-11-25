import structlog
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from db.models import AuditLog

log = structlog.get_logger(__name__)


def log_action(
    db: Session,
    action_type: str,
    outcome: str = "success",
    user_id: Optional[str] = None,
    hunt_session_id: Optional[str] = None,
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    payload_summary: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    error_detail: Optional[str] = None,
) -> AuditLog:
    """
    Write an immutable audit log entry to the database.
    Called on every significant agent or user action.
    """
    entry = AuditLog(
        hunt_session_id=hunt_session_id,
        user_id=user_id,
        action_type=action_type,
        entity_type=entity_type,
        entity_id=entity_id,
        payload_summary=payload_summary or {},
        ip_address=ip_address,
        user_agent=user_agent,
        outcome=outcome,
        error_detail=error_detail,
    )
    db.add(entry)
    db.flush()

    log.info(
        "audit_log",
        action=action_type,
        outcome=outcome,
        user_id=user_id,
        entity=f"{entity_type}:{entity_id}" if entity_type else None,
    )
    return entry


# Action type constants
class AuditAction:
    # Auth
    LOGIN = "auth.login"
    LOGOUT = "auth.logout"
    TOKEN_REFRESH = "auth.token_refresh"
    LOGIN_FAILED = "auth.login_failed"

    # Hunt session
    HUNT_CREATED = "hunt.created"
    HUNT_STARTED = "hunt.started"
    HUNT_COMPLETED = "hunt.completed"
    HUNT_FAILED = "hunt.failed"
    HUNT_CANCELLED = "hunt.cancelled"

    # Hypotheses
    HYPOTHESES_GENERATED = "hypothesis.generated"

    # Queries
    QUERY_PLANNED = "query.planned"
    QUERY_APPROVED = "query.approved"
    QUERY_REJECTED = "query.rejected"
    QUERY_EXECUTED = "query.executed"
    QUERY_FAILED = "query.failed"

    # Evidence
    EVIDENCE_AGGREGATED = "evidence.aggregated"

    # Reports
    REPORT_GENERATED = "report.generated"
    REPORT_DOWNLOADED = "report.downloaded"

    # Admin
    USER_CREATED = "admin.user_created"
    USER_UPDATED = "admin.user_updated"
    USER_DEACTIVATED = "admin.user_deactivated"
