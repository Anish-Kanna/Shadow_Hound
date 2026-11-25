from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional
from pathlib import Path
import math

from db.session import get_db
from db.models import (
    HuntSession, HuntStatus, HuntVerdict, PlannedQuery,
    QueryStatus, User, UserRole
)
from api.schemas import (
    HuntCreateRequest, HuntSessionOut, HuntSessionDetail,
    CancelHuntRequest, PaginatedResponse, HuntReportOut
)
from api.auth import get_current_user, require_analyst, require_approver
from api.audit import log_action, AuditAction

router = APIRouter(prefix="/hunts", tags=["hunts"])


@router.post("", response_model=HuntSessionOut, status_code=status.HTTP_201_CREATED)
def create_hunt(
    body: HuntCreateRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Create a new hunt session and queue it for async execution."""
    from config.settings import get_settings
    settings = get_settings()

    session = HuntSession(
        title=body.title,
        trigger_type=body.trigger_type,
        trigger_context=body.trigger_context,
        analyst_id=current_user.id,
        max_iterations=body.max_iterations,
        confidence_threshold=body.confidence_threshold,
        status=HuntStatus.PENDING,
        verdict=HuntVerdict.PENDING,
    )
    db.add(session)
    db.flush()

    log_action(
        db, AuditAction.HUNT_CREATED,
        user_id=current_user.id,
        hunt_session_id=session.id,
        entity_type="hunt_session", entity_id=session.id,
        payload_summary={"title": body.title, "trigger_type": body.trigger_type},
        ip_address=request.client.host if request.client else None,
    )
    db.commit()

    # Queue async task (requires Redis + Celery worker)
    use_celery = False
    try:
        import redis
        r = redis.Redis.from_url(settings.redis_url, socket_timeout=1.0)
        r.ping()
        use_celery = True
    except Exception:
        pass

    if use_celery:
        try:
            from agent.tasks import run_hunt_task
            task = run_hunt_task.delay(session.id)
            session.celery_task_id = task.id
            db.commit()

            log_action(db, AuditAction.HUNT_STARTED, user_id=current_user.id,
                       hunt_session_id=session.id, entity_type="hunt_session", entity_id=session.id,
                       payload_summary={"celery_task_id": task.id})
            db.commit()
        except Exception:
            background_tasks.add_task(run_hunt_standalone, session.id)
    else:
        background_tasks.add_task(run_hunt_standalone, session.id)

    return session


def run_hunt_standalone(session_id: str):
    from db.session import db_context
    from db.models import HuntSession, HuntStatus
    from agent.orchestrator import HuntOrchestrator
    from datetime import datetime, timezone
    import structlog
    log = structlog.get_logger(__name__)

    with db_context() as db:
        session = db.query(HuntSession).filter(HuntSession.id == session_id).first()
        if not session:
            return
        log.info("standalone_hunt_start", session_id=session_id)
        session.started_at = datetime.now(timezone.utc)
        db.commit()
        orchestrator = HuntOrchestrator(db)
        try:
            hypotheses = orchestrator.run_hypothesis_phase(session, 1)
            if hypotheses:
                try:
                    orchestrator.run_query_planning_phase(session, hypotheses[0])
                except Exception as qe:
                    log.warning("query_planning_failed_retrying", error=str(qe))
                    # Retry once — LLM JSON can be flaky
                    try:
                        orchestrator.run_query_planning_phase(session, hypotheses[0])
                    except Exception:
                        log.warning("query_planning_failed_final", error=str(qe))
                        session.status = HuntStatus.AWAITING_APPROVAL
                        db.commit()
        except Exception as e:
            log.exception("standalone_hunt_failed", session_id=session_id, error=str(e))
            session.status = HuntStatus.FAILED
            session.error_message = str(e)
            db.commit()


@router.get("", response_model=PaginatedResponse)
def list_hunts(
    page: int = 1,
    page_size: int = 20,
    status_filter: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """List hunt sessions. Admins see all; analysts see their own."""
    query = db.query(HuntSession)
    if current_user.role == UserRole.ANALYST:
        query = query.filter(HuntSession.analyst_id == current_user.id)
    if status_filter:
        try:
            query = query.filter(HuntSession.status == HuntStatus(status_filter))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status_filter}")

    total = query.count()
    sessions = query.order_by(desc(HuntSession.created_at)).offset(
        (page - 1) * page_size
    ).limit(page_size).all()

    return PaginatedResponse(
        items=[HuntSessionOut.model_validate(s) for s in sessions],
        total=total,
        page=page,
        page_size=page_size,
        pages=math.ceil(total / page_size),
    )


@router.get("/{hunt_id}", response_model=HuntSessionDetail)
def get_hunt(
    hunt_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Get full hunt session details including hypotheses, queries, and evidence."""
    session = _get_session_or_404(hunt_id, db, current_user)
    return session


@router.post("/{hunt_id}/cancel", response_model=HuntSessionOut)
def cancel_hunt(
    hunt_id: str,
    body: CancelHuntRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Cancel a running hunt session."""
    session = _get_session_or_404(hunt_id, db, current_user)

    if session.status in (HuntStatus.COMPLETED, HuntStatus.FAILED, HuntStatus.CANCELLED):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel a hunt in status: {session.status.value}"
        )

    try:
        from agent.tasks import cancel_hunt_task
        cancel_hunt_task.delay(hunt_id)
    except Exception:
        # Redis not available — cancel locally
        session.status = HuntStatus.CANCELLED

    log_action(
        db, AuditAction.HUNT_CANCELLED,
        user_id=current_user.id,
        hunt_session_id=hunt_id,
        entity_type="hunt_session", entity_id=hunt_id,
        payload_summary={"reason": body.reason},
    )
    db.commit()
    return session


@router.get("/{hunt_id}/report", response_model=HuntReportOut)
def get_report(
    hunt_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Get the hunt report for a completed session."""
    session = _get_session_or_404(hunt_id, db, current_user)
    if not session.report:
        raise HTTPException(status_code=404, detail="Report not yet generated")

    log_action(db, AuditAction.REPORT_DOWNLOADED,
               user_id=current_user.id, hunt_session_id=hunt_id,
               entity_type="hunt_report", entity_id=session.report.id)
    db.commit()
    return session.report


def get_user_for_download(
    request: Request,
    token: Optional[str] = None,
    db: Session = Depends(get_db),
) -> User:
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        jwt_token = auth_header.split(" ")[1]
    else:
        jwt_token = token
        
    if not jwt_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
        
    from api.auth import decode_token
    payload = decode_token(jwt_token)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Expected access token")
        
    user = db.query(User).filter(User.id == payload["sub"]).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
        
    from db.models import UserRole
    if user.role not in [UserRole.ANALYST, UserRole.APPROVER, UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Requires analyst permissions")
        
    return user


@router.get("/{hunt_id}/report/download")
def download_report(
    hunt_id: str,
    format: str = "pdf",
    token: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_user_for_download),
):
    """Download the hunt report as PDF, JSON, or Markdown."""
    session = _get_session_or_404(hunt_id, db, current_user)
    if not session.report:
        raise HTTPException(status_code=404, detail="Report not yet generated")

    report = session.report
    path_map = {"pdf": report.pdf_path, "json": report.json_path, "md": report.markdown_path}
    path = path_map.get(format)

    if not path or not Path(path).exists():
        raise HTTPException(status_code=404, detail=f"Report file not found for format: {format}")

    media_types = {"pdf": "application/pdf", "json": "application/json", "md": "text/markdown"}
    return FileResponse(
        path=path,
        media_type=media_types.get(format, "application/octet-stream"),
        filename=Path(path).name,
    )


@router.get("/{hunt_id}/queries")
def get_queries(
    hunt_id: str,
    status_filter: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Get all queries for a hunt session, optionally filtered by status."""
    session = _get_session_or_404(hunt_id, db, current_user)
    queries = session.queries
    if status_filter:
        try:
            qs = QueryStatus(status_filter)
            queries = [q for q in queries if q.status == qs]
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status_filter}")
    return queries


# ── Internal helper ───────────────────────────────────────────────────────────

def _get_session_or_404(hunt_id: str, db: Session, current_user: User) -> HuntSession:
    session = db.query(HuntSession).filter(HuntSession.id == hunt_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Hunt session not found")
    if current_user.role == UserRole.ANALYST and session.analyst_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    return session
