from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request, status
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from db.session import get_db
from db.models import PlannedQuery, QueryStatus, HuntSession, User
from api.schemas import QueryApproveRequest, QueryRejectRequest, BulkApproveRequest, PlannedQueryOut
from api.auth import require_approver
from api.audit import log_action, AuditAction

router = APIRouter(prefix="/hunts/{hunt_id}/queries", tags=["query-approval"])


def _check_and_trigger_execution(hunt_id: str, db: Session, background_tasks: BackgroundTasks):
    pending_count = db.query(PlannedQuery).filter(
        PlannedQuery.hunt_session_id == hunt_id,
        PlannedQuery.status == QueryStatus.PENDING_APPROVAL
    ).count()
    if pending_count == 0:
        background_tasks.add_task(run_execution_standalone, hunt_id)


def run_execution_standalone(session_id: str):
    from db.session import db_context
    from db.models import HuntSession, Hypothesis
    from agent.orchestrator import HuntOrchestrator
    import structlog
    log = structlog.get_logger(__name__)

    with db_context() as db:
        session = db.query(HuntSession).filter(HuntSession.id == session_id).first()
        if not session:
            return
        log.info("standalone_execution_start", session_id=session_id)
        orchestrator = HuntOrchestrator(db)
        try:
            query_results = orchestrator.run_execution_phase(session)
            top_hyp = db.query(Hypothesis).filter(
                Hypothesis.hunt_session_id == session_id
            ).order_by(Hypothesis.priority_rank.asc()).first()
            if top_hyp:
                analysis = orchestrator.run_analysis_phase(session, top_hyp, query_results)
                overall = analysis.get("overall_assessment", {})
                session.final_confidence = float(overall.get("composite_confidence", 0.0))
                db.commit()
            orchestrator.run_report_phase(session)
        except Exception as e:
            log.exception("standalone_execution_failed", session_id=session_id, error=str(e))


@router.get("/{query_id}", response_model=PlannedQueryOut)
def get_query(
    hunt_id: str,
    query_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_approver),
):
    """Get a specific planned query for review."""
    query = _get_query_or_404(hunt_id, query_id, db)
    return query


@router.post("/{query_id}/approve", response_model=PlannedQueryOut)
def approve_query(
    hunt_id: str,
    query_id: str,
    body: QueryApproveRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_approver),
):
    """
    Approve a planned query for execution.
    Optionally supply a modified_query if the approver wants to edit it first.
    """
    query = _get_query_or_404(hunt_id, query_id, db)

    if query.status != QueryStatus.PENDING_APPROVAL:
        raise HTTPException(
            status_code=400,
            detail=f"Query is not pending approval. Current status: {query.status.value}"
        )

    query.status = QueryStatus.APPROVED
    query.approved_by = current_user.id
    query.approved_at = datetime.now(timezone.utc)
    if body.modified_query:
        # Re-validate modified query for safety
        from agent.query_planner import validate_query
        is_safe, violation = validate_query(body.modified_query, query.query_language)
        if not is_safe:
            raise HTTPException(
                status_code=400,
                detail=f"Modified query failed safety validation: {violation}"
            )
        query.modified_query = body.modified_query

    log_action(
        db, AuditAction.QUERY_APPROVED,
        user_id=current_user.id,
        hunt_session_id=hunt_id,
        entity_type="planned_query", entity_id=query_id,
        payload_summary={
            "data_source": query.data_source.value,
            "query_language": query.query_language,
            "was_modified": body.modified_query is not None,
        },
        ip_address=request.client.host if request.client else None,
    )
    db.commit()
    _check_and_trigger_execution(hunt_id, db, background_tasks)
    return query


@router.post("/{query_id}/reject", response_model=PlannedQueryOut)
def reject_query(
    hunt_id: str,
    query_id: str,
    body: QueryRejectRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_approver),
):
    """Reject a planned query with a mandatory reason."""
    query = _get_query_or_404(hunt_id, query_id, db)

    if query.status != QueryStatus.PENDING_APPROVAL:
        raise HTTPException(
            status_code=400,
            detail=f"Query is not pending approval. Current status: {query.status.value}"
        )

    query.status = QueryStatus.REJECTED
    query.rejection_reason = body.rejection_reason

    log_action(
        db, AuditAction.QUERY_REJECTED,
        user_id=current_user.id,
        hunt_session_id=hunt_id,
        entity_type="planned_query", entity_id=query_id,
        payload_summary={
            "data_source": query.data_source.value,
            "rejection_reason": body.rejection_reason,
        },
        ip_address=request.client.host if request.client else None,
    )
    db.commit()
    return query


@router.post("/bulk-approve", response_model=list)
def bulk_approve(
    hunt_id: str,
    body: BulkApproveRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_approver),
):
    """Bulk approve multiple queries at once, optionally with per-query modifications."""
    from agent.query_planner import validate_query

    results = []
    for query_id in body.query_ids:
        query = db.query(PlannedQuery).filter(
            PlannedQuery.id == query_id,
            PlannedQuery.hunt_session_id == hunt_id,
        ).first()

        if not query:
            results.append({"query_id": query_id, "status": "not_found"})
            continue

        if query.status != QueryStatus.PENDING_APPROVAL:
            results.append({"query_id": query_id, "status": "skipped", "reason": query.status.value})
            continue

        modified = body.modified_queries.get(query_id) if body.modified_queries else None
        if modified:
            is_safe, violation = validate_query(modified, query.query_language)
            if not is_safe:
                results.append({"query_id": query_id, "status": "rejected_unsafe", "reason": violation})
                continue
            query.modified_query = modified

        query.status = QueryStatus.APPROVED
        query.approved_by = current_user.id
        query.approved_at = datetime.now(timezone.utc)

        log_action(
            db, AuditAction.QUERY_APPROVED,
            user_id=current_user.id,
            hunt_session_id=hunt_id,
            entity_type="planned_query", entity_id=query_id,
            payload_summary={"bulk": True, "data_source": query.data_source.value},
            ip_address=request.client.host if request.client else None,
        )
        results.append({"query_id": query_id, "status": "approved"})

    db.commit()
    _check_and_trigger_execution(hunt_id, db, background_tasks)
    return results


def _get_query_or_404(hunt_id: str, query_id: str, db: Session) -> PlannedQuery:
    query = db.query(PlannedQuery).filter(
        PlannedQuery.id == query_id,
        PlannedQuery.hunt_session_id == hunt_id,
    ).first()
    if not query:
        raise HTTPException(status_code=404, detail="Query not found")
    return query
