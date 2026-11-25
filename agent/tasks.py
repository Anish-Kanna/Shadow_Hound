import structlog
from datetime import datetime, timezone
from celery import Celery
from celery.signals import task_failure, task_success
from config.settings import get_settings
from db.session import db_context
from db.models import HuntSession, HuntStatus, QueryStatus

log = structlog.get_logger(__name__)
settings = get_settings()

celery_app = Celery(
    "shadowhound",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_soft_time_limit=settings.max_hunt_duration_minutes * 60,
    task_time_limit=(settings.max_hunt_duration_minutes + 10) * 60,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
)


@celery_app.task(bind=True, name="shadowhound.run_hunt", max_retries=0)
def run_hunt_task(self, session_id: str):
    """
    Main async task that runs the full hunt loop.
    Pauses at the approval gate and resumes when all queries are approved.
    """
    from agent.orchestrator import HuntOrchestrator

    log.info("hunt_task_started", session_id=session_id, task_id=self.request.id)

    with db_context() as db:
        session = db.query(HuntSession).filter(HuntSession.id == session_id).first()
        if not session:
            log.error("hunt_session_not_found", session_id=session_id)
            return {"status": "error", "reason": "session_not_found"}

        session.celery_task_id = self.request.id
        session.started_at = datetime.now(timezone.utc)
        db.commit()

        orchestrator = HuntOrchestrator(db)

        try:
            for iteration in range(1, session.max_iterations + 1):
                log.info("hunt_iteration_start", session_id=session_id, iteration=iteration)

                # Phase 1: Generate/Refine Hypotheses
                hypotheses = orchestrator.run_hypothesis_phase(session, iteration)
                if not hypotheses:
                    log.error("no_hypotheses_generated", session_id=session_id)
                    session.status = HuntStatus.FAILED
                    session.error_message = "No hypotheses could be generated"
                    db.commit()
                    return {"status": "failed", "reason": "no_hypotheses"}

                top_hypothesis = hypotheses[0]

                # Gather any evidence gaps from previous iteration
                evidence_gaps = []
                if iteration > 1:
                    from db.models import Evidence
                    all_evidence = db.query(Evidence).filter(
                        Evidence.hunt_session_id == session_id
                    ).all()
                    # Evidence gaps stored in raw_data from last aggregation
                    if all_evidence:
                        last_ev = all_evidence[-1]
                        evidence_gaps = (last_ev.raw_data or {}).get(
                            "evidence_gaps", []
                        )

                # Phase 2: Plan Queries
                queries = orchestrator.run_query_planning_phase(
                    session, top_hypothesis, evidence_gaps
                )

                # Phase 3: Wait for approval
                # Approval is done by the analyst via API.
                # The task polls (or uses a Redis event) for all queries to be resolved.
                approval_result = _wait_for_approval(session_id, [str(q.id) for q in queries])

                if approval_result == "cancelled":
                    session.status = HuntStatus.CANCELLED
                    db.commit()
                    return {"status": "cancelled"}

                # Phase 4: Execute approved queries
                query_results = orchestrator.run_execution_phase(session)

                if not query_results:
                    log.warning("no_results_from_execution", session_id=session_id)

                # Phase 5: Aggregate Evidence
                analysis = orchestrator.run_analysis_phase(
                    session, top_hypothesis, query_results
                )

                # Phase 6: Decide continuation
                should_continue, reason = orchestrator.decide_continuation(session, analysis)
                log.info("loop_decision", session_id=session_id,
                         should_continue=should_continue, reason=reason)

                if not should_continue:
                    break

            # Phase 7: Generate Report
            report_path = orchestrator.run_report_phase(session)
            log.info("hunt_complete", session_id=session_id, report_path=report_path)
            return {"status": "completed", "report_path": report_path}

        except Exception as e:
            log.exception("hunt_task_failed", session_id=session_id, error=str(e))
            session.status = HuntStatus.FAILED
            session.error_message = str(e)
            db.commit()
            raise


def _wait_for_approval(session_id: str, query_ids: list, poll_interval: int = 10,
                       max_wait_seconds: int = 7200) -> str:
    """
    Poll until all queries are approved or rejected, or the session is cancelled.
    Returns 'ready' or 'cancelled'.
    """
    import time
    import redis as redis_lib

    r = redis_lib.from_url(settings.redis_url)
    cancel_key = f"shadowhound:hunt:{session_id}:cancel"
    elapsed = 0

    while elapsed < max_wait_seconds:
        if r.exists(cancel_key):
            log.info("hunt_cancelled_during_approval", session_id=session_id)
            return "cancelled"

        with db_context() as db:
            queries = db.query(
                __import__("db.models", fromlist=["PlannedQuery"]).PlannedQuery
            ).filter(
                __import__("db.models", fromlist=["PlannedQuery"]).PlannedQuery.id.in_(query_ids)
            ).all()

            statuses = {q.status for q in queries}
            pending = {QueryStatus.PENDING_APPROVAL} & statuses

            if not pending:
                log.info("all_queries_resolved", session_id=session_id)
                return "ready"

        time.sleep(poll_interval)
        elapsed += poll_interval

    log.warning("approval_wait_timeout", session_id=session_id)
    return "ready"  # Proceed with whatever was approved


@celery_app.task(name="shadowhound.cancel_hunt")
def cancel_hunt_task(session_id: str):
    """Signal a running hunt to cancel."""
    import redis as redis_lib
    r = redis_lib.from_url(settings.redis_url)
    r.setex(f"shadowhound:hunt:{session_id}:cancel", 3600, "1")
    log.info("hunt_cancel_signal_sent", session_id=session_id)
