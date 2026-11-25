import structlog
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from db.models import (
    HuntSession, Hypothesis, PlannedQuery, Evidence, HuntStatus, HuntVerdict,
    QueryStatus, EvidenceClassification, DataSource
)
from agent.hypothesis_engine import generate_hypotheses
from agent.query_planner import plan_queries
from agent.evidence_aggregator import aggregate_evidence, decide_loop_continuation
from agent.report_builder import build_report
from integrations.dispatcher import QueryDispatcher
from config.settings import get_settings

log = structlog.get_logger(__name__)
settings = get_settings()


class HuntOrchestrator:
    """
    Central orchestrator for the ShadowHound threat hunting agent loop.

    Phases:
      1. Hypothesize
      2. Plan queries
      3. Wait for analyst approval (async — orchestrator pauses, resumes when approved)
      4. Execute approved queries
      5. Aggregate evidence
      6. Decide: continue loop or generate report
      7. Report
    """

    def __init__(self, db: Session, dispatcher: Optional[QueryDispatcher] = None):
        self.db = db
        self.dispatcher = dispatcher or QueryDispatcher()

    # ── Phase 1: Hypothesize ────────────────────────────────────────────────

    def run_hypothesis_phase(self, session: HuntSession, iteration: int) -> List[Hypothesis]:
        log.info("phase_hypothesize", session_id=session.id, iteration=iteration)

        session.status = HuntStatus.HYPOTHESIZING
        self.db.commit()

        available_sources = self._get_available_sources()
        recent_intel = self._fetch_recent_intel()

        previous_hypotheses = None
        evidence_so_far = None

        if iteration > 1:
            previous_hypotheses = [
                {
                    "description": h.description,
                    "mitre_techniques": h.mitre_techniques,
                    "priority_rank": h.priority_rank,
                }
                for h in session.hypotheses if h.iteration == iteration - 1
            ]
            evidence_so_far = [
                {
                    "data_source": e.data_source.value,
                    "summary": e.summary,
                    "classification": e.classification.value,
                    "confidence_score": e.confidence_score,
                }
                for e in session.evidence
            ]

        raw_hypotheses = generate_hypotheses(
            trigger_type=session.trigger_type,
            trigger_context=session.trigger_context,
            available_data_sources=available_sources,
            recent_intel=recent_intel,
            previous_hypotheses=previous_hypotheses,
            evidence_so_far=evidence_so_far,
            iteration=iteration,
        )

        # Persist hypotheses
        db_hypotheses = []
        for i, h in enumerate(raw_hypotheses):
            db_h = Hypothesis(
                hunt_session_id=session.id,
                description=h["description"],
                mitre_tactics=h.get("mitre_tactics", []),
                mitre_techniques=h.get("mitre_techniques", []),
                priority_rank=h.get("priority_rank", i + 1),
                priority_label=h.get("priority_label", "medium"),
                intel_sources=h.get("intel_sources", []),
                suggested_data_sources=h.get("suggested_data_sources", []),
                initial_query_templates=h.get("initial_query_templates", {}),
                iteration=iteration,
                is_active=(i == 0),  # Top-ranked is active
            )
            self.db.add(db_h)
            db_hypotheses.append(db_h)

        self.db.commit()
        log.info("hypotheses_persisted", count=len(db_hypotheses))
        return db_hypotheses

    # ── Phase 2: Plan Queries ────────────────────────────────────────────────

    def run_query_planning_phase(
        self, session: HuntSession, hypothesis: Hypothesis,
        evidence_gaps: Optional[List[str]] = None
    ) -> List[PlannedQuery]:
        log.info("phase_query_planning", session_id=session.id, hypothesis_id=hypothesis.id)

        session.status = HuntStatus.PLANNING
        self.db.commit()

        available_sources = self._get_available_sources()
        h_dict = {
            "description": hypothesis.description,
            "mitre_tactics": hypothesis.mitre_tactics,
            "mitre_techniques": hypothesis.mitre_techniques,
            "priority_label": hypothesis.priority_label,
            "suggested_data_sources": hypothesis.suggested_data_sources,
            "initial_query_templates": hypothesis.initial_query_templates,
        }

        planned = plan_queries(h_dict, available_sources, evidence_gaps)

        db_queries = []
        for q in planned:
            if not q.get("validation_passed", False):
                log.warning("skipping_invalid_query",
                            source=q["data_source"],
                            violation=q.get("validation_violation"))
                continue

            try:
                ds = DataSource(q["data_source"])
            except ValueError:
                log.warning("unknown_data_source", source=q["data_source"])
                continue

            db_q = PlannedQuery(
                hunt_session_id=session.id,
                hypothesis_id=hypothesis.id,
                data_source=ds,
                query_language=q.get("query_language", "unknown"),
                query_text=q["query_text"],
                query_rationale=q["query_rationale"],
                status=QueryStatus.PENDING_APPROVAL,
            )
            self.db.add(db_q)
            db_queries.append(db_q)

        session.status = HuntStatus.AWAITING_APPROVAL
        self.db.commit()

        log.info("queries_planned_and_pending", count=len(db_queries))
        return db_queries

    # ── Phase 3: Approval (async — handled by API endpoint) ─────────────────
    # Approval is done via POST /api/hunts/{id}/queries/{qid}/approve
    # The Celery task resumes once all queries are approved/rejected.

    # ── Phase 4: Execute Queries ─────────────────────────────────────────────

    def run_execution_phase(self, session: HuntSession) -> List[Dict[str, Any]]:
        log.info("phase_execution", session_id=session.id)

        session.status = HuntStatus.EXECUTING
        self.db.commit()

        approved_queries = [
            q for q in session.queries
            if q.status == QueryStatus.APPROVED
        ]

        results = []
        for query in approved_queries:
            final_query_text = query.modified_query or query.query_text
            log.info("executing_query",
                     query_id=str(query.id),
                     source=query.data_source.value)

            start_time = datetime.now(timezone.utc)
            try:
                raw_result = self.dispatcher.dispatch(
                    data_source=query.data_source.value,
                    query_language=query.query_language,
                    query_text=final_query_text,
                )
                duration_ms = int(
                    (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                )
                query.executed_at = datetime.now(timezone.utc)
                query.execution_duration_ms = duration_ms
                query.rows_returned = len(raw_result.get("rows", []))
                query.status = QueryStatus.EXECUTED

                results.append({
                    "query_id": str(query.id),
                    "data_source": query.data_source.value,
                    "query_language": query.query_language,
                    "query_text": final_query_text,
                    "rows_returned": query.rows_returned,
                    "result": raw_result,
                    "duration_ms": duration_ms,
                })
            except Exception as e:
                log.error("query_execution_failed",
                          query_id=str(query.id),
                          source=query.data_source.value,
                          error=str(e))
                query.status = QueryStatus.FAILED
                results.append({
                    "query_id": str(query.id),
                    "data_source": query.data_source.value,
                    "error": str(e),
                    "rows_returned": 0,
                    "result": {},
                })

        self.db.commit()
        log.info("execution_complete", results_count=len(results))
        return results

    # ── Phase 5: Aggregate Evidence ──────────────────────────────────────────

    def run_analysis_phase(
        self, session: HuntSession, hypothesis: Hypothesis,
        query_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        log.info("phase_analysis", session_id=session.id)

        session.status = HuntStatus.ANALYZING
        self.db.commit()

        previous_evidence = [
            {
                "data_source": e.data_source.value,
                "summary": e.summary,
                "classification": e.classification.value,
                "confidence_score": e.confidence_score,
            }
            for e in session.evidence
        ]

        h_dict = {
            "description": hypothesis.description,
            "mitre_tactics": hypothesis.mitre_tactics,
            "mitre_techniques": hypothesis.mitre_techniques,
        }

        analysis = aggregate_evidence(h_dict, query_results, previous_evidence or None)

        # Persist per-source evidence
        for source_analysis in analysis.get("per_source_analysis", []):
            query_id = source_analysis.get("query_id")
            try:
                ds = DataSource(source_analysis["data_source"])
            except ValueError:
                ds = DataSource.PLAYBOOKS  # fallback

            try:
                cls = EvidenceClassification(source_analysis["classification"])
            except ValueError:
                cls = EvidenceClassification.NEUTRAL

            ev = Evidence(
                hunt_session_id=session.id,
                query_id=query_id,
                data_source=ds,
                raw_data=source_analysis,
                summary="; ".join(source_analysis.get("key_findings", [])),
                classification=cls,
                confidence_score=float(source_analysis.get("confidence_score", 0)),
                confidence_reasoning=source_analysis.get("confidence_reasoning", ""),
                iocs_extracted=source_analysis.get("iocs_extracted", []),
                mitre_techniques_observed=source_analysis.get("mitre_techniques_observed", []),
                threat_timeline_entries=source_analysis.get("timeline_entries", []),
            )
            self.db.add(ev)

        self.db.commit()
        return analysis

    # ── Phase 6: Loop Decision ───────────────────────────────────────────────

    def decide_continuation(
        self, session: HuntSession, analysis: Dict[str, Any]
    ) -> tuple[bool, str]:
        overall = analysis.get("overall_assessment", {})
        composite_confidence = float(overall.get("composite_confidence", 0))
        classification = overall.get("overall_classification", "neutral")
        should_escalate = overall.get("should_escalate_to_ir", False)

        session.current_iteration += 1
        session.final_confidence = composite_confidence
        self.db.commit()

        return decide_loop_continuation(
            composite_confidence=composite_confidence,
            current_iteration=session.current_iteration,
            max_iterations=session.max_iterations,
            confidence_threshold=session.confidence_threshold,
            overall_classification=classification,
            should_escalate=should_escalate,
        )

    # ── Phase 7: Report ──────────────────────────────────────────────────────

    def run_report_phase(self, session: HuntSession) -> str:
        log.info("phase_reporting", session_id=session.id)

        session.status = HuntStatus.REPORTING
        self.db.commit()

        report_path = build_report(session, self.db)

        session.status = HuntStatus.COMPLETED
        session.completed_at = datetime.now(timezone.utc)
        self.db.commit()

        return report_path

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _get_available_sources(self) -> List[str]:
        configured = []
        s = settings

        if s.crowdstrike_client_id:
            configured.append("crowdstrike")
        if s.sentinelone_api_token:
            configured.append("sentinelone")
        if s.defender_tenant_id:
            configured.append("defender")
        if s.splunk_token:
            configured.append("splunk")
        if s.sentinel_workspace_id:
            configured.append("sentinel")
        if s.misp_api_key:
            configured.append("misp")
        if s.virustotal_api_key:
            configured.append("virustotal")
        if s.opencti_token:
            configured.append("opencti")

        # Always include playbooks
        configured.append("playbooks")

        return configured

    def _fetch_recent_intel(self) -> List[Dict[str, Any]]:
        """Fetch recent threat intel for hypothesis context. Returns empty list gracefully."""
        try:
            from integrations.threat_intel.misp_client import MISPClient
            mc = MISPClient()
            return mc.get_recent_events(days=7, limit=20)
        except Exception as e:
            log.warning("intel_fetch_failed", error=str(e))
            return []
