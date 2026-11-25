"""Initial schema — all ShadowHound tables

Revision ID: 001_initial
Revises: None
Create Date: 2026-07-14
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Users ─────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("email", sa.String(), unique=True, nullable=False),
        sa.Column("username", sa.String(), unique=True, nullable=False),
        sa.Column("hashed_password", sa.String(), nullable=False),
        sa.Column("full_name", sa.String(), nullable=False),
        sa.Column("role", sa.Enum("analyst", "approver", "admin", name="userrole"), nullable=False),
        sa.Column("is_active", sa.Boolean(), default=True),
        sa.Column("mfa_enabled", sa.Boolean(), default=False),
        sa.Column("mfa_secret", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_users_username", "users", ["username"])

    # ── Hunt Sessions ─────────────────────────────────────────────────────────
    op.create_table(
        "hunt_sessions",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("trigger_type", sa.String(), nullable=False),
        sa.Column("trigger_context", sa.JSON(), nullable=False),
        sa.Column("status", sa.Enum(
            "pending", "hypothesizing", "planning", "awaiting_approval",
            "executing", "analyzing", "reporting", "completed", "failed", "cancelled",
            name="huntstatus"
        ), nullable=False),
        sa.Column("verdict", sa.Enum(
            "confirmed_threat", "inconclusive", "no_finding", "pending",
            name="huntverdict"
        ), nullable=False),
        sa.Column("analyst_id", sa.String(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("approver_id", sa.String(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("current_iteration", sa.Integer(), default=0),
        sa.Column("max_iterations", sa.Integer(), default=5),
        sa.Column("confidence_threshold", sa.Integer(), default=70),
        sa.Column("final_confidence", sa.Float(), nullable=True),
        sa.Column("celery_task_id", sa.String(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
    )
    op.create_index("ix_hunt_sessions_analyst_id", "hunt_sessions", ["analyst_id"])
    op.create_index("ix_hunt_sessions_status", "hunt_sessions", ["status"])
    op.create_index("ix_hunt_sessions_created_at", "hunt_sessions", ["created_at"])

    # ── Hypotheses ────────────────────────────────────────────────────────────
    op.create_table(
        "hypotheses",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("hunt_session_id", sa.String(), sa.ForeignKey("hunt_sessions.id"), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("mitre_tactics", sa.JSON(), default=[]),
        sa.Column("mitre_techniques", sa.JSON(), default=[]),
        sa.Column("priority_rank", sa.Integer(), nullable=False),
        sa.Column("priority_label", sa.String(), nullable=False),
        sa.Column("intel_sources", sa.JSON(), default=[]),
        sa.Column("suggested_data_sources", sa.JSON(), default=[]),
        sa.Column("initial_query_templates", sa.JSON(), default={}),
        sa.Column("iteration", sa.Integer(), default=1),
        sa.Column("is_active", sa.Boolean(), default=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Planned Queries ───────────────────────────────────────────────────────
    op.create_table(
        "planned_queries",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("hunt_session_id", sa.String(), sa.ForeignKey("hunt_sessions.id"), nullable=False),
        sa.Column("hypothesis_id", sa.String(), sa.ForeignKey("hypotheses.id"), nullable=False),
        sa.Column("data_source", sa.Enum(
            "crowdstrike", "sentinelone", "defender", "splunk", "sentinel",
            "elastic", "misp", "virustotal", "opencti", "playbooks",
            name="datasource"
        ), nullable=False),
        sa.Column("query_language", sa.String(), nullable=False),
        sa.Column("query_text", sa.Text(), nullable=False),
        sa.Column("query_rationale", sa.Text(), nullable=False),
        sa.Column("status", sa.Enum(
            "pending_approval", "approved", "rejected", "executed", "failed",
            name="querystatus"
        ), nullable=False),
        sa.Column("approved_by", sa.String(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("modified_query", sa.Text(), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("execution_duration_ms", sa.Integer(), nullable=True),
        sa.Column("rows_returned", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_planned_queries_session_status", "planned_queries", ["hunt_session_id", "status"])

    # ── Evidence ──────────────────────────────────────────────────────────────
    op.create_table(
        "evidence",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("hunt_session_id", sa.String(), sa.ForeignKey("hunt_sessions.id"), nullable=False),
        sa.Column("query_id", sa.String(), sa.ForeignKey("planned_queries.id"), nullable=False),
        sa.Column("data_source", sa.Enum(
            "crowdstrike", "sentinelone", "defender", "splunk", "sentinel",
            "elastic", "misp", "virustotal", "opencti", "playbooks",
            name="datasource"
        ), nullable=False),
        sa.Column("raw_data", sa.JSON(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("classification", sa.Enum(
            "confirming", "contradicting", "neutral",
            name="evidenceclassification"
        ), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False),
        sa.Column("confidence_reasoning", sa.Text(), nullable=False),
        sa.Column("iocs_extracted", sa.JSON(), default=[]),
        sa.Column("mitre_techniques_observed", sa.JSON(), default=[]),
        sa.Column("threat_timeline_entries", sa.JSON(), default=[]),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Hunt Reports ──────────────────────────────────────────────────────────
    op.create_table(
        "hunt_reports",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("hunt_session_id", sa.String(), sa.ForeignKey("hunt_sessions.id"), nullable=False, unique=True),
        sa.Column("verdict", sa.Enum(
            "confirmed_threat", "inconclusive", "no_finding", "pending",
            name="huntverdict"
        ), nullable=False),
        sa.Column("executive_summary", sa.Text(), nullable=False),
        sa.Column("hypothesis_summary", sa.JSON(), nullable=False),
        sa.Column("evidence_summary", sa.JSON(), nullable=False),
        sa.Column("threat_timeline", sa.JSON(), default=[]),
        sa.Column("ioc_list", sa.JSON(), default=[]),
        sa.Column("mitre_attack_map", sa.JSON(), default={}),
        sa.Column("analyst_recommendations", sa.JSON(), default=[]),
        sa.Column("hunt_metadata", sa.JSON(), default={}),
        sa.Column("final_confidence", sa.Float(), nullable=False),
        sa.Column("pdf_path", sa.String(), nullable=True),
        sa.Column("json_path", sa.String(), nullable=True),
        sa.Column("markdown_path", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Audit Logs ────────────────────────────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("hunt_session_id", sa.String(), sa.ForeignKey("hunt_sessions.id"), nullable=True),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("action_type", sa.String(), nullable=False),
        sa.Column("entity_type", sa.String(), nullable=True),
        sa.Column("entity_id", sa.String(), nullable=True),
        sa.Column("payload_summary", sa.JSON(), default={}),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("user_agent", sa.String(), nullable=True),
        sa.Column("outcome", sa.String(), nullable=False),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_audit_logs_action_type", "audit_logs", ["action_type"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])
    op.create_index("ix_audit_logs_action_created", "audit_logs", ["action_type", "created_at"])

    # ── Threat Intel Cache ────────────────────────────────────────────────────
    op.create_table(
        "threat_intel_cache",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("indicator_type", sa.String(), nullable=False),
        sa.Column("indicator_value", sa.String(), nullable=False),
        sa.Column("context", sa.JSON(), default={}),
        sa.Column("malicious", sa.Boolean(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_intel_cache_indicator", "threat_intel_cache", ["indicator_type", "indicator_value"])


def downgrade() -> None:
    op.drop_table("threat_intel_cache")
    op.drop_table("audit_logs")
    op.drop_table("hunt_reports")
    op.drop_table("evidence")
    op.drop_table("planned_queries")
    op.drop_table("hypotheses")
    op.drop_table("hunt_sessions")
    op.drop_table("users")

    # Drop enums (PostgreSQL only — SQLite ignores these)
    for name in ["userrole", "huntstatus", "huntverdict", "querystatus",
                 "datasource", "evidenceclassification"]:
        sa.Enum(name=name).drop(op.get_bind(), checkfirst=True)
