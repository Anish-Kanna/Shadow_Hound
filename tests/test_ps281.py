"""
ShadowHound — Full test suite

Run with:
    pytest tests/ -v --tb=short
    pytest tests/ -v -k "test_hypothesis"  # run specific tests
"""
import pytest
import json
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock, AsyncMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.models import Base, User, HuntSession, HuntStatus, HuntVerdict, UserRole, QueryStatus


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def db_engine():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture
def db(db_engine):
    Session = sessionmaker(bind=db_engine)
    session = Session()
    yield session
    session.rollback()
    session.close()


@pytest.fixture
def analyst_user(db):
    user = User(
        id="analyst-1",
        email="analyst@test.com",
        username="analyst1",
        full_name="Test Analyst",
        hashed_password="$2b$12$fakehash",
        role=UserRole.ANALYST,
    )
    db.add(user)
    db.flush()
    return user


@pytest.fixture
def approver_user(db):
    user = User(
        id="approver-1",
        email="approver@test.com",
        username="approver1",
        full_name="Test Approver",
        hashed_password="$2b$12$fakehash",
        role=UserRole.APPROVER,
    )
    db.add(user)
    db.flush()
    return user


@pytest.fixture
def hunt_session(db, analyst_user):
    session = HuntSession(
        id="hunt-1",
        title="Test Hunt — Lateral Movement via WMI",
        trigger_type="analyst_request",
        trigger_context={"description": "Suspected WMI lateral movement from finance segment"},
        analyst_id=analyst_user.id,
        status=HuntStatus.PENDING,
        verdict=HuntVerdict.PENDING,
        max_iterations=3,
        confidence_threshold=70,
    )
    db.add(session)
    db.flush()
    return session


# ── Auth tests ────────────────────────────────────────────────────────────────

class TestAuth:
    def test_password_hash_and_verify(self):
        from api.auth import hash_password, verify_password
        hashed = hash_password("SecurePassword123!")
        assert verify_password("SecurePassword123!", hashed)
        assert not verify_password("wrongpassword", hashed)

    def test_create_and_decode_access_token(self):
        from api.auth import create_access_token, decode_token
        token = create_access_token("user-123", "test@test.com", "analyst")
        payload = decode_token(token)
        assert payload["sub"] == "user-123"
        assert payload["email"] == "test@test.com"
        assert payload["role"] == "analyst"
        assert payload["type"] == "access"

    def test_create_and_decode_refresh_token(self):
        from api.auth import create_refresh_token, decode_token
        token = create_refresh_token("user-456")
        payload = decode_token(token)
        assert payload["sub"] == "user-456"
        assert payload["type"] == "refresh"

    def test_decode_invalid_token_raises(self):
        from api.auth import decode_token
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            decode_token("this.is.not.valid")
        assert exc_info.value.status_code == 401


# ── Hypothesis Engine tests ───────────────────────────────────────────────────

class TestHypothesisEngine:
    def test_generate_hypotheses_returns_list(self):
        from agent.hypothesis_engine import generate_hypotheses

        mock_response_data = {
            "hypotheses": [
                {
                    "description": "Adversary using WMI for lateral movement",
                    "mitre_tactics": ["TA0008"],
                    "mitre_techniques": ["T1047"],
                    "priority_rank": 1,
                    "priority_label": "high",
                    "intel_sources": ["internal"],
                    "suggested_data_sources": ["splunk", "crowdstrike"],
                    "initial_query_templates": {
                        "splunk": "index=* EventCode=4688 CommandLine=*wmic*"
                    }
                }
            ]
        }

        mock_response = MagicMock()
        mock_response.text = json.dumps(mock_response_data)

        with patch("agent.hypothesis_engine._get_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.models.generate_content.return_value = mock_response
            mock_get_client.return_value = mock_client
            hypotheses = generate_hypotheses(
                trigger_type="analyst_request",
                trigger_context={"description": "WMI lateral movement suspected"},
                available_data_sources=["splunk", "crowdstrike"],
                recent_intel=[],
            )

        assert isinstance(hypotheses, list)
        assert len(hypotheses) == 1
        assert hypotheses[0]["priority_rank"] == 1
        assert "T1047" in hypotheses[0]["mitre_techniques"]

    def test_generate_hypotheses_handles_malformed_json(self):
        from agent.hypothesis_engine import generate_hypotheses

        mock_response = MagicMock()
        mock_response.text = "not valid json at all"

        with patch("agent.hypothesis_engine._get_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.models.generate_content.return_value = mock_response
            mock_get_client.return_value = mock_client
            with pytest.raises(ValueError, match="invalid JSON"):
                generate_hypotheses(
                    trigger_type="analyst_request",
                    trigger_context={},
                    available_data_sources=["splunk"],
                    recent_intel=[],
                )

    def test_generate_hypotheses_strips_markdown_fences(self):
        from agent.hypothesis_engine import generate_hypotheses

        mock_response = {"hypotheses": [
            {"description": "Test", "mitre_tactics": [], "mitre_techniques": [],
             "priority_rank": 1, "priority_label": "medium",
             "intel_sources": [], "suggested_data_sources": [],
             "initial_query_templates": {}}
        ]}
        wrapped = f"```json\n{json.dumps(mock_response)}\n```"

        mock_response = MagicMock()
        mock_response.text = wrapped

        with patch("agent.hypothesis_engine._get_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.models.generate_content.return_value = mock_response
            mock_get_client.return_value = mock_client
            result = generate_hypotheses("analyst_request", {}, ["splunk"], [])

        assert len(result) == 1
        assert result[0]["description"] == "Test"


# ── Query Planner tests ───────────────────────────────────────────────────────

class TestQueryPlanner:
    def test_validate_query_blocks_delete(self):
        from agent.query_planner import validate_query
        is_safe, reason = validate_query("DELETE FROM logs WHERE id=1", "SQL")
        assert not is_safe
        assert "delete" in reason.lower()

    def test_validate_query_blocks_drop(self):
        from agent.query_planner import validate_query
        is_safe, reason = validate_query("DROP TABLE security_events", "SQL")
        assert not is_safe

    def test_validate_query_allows_safe_kql(self):
        from agent.query_planner import validate_query
        kql = """
        DeviceProcessEvents
        | where Timestamp >= ago(7d)
        | where ProcessCommandLine contains "wmic"
        | project Timestamp, DeviceName, ProcessCommandLine
        | limit 1000
        """
        is_safe, reason = validate_query(kql, "KQL")
        assert is_safe
        assert reason is None

    def test_validate_query_blocks_spl_outputlookup(self):
        from agent.query_planner import validate_query
        spl = "search index=* | outputlookup exfil.csv"
        is_safe, reason = validate_query(spl, "SPL")
        assert not is_safe

    def test_plan_queries_returns_list(self):
        from agent.query_planner import plan_queries

        mock_response_data = {
            "queries": [
                {
                    "data_source": "splunk",
                    "query_language": "SPL",
                    "query_text": "search index=* EventCode=4688 CommandLine=*wmic* | table _time, CommandLine, Computer | sort -_time | head 1000",
                    "query_rationale": "Find WMI process creations",
                    "estimated_cost": "medium",
                    "expected_field_results": ["_time", "CommandLine", "Computer"]
                }
            ]
        }

        mock_response = MagicMock()
        mock_response.text = json.dumps(mock_response_data)

        with patch("agent.query_planner._get_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.models.generate_content.return_value = mock_response
            mock_get_client.return_value = mock_client
            queries = plan_queries(
                hypothesis={"description": "WMI lateral movement", "mitre_tactics": ["TA0008"],
                            "mitre_techniques": ["T1047"], "priority_label": "high",
                            "suggested_data_sources": ["splunk"], "initial_query_templates": {}},
                available_data_sources=["splunk"],
            )

        assert isinstance(queries, list)
        assert len(queries) == 1
        assert queries[0]["validation_passed"] is True


# ── Evidence Aggregator tests ─────────────────────────────────────────────────

class TestEvidenceAggregator:
    def test_aggregate_evidence_returns_structure(self):
        from agent.evidence_aggregator import aggregate_evidence

        mock_response_data = {
            "per_source_analysis": [
                {
                    "data_source": "splunk",
                    "query_id": "query-1",
                    "classification": "confirming",
                    "confidence_score": 82,
                    "confidence_reasoning": "WMI process creation observed with lateral movement indicators",
                    "key_findings": ["WMI used to create process on remote host"],
                    "iocs_extracted": [{"type": "ip", "value": "10.0.0.42", "context": "destination", "malicious_confidence": 75}],
                    "mitre_techniques_observed": ["T1047"],
                    "timeline_entries": [{"timestamp": "2024-01-15T10:30:00Z", "event": "WMI remote exec", "actor": "svchost.exe", "source": "splunk"}]
                }
            ],
            "overall_assessment": {
                "composite_confidence": 82,
                "overall_classification": "confirming",
                "summary": "Strong evidence of WMI-based lateral movement.",
                "evidence_gaps": ["No network capture to confirm C2"],
                "recommended_next_queries": ["Check firewall logs for outbound connections"],
                "should_escalate_to_ir": False,
                "escalation_reasoning": ""
            }
        }

        mock_response = MagicMock()
        mock_response.text = json.dumps(mock_response_data)

        with patch("agent.evidence_aggregator._get_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.models.generate_content.return_value = mock_response
            mock_get_client.return_value = mock_client
            result = aggregate_evidence(
                hypothesis={"description": "WMI lateral movement", "mitre_tactics": ["TA0008"], "mitre_techniques": ["T1047"]},
                query_results=[{"query_id": "query-1", "data_source": "splunk", "rows_returned": 5, "result": {"rows": []}}],
            )

        assert "per_source_analysis" in result
        assert "overall_assessment" in result
        assert result["overall_assessment"]["composite_confidence"] == 82

    def test_decide_continuation_stops_at_threshold(self):
        from agent.evidence_aggregator import decide_loop_continuation
        should_continue, reason = decide_loop_continuation(
            composite_confidence=75, current_iteration=2, max_iterations=5,
            confidence_threshold=70, overall_classification="confirming", should_escalate=False
        )
        assert not should_continue
        assert "CONFIDENCE_THRESHOLD_MET" in reason

    def test_decide_continuation_continues_below_threshold(self):
        from agent.evidence_aggregator import decide_loop_continuation
        should_continue, reason = decide_loop_continuation(
            composite_confidence=45, current_iteration=2, max_iterations=5,
            confidence_threshold=70, overall_classification="neutral", should_escalate=False
        )
        assert should_continue
        assert "CONTINUE" in reason

    def test_decide_continuation_stops_at_max_iterations(self):
        from agent.evidence_aggregator import decide_loop_continuation
        should_continue, reason = decide_loop_continuation(
            composite_confidence=40, current_iteration=5, max_iterations=5,
            confidence_threshold=70, overall_classification="neutral", should_escalate=False
        )
        assert not should_continue
        assert "MAX_ITERATIONS" in reason

    def test_decide_continuation_stops_on_escalation(self):
        from agent.evidence_aggregator import decide_loop_continuation
        should_continue, reason = decide_loop_continuation(
            composite_confidence=90, current_iteration=1, max_iterations=5,
            confidence_threshold=70, overall_classification="confirming", should_escalate=True
        )
        assert not should_continue
        assert "ESCALATION" in reason


# ── Integration tests ─────────────────────────────────────────────────────────

class TestCrowdStrikeClient:
    def test_normalize_event(self):
        from integrations.edr.crowdstrike_client import CrowdStrikeClient
        raw = {
            "incident_id": "inc-123",
            "created": "2024-01-15T10:00:00Z",
            "status": "20",
            "severity": 80,
            "tactics": ["Lateral Movement"],
            "techniques": ["WMI"],
            "hosts": ["WORKSTATION01"],
            "users": ["jdoe"],
            "description": "WMI lateral movement detected",
        }
        normalized = CrowdStrikeClient._normalize_event(raw)
        assert normalized["incident_id"] == "inc-123"
        assert normalized["severity"] == 80
        assert "WORKSTATION01" in normalized["hosts"]


class TestVirusTotalClient:
    def test_detect_ip_type(self):
        from integrations.threat_intel.virustotal_client import VirusTotalClient
        assert VirusTotalClient._detect_type("192.168.1.1") == "ip"

    def test_detect_domain_type(self):
        from integrations.threat_intel.virustotal_client import VirusTotalClient
        assert VirusTotalClient._detect_type("malicious.example.com") == "domain"

    def test_detect_sha256_type(self):
        from integrations.threat_intel.virustotal_client import VirusTotalClient
        sha256 = "a" * 64
        assert VirusTotalClient._detect_type(sha256) == "file"

    def test_detect_url_type(self):
        from integrations.threat_intel.virustotal_client import VirusTotalClient
        assert VirusTotalClient._detect_type("https://malicious.com/payload") == "url"

    def test_detect_unknown_type(self):
        from integrations.threat_intel.virustotal_client import VirusTotalClient
        assert VirusTotalClient._detect_type("not_an_ioc_$$") == "unknown"


# ── Audit log tests ───────────────────────────────────────────────────────────

class TestAuditLog:
    def test_log_action_creates_entry(self, db, analyst_user, hunt_session):
        from api.audit import log_action, AuditAction
        entry = log_action(
            db,
            action_type=AuditAction.HUNT_CREATED,
            user_id=analyst_user.id,
            hunt_session_id=hunt_session.id,
            entity_type="hunt_session",
            entity_id=hunt_session.id,
            payload_summary={"title": "Test Hunt"},
            ip_address="127.0.0.1",
        )
        assert entry.id is not None
        assert entry.action_type == AuditAction.HUNT_CREATED
        assert entry.outcome == "success"
        assert entry.user_id == analyst_user.id

    def test_log_action_failure_outcome(self, db):
        from api.audit import log_action
        entry = log_action(
            db,
            action_type="auth.login_failed",
            outcome="failure",
            payload_summary={"email": "bad@test.com"},
            error_detail="Invalid password",
        )
        assert entry.outcome == "failure"
        assert entry.error_detail == "Invalid password"


# ── Query validation edge cases ───────────────────────────────────────────────

class TestQueryValidationEdgeCases:
    @pytest.mark.parametrize("query,language,should_pass", [
        ("SELECT timestamp, src_ip FROM firewall_logs WHERE action='DENY' LIMIT 1000", "SQL", True),
        ("DELETE FROM firewall_logs", "SQL", False),
        ("search index=network | where dest_port=443 | stats count by src_ip", "SPL", True),
        ("search index=network | outputlookup results.csv", "SPL", False),
        ("DeviceProcessEvents | where Timestamp >= ago(7d) | limit 1000", "KQL", True),
        ("DeviceProcessEvents | invoke SomeFunction()", "KQL", False),
        ("EXEC xp_cmdshell('whoami')", "SQL", False),
        ("sp_executesql N'SELECT 1'", "SQL", False),
    ])
    def test_query_validation(self, query, language, should_pass):
        from agent.query_planner import validate_query
        is_safe, reason = validate_query(query, language)
        assert is_safe == should_pass, f"Expected {should_pass} for: {query[:50]}"


# ── FastAPI integration test (using TestClient) ───────────────────────────────

class TestAPIEndpoints:
    @pytest.fixture
    def client(self, db, db_engine):
        from fastapi.testclient import TestClient
        from main import app
        from db.session import get_db

        def override_db():
            yield db

        app.dependency_overrides[get_db] = override_db
        # Patch the engine used in main.py's lifespan to avoid connecting to real PostgreSQL
        with patch("main.engine", db_engine), \
             patch("main.settings") as mock_settings:
            mock_settings.app_env = "testing"  # skip Base.metadata.create_all
            mock_settings.llm_model = "gemini-2.5-flash"
            mock_settings.otel_exporter_otlp_endpoint = "http://localhost:4317"
            mock_settings.otel_service_name = "shadowhound-test"
            with TestClient(app) as c:
                yield c
        app.dependency_overrides.clear()

    def test_health_endpoint(self, client):
        with patch("main.engine") as mock_engine:
            mock_conn = MagicMock()
            mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
            mock_engine.connect.return_value.__exit__ = MagicMock(return_value=False)
            # Health endpoint always returns 200 even if services are degraded
            resp = client.get("/health")
            assert resp.status_code == 200
            data = resp.json()
            assert "status" in data
            assert "version" in data

    def test_login_with_invalid_credentials(self, client, db):
        from api.auth import hash_password
        from db.models import User, UserRole
        user = User(
            id="api-test-user",
            email="apitest@test.com",
            username="apitest",
            full_name="API Test User",
            hashed_password=hash_password("CorrectPassword123!"),
            role=UserRole.ANALYST,
        )
        db.add(user)
        db.flush()

        resp = client.post("/api/v1/auth/login", json={"email": "apitest@test.com", "password": "WrongPassword"})
        assert resp.status_code == 401

    def test_protected_endpoint_without_token(self, client):
        resp = client.get("/api/v1/hunts")
        # HTTPBearer returns 401 when no Authorization header is provided
        assert resp.status_code in (401, 403)

    def test_login_returns_tokens(self, client, db):
        from api.auth import hash_password
        from db.models import User, UserRole
        user = User(
            id="login-test-user",
            email="logintest@test.com",
            username="logintest",
            full_name="Login Test User",
            hashed_password=hash_password("StrongPassword456!"),
            role=UserRole.ANALYST,
        )
        db.add(user)
        db.flush()

        resp = client.post("/api/v1/auth/login", json={"email": "logintest@test.com", "password": "StrongPassword456!"})
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
