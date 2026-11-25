from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime
from db.models import (
    HuntStatus, HuntVerdict, QueryStatus, UserRole,
    DataSource, EvidenceClassification
)


# ── Auth ──────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


# ── User ──────────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    full_name: str = Field(..., min_length=2, max_length=100)
    password: str = Field(..., min_length=12)
    role: UserRole = UserRole.ANALYST


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    username: str
    full_name: str
    role: UserRole
    is_active: bool
    mfa_enabled: bool
    created_at: datetime


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    is_active: Optional[bool] = None
    role: Optional[UserRole] = None


# ── Hunt Session ──────────────────────────────────────────────────────────────

class HuntCreateRequest(BaseModel):
    title: str = Field(..., min_length=5, max_length=200)
    trigger_type: str = Field(..., pattern="^(analyst_request|scheduled|intel_alert)$")
    trigger_context: Dict[str, Any] = Field(default_factory=dict)
    max_iterations: int = Field(default=5, ge=1, le=10)
    confidence_threshold: int = Field(default=70, ge=50, le=99)


class HypothesisOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    description: str
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    priority_rank: int
    priority_label: str
    intel_sources: List[str]
    suggested_data_sources: List[str]
    iteration: int
    is_active: bool
    created_at: datetime


class PlannedQueryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    hypothesis_id: str
    data_source: DataSource
    query_language: str
    query_text: str
    query_rationale: str
    status: QueryStatus
    approved_by: Optional[str]
    approved_at: Optional[datetime]
    rejection_reason: Optional[str]
    modified_query: Optional[str]
    executed_at: Optional[datetime]
    execution_duration_ms: Optional[int]
    rows_returned: Optional[int]
    created_at: datetime


class EvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    data_source: DataSource
    summary: str
    classification: EvidenceClassification
    confidence_score: float
    confidence_reasoning: str
    iocs_extracted: List[Dict[str, Any]]
    mitre_techniques_observed: List[str]
    created_at: datetime


class HuntSessionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    title: str
    trigger_type: str
    trigger_context: Dict[str, Any]
    status: HuntStatus
    verdict: HuntVerdict
    analyst_id: str
    current_iteration: int
    max_iterations: int
    confidence_threshold: int
    final_confidence: Optional[float]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    error_message: Optional[str]


class HuntSessionDetail(HuntSessionOut):
    hypotheses: List[HypothesisOut] = []
    queries: List[PlannedQueryOut] = []
    evidence: List[EvidenceOut] = []


# ── Query Approval ────────────────────────────────────────────────────────────

class QueryApproveRequest(BaseModel):
    modified_query: Optional[str] = None  # If approver edits the query


class QueryRejectRequest(BaseModel):
    rejection_reason: str = Field(..., min_length=10)


class BulkApproveRequest(BaseModel):
    query_ids: List[str]
    modified_queries: Optional[Dict[str, str]] = None  # {query_id: modified_text}


# ── Report ────────────────────────────────────────────────────────────────────

class HuntReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    hunt_session_id: str
    verdict: HuntVerdict
    executive_summary: str
    hypothesis_summary: Dict[str, Any]
    evidence_summary: List[Dict[str, Any]]
    threat_timeline: List[Dict[str, Any]]
    ioc_list: List[Dict[str, Any]]
    mitre_attack_map: Dict[str, Any]
    analyst_recommendations: List[Dict[str, Any]]
    hunt_metadata: Dict[str, Any]
    final_confidence: float
    pdf_path: Optional[str]
    json_path: Optional[str]
    markdown_path: Optional[str]
    created_at: datetime


# ── Pagination ────────────────────────────────────────────────────────────────

class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    page_size: int
    pages: int


# ── Cancel ────────────────────────────────────────────────────────────────────

class CancelHuntRequest(BaseModel):
    reason: Optional[str] = None


# ── Health ────────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    version: str = "1.0.0"
    environment: str
    database: str
    redis: str
    llm: str
