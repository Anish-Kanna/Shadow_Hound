from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from db.session import get_db
from db.models import User, AuditLog
from api.schemas import (
    LoginRequest, TokenResponse, RefreshRequest,
    UserCreate, UserOut, UserUpdate
)
from api.auth import (
    verify_password, hash_password, create_access_token,
    create_refresh_token, decode_token, get_current_user, require_admin
)
from api.audit import log_action, AuditAction
from config.settings import get_settings

settings = get_settings()

auth_router = APIRouter(prefix="/auth", tags=["auth"])
users_router = APIRouter(prefix="/users", tags=["users"])


# ── Auth endpoints ────────────────────────────────────────────────────────────

@auth_router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()

    if not user or not verify_password(body.password, user.hashed_password):
        log_action(db, AuditAction.LOGIN_FAILED, outcome="failure",
                   payload_summary={"email": body.email},
                   ip_address=request.client.host if request.client else None)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated")

    access_token = create_access_token(user.id, user.email, user.role.value)
    refresh_token = create_refresh_token(user.id)

    log_action(db, AuditAction.LOGIN, user_id=user.id,
               payload_summary={"email": user.email},
               ip_address=request.client.host if request.client else None)
    db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@auth_router.post("/refresh", response_model=TokenResponse)
def refresh_token(body: RefreshRequest, db: Session = Depends(get_db)):
    payload = decode_token(body.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Expected refresh token")

    user = db.query(User).filter(User.id == payload["sub"]).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    access_token = create_access_token(user.id, user.email, user.role.value)
    new_refresh = create_refresh_token(user.id)

    log_action(db, AuditAction.TOKEN_REFRESH, user_id=user.id)
    db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@auth_router.get("/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user


# ── User management (Admin only) ──────────────────────────────────────────────

@users_router.post("", response_model=UserOut, status_code=201)
def create_user(
    body: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")

    user = User(
        email=body.email,
        username=body.username,
        full_name=body.full_name,
        hashed_password=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    db.flush()
    log_action(db, AuditAction.USER_CREATED, user_id=current_user.id,
               entity_type="user", entity_id=user.id,
               payload_summary={"email": body.email, "role": body.role.value})
    db.commit()
    return user


@users_router.get("", response_model=list)
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    return [UserOut.model_validate(u) for u in db.query(User).order_by(User.created_at).all()]


@users_router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: str,
    body: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if body.full_name is not None:
        user.full_name = body.full_name
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.role is not None:
        user.role = body.role

    log_action(db, AuditAction.USER_UPDATED, user_id=current_user.id,
               entity_type="user", entity_id=user_id,
               payload_summary=body.model_dump(exclude_none=True))
    db.commit()
    return user


@users_router.get("/audit-log")
def get_audit_log(
    page: int = 1,
    page_size: int = 50,
    action_type: str = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    query = db.query(AuditLog)
    if action_type:
        query = query.filter(AuditLog.action_type == action_type)
    total = query.count()
    logs = query.order_by(desc(AuditLog.created_at)).offset(
        (page - 1) * page_size
    ).limit(page_size).all()
    return {"items": logs, "total": total, "page": page, "page_size": page_size}
