import structlog
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from config.settings import get_settings
from db.session import engine
from db.models import Base
from api.routers.hunts import router as hunts_router
from api.routers.queries import router as queries_router
from api.routers.auth_users import auth_router, users_router

log = structlog.get_logger(__name__)
settings = get_settings()


def setup_telemetry(app: FastAPI):
    try:
        import socket
        host, port = settings.otel_exporter_otlp_endpoint.replace("http://", "").split(":")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        sock.connect((host, int(port)))
        sock.close()
    except Exception:
        # OTel collector not available — skip tracing to avoid retry delays
        return

    provider = TracerProvider()
    exporter = OTLPSpanExporter(endpoint=settings.otel_exporter_otlp_endpoint)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app)


def setup_structlog():
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    setup_structlog()
    log.info("shadowhound_starting", env=settings.app_env, model=settings.llm_model)

    # Create all DB tables (use Alembic in production instead)
    if settings.app_env == "development":
        Base.metadata.create_all(bind=engine)
        log.info("database_tables_created")

    yield

    # Shutdown
    log.info("shadowhound_shutting_down")


app = FastAPI(
    title="ShadowHound — AI Threat Hunting Agent",
    description="Agentic AI system for hypothesis-driven threat hunting",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── Middleware ─────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # dashboard dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    log.info("http_request", method=request.method, path=request.url.path,
             client=request.client.host if request.client else None)
    response = await call_next(request)
    log.info("http_response", method=request.method, path=request.url.path,
             status_code=response.status_code)
    return response


# ── Global exception handler ──────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    log.exception("unhandled_exception", path=request.url.path, error=str(exc))
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal error occurred. Please contact support."},
    )


# ── Routers ───────────────────────────────────────────────────────────────────

app.include_router(auth_router, prefix="/api/v1")
app.include_router(users_router, prefix="/api/v1")
app.include_router(hunts_router, prefix="/api/v1")
app.include_router(queries_router, prefix="/api/v1")


# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/health", tags=["health"])
async def health_check():
    from sqlalchemy import text
    import redis as redis_lib

    db_status = "ok"
    redis_status = "ok"
    llm_status = "ok"

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"error: {e}"

    try:
        r = redis_lib.from_url(settings.redis_url)
        r.ping()
    except Exception as e:
        redis_status = f"error: {e}"

    try:
        from google import genai
        genai_client = genai.Client(api_key=settings.gemini_api_key)
        genai_client.models.generate_content(
            model=settings.llm_model,
            contents="ping",
            config={"max_output_tokens": 5},
        )
    except Exception as e:
        llm_status = f"error: {e}"

    overall = "ok" if all(s == "ok" for s in [db_status, redis_status, llm_status]) else "degraded"
    return {
        "status": overall,
        "version": "1.0.0",
        "environment": settings.app_env,
        "database": db_status,
        "redis": redis_status,
        "llm": llm_status,
    }


# ── Setup telemetry ───────────────────────────────────────────────────────────
setup_telemetry(app)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.app_host, port=settings.app_port,
                reload=(settings.app_env == "development"), log_level=settings.log_level.lower())
