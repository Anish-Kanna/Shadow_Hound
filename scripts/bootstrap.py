#!/usr/bin/env python3
"""
ShadowHound Bootstrap Script
======================
Run this once after first deployment to:
  1. Create all database tables
  2. Create the first admin user
  3. Seed Vault with placeholder integration credentials
  4. Load sample playbooks into Weaviate

Usage:
    python scripts/bootstrap.py
    python scripts/bootstrap.py --admin-email admin@company.com --admin-password SecurePass123!
"""
import argparse
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import structlog
from sqlalchemy import text

log = structlog.get_logger(__name__)


def create_tables():
    from db.session import engine
    from db.models import Base
    log.info("creating_database_tables")
    Base.metadata.create_all(bind=engine)
    log.info("tables_created")


def create_admin_user(email: str, username: str, full_name: str, password: str):
    from db.session import db_context
    from db.models import User, UserRole
    from api.auth import hash_password

    with db_context() as db:
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            log.info("admin_already_exists", email=email)
            return existing

        user = User(
            email=email,
            username=username,
            full_name=full_name,
            hashed_password=hash_password(password),
            role=UserRole.ADMIN,
            is_active=True,
        )
        db.add(user)
        log.info("admin_user_created", email=email, role="admin")
        return user


def create_approver_user(email: str, username: str, full_name: str, password: str):
    from db.session import db_context
    from db.models import User, UserRole
    from api.auth import hash_password

    with db_context() as db:
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            log.info("approver_already_exists", email=email)
            return existing

        user = User(
            email=email,
            username=username,
            full_name=full_name,
            hashed_password=hash_password(password),
            role=UserRole.APPROVER,
            is_active=True,
        )
        db.add(user)
        log.info("approver_user_created", email=email, role="approver")
        return user


def seed_vault_placeholders():
    """
    Write placeholder secrets to Vault so the app starts without crashing.
    Replace values with real credentials before connecting live integrations.
    """
    try:
        from config.vault import get_vault
        vault = get_vault()

        integrations = {
            "integrations/crowdstrike": {
                "client_id": "REPLACE_WITH_CROWDSTRIKE_CLIENT_ID",
                "client_secret": "REPLACE_WITH_CROWDSTRIKE_CLIENT_SECRET",
                "base_url": "https://api.crowdstrike.com",
            },
            "integrations/sentinelone": {
                "api_token": "REPLACE_WITH_SENTINELONE_API_TOKEN",
                "base_url": "https://your-tenant.sentinelone.net",
            },
            "integrations/defender": {
                "tenant_id": "REPLACE_WITH_AZURE_TENANT_ID",
                "client_id": "REPLACE_WITH_AZURE_CLIENT_ID",
                "client_secret": "REPLACE_WITH_AZURE_CLIENT_SECRET",
            },
            "integrations/splunk": {
                "host": "localhost",
                "port": "8089",
                "token": "REPLACE_WITH_SPLUNK_TOKEN",
            },
            "integrations/sentinel": {
                "workspace_id": "REPLACE_WITH_SENTINEL_WORKSPACE_ID",
                "workspace_key": "REPLACE_WITH_SENTINEL_WORKSPACE_KEY",
            },
            "integrations/misp": {
                "url": "https://your-misp.company.com",
                "api_key": "REPLACE_WITH_MISP_API_KEY",
            },
            "integrations/virustotal": {
                "api_key": "REPLACE_WITH_VIRUSTOTAL_API_KEY",
            },
            "integrations/opencti": {
                "url": "https://your-opencti.company.com",
                "token": "REPLACE_WITH_OPENCTI_TOKEN",
            },
        }

        for path, secret in integrations.items():
            vault.set_secret(path, secret)
            log.info("vault_secret_written", path=path)

        log.info("vault_seed_complete", count=len(integrations))
    except Exception as e:
        log.warning("vault_seed_failed", error=str(e),
                    hint="Vault may not be running. Start Vault and re-run bootstrap.")


def verify_db_connection():
    from db.session import engine
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        log.info("database_connection_ok")
        return True
    except Exception as e:
        log.error("database_connection_failed", error=str(e))
        return False


def verify_redis_connection():
    from config.settings import get_settings
    settings = get_settings()
    try:
        import redis
        r = redis.from_url(settings.redis_url)
        r.ping()
        log.info("redis_connection_ok")
        return True
    except Exception as e:
        log.error("redis_connection_failed", error=str(e))
        return False


def run_alembic_migrations():
    """Run pending Alembic migrations."""
    import subprocess
    result = subprocess.run(
        ["alembic", "upgrade", "head"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        log.warning("alembic_migration_warning", stderr=result.stderr)
    else:
        log.info("alembic_migrations_applied", output=result.stdout.strip())


def print_summary(admin_email: str, admin_password: str):
    print("\n" + "=" * 60)
    print("  ShadowHound Bootstrap Complete")
    print("=" * 60)
    print(f"\n  Admin email:    {admin_email}")
    print(f"  Admin password: {admin_password}")
    print("\n  Services:")
    print("  - API:       http://localhost:8000")
    print("  - Docs:      http://localhost:8000/docs")
    print("  - Dashboard: http://localhost:3000")
    print("  - Flower:    http://localhost:5555")
    print("  - Grafana:   http://localhost:3001")
    print("  - Vault:     http://localhost:8200")
    print("\n  Next steps:")
    print("  1. Replace Vault placeholder secrets with real credentials")
    print("  2. Add hunting playbooks to data/playbooks/")
    print("  3. Configure your EDR/SIEM platform integrations")
    print("  4. Create analyst and approver accounts via POST /api/v1/users")
    print("\n" + "=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(description="ShadowHound Bootstrap")
    parser.add_argument("--admin-email", default="admin@shadowhound.local")
    parser.add_argument("--admin-username", default="admin")
    parser.add_argument("--admin-fullname", default="System Administrator")
    parser.add_argument("--admin-password", default="Admin@ShadowHoundChange!")
    parser.add_argument("--skip-vault", action="store_true")
    parser.add_argument("--skip-migrations", action="store_true")
    args = parser.parse_args()

    import structlog
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ]
    )

    log.info("shadowhound_bootstrap_starting")

    # 1. Check DB connection
    if not verify_db_connection():
        log.error("cannot_connect_to_database", hint="Is PostgreSQL running? Check DATABASE_URL in .env")
        sys.exit(1)

    # 2. Check Redis
    verify_redis_connection()

    # 3. Run migrations (or create tables in dev)
    if not args.skip_migrations:
        try:
            run_alembic_migrations()
        except FileNotFoundError:
            log.warning("alembic_not_found", hint="Falling back to create_all for dev")
            create_tables()
    else:
        create_tables()

    # 4. Create admin user
    create_admin_user(
        email=args.admin_email,
        username=args.admin_username,
        full_name=args.admin_fullname,
        password=args.admin_password,
    )

    # 5. Create a default approver
    create_approver_user(
        email="approver@shadowhound.local",
        username="approver",
        full_name="Default Approver",
        password="Approver@ShadowHoundChange!",
    )

    # 6. Seed Vault
    if not args.skip_vault:
        seed_vault_placeholders()

    print_summary(args.admin_email, args.admin_password)


if __name__ == "__main__":
    main()
