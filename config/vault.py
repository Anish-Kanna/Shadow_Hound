import hvac
import structlog
from functools import lru_cache
from typing import Optional, Dict, Any
from config.settings import get_settings

log = structlog.get_logger(__name__)
settings = get_settings()


class VaultClient:
    def __init__(self):
        self._client = hvac.Client(url=settings.vault_url, token=settings.vault_token)
        self._mount = settings.vault_mount_path

    def _ensure_authenticated(self):
        if not self._client.is_authenticated():
            raise RuntimeError("Vault client is not authenticated")

    def get_secret(self, path: str) -> Optional[Dict[str, Any]]:
        self._ensure_authenticated()
        try:
            response = self._client.secrets.kv.v2.read_secret_version(
                path=path, mount_point=self._mount
            )
            return response["data"]["data"]
        except Exception as e:
            log.error("vault_read_error", path=path, error=str(e))
            return None

    def set_secret(self, path: str, data: Dict[str, Any]) -> bool:
        self._ensure_authenticated()
        try:
            self._client.secrets.kv.v2.create_or_update_secret(
                path=path, secret=data, mount_point=self._mount
            )
            return True
        except Exception as e:
            log.error("vault_write_error", path=path, error=str(e))
            return False

    def get_integration_creds(self, integration: str) -> Dict[str, str]:
        secret = self.get_secret(f"integrations/{integration}")
        if not secret:
            log.warning("vault_creds_missing", integration=integration)
            return {}
        return secret


@lru_cache()
def get_vault() -> VaultClient:
    return VaultClient()
