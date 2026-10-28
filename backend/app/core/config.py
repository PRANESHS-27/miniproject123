"""Centralized configuration loaded from environment / .env file."""

from functools import lru_cache
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings.

    Values are read from environment variables or a .env file.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ===== Application =====
    app_name: str = "VulnWatch"
    app_env: str = "development"
    # ``secret_key`` MUST be set in any non-development environment. We
    # ship a non-empty dev fallback so `uvicorn app.main:app` works out of
    # the box, but the main app refuses to start in production if it sees
    # this fallback. See :func:`app.core.security.assert_safe_secret`.
    secret_key: str = Field(
        default="dev-only-do-not-use-in-production-XYZ-please-set-SECRET_KEY"
    )
    access_token_expire_minutes: int = 1440
    refresh_token_expire_minutes: int = 60 * 24 * 7  # 7 days
    algorithm: str = "HS256"

    # ===== Bootstrap admin (24a) =====
    # All three are required for the first-run admin to be created. When
    # the user table is empty, ``_bootstrap_admin`` creates an account
    # using these values. Defaults exist for development convenience, but
    # ``APP_ENV=production`` requires all three to be set explicitly —
    # shipping a default-credential admin is the single most common
    # production-deploy mistake.
    admin_username: str = "admin"
    admin_email: str = "admin@vulnwatch.local"
    admin_password: str = "Admin@123"
    # When True, refuses to seed the bootstrap admin at all if the
    # operator hasn't supplied ADMIN_PASSWORD. Recommended for any
    # production-style environment so the admin row must be created via
    # the registration endpoint by a real operator who knows the secret.
    require_admin_password: bool = False

    # ===== Database =====
    database_url: str = "sqlite:///./vulnwatch.db"

    # ===== AI / LLM =====
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o-mini"
    ollama_host: Optional[str] = None
    ollama_model: str = "llama3.1"
    # Gemini (Google AI Studio) — free tier, no card required.
    # https://aistudio.google.com/apikey
    gemini_api_key: Optional[str] = None
    gemini_model: str = "gemini-2.0-flash"
    # Groq — free hosted LLM inference (very fast). https://console.groq.com/keys
    groq_api_key: Optional[str] = None
    groq_model: str = "llama-3.1-8b-instant"

    # ===== Vector store =====
    chroma_persist_dir: str = "./chroma-data"
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"

    # ===== CVE Sources =====
    nvd_api_key: Optional[str] = None
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cisa_kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )

    # ===== Filters =====
    # Comma-separated list of CPE vendor strings to **exclude** from the
    # vulnerability feed and from CVE matching. Case-insensitive.
    # Default blocks "Apple/Google/etc." brand-bundle CVEs that aren't
    # relevant to server-side / web app stacks.
    excluded_vendors: str = "apple,google,microsoft,adobe,oracle"

    # ===== Scheduler =====
    fetch_interval_hours: int = 24
    fetch_results_per_page: int = 2000

    # Master kill-switch for the in-process APScheduler. When False, the
    # scheduler stays dormant (no automatic NVD / KEV / asset scans).
    # Use ``python -m scheduler.run_once`` to refetch manually.
    enable_scheduler: bool = True

    # ===== Networking =====
    # TLS verification for outbound HTTPS to NVD / CISA. Leave empty to skip
    # certificate verification by default — Windows + corporate AV (Avast,
    # Kaspersky, etc.) intercepts TLS with a custom root that Python's certifi
    # bundle doesn't include, which would otherwise break every sync.
    # Set to a PEM path (e.g. certifi.where()) to enable verification.
    # Values: ""  -> skip verify (default), "true" -> default trust store,
    # "/path/to/bundle.pem" -> use that CA bundle, "false"/"0"/"no" -> skip verify.
    ssl_verify: str = Field(default="true")

    # CORS — comma-separated list of allowed origins for the API. Empty
    # means use the default localhost dev origins. Wildcards are not
    # supported (incompatible with credentials).
    cors_allowed_origins: str = ""

    # ===== Rate limiting (24c) =====
    # Max login attempts per minute per client IP. Lower in production,
    # higher (or 0 = disabled) for local dev convenience.
    login_rate_limit_per_minute: int = 5

    # ===== Asset scanner =====
    asset_scan_interval_hours: int = 24
    asset_scan_timeout_seconds: float = 10.0
    asset_scan_max_concurrency: int = 5
    asset_scan_user_agent: str = "VulnWatch/1.0 AssetScanner (+https://vulnwatch.local)"

    # ===== Backups (free-priority #20) =====
    # Local directory the backup script writes to. Operators should mount
    # a persistent volume here in production so the file survives container
    # restarts.
    backup_dir: str = "./backups"
    # How many local + S3 backups ``backup prune --keep N`` retains.
    backup_retention_count: int = 7
    # Opt-in: when True, the in-process APScheduler runs a daily backup
    # job (see app/services/scheduler_jobs.py). Off by default so a
    # dev install doesn't accidentally spam S3.
    backup_enabled: bool = False
    # UTC hour for the daily backup (0-23). 03:00 UTC is the default —
    # low-traffic for most operators.
    backup_schedule_hour_utc: int = 3
    # Opt-in: when True AND AWS credentials are set, every backup is
    # uploaded to ``s3_bucket`` under ``backups/<name>``. Kept separate
    # from "is S3 configured" so operators with S3 configured for other
    # features can still keep backups local-only.
    backup_upload_to_s3: bool = False

    # ===== Health / sync monitoring (free-priority #19) =====
    # A sync source is considered "stale" if its last successful run is
    # older than this many hours. Surfaces in /api/sync/status and
    # /api/health so operators see a red flag before NVD drift becomes
    # a missed-CVE incident.
    sync_stale_hours: int = 48
    # Asset scans are scheduled daily; consider them stale after this
    # many hours of inactivity. 36h catches a missed daily run before
    # the second miss.
    asset_scan_stale_hours: int = 36

    @property
    def asset_probe_paths(self) -> list[str]:
        """Default list of admin / sensitive paths to probe. Overridable via
        ``ASSET_PROBE_PATHS`` in env (comma-separated)."""
        from os import getenv

        raw = getenv("ASSET_PROBE_PATHS")
        if raw:
            return [p.strip() for p in raw.split(",") if p.strip()]
        return [
            "/.env",
            "/.git/HEAD",
            "/wp-admin/",
            "/wp-login.php",
            "/administrator/",
            "/admin/",
            "/phpmyadmin/",
            "/server-status",
            "/server-info",
            "/elmah.axd",
            "/manager/html",
            "/actuator/env",
            "/api/",
            "/.well-known/security.txt",
        ]

    # ===== AWS =====
    aws_region: Optional[str] = None
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    s3_bucket: Optional[str] = None

    # Convenience properties ------------------------------------------------
    @property
    def use_openai(self) -> bool:
        return bool(self.openai_api_key)


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()


settings = get_settings()