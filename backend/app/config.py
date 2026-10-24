from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BACKEND_DIR / "data"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=(".env", "../.env"), extra="ignore")

    # Database. Postgres in docker/prod; SQLite works for quick local runs and tests.
    database_url: str = f"sqlite:///{BACKEND_DIR / 'triage.db'}"

    # LLM
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-sonnet-5-5"
    llm_temperature: float | None = None  # leave unset to use the model default
    max_tool_rounds: int = 4
    # USD per million tokens, used for the cost-per-alert metric.
    # Check https://www.anthropic.com/pricing and set these for the model you use.
    price_input_per_mtok: float = 3.0
    price_output_per_mtok: float = 15.0

    # Guardrail: verdicts below this confidence go to a human instead of auto-closing.
    review_confidence_threshold: float = 0.6

    # Threat intel. "fixtures" uses data/intel_fixtures.json (deterministic, no keys),
    # "live" calls AbuseIPDB / VirusTotal, "auto" goes live only when keys are set.
    intel_mode: str = "auto"
    abuseipdb_api_key: str | None = None
    virustotal_api_key: str | None = None
    intel_cache_ttl_hours: int = 24

    # ATT&CK mapper: "auto" tries sentence-transformers, falls back to TF-IDF.
    embedding_backend: str = "auto"
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"

    # Which triage engine the API uses: "auto" = LLM agent if a key is set, else rules baseline.
    triage_engine: str = "auto"

    cors_origins: str = "http://localhost:3000"

    @property
    def use_llm(self) -> bool:
        if self.triage_engine == "llm":
            return True
        if self.triage_engine == "baseline":
            return False
        return bool(self.anthropic_api_key)


@lru_cache
def get_settings() -> Settings:
    return Settings()
