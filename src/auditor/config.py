from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    openai_api_key: str = Field(..., alias="OPENAI_API_KEY")

    data_dir: Path = PROJECT_ROOT / "data"
    chroma_dir: Path = PROJECT_ROOT / ".chromadb"
    chroma_collection: str = "frameworks_v2"

    embedding_model: str = "text-embedding-3-small"
    synthesis_model: str = "gpt-5"
    fast_model: str = "gpt-5-mini"
    # Reasoning effort for the compliance-Q&A synthesis call. The task is
    # grounded extraction from cited excerpts, not open-ended reasoning, so
    # "low" cuts time-to-first-token sharply without hurting answer quality.
    synthesis_reasoning_effort: str = "low"
    # Reasoning effort for audit-path LLM calls (per-artifact finding extraction
    # and the executive summary). These summarize scanner/heuristic output that's
    # already been gathered, so "low" effort keeps quality while cutting latency.
    audit_reasoning_effort: str = "low"

    chunk_size: int = 1000
    chunk_overlap: int = 100
    retrieval_k: int = 10

    # Security: when False, targets that touch the server's filesystem or OS
    # (codebase paths, host audits, chat-referenced files) are refused. Set
    # AUDITOR_ALLOW_LOCAL_TARGETS=false for shared/hosted deployments so a user
    # can't read or scan the server. Default True for normal local use.
    allow_local_targets: bool = Field(default=True, alias="AUDITOR_ALLOW_LOCAL_TARGETS")
    # Max size (bytes) of a chat-referenced file the intake parser will read.
    max_intake_file_bytes: int = 5_000_000


settings = Settings()
