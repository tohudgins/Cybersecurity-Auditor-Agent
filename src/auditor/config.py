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

    # Models — all overridable via .env. Tiered by task:
    #   synthesis_model — compliance Q&A synthesis (quality-critical, cited answers)
    #   audit_model     — per-artifact audit finding extraction (summarizes scanner
    #                     output; a fast mini model keeps audits quick)
    #   fast_model      — executive summary (short, fast)
    # Defaults track the current OpenAI lineup (June 2026); bump them here or via
    # env as newer models ship — no other code change needed.
    embedding_model: str = Field(default="text-embedding-3-small", alias="AUDITOR_EMBEDDING_MODEL")
    synthesis_model: str = Field(default="gpt-5.5", alias="AUDITOR_SYNTHESIS_MODEL")
    audit_model: str = Field(default="gpt-5.4-mini", alias="AUDITOR_AUDIT_MODEL")
    fast_model: str = Field(default="gpt-5.4-mini", alias="AUDITOR_FAST_MODEL")
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

    # Default control baseline used as the assessment denominator (coverage) when
    # a run doesn't specify one. "moderate" = the NIST SP 800-53B Moderate set
    # (~191 controls) — the honest denominator a real engagement assesses against,
    # so most controls read "not-assessed" unless an artifact exercises them.
    # Set to "low" / "high" / "auditor-curated" to change the default.
    # Override per deployment via AUDITOR_DEFAULT_BASELINE.
    default_baseline: str = Field(default="moderate", alias="AUDITOR_DEFAULT_BASELINE")

    # Fast/deterministic mode default: when True, audits skip the LLM narrative
    # layer (per-artifact analysis + executive summary) for a near-instant
    # scanner/heuristic-only pass. The UI exposes a per-run toggle; this is the
    # fallback when a run doesn't specify one. Override via AUDITOR_FAST_MODE.
    fast_mode: bool = Field(default=False, alias="AUDITOR_FAST_MODE")

    # Security: when False, targets that touch the server's filesystem or OS
    # (codebase paths, host audits, chat-referenced files) are refused. Set
    # AUDITOR_ALLOW_LOCAL_TARGETS=false for shared/hosted deployments so a user
    # can't read or scan the server. Default True for normal local use.
    allow_local_targets: bool = Field(default=True, alias="AUDITOR_ALLOW_LOCAL_TARGETS")
    # Max size (bytes) of a chat-referenced file the intake parser will read.
    max_intake_file_bytes: int = 5_000_000
    # Adaptive scope planning: when True, the planning node may pull adjacent
    # attack surface into scope (e.g. a codebase's Dockerfile base image → a
    # container-image scan). Deterministic, bounded, and concurrent with the
    # main scan, so it broadens coverage without serial cost. Set
    # AUDITOR_AUTO_EXPAND_SCOPE=false to assess only the targets named.
    auto_expand_scope: bool = Field(default=True, alias="AUDITOR_AUTO_EXPAND_SCOPE")


settings = Settings()
