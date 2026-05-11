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

    chunk_size: int = 1000
    chunk_overlap: int = 100
    retrieval_k: int = 10


settings = Settings()
