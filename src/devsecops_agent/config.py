from typing import Optional, Literal
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration for the Autonomous DevSecOps Multi-Agent Framework."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Execution Environment
    ENVIRONMENT: str = "development"
    SANDBOX_DRIVER: Literal["auto", "docker", "local"] = "auto"
    SANDBOX_TIMEOUT_SECONDS: int = 45

    # LLM Settings (Hybrid Architecture)
    LLM_PROVIDER: Literal["mock", "ollama", "openai", "gemini"] = "mock"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_DEFAULT_MODEL: str = "qwen2.5-coder:7b"
    HOSTED_LLM_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    HOSTED_LLM_MODEL: str = "gpt-4o-mini"
    GEMINI_API_KEY: Optional[str] = None
    GEMINI_MODEL: str = "gemini-2.5-flash"

    # Orchestrator Policy
    MAX_PATCH_ATTEMPTS: int = 3
    AUTO_SUBMIT_PR: bool = False
    OUTPUT_REPORT_DIR: str = "reports"


settings = Settings()
