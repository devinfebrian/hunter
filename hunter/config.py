"""Configuration management for Hunter"""

from typing import List
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Hunter configuration"""
    model_config = {"env_file": ".env", "env_prefix": "HUNTER_"}
    
    # Kimi API Configuration (OpenAI-compatible)
    # Get API key from: https://platform.moonshot.cn/
    kimi_api_key: str = Field(default="", description="Kimi API key")
    
    # Model options: kimi-k2-5, kimi-k2-5-thinking, kimi-k2, kimi-k2-thinking
    kimi_model: str = Field(default="kimi-k2-5-thinking", description="Kimi model to use")
    
    kimi_base_url: str = Field(default="https://api.moonshot.cn/v1", description="Kimi API base URL")
    
    # Rate Limiting
    max_requests_per_minute: int = Field(default=100, description="Max requests per minute")
    delay_between_requests: float = Field(default=0.6, description="Delay between requests in seconds")
    
    # Safety Settings
    safe_mode: bool = Field(default=True, description="Enable safe mode - no destructive operations")
    auto_approve_level: str = Field(default="info", description="Auto-approve findings up to this level")
    require_approval_for: List[str] = Field(
        default_factory=lambda: ["sqli_write", "delete", "update"],
        description="Operations requiring explicit approval"
    )
    strict_scope: bool = Field(default=True, description="Strict scope enforcement")
    
    # Token Budgeting
    token_budget_recon: int = Field(default=50000, description="Token budget for reconnaissance")
    token_budget_analysis: int = Field(default=200000, description="Token budget per agent")
    token_budget_report: int = Field(default=20000, description="Token budget for reporting")
    
    # Tool Paths
    subfinder_path: str = Field(default="subfinder", description="Path to subfinder binary")
    assetfinder_path: str = Field(default="assetfinder", description="Path to assetfinder binary")
    httpx_path: str = Field(default="httpx", description="Path to httpx binary")
    
    # Output
    output_dir: str = Field(default="./output", description="Output directory")
    log_level: str = Field(default="INFO", description="Logging level")


# Global settings instance
settings = Settings()
