import os
from typing import List, Union, Optional
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "Cyber Monkey"
    API_V1_STR: str = "/api"
    
    # Environment configs loaded from .env
    DATABASE_URL: str
    SECRET_KEY: str
    CORS_ORIGINS: Union[List[str], str] = []
    
    # DNS Resolver Settings
    DNS_RESOLVER: Optional[str] = None
    DNS_TIMEOUT: float = 2.0
    
    # theHarvester Settings
    THEHARVESTER_PATH: str = "C:\\Tools\\theHarvester"
    THEHARVESTER_TIMEOUT: float = 300.0
    THEHARVESTER_SOURCES: str = "crtsh,certspotter"

    # Shodan Settings
    SHODAN_API_KEY: Optional[str] = None

    # Wazuh SOC Integration Settings
    WAZUH_API_URL: Optional[str] = None
    WAZUH_API_USER: Optional[str] = None
    WAZUH_API_PASSWORD: Optional[str] = None
    WAZUH_VERIFY_SSL: bool = False

    # Storage Paths
    MALWARE_STORAGE_PATH: str = "storage/malware_samples"
    FORENSICS_STORAGE_PATH: str = "storage/forensics_evidence"

    # AI Cyber Assistant Settings
    AI_PROVIDER: str = "none"
    OPENAI_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None
    AI_MODEL: Optional[str] = None

    # Network Telemetry Settings
    ZEEK_LOG_PATH: Optional[str] = None
    SURICATA_LOG_PATH: Optional[str] = None

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
