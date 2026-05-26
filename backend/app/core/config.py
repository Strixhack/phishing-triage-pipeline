from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "sqlite+aiosqlite:////data/triage.db"

    @property
    def async_database_url(self) -> str:
        url = self.database_url
        if url.startswith("sqlite:///") and "aiosqlite" not in url:
            url = url.replace("sqlite:///", "sqlite+aiosqlite:///")
        return url

    use_mock_stubs: bool = True

    vt_api_key: str = "MOCK"
    abuseipdb_api_key: str = "MOCK"
    misp_url: str = "MOCK"
    misp_api_key: str = "MOCK"
    thehive_url: str = "MOCK"
    thehive_api_key: str = "MOCK"
    cortex_url: str = "MOCK"
    cortex_api_key: str = "MOCK"

    mock_stub_base_url: str = "http://mock-stubs:9000"

    nis2_org_name: str = "Demo Organisation"
    nis2_early_warning_hours: int = 24
    nis2_notification_hours: int = 72
    nis2_significant_threshold: float = 55.0

    enable_yara: bool = True
    enable_mitre: bool = True
    enable_campaign_detection: bool = True
    enable_cortex: bool = True

    class Config:
        env_file = ".env"


settings = Settings()
