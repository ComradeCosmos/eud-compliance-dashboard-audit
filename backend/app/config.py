import os

class Settings:
    ENV: str = os.getenv("SAMP_ENV", "Development")  # Production, UAT, Development
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./samp_audit.db")
    ZAP_API_URL: str = os.getenv("ZAP_API_URL", "http://127.0.0.1:8090")
    ZAP_API_KEY: str = os.getenv("ZAP_API_KEY", "")
    ZAP_SIMULATION_MODE: bool = os.getenv("ZAP_SIMULATION_MODE", "True").lower() == "true"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "samp_fallback_secret_key_change_me_in_prod")

settings = Settings()
