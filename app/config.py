import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Config:
    """Application configuration"""

    # Database Configuration
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = os.getenv("DB_PORT", "5432")
    DB_NAME = os.getenv("DB_NAME", "user_service_db")
    DB_USER = os.getenv("DB_USER", "postgres")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "postgres")

    # Build database URL
    DATABASE_URL = os.getenv(
        "DATABASE_URL",
        f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}",
    )

    # For development with SQLite, uncomment:
    # DATABASE_URL = 'sqlite:///./user_service.db'

    # JWT Configuration
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-this")
    JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_EXPIRATION_MINUTES = int(os.getenv("JWT_EXPIRATION_MINUTES", "15"))

    # gRPC Server Configuration
    GRPC_HOST = os.getenv("GRPC_HOST", "0.0.0.0")
    GRPC_PORT = int(os.getenv("GRPC_PORT", "50051"))

    # Email Configuration
    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "")
    SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"

    # Application Configuration
    APP_NAME = os.getenv("APP_NAME", "UserService")
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES = int(
        os.getenv("PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES", "30")
    )
    FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")


config = Config()
