from sqlalchemy import Column, String, DateTime, Integer, BigInteger
from datetime import datetime
from app.database import Base


class User(Base):
    """User model for storing user account information"""

    __tablename__ = "users"

    # Primary Key - auto-incrementing integer
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Authentication fields
    username = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)

    # Personal Information
    first_name = Column(String(255), nullable=False)
    last_name = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)

    # Shipping Address
    street_name = Column(String(255), nullable=False)
    street_number = Column(String(50), nullable=False)
    city = Column(String(255), nullable=False)
    country = Column(String(255), nullable=False)
    postal_code = Column(String(20), nullable=False)

    # Role (for future use - RBAC)
    role = Column(String(50), default="user", nullable=False)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    # Password Reset (optional tracking)
    last_password_reset = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<User(id={self.id}, username={self.username})>"

    def to_dict(self):
        """Convert user object to dictionary (exclude sensitive data)"""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "street_name": self.street_name,
            "street_number": self.street_number,
            "city": self.city,
            "country": self.country,
            "postal_code": self.postal_code,
            "role": self.role,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Session(Base):
    """Session model for tracking user sessions (optional - for logout functionality)"""

    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=False, index=True)
    token_jti = Column(String(255), unique=True, nullable=False, index=True)  # JWT ID
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(
        String(10), default="false", nullable=False
    )  # 'true' or 'false' as string
    revoked_at = Column(DateTime, nullable=True)

    def __repr__(self):
        return (
            f"<Session(id={self.id}, user_id={self.user_id}, revoked={self.revoked})>"
        )


class PasswordResetToken(Base):
    """Password reset token model for tracking password reset requests"""

    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=False, index=True)
    token = Column(String(255), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(
        String(10), default="false", nullable=False
    )  # 'true' or 'false' as string
    used_at = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<PasswordResetToken(id={self.id}, user_id={self.user_id}, used={self.used})>"
