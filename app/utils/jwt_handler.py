import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from app.config import config
import uuid


def generate_jwt(user_id: int, username: str, role: str = "user") -> str:
    """
    Generate a JWT token for a user

    Args:
        user_id: User's unique identifier (integer)
        username: User's username
        role: User's role (default: 'user')

    Returns:
        JWT token as string
    """
    now = datetime.now(timezone.utc)
    expiration = now + timedelta(minutes=config.JWT_EXPIRATION_MINUTES)

    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "iat": now,  # Issued at
        "exp": expiration,  # Expiration time
        "jti": str(uuid.uuid4()),  # JWT ID (unique identifier for this token)
    }

    token = jwt.encode(payload, config.JWT_SECRET_KEY, algorithm=config.JWT_ALGORITHM)

    return token


def validate_jwt(token: str) -> Dict[str, Any]:
    """
    Validate and decode a JWT token

    Args:
        token: JWT token string

    Returns:
        Dictionary with decoded payload and validation status
        {
            'valid': bool,
            'user_id': str,
            'username': str,
            'role': str,
            'jti': str,
            'exp': int,
            'error': str (if invalid)
        }
    """
    try:
        payload = jwt.decode(
            token, config.JWT_SECRET_KEY, algorithms=[config.JWT_ALGORITHM]
        )

        return {
            "valid": True,
            "user_id": payload.get("user_id"),
            "username": payload.get("username"),
            "role": payload.get("role", "user"),
            "jti": payload.get("jti"),
            "exp": payload.get("exp"),
        }
    except jwt.ExpiredSignatureError:
        return {"valid": False, "error": "Token has expired"}
    except jwt.InvalidTokenError as e:
        return {"valid": False, "error": f"Invalid token: {str(e)}"}
    except Exception as e:
        return {"valid": False, "error": f"Token validation error: {str(e)}"}


def generate_reset_token(user_id: int, expiration_minutes: Optional[int] = None) -> str:
    """
    Generate a password reset token

    Args:
        user_id: User's unique identifier (integer)
        expiration_minutes: Token expiration time in minutes

    Returns:
        Reset token as string
    """
    if expiration_minutes is None:
        expiration_minutes = config.PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES

    now = datetime.now(timezone.utc)
    expiration = now + timedelta(minutes=expiration_minutes)

    payload = {
        "user_id": user_id,
        "type": "password_reset",
        "iat": now,
        "exp": expiration,
        "jti": str(uuid.uuid4()),
    }

    token = jwt.encode(payload, config.JWT_SECRET_KEY, algorithm=config.JWT_ALGORITHM)

    return token


def validate_reset_token(token: str) -> Dict[str, Any]:
    """
    Validate a password reset token

    Args:
        token: Reset token string

    Returns:
        Dictionary with validation result
    """
    try:
        payload = jwt.decode(
            token, config.JWT_SECRET_KEY, algorithms=[config.JWT_ALGORITHM]
        )

        if payload.get("type") != "password_reset":
            return {"valid": False, "error": "Invalid token type"}

        return {
            "valid": True,
            "user_id": payload.get("user_id"),
            "jti": payload.get("jti"),
        }
    except jwt.ExpiredSignatureError:
        return {"valid": False, "error": "Reset token has expired"}
    except jwt.InvalidTokenError as e:
        return {"valid": False, "error": f"Invalid reset token: {str(e)}"}
    except Exception as e:
        return {"valid": False, "error": f"Token validation error: {str(e)}"}
