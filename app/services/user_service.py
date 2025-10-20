import grpc
from datetime import datetime, timedelta
import logging
from typing import Optional
from uuid import UUID

# Import generated gRPC code (will be generated from proto file)
import app.generated.user_service_pb2 as user_service_pb2
import app.generated.user_service_pb2_grpc as user_service_pb2_grpc

# Import database and models
from app.database import SessionLocal
from app.models.user import User, Session, PasswordResetToken
from app.utils.password import hash_password, verify_password
from app.utils.jwt_handler import (
    generate_jwt,
    validate_jwt,
    generate_reset_token,
    validate_reset_token,
)
from app.services.email_service import email_service
from app.config import config

logger = logging.getLogger(__name__)


class UserServiceServicer(user_service_pb2_grpc.UserServiceServicer):
    """gRPC service implementation for UserService"""

    def SignUp(self, request, context):
        """Handle user registration"""
        db = SessionLocal()
        try:
            # Validate required fields
            if not all(
                [
                    request.username,
                    request.password,
                    request.first_name,
                    request.last_name,
                    request.shipping_address.street_name,
                    request.shipping_address.street_number,
                    request.shipping_address.city,
                    request.shipping_address.country,
                    request.shipping_address.postal_code,
                ]
            ):
                return user_service_pb2.SignUpResponse(
                    success=False, message="All fields are required"
                )

            # Check if username already exists
            existing_user = (
                db.query(User).filter(User.username == request.username).first()
            )
            if existing_user:
                return user_service_pb2.SignUpResponse(
                    success=False, message="Username already exists"
                )

            # Hash password
            password_hash = hash_password(request.password)

            # Create new user
            new_user = User(
                username=request.username,
                password_hash=password_hash,
                first_name=request.first_name,
                last_name=request.last_name,
                street_name=request.shipping_address.street_name,
                street_number=request.shipping_address.street_number,
                city=request.shipping_address.city,
                country=request.shipping_address.country,
                postal_code=request.shipping_address.postal_code,
            )

            db.add(new_user)
            db.commit()
            db.refresh(new_user)

            logger.info(f"User registered successfully: {new_user.username}")

            return user_service_pb2.SignUpResponse(
                success=True,
                message="User registered successfully",
                user_id=str(new_user.id),
            )

        except Exception as e:
            db.rollback()
            logger.error(f"Error during sign up: {str(e)}")
            return user_service_pb2.SignUpResponse(
                success=False, message=f"Registration failed: {str(e)}"
            )
        finally:
            db.close()

    def SignIn(self, request, context):
        """Handle user authentication"""
        db = SessionLocal()
        try:
            # Validate required fields
            if not request.username or not request.password:
                return user_service_pb2.SignInResponse(
                    success=False, message="Username and password are required"
                )

            # Find user by username
            user = db.query(User).filter(User.username == request.username).first()
            if not user:
                return user_service_pb2.SignInResponse(
                    success=False, message="User not found"
                )

            # Verify password
            if not verify_password(request.password, user.password_hash):
                return user_service_pb2.SignInResponse(
                    success=False, message="Invalid credentials"
                )

            # Generate JWT token
            jwt_token = generate_jwt(
                user_id=str(user.id), username=user.username, role=user.role
            )

            # Optionally store session for tracking (for logout functionality)
            token_data = validate_jwt(jwt_token)
            if token_data["valid"]:
                session = Session(
                    user_id=user.id,
                    token_jti=token_data["jti"],
                    expires_at=datetime.utcfromtimestamp(token_data["exp"]),
                )
                db.add(session)
                db.commit()

            logger.info(f"User signed in successfully: {user.username}")

            return user_service_pb2.SignInResponse(
                success=True,
                jwt=jwt_token,
                message="Sign in successful",
                user_id=str(user.id),
            )

        except Exception as e:
            db.rollback()
            logger.error(f"Error during sign in: {str(e)}")
            return user_service_pb2.SignInResponse(
                success=False, message=f"Sign in failed: {str(e)}"
            )
        finally:
            db.close()

    def ResetPassword(self, request, context):
        """Handle password reset request"""
        db = SessionLocal()
        try:
            # Validate required fields
            if not request.username and not request.email:
                return user_service_pb2.ResetPasswordResponse(
                    success=False, message="Username or email is required"
                )

            # Find user by username
            # Note: Since we don't have email field in User model, we use username
            user = db.query(User).filter(User.username == request.username).first()
            if not user:
                # Don't reveal if user exists or not for security
                return user_service_pb2.ResetPasswordResponse(
                    success=True,
                    message="If the user exists, a password reset email has been sent",
                )

            # Generate reset token
            reset_token = generate_reset_token(str(user.id))

            # Store reset token in database
            token_data = validate_reset_token(reset_token)
            if token_data["valid"]:
                reset_token_record = PasswordResetToken(
                    user_id=user.id,
                    token=token_data["jti"],
                    expires_at=datetime.utcnow()
                    + timedelta(minutes=config.PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES),
                )
                db.add(reset_token_record)
                db.commit()

            # Send password reset email
            # Note: We're using username as email for this example
            # In production, you would have a separate email field
            email_sent = email_service.send_password_reset_email(
                to_email=request.email or f"{user.username}@example.com",
                username=user.username,
                reset_token=reset_token,
            )

            if email_sent:
                logger.info(f"Password reset email sent to user: {user.username}")
            else:
                logger.warning(
                    f"Failed to send password reset email to: {user.username}"
                )

            return user_service_pb2.ResetPasswordResponse(
                success=True,
                message="If the user exists, a password reset email has been sent",
            )

        except Exception as e:
            db.rollback()
            logger.error(f"Error during password reset: {str(e)}")
            return user_service_pb2.ResetPasswordResponse(
                success=False, message="Password reset request failed"
            )
        finally:
            db.close()

    def ValidateToken(self, request, context):
        """Validate JWT token"""
        db = SessionLocal()
        try:
            # Validate required fields
            if not request.jwt:
                return user_service_pb2.ValidateTokenResponse(
                    valid=False, message="Token is required"
                )

            # Validate JWT
            token_data = validate_jwt(request.jwt)

            if not token_data["valid"]:
                return user_service_pb2.ValidateTokenResponse(
                    valid=False, message=token_data.get("error", "Invalid token")
                )

            # Check if session is revoked (for logout functionality)
            session = (
                db.query(Session).filter(Session.token_jti == token_data["jti"]).first()
            )

            if session and session.revoked == "true":
                return user_service_pb2.ValidateTokenResponse(
                    valid=False, message="Token has been revoked"
                )

            return user_service_pb2.ValidateTokenResponse(
                valid=True,
                user_id=token_data["user_id"],
                username=token_data["username"],
                role=token_data["role"],
                message="Token is valid",
            )

        except Exception as e:
            logger.error(f"Error during token validation: {str(e)}")
            return user_service_pb2.ValidateTokenResponse(
                valid=False, message=f"Token validation failed: {str(e)}"
            )
        finally:
            db.close()

    def GetUser(self, request, context):
        """Get user information by user ID"""
        db = SessionLocal()
        try:
            # Validate required fields
            if not request.user_id:
                return user_service_pb2.GetUserResponse(
                    success=False, message="User ID is required"
                )

            # Find user by ID
            try:
                user_uuid = UUID(request.user_id)
            except ValueError:
                return user_service_pb2.GetUserResponse(
                    success=False, message="Invalid user ID format"
                )

            user = db.query(User).filter(User.id == user_uuid).first()
            if not user:
                return user_service_pb2.GetUserResponse(
                    success=False, message="User not found"
                )

            # Create address message
            address = user_service_pb2.Address(
                street_name=user.street_name,
                street_number=user.street_number,
                city=user.city,
                country=user.country,
                postal_code=user.postal_code,
            )

            return user_service_pb2.GetUserResponse(
                success=True,
                user_id=str(user.id),
                username=user.username,
                first_name=user.first_name,
                last_name=user.last_name,
                shipping_address=address,
                message="User found",
            )

        except Exception as e:
            logger.error(f"Error getting user: {str(e)}")
            return user_service_pb2.GetUserResponse(
                success=False, message=f"Failed to get user: {str(e)}"
            )
        finally:
            db.close()

    def Logout(self, request, context):
        """Handle user logout by revoking token"""
        db = SessionLocal()
        try:
            # Validate required fields
            if not request.jwt:
                return user_service_pb2.LogoutResponse(
                    success=False, message="Token is required"
                )

            # Validate and extract token data
            token_data = validate_jwt(request.jwt)

            if not token_data["valid"]:
                return user_service_pb2.LogoutResponse(
                    success=False, message="Invalid token"
                )

            # Find and revoke session
            session = (
                db.query(Session).filter(Session.token_jti == token_data["jti"]).first()
            )

            if session:
                session.revoked = "true"
                session.revoked_at = datetime.utcnow()
                db.commit()

                logger.info(f"User logged out: {token_data['username']}")

                return user_service_pb2.LogoutResponse(
                    success=True, message="Logout successful"
                )
            else:
                return user_service_pb2.LogoutResponse(
                    success=False, message="Session not found"
                )

        except Exception as e:
            db.rollback()
            logger.error(f"Error during logout: {str(e)}")
            return user_service_pb2.LogoutResponse(
                success=False, message=f"Logout failed: {str(e)}"
            )
        finally:
            db.close()
