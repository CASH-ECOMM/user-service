import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
import logging
from app.config import config

logger = logging.getLogger(__name__)


class EmailService:
    """Service for sending emails"""

    def __init__(self):
        self.smtp_host = config.SMTP_HOST
        self.smtp_port = config.SMTP_PORT
        self.smtp_username = config.SMTP_USERNAME
        self.smtp_password = config.SMTP_PASSWORD
        self.from_email = config.SMTP_FROM_EMAIL
        self.use_tls = config.SMTP_USE_TLS

    def send_email(
        self, to_email: str, subject: str, body: str, html: Optional[str] = None
    ) -> bool:
        """
        Send an email

        Args:
            to_email: Recipient email address
            subject: Email subject
            body: Plain text email body
            html: Optional HTML email body

        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            # Create message
            msg = MIMEMultipart("alternative")
            msg["From"] = self.from_email
            msg["To"] = to_email
            msg["Subject"] = subject

            # Attach plain text
            text_part = MIMEText(body, "plain")
            msg.attach(text_part)

            # Attach HTML if provided
            if html:
                html_part = MIMEText(html, "html")
                msg.attach(html_part)

            # Connect to SMTP server and send
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()

                if self.smtp_username and self.smtp_password:
                    server.login(self.smtp_username, self.smtp_password)

                server.send_message(msg)

            logger.info(f"Email sent successfully to {to_email}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {str(e)}")
            return False

    def send_password_reset_email(
        self, to_email: str, username: str, reset_token: str
    ) -> bool:
        """
        Send a password reset email

        Args:
            to_email: Recipient email address
            username: User's username
            reset_token: Password reset token

        Returns:
            True if email sent successfully, False otherwise
        """
        reset_url = f"{config.FRONTEND_URL}/reset-password?token={reset_token}"

        subject = f"{config.APP_NAME} - Password Reset Request"

        body = f"""
Hello {username},

You requested to reset your password for your {config.APP_NAME} account.

Please click the link below to reset your password:

{reset_url}

This link will expire in {config.PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES} minutes.

If you did not request a password reset, please ignore this email.

Best regards,
{config.APP_NAME} Team
"""

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .button {{ 
            display: inline-block; 
            padding: 12px 24px; 
            background-color: #007bff; 
            color: white; 
            text-decoration: none; 
            border-radius: 5px; 
            margin: 20px 0;
        }}
        .footer {{ margin-top: 30px; font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>Password Reset Request</h2>
        <p>Hello {username},</p>
        <p>You requested to reset your password for your {config.APP_NAME} account.</p>
        <p>Please click the button below to reset your password:</p>
        <a href="{reset_url}" class="button">Reset Password</a>
        <p>This link will expire in {config.PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES} minutes.</p>
        <p>If you did not request a password reset, please ignore this email.</p>
        <div class="footer">
            <p>Best regards,<br>{config.APP_NAME} Team</p>
        </div>
    </div>
</body>
</html>
"""

        return self.send_email(to_email, subject, body, html)


# Create a singleton instance
email_service = EmailService()
