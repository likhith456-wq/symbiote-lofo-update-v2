import os
import smtplib
from email.message import EmailMessage


def email_mode():
    mode = os.getenv("EMAIL_MODE", "production").strip().lower()
    if mode not in {"development", "production"}:
        raise ValueError("EMAIL_MODE must be development or production.")
    if mode == "development":
        if os.getenv("APP_ENV", "").strip().lower() != "development":
            raise RuntimeError(
                "Development email mode requires APP_ENV=development."
            )
        deployment_markers = (
            "RENDER",
            "DYNO",
            "K_SERVICE",
            "VERCEL",
            "AWS_EXECUTION_ENV",
            "WEBSITE_INSTANCE_ID",
            "ECS_CONTAINER_METADATA_URI",
            "FLY_APP_NAME",
            "RAILWAY_ENVIRONMENT",
            "HEROKU_APP_NAME",
            "CF_INSTANCE_INDEX",
        )
        if any(
            os.getenv(name, "").strip().lower() in {"1", "true", "yes"}
            for name in deployment_markers
        ):
            raise RuntimeError(
                "Development email mode is disabled on hosted deployments."
            )
    return mode


def deliver_password_reset_code(recipient, code):
    if email_mode() == "development":
        return code

    host = os.getenv("SMTP_HOST", "").strip()
    sender = os.getenv("SMTP_FROM_EMAIL", "").strip() or os.getenv(
        "SMTP_USERNAME", ""
    ).strip()
    if not host or not sender:
        raise RuntimeError(
            "Production email delivery requires SMTP_HOST and a sender address."
        )

    message = EmailMessage()
    message["Subject"] = "Your Symbiote Lofo AI password reset code"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        f"Your password reset code is: {code}\n\n"
        "This code expires in 10 minutes. If you did not request a password reset, "
        "you can ignore this email."
    )
    with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587")), timeout=15) as server:
        if os.getenv("SMTP_USE_TLS", "true").strip().lower() == "true":
            server.starttls()
        username = os.getenv("SMTP_USERNAME", "").strip()
        password = os.getenv("SMTP_PASSWORD", "")
        if username and password:
            server.login(username, password)
        server.send_message(message, to_addrs=[recipient])
    return None
