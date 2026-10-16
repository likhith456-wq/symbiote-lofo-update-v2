import json
import os
import smtplib
from email.message import EmailMessage
from urllib.error import HTTPError
from urllib.request import Request, urlopen


class EmailDeliveryError(ValueError):
    pass


def password_reset_email_configured():
    resend_configured = bool(
        os.getenv("RESEND_API_KEY", "").strip()
        and os.getenv("RESEND_FROM_EMAIL", "").strip()
    )
    smtp_sender = os.getenv("SMTP_FROM_EMAIL", "").strip() or os.getenv(
        "SMTP_USERNAME", ""
    ).strip()
    smtp_configured = bool(os.getenv("SMTP_HOST", "").strip() and smtp_sender)
    return bool(resend_configured or smtp_configured)


def send_password_reset_email(recipient, code):
    subject = "Your Symbiote Lofo AI password reset code"
    body = (
        f"Your password reset verification code is: {code}\n\n"
        "This code expires in 10 minutes. If you did not request a password reset, "
        "you can ignore this email."
    )
    api_key = os.getenv("RESEND_API_KEY", "").strip()
    resend_sender = os.getenv("RESEND_FROM_EMAIL", "").strip()
    if api_key and resend_sender:
        request = Request(
            "https://api.resend.com/emails",
            data=json.dumps(
                {
                    "from": resend_sender,
                    "to": [recipient],
                    "subject": subject,
                    "text": body,
                }
            ).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=15) as response:
                response.read()
        except HTTPError as error:
            messages = {
                401: (
                    "Resend rejected the API key (HTTP 401). Check that "
                    "RESEND_API_KEY is valid and active."
                ),
                403: (
                    "Resend denied the request (HTTP 403). Check the API key "
                    "permissions and verify the sender domain."
                ),
                422: (
                    "Resend rejected the email details (HTTP 422). Check that "
                    "RESEND_FROM_EMAIL is a valid address on a verified domain."
                ),
                429: (
                    "Resend rate-limited the request (HTTP 429). Wait briefly "
                    "before requesting another code."
                ),
            }
            message = messages.get(
                error.code,
                f"Resend could not send the email (HTTP {error.code}). "
                "Check the Resend service and configuration.",
            )
            raise EmailDeliveryError(message) from error
        return

    host = os.getenv("SMTP_HOST", "").strip()
    sender = os.getenv("SMTP_FROM_EMAIL", "").strip() or os.getenv(
        "SMTP_USERNAME", ""
    ).strip()
    if not host or not sender:
        raise ValueError(
            "Configure RESEND_API_KEY and RESEND_FROM_EMAIL, or SMTP_HOST and "
            "SMTP_FROM_EMAIL (or SMTP_USERNAME)."
        )
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = recipient
    message.set_content(body)
    with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587")), timeout=15) as server:
        if os.getenv("SMTP_USE_TLS", "true").lower() == "true":
            server.starttls()
        username = os.getenv("SMTP_USERNAME")
        password = os.getenv("SMTP_PASSWORD")
        if username and password:
            server.login(username, password)
        server.send_message(message, to_addrs=[recipient])
