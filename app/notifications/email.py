"""Email notifications via SMTP. Uses config credentials; sanitizes content."""

import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.config import get_settings
from app.security.sanitization import sanitize_text

logger = logging.getLogger(__name__)

MAX_SUBJECT_LENGTH = 200
MAX_BODY_LENGTH = 50_000


async def send_alert_email(
    to_email: str,
    subject: str,
    body_plain: str,
    body_html: str | None = None,
) -> bool:
    """
    Send an email using SMTP settings from config. Returns True if sent.
    to_email, subject, and body are sanitized and length-limited.
    """
    settings = get_settings()
    if not settings.smtp_host or not (to_email or "").strip():
        logger.debug("email.not_configured")
        return False

    to_addr = sanitize_text(to_email.strip())[:255]
    if not to_addr or "@" not in to_addr:
        logger.warning("email.invalid_recipient")
        return False

    subj = sanitize_text(subject.strip())[:MAX_SUBJECT_LENGTH]
    plain = sanitize_text(body_plain.strip())[:MAX_BODY_LENGTH]
    if body_html:
        html = sanitize_text(body_html.strip())[:MAX_BODY_LENGTH]
    else:
        html = None

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subj
    msg["From"] = settings.smtp_user or "noreply@kestrel.local"
    msg["To"] = to_addr
    msg.attach(MIMEText(plain, "plain", "utf-8"))
    if html:
        msg.attach(MIMEText(html, "html", "utf-8"))

    try:
        import aiosmtplib

        use_tls = settings.smtp_port in (587, 465)
        smtp = aiosmtplib.SMTP(
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            use_tls=use_tls,
            username=settings.smtp_user or None,
            password=settings.smtp_password.get_secret_value() or None,
        )
        async with smtp:
            from_addr = msg["From"] or "noreply@kestrel.local"
            await smtp.sendmail(from_addr, [to_addr], msg.as_string())
        return True
    except ImportError:
        logger.warning("email.aiosmtplib_not_installed")
        return False
    except Exception as e:
        logger.warning("email.delivery_error", error=str(e))
        return False
