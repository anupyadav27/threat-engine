"""
SES email utility for auth-related emails.
Requires IAM role with ses:SendEmail permission on the EKS node/pod.
"""
import logging
import os

logger = logging.getLogger(__name__)

SES_FROM_EMAIL = os.getenv("SES_FROM_EMAIL", "noreply@threatengine.io")
AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")


def _ses_client():
    try:
        import boto3
        return boto3.client("ses", region_name=AWS_REGION)
    except ImportError:
        raise RuntimeError("boto3 not installed")


def send_invite_email(to_email: str, invite_token: str, tenant_name: str, invited_by: str):
    """Send team invite email with accept link."""
    accept_url = f"{FRONTEND_URL}/auth/invite/{invite_token}"
    subject = f"You've been invited to join {tenant_name} on Threat Engine"
    body_html = f"""
    <html><body style="font-family: sans-serif; background:#070b14; color:#f1f5f9; padding:40px;">
      <div style="max-width:500px; margin:0 auto; background:#0d1117; border-radius:12px;
                  padding:40px; border:1px solid #1e2d3d;">
        <div style="margin-bottom:28px;">
          <span style="font-size:22px; font-weight:800; color:#f1f5f9;">Threat Engine</span>
          <span style="font-size:11px; color:#818cf8; margin-left:8px; text-transform:uppercase;
                       letter-spacing:0.1em;">Cloud Security</span>
        </div>
        <h2 style="color:#f1f5f9; margin-bottom:12px;">You've been invited</h2>
        <p style="color:#94a3b8; line-height:1.6;">
          <strong style="color:#e2e8f0;">{invited_by}</strong> has invited you to join
          <strong style="color:#e2e8f0;">{tenant_name}</strong> on Threat Engine.
        </p>
        <a href="{accept_url}" style="display:inline-block; margin-top:28px; padding:14px 28px;
           background:linear-gradient(135deg,#2563eb,#4f46e5); color:white; text-decoration:none;
           border-radius:8px; font-weight:700; font-size:15px;">
          Accept Invitation
        </a>
        <p style="margin-top:28px; color:#475569; font-size:12px;">
          This invite expires in 48 hours. If you didn't expect this email, you can ignore it.
        </p>
        <p style="margin-top:8px; color:#334155; font-size:11px; word-break:break-all;">
          Or copy this link: {accept_url}
        </p>
      </div>
    </body></html>
    """
    _send(to_email, subject, body_html)


def send_password_reset_email(to_email: str, reset_token: str):
    """Send password reset link."""
    reset_url = f"{FRONTEND_URL}/auth/reset-password/{reset_token}"
    subject = "Reset your Threat Engine password"
    body_html = f"""
    <html><body style="font-family: sans-serif; background:#070b14; color:#f1f5f9; padding:40px;">
      <div style="max-width:500px; margin:0 auto; background:#0d1117; border-radius:12px;
                  padding:40px; border:1px solid #1e2d3d;">
        <div style="margin-bottom:28px;">
          <span style="font-size:22px; font-weight:800; color:#f1f5f9;">Threat Engine</span>
        </div>
        <h2 style="color:#f1f5f9; margin-bottom:12px;">Reset your password</h2>
        <p style="color:#94a3b8; line-height:1.6;">
          We received a request to reset the password for your account (<strong style="color:#e2e8f0;">{to_email}</strong>).
          Click the button below to choose a new password.
        </p>
        <a href="{reset_url}" style="display:inline-block; margin-top:28px; padding:14px 28px;
           background:linear-gradient(135deg,#2563eb,#4f46e5); color:white; text-decoration:none;
           border-radius:8px; font-weight:700; font-size:15px;">
          Reset Password
        </a>
        <p style="margin-top:28px; color:#475569; font-size:12px;">
          This link expires in 1 hour. If you didn't request a password reset, you can ignore this email.
        </p>
        <p style="margin-top:8px; color:#334155; font-size:11px; word-break:break-all;">
          Or copy this link: {reset_url}
        </p>
      </div>
    </body></html>
    """
    _send(to_email, subject, body_html)


def _send(to_email: str, subject: str, body_html: str):
    try:
        client = _ses_client()
        client.send_email(
            Source=SES_FROM_EMAIL,
            Destination={"ToAddresses": [to_email]},
            Message={
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {"Html": {"Data": body_html, "Charset": "UTF-8"}},
            },
        )
        logger.info(f"Email sent to {to_email}: {subject}")
    except Exception as e:
        # Log but don't raise — email failure should not block auth flows
        logger.error(f"Failed to send email to {to_email}: {e}")
