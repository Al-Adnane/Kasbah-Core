import hashlib
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional, Dict
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

class MagicLinkAuth:
    def __init__(self, db_path=".kasbah_auth.db"):
        self.conn = None  # Would be DB connection in production
        self.tokens = {}  # In-memory store for demo
        
    def send_magic_link(self, email: str) -> str:
        """Generate and send magic link"""
        token = secrets.token_urlsafe(32)
        expires_at = time.time() + 3600  # 1 hour expiration
        
        # Store token (in production: database)
        self.tokens[token] = {
            "email": email,
            "expires_at": expires_at,
            "used": False
        }
        
        # Generate API key immediately
        api_key = f"kasbah_sk_live_{secrets.token_urlsafe(32)}"
        self.tokens[token]["api_key"] = api_key
        
        # Send email (in production: use SendGrid/Mailgun)
        magic_url = f"https://kasbahcore.com/auth/verify?token={token}"
        
        # Simplified email sending
        try:
            msg = MIMEMultipart()
            msg['Subject'] = '🏰 Your Kasbah Access Link'
            msg['From'] = 'access@kasbahcore.com'
            msg['To'] = email
            
            html = f"""
            <html>
            <body>
                <h2>Welcome to Kasbah!</h2>
                <p>Click the link below to access your account:</p>
                <p><a href="{magic_url}">{magic_url}</a></p>
                <p>Your API key is already generated and waiting for you.</p>
                <p>This link expires in 1 hour.</p>
                <br>
                <p>- The Kasbah Team</p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(html, 'html'))
            
            # In production, use proper email service
            # with smtplib.SMTP('smtp.gmail.com', 587) as server:
            #     server.starttls()
            #     server.login(os.getenv('EMAIL_USER'), os.getenv('EMAIL_PASS'))
            #     server.send_message(msg)
            
            print(f"[DEMO] Magic link sent to {email}: {magic_url}")
            
        except Exception as e:
            print(f"Error sending email: {e}")
        
        return token
    
    def verify_magic_link(self, token: str) -> Optional[Dict]:
        """Verify magic link and return credentials"""
        if token not in self.tokens:
            return None
        
        token_data = self.tokens[token]
        
        # Check expiration
        if time.time() > token_data["expires_at"]:
            del self.tokens[token]
            return None
        
        # Check if already used
        if token_data.get("used", False):
            return None
        
        # Mark as used
        token_data["used"] = True
        
        # Create trial period
        trial_ends = time.time() + (14 * 86400)  # 14 days
        
        return {
            "email": token_data["email"],
            "api_key": token_data["api_key"],
            "trial_ends": trial_ends,
            "free_calls_remaining": 10000,
            "created_at": time.time()
        }

# FastAPI endpoints
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, EmailStr

router = APIRouter(prefix="/api/auth", tags=["authentication"])
auth_manager = MagicLinkAuth()

class MagicLinkRequest(BaseModel):
    email: EmailStr

@router.post("/magic-link")
async def request_magic_link(request: MagicLinkRequest):
    """Request a magic link for passwordless login"""
    token = auth_manager.send_magic_link(request.email)
    
    if token:
        return {
            "success": True,
            "message": "Check your email for the magic link!",
            "expires_in": "1 hour",
            "note": "This is a demo. In production, the email would be sent."
        }
    else:
        raise HTTPException(status_code=400, detail="Failed to send magic link")

@router.get("/verify")
async def verify_link(token: str):
    """Verify magic link and return API key"""
    credentials = auth_manager.verify_magic_link(token)
    
    if credentials:
        return {
            "success": True,
            "api_key": credentials["api_key"],
            "email": credentials["email"],
            "trial_ends": datetime.fromtimestamp(credentials["trial_ends"]).isoformat(),
            "free_calls_remaining": credentials["free_calls_remaining"],
            "message": "Save your API key now! It won't be shown again."
        }
    else:
        raise HTTPException(status_code=401, detail="Invalid or expired link")

@router.post("/signup/instant")
async def instant_signup(email: EmailStr):
    """One-click signup with immediate API key"""
    # Generate API key
    api_key = f"kasbah_sk_live_{secrets.token_urlsafe(32)}"
    
    # Create trial account
    trial_ends = time.time() + (14 * 86400)
    
    # In production, store in database
    print(f"[DEMO] Created instant account for {email}")
    
    return {
        "success": True,
        "api_key": api_key,
        "email": email,
        "trial_ends": datetime.fromtimestamp(trial_ends).isoformat(),
        "free_calls_remaining": 10000,
        "next_steps": [
            "Copy your API key above",
            "Add to your code: kasbah.init(api_key='YOUR_KEY')",
            "Your first 10,000 calls are free",
            "No credit card required for 14 days"
        ]
    }
