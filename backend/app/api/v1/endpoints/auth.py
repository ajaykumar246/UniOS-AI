import datetime
from datetime import timezone
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.schemas.auth import (
    RegisterRequest,
    LoginRequest,
    ResendVerificationRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    MFAVerifyRequest,
    SocialLoginRequest,
    MFAEnrollVerifyRequest
)
from app.core.supabase_api import supabase_auth_api
from app.core.supabase import supabase_admin

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])
security = HTTPBearer()

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(request: RegisterRequest):
    try:
        res = await supabase_auth_api.sign_up(
            email=request.email,
            password=request.password,
            full_name=request.full_name,
            terms_accepted=request.terms_accepted
        )
        return {
            "message": "Registration successful. Please check your email to verify your account.",
            "user": res.get("user")
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/verify-email")
async def verify_email(token: str, email: str):
    try:
        res = await supabase_auth_api.verify_otp(email=email, token=token, type="signup")
        return {
            "message": "Email verified successfully.",
            "session": res.get("session")
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/resend-verification")
async def resend_verification(request: ResendVerificationRequest):
    try:
        await supabase_auth_api.resend_verification(request.email)
        return {"message": "Verification email resent successfully."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/login")
async def login(request: LoginRequest):
    # Lockout Guard: Check if the user account is locked
    profile = None
    try:
        res = supabase_admin.table("users").select("user_id, failed_login_attempts, account_locked_until").eq("email", request.email).execute()
        if res.data:
            profile = res.data[0]
    except Exception:
        pass

    if profile:
        locked_until = profile.get("account_locked_until")
        if locked_until:
            locked_time = datetime.datetime.fromisoformat(locked_until.replace('Z', '+00:00'))
            if locked_time > datetime.datetime.now(timezone.utc):
                time_left = locked_time - datetime.datetime.now(timezone.utc)
                minutes_left = int(time_left.total_seconds() / 60) + 1
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail=f"Account is temporarily locked due to failed login attempts. Try again in {minutes_left} minutes."
                )

    try:
        session_data = await supabase_auth_api.sign_in(request.email, request.password)
        user_info = session_data.get("user", {})
        user_id = user_info.get("id")

        # Login succeeded: Reset lockout counter and update last login
        if profile and user_id:
            supabase_admin.table("users").update({
                "failed_login_attempts": 0,
                "account_locked_until": None,
                "last_login": datetime.datetime.now(timezone.utc).isoformat()
            }).eq("user_id", user_id).execute()

        # Check if MFA is required
        factors = user_info.get("factors", []) or []
        active_totp = [f for f in factors if f.get("factor_type") == "totp" and f.get("status") == "verified"]

        clean_session = {
            "access_token": session_data.get("access_token"),
            "refresh_token": session_data.get("refresh_token"),
            "expires_in": session_data.get("expires_in"),
            "token_type": session_data.get("token_type", "bearer")
        }

        if active_totp:
            return {
                "requires_mfa": True,
                "user_id": user_id,
                "session": clean_session
            }

        return {
            "requires_mfa": False,
            "session": clean_session
        }

    except Exception as e:
        # Increment failed login attempts
        if profile:
            attempts = profile.get("failed_login_attempts", 0) + 1
            update_data = {"failed_login_attempts": attempts}
            if attempts >= 5:
                locked_until = (datetime.datetime.now(timezone.utc) + datetime.timedelta(minutes=15)).isoformat()
                update_data["account_locked_until"] = locked_until
            
            supabase_admin.table("users").update(update_data).eq("user_id", profile.get("user_id")).execute()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

@router.post("/social")
async def social_login(request: SocialLoginRequest):
    if request.provider not in ("google", "github", "facebook"):
        raise HTTPException(status_code=400, detail="Unsupported social provider")
    
    redirect_to = request.redirect_to or "http://localhost:3000/callback"
    # Construct PKCE authorization URL for Supabase Auth redirect
    url = f"{supabase_admin.supabase_url}/auth/v1/authorize?provider={request.provider}&redirect_to={redirect_to}"
    return {"url": url}

@router.post("/mfa/verify")
async def mfa_verify(request: MFAVerifyRequest, credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        # Get user factors
        admin_res = supabase_admin.auth.admin.get_user_by_id(request.user_id)
        user_data = admin_res.user
        factors = getattr(user_data, "factors", []) or []
        totp_factor = next((f for f in factors if f.factor_type == "totp" and f.status == "verified"), None)

        if not totp_factor:
            raise HTTPException(status_code=400, detail="No verified TOTP factor found for this user.")

        # Challenge the MFA factor
        challenge = await supabase_auth_api.mfa_challenge(token, totp_factor.id)
        challenge_id = challenge.get("id")

        # Verify the challenge using user's token and TOTP code
        verified_session = await supabase_auth_api.mfa_verify(
            token=token,
            factor_id=totp_factor.id,
            challenge_id=challenge_id,
            code=request.totp_code
        )
        return {"session": verified_session}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/mfa/enroll")
async def mfa_enroll(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        res = await supabase_auth_api.mfa_enroll(token)
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/mfa/verify-enroll")
async def mfa_verify_enroll(request: MFAEnrollVerifyRequest, credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        # Challenge the newly enrolled factor
        challenge = await supabase_auth_api.mfa_challenge(token, request.factor_id)
        challenge_id = challenge.get("id")

        # Verify enrollment and activate it
        res = await supabase_auth_api.mfa_verify(token, request.factor_id, challenge_id, request.code)

        # Update public.users record
        # Extract user_id from token
        from jose import jwt
        from app.core.config import settings
        payload = jwt.decode(token, settings.SUPABASE_JWT_SECRET, algorithms=["HS256"], options={"verify_aud": False})
        user_id = payload.get("sub")
        
        if user_id:
            supabase_admin.table("users").update({"mfa_enabled": True}).eq("user_id", user_id).execute()

        return {"message": "MFA activated successfully.", "session": res}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/forgot-password")
async def forgot_password(request: ForgotPasswordRequest):
    try:
        await supabase_auth_api.forgot_password(request.email)
        return {"message": "Password recovery email has been sent."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/reset-password")
async def reset_password(request: ResetPasswordRequest, credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        await supabase_auth_api.update_password(token, request.new_password)
        return {"message": "Password has been reset successfully."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/logout")
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        await supabase_auth_api.logout(token)
        return {"message": "Logged out successfully."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
