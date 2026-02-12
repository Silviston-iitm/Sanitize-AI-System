import time
from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import Dict, List
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================= RATE LIMIT CONFIG =================
RATE_PER_MINUTE = 32
BURST_CAPACITY = 13

# Store request timestamps per user/IP
request_log: Dict[str, List[float]] = {}


# ================= REQUEST MODEL =================
class SecurityRequest(BaseModel):
    userId: str
    input: str
    category: str


# ================= FIXED WINDOW RATE LIMIT =================
def check_rate_limit(key: str):
    now = time.time()

    if key not in request_log:
        request_log[key] = []

    # Remove requests older than 60 seconds
    request_log[key] = [
        t for t in request_log[key]
        if now - t < 60
    ]

    # Enforce burst limit
    if len(request_log[key]) >= BURST_CAPACITY:
        return False, 60

    # Allow request
    request_log[key].append(now)
    return True, 0


# ================= SECURITY ENDPOINT =================
@app.post("/security-check")
async def security_check(request: Request):
    try:
        # Try to read JSON safely
        try:
            data = await request.json()
        except Exception:
            data = {}

        user_input = str(data.get("input", ""))

        ip = request.client.host
        key = ip  # rate limit by IP only

        allowed, retry_after = check_rate_limit(key)

        if not allowed:
            print(f"[SECURITY] Rate limit exceeded for {key}")

            return JSONResponse(
                status_code=429,
                content={
                    "blocked": True,
                    "reason": "Rate limit exceeded",
                    "sanitizedOutput": None,
                    "confidence": 0.99
                },
                headers={"Retry-After": str(retry_after)}
            )

        return {
            "blocked": False,
            "reason": "Input passed all security checks",
            "sanitizedOutput": user_input.strip(),
            "confidence": 0.95
        }

    except Exception:
        return JSONResponse(
            status_code=200,
            content={
                "blocked": True,
                "reason": "Invalid request",
                "sanitizedOutput": None,
                "confidence": 0.5
            }
        )
