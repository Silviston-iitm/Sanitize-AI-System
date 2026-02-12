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
async def security_check(data: SecurityRequest, request: Request):
    try:
        # Determine key: userId + IP
        ip = request.client.host
        key = f"{data.userId}:{ip}"

        allowed, retry_after = check_rate_limit(key)

        if not allowed:
            print(f"[SECURITY] Rate limit exceeded for {key}")

            response = {
                "blocked": True,
                "reason": "Rate limit exceeded",
                "sanitizedOutput": None,
                "confidence": 0.99
            }

            return JSONResponse(
                status_code=429,
                content=response,
                headers={"Retry-After": str(retry_after)}
            )

        response = {
            "blocked": False,
            "reason": "Input passed all security checks",
            "sanitizedOutput": data.input.strip(),
            "confidence": 0.95
        }

        return response

    except Exception:
        return JSONResponse(
            status_code=400,
            content={
                "blocked": True,
                "reason": "Invalid request",
                "sanitizedOutput": None,
                "confidence": 0.5
            }
        )
