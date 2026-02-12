import time
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from typing import Dict
from fastapi.responses import JSONResponse

app = FastAPI()

# ================= RATE LIMIT CONFIG =================
RATE_PER_MINUTE = 32
BURST_CAPACITY = 13
REFILL_RATE_PER_SEC = RATE_PER_MINUTE / 60.0  # tokens per second

# In-memory token buckets
buckets: Dict[str, dict] = {}


# ================= REQUEST MODEL =================
class SecurityRequest(BaseModel):
    userId: str
    input: str
    category: str


# ================= TOKEN BUCKET FUNCTION =================
def check_rate_limit(key: str):
    now = time.time()

    if key not in buckets:
        buckets[key] = {
            "tokens": BURST_CAPACITY,
            "last_refill": now
        }

    bucket = buckets[key]

    # Refill tokens
    elapsed = now - bucket["last_refill"]
    refill = elapsed * REFILL_RATE_PER_SEC
    bucket["tokens"] = min(
        BURST_CAPACITY,
        bucket["tokens"] + refill
    )
    bucket["last_refill"] = now

    if bucket["tokens"] >= 1:
        bucket["tokens"] -= 1
        return True, 0
    else:
        # calculate retry time
        needed = 1 - bucket["tokens"]
        retry_after = needed / REFILL_RATE_PER_SEC
        return False, int(retry_after) + 1


# ================= SECURITY ENDPOINT =================
@app.post("/security-check")
async def security_check(data: SecurityRequest, request: Request):
    try:
        # Determine key: userId + IP
        ip = request.client.host
        key = f"{data.userId}:{ip}"

        allowed, retry_after = check_rate_limit(key)

        if not allowed:
            # Log event
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

        # If allowed
        response = {
            "blocked": False,
            "reason": "Input passed all security checks",
            "sanitizedOutput": data.input.strip(),
            "confidence": 0.95
        }

        return response

    except Exception:
        # Do not leak system info
        return JSONResponse(
            status_code=400,
            content={
                "blocked": True,
                "reason": "Invalid request",
                "sanitizedOutput": None,
                "confidence": 0.5
            }
        )
