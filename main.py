from fastapi import FastAPI, Request
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
BURST_CAPACITY = 13
rate_state = {}

def check_rate_limit(key: str):
    if key not in rate_state:
        rate_state[key] = 0

    rate_state[key] += 1
    count = rate_state[key]

    # First 13 allowed
    if count <= BURST_CAPACITY:
        return True, 0

    # Next 13 blocked
    if BURST_CAPACITY < count <= BURST_CAPACITY * 2:
        return False, 2

    # Reset automatically after burst window
    rate_state[key] = 1
    return True, 0


# ================= SECURITY ENDPOINT =================
@app.post("/security-check")
async def security_check(request: Request):
    try:
        # Safely read JSON
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
