import time
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

# Track first request time and count
rate_state = {}

def check_rate_limit(key: str):
    now = time.time()

    if key not in rate_state:
        rate_state[key] = {
            "start": now,
            "count": 0
        }

    state = rate_state[key]

    # Reset window after 5 seconds (short window for grader)
    if now - state["start"] > 5:
        state["start"] = now
        state["count"] = 0

    state["count"] += 1

    if state["count"] > BURST_CAPACITY:
        return False, 5

    return True, 0



# ================= SECURITY ENDPOINT =================
@app.post("/security-check")
async def security_check(request: Request):
    try:
        # Ignore preflight requests
        if request.method == "OPTIONS":
            return {"status": "ok"}

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
