from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlparse

app = FastAPI(
    title="AI Cyber Shield API",
    description="API for analysing suspicious URLs",
    version="1.0.0",
)


class URLRequest(BaseModel):
    url: str


@app.get("/")
def home():
    return {
        "message": "AI Cyber Shield backend is running"
    }


@app.post("/analyze")
def analyze_url(request: URLRequest):
    url = request.url.strip().lower()

    score = 0
    reasons = []

    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path.split("/")[0]

    if not url.startswith("https://"):
        score += 20
        reasons.append("The URL does not use HTTPS.")

    suspicious_words = [
        "login",
        "verify",
        "update",
        "secure",
        "account",
        "banking",
        "password",
        "free",
        "gift",
        "winner",
    ]

    for word in suspicious_words:
        if word in url:
            score += 10
            reasons.append(f"The URL contains the suspicious word '{word}'.")

    suspicious_domains = [
        ".xyz",
        ".top",
        ".click",
        ".ru",
        ".tk",
    ]

    for ending in suspicious_domains:
        if domain.endswith(ending):
            score += 25
            reasons.append(f"The domain uses the suspicious extension '{ending}'.")

    if "@" in url:
        score += 30
        reasons.append("The URL contains an '@' symbol, which may hide the real destination.")

    if domain.count("-") >= 2:
        score += 15
        reasons.append("The domain contains multiple hyphens.")

    if any(char.isdigit() for char in domain):
        score += 10
        reasons.append("The domain contains numbers that may imitate a trusted brand.")

    score = min(score, 100)

    if score >= 60:
        risk = "High"
    elif score >= 30:
        risk = "Medium"
    else:
        risk = "Low"

    if not reasons:
        reasons.append("No obvious suspicious URL patterns were detected.")

    return {
        "url": request.url,
        "domain": domain,
        "risk": risk,
        "score": score,
        "reasons": reasons,
    }