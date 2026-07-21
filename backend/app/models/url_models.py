from typing import List

from pydantic import BaseModel, Field, field_validator

from app.models.response_models import RiskBreakdownItem


class URLAnalysisRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=3,
        max_length=2048,
        examples=["https://example.com"],
    )

    @field_validator("url")
    @classmethod
    def clean_url(cls, value: str) -> str:
        cleaned_url = value.strip()

        if not cleaned_url:
            raise ValueError("URL cannot be empty.")

        return cleaned_url


class URLSignals(BaseModel):
    normalized_url: str
    domain: str

    uses_https: bool
    contains_ip_address: bool
    contains_at_symbol: bool
    contains_punycode: bool

    suspicious_keywords: List[str]
    possible_brand_impersonation: List[str]

    url_length: int
    is_long_url: bool

    subdomain_count: int
    has_many_subdomains: bool


class URLAnalysisResponse(BaseModel):
    input_url: str

    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    threat_type: str

    summary: str
    signals: URLSignals

    risk_breakdown: List[RiskBreakdownItem]
    recommended_actions: List[str]

    disclaimer: str