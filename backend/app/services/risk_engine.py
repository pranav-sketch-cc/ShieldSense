from app.config.constants import (
    RISK_LEVEL_LOW_MAX,
    RISK_LEVEL_MEDIUM_MAX,
)
from app.models.response_models import RiskBreakdownItem


def calculate_url_risk(
    *,
    uses_https: bool,
    contains_ip_address: bool,
    contains_at_symbol: bool,
    contains_punycode: bool,
    suspicious_keywords: list[str],
    possible_brand_impersonation: list[str],
    is_long_url: bool,
    has_many_subdomains: bool,
) -> tuple[int, list[RiskBreakdownItem]]:
    """
    Convert URL signals into a transparent rule-based score.
    """
    score = 0
    breakdown: list[RiskBreakdownItem] = []

    def add_risk(
        signal: str,
        points: int,
        reason: str,
    ) -> None:
        nonlocal score

        score += points

        breakdown.append(
            RiskBreakdownItem(
                signal=signal,
                points=points,
                reason=reason,
            )
        )

    if not uses_https:
        add_risk(
            signal="No HTTPS",
            points=15,
            reason=(
                "The URL does not use an encrypted HTTPS connection."
            ),
        )

    if contains_ip_address:
        add_risk(
            signal="IP address used as hostname",
            points=25,
            reason=(
                "The URL uses a numeric IP address instead "
                "of a normal domain name."
            ),
        )

    if suspicious_keywords:
        keyword_points = min(
            len(suspicious_keywords) * 5,
            20,
        )

        add_risk(
            signal="Suspicious keywords",
            points=keyword_points,
            reason=(
                "The URL contains words frequently used in "
                "phishing or social-engineering attempts: "
                + ", ".join(suspicious_keywords)
                + "."
            ),
        )

    if is_long_url:
        add_risk(
            signal="Unusually long URL",
            points=10,
            reason=(
                "A long URL may make the real destination "
                "more difficult to notice."
            ),
        )

    if has_many_subdomains:
        add_risk(
            signal="Many subdomains",
            points=10,
            reason=(
                "Multiple subdomains can be used to make a "
                "suspicious address look legitimate."
            ),
        )

    if contains_at_symbol:
        add_risk(
            signal="@ symbol in URL",
            points=20,
            reason=(
                "An @ symbol can make the visible beginning "
                "of a URL different from its actual destination."
            ),
        )

    if contains_punycode:
        add_risk(
            signal="Punycode domain",
            points=20,
            reason=(
                "Punycode can represent international characters "
                "and may sometimes be used for visual look-alike domains."
            ),
        )

    if possible_brand_impersonation:
        add_risk(
            signal="Possible brand impersonation",
            points=30,
            reason=(
                "The domain resembles or contains a variation of: "
                + ", ".join(possible_brand_impersonation)
                + "."
            ),
        )

    return min(score, 100), breakdown


def get_risk_level(score: int) -> str:
    if score <= RISK_LEVEL_LOW_MAX:
        return "Low"

    if score <= RISK_LEVEL_MEDIUM_MAX:
        return "Medium"

    return "High"