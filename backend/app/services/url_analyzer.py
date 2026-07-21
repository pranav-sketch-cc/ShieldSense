from app.models.url_models import (
    URLAnalysisResponse,
    URLSignals,
)
from app.services.risk_engine import (
    calculate_url_risk,
    get_risk_level,
)
from app.utils.url_utils import (
    contains_punycode,
    count_subdomains,
    extract_domain,
    find_possible_brand_impersonation,
    find_suspicious_keywords,
    is_ip_address,
    normalize_url,
    uses_https,
)


def determine_threat_type(
    *,
    risk_score: int,
    contains_ip: bool,
    punycode_detected: bool,
    suspicious_keywords: list[str],
    brand_impersonation: list[str],
) -> str:
    if brand_impersonation:
        return "Possible Typosquatting or Brand Impersonation"

    if punycode_detected:
        return "Possible Homograph Attack"

    if contains_ip:
        return "Suspicious Direct-IP URL"

    if suspicious_keywords and risk_score >= 30:
        return "Possible Phishing URL"

    if risk_score >= 30:
        return "Suspicious URL"

    return "No Strong Threat Pattern Detected"


def build_summary(
    *,
    risk_level: str,
    risk_breakdown,
) -> str:
    if not risk_breakdown:
        return (
            "The current local checks did not detect any strong "
            "suspicious patterns. This does not guarantee that "
            "the URL is safe."
        )

    detected_signals = [
        item.signal.lower()
        for item in risk_breakdown
    ]

    joined_signals = ", ".join(detected_signals)

    if risk_level == "High":
        return (
            "Several significant warning signs were detected: "
            f"{joined_signals}. Avoid interacting with this link "
            "until it has been verified."
        )

    if risk_level == "Medium":
        return (
            "Some suspicious warning signs were detected: "
            f"{joined_signals}. Verify the domain before continuing."
        )

    return (
        "A limited number of warning signs were detected: "
        f"{joined_signals}. Continue carefully."
    )


def get_recommended_actions(
    risk_level: str,
) -> list[str]:
    if risk_level == "High":
        return [
            (
                "Do not enter passwords, OTPs, card details, "
                "or other sensitive information."
            ),
            (
                "Open the organization's official website or app "
                "manually instead of using this link."
            ),
            (
                "Verify the message through a trusted contact "
                "method before taking action."
            ),
        ]

    if risk_level == "Medium":
        return [
            (
                "Avoid entering sensitive information until the "
                "domain and sender have been verified."
            ),
            (
                "Navigate to the official website manually rather "
                "than opening the submitted link."
            ),
        ]

    return [
        (
            "Confirm that the domain exactly matches the expected "
            "official website."
        ),
        (
            "Do not share passwords, OTPs, or payment information "
            "unless the website is verified."
        ),
    ]


def analyze_url(raw_url: str) -> URLAnalysisResponse:
    """
    Run the complete local URL-analysis pipeline.
    """
    normalized_url = normalize_url(raw_url)
    domain = extract_domain(normalized_url)

    https_detected = uses_https(normalized_url)
    contains_ip = is_ip_address(domain)

    suspicious_keywords = find_suspicious_keywords(
        normalized_url
    )

    url_length = len(normalized_url)
    is_long_url = url_length > 100

    subdomain_count = count_subdomains(domain)
    has_many_subdomains = subdomain_count >= 3

    at_symbol_detected = "@" in normalized_url
    punycode_detected = contains_punycode(domain)

    brand_impersonation = (
        find_possible_brand_impersonation(domain)
    )

    risk_score, risk_breakdown = calculate_url_risk(
        uses_https=https_detected,
        contains_ip_address=contains_ip,
        contains_at_symbol=at_symbol_detected,
        contains_punycode=punycode_detected,
        suspicious_keywords=suspicious_keywords,
        possible_brand_impersonation=brand_impersonation,
        is_long_url=is_long_url,
        has_many_subdomains=has_many_subdomains,
    )

    risk_level = get_risk_level(risk_score)

    threat_type = determine_threat_type(
        risk_score=risk_score,
        contains_ip=contains_ip,
        punycode_detected=punycode_detected,
        suspicious_keywords=suspicious_keywords,
        brand_impersonation=brand_impersonation,
    )

    signals = URLSignals(
        normalized_url=normalized_url,
        domain=domain,
        uses_https=https_detected,
        contains_ip_address=contains_ip,
        contains_at_symbol=at_symbol_detected,
        contains_punycode=punycode_detected,
        suspicious_keywords=suspicious_keywords,
        possible_brand_impersonation=brand_impersonation,
        url_length=url_length,
        is_long_url=is_long_url,
        subdomain_count=subdomain_count,
        has_many_subdomains=has_many_subdomains,
    )

    return URLAnalysisResponse(
        input_url=raw_url,
        risk_score=risk_score,
        risk_level=risk_level,
        threat_type=threat_type,
        summary=build_summary(
            risk_level=risk_level,
            risk_breakdown=risk_breakdown,
        ),
        signals=signals,
        risk_breakdown=risk_breakdown,
        recommended_actions=get_recommended_actions(
            risk_level
        ),
        disclaimer=(
            "This result is based on heuristic URL checks and "
            "does not guarantee that a website is safe or malicious."
        ),
    )