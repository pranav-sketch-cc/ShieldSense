import ipaddress
import re
from difflib import SequenceMatcher
from urllib.parse import urlparse

from app.config.constants import KNOWN_BRANDS, SUSPICIOUS_KEYWORDS


def normalize_url(raw_url: str) -> str:
    """
    Add a URL scheme when the user does not provide one.

    Example:
        google.com -> https://google.com
    """
    cleaned_url = raw_url.strip()

    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        cleaned_url,
    ):
        cleaned_url = f"https://{cleaned_url}"

    return cleaned_url


def extract_domain(normalized_url: str) -> str:
    """
    Extract the hostname from a normalized URL.
    """
    parsed_url = urlparse(normalized_url)
    domain = parsed_url.hostname

    if not domain:
        raise ValueError(
            "A valid domain could not be extracted from the URL."
        )

    return domain.lower().strip(".")


def uses_https(normalized_url: str) -> bool:
    parsed_url = urlparse(normalized_url)
    return parsed_url.scheme.lower() == "https"


def is_ip_address(domain: str) -> bool:
    """
    Check whether the hostname is an IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def find_suspicious_keywords(normalized_url: str) -> list[str]:
    """
    Find phishing-related words anywhere in the URL.
    """
    lowercase_url = normalized_url.lower()

    matches = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in lowercase_url
    ]

    return sorted(matches)


def count_subdomains(domain: str) -> int:
    """
    Lightweight subdomain counter for the hackathon MVP.

    example.com -> 0
    login.example.com -> 1
    secure.login.example.com -> 2
    """
    if is_ip_address(domain):
        return 0

    domain_parts = domain.split(".")

    if len(domain_parts) <= 2:
        return 0

    return len(domain_parts) - 2


def contains_punycode(domain: str) -> bool:
    """
    Punycode labels begin with xn--.

    Punycode itself is not automatically malicious,
    but it can be used for visual look-alike domains.
    """
    return any(
        label.startswith("xn--")
        for label in domain.split(".")
    )


def get_main_domain_label(domain: str) -> str:
    """
    Extract the likely main domain label.

    paypal.com -> paypal
    login.paypal.com -> paypal
    """
    if is_ip_address(domain):
        return domain

    parts = domain.split(".")

    if len(parts) < 2:
        return parts[0]

    return parts[-2]


def normalize_lookalike_text(value: str) -> str:
    """
    Replace common character substitutions.

    paypa1 -> paypal
    g00gle -> google
    """
    substitution_table = str.maketrans(
        {
            "0": "o",
            "1": "l",
            "3": "e",
            "4": "a",
            "5": "s",
            "7": "t",
        }
    )

    return value.lower().translate(substitution_table)


def find_possible_brand_impersonation(
    domain: str,
) -> list[str]:
    """
    Detect possible brand look-alikes using simple heuristics.

    This does not prove phishing.
    It only generates a warning signal.
    """
    if is_ip_address(domain):
        return []

    domain_labels = domain.split(".")
    main_domain_label = get_main_domain_label(domain)
    detected_brands: set[str] = set()

    for label in domain_labels:
        normalized_label = normalize_lookalike_text(label)

        for brand in KNOWN_BRANDS:
            # Avoid flagging a normal official-style domain
            # such as paypal.com.
            if main_domain_label == brand:
                continue

            if brand in normalized_label:
                detected_brands.add(brand)
                continue

            similarity = SequenceMatcher(
                None,
                normalized_label,
                brand,
            ).ratio()

            if similarity >= 0.80:
                detected_brands.add(brand)

    return sorted(detected_brands)