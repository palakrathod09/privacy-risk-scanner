"""
Privacy Risk Scanner - Detection Engine
Regex + checksum based detectors for common categories of sensitive
information (PII, credentials, financial data).

Each detector returns a list of dicts:
    {
        "category": str,
        "severity": "low" | "medium" | "high" | "critical",
        "match": str (partially redacted),
        "context": str (surrounding text, redacted),
        "line": int,
    }
"""
import re

# ---------------------------------------------------------------------------
# Severity weights used for the aggregate risk score (0-100)
# ---------------------------------------------------------------------------
SEVERITY_WEIGHT = {
    "low": 1,
    "medium": 3,
    "high": 6,
    "critical": 10,
}

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def _luhn_valid(number: str) -> bool:
    """Validate a credit-card-like number using the Luhn checksum."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 12:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _redact(value: str, keep: int = 4) -> str:
    """Show only the last `keep` characters, mask the rest."""
    value = value.strip()
    if len(value) <= keep:
        return "*" * len(value)
    return "*" * (len(value) - keep) + value[-keep:]


def _line_number(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _context(text: str, start: int, end: int, radius: int = 40) -> str:
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    snippet = text[lo:hi].replace("\n", " ")
    return snippet.strip()


# ---------------------------------------------------------------------------
# Pattern definitions: (category, severity, compiled regex, validator|None)
# ---------------------------------------------------------------------------
PATTERNS = [
    (
        "Email Address", "medium",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        None,
    ),
    (
        "Phone Number", "medium",
        re.compile(r"(?<!\d)(\+?\d{1,3}[-.\s]?)?(\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?!\d)"),
        None,
    ),
    (
        "US Social Security Number", "critical",
        re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        None,
    ),
    (
        "Credit Card Number", "critical",
        re.compile(r"\b(?:\d[ -]?){13,16}\b"),
        _luhn_valid,
    ),
    (
        "IBAN", "high",
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
        None,
    ),
    (
        "IPv4 Address", "low",
        re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
        None,
    ),
    (
        "AWS Access Key", "critical",
        re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        None,
    ),
    (
        "Generic API Key / Secret", "high",
        re.compile(r"\b(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}['\"]?", re.IGNORECASE),
        None,
    ),
    (
        "Private Key Block", "critical",
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        None,
    ),
    (
        "US Passport Number", "high",
        re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
        None,
    ),
    (
        "Date of Birth", "high",
        re.compile(r"\b(DOB|Date of Birth)\s*[:\-]?\s*(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}[\/\-]\d{1,2}[\/\-]\d{1,2})", re.IGNORECASE),
        None,
    ),
    (
        "Physical Street Address", "medium",
        re.compile(r"\b\d{1,5}\s+([A-Za-z0-9.\s]{2,30})\s+(Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b", re.IGNORECASE),
        None,
    ),
    (
        "US Bank Routing/Account Pattern", "high",
        re.compile(r"\b(account|acct|routing)\s*(#|no\.?|number)?\s*[:\-]?\s*\d{6,17}\b", re.IGNORECASE),
        None,
    ),
    (
        "Driver's License (generic US)", "medium",
        re.compile(r"\b(DL|Driver'?s?\s*License)\s*[:#\-]?\s*[A-Z0-9]{6,12}\b", re.IGNORECASE),
        None,
    ),
    (
        "Medical / Health Record Reference", "high",
        re.compile(r"\b(patient\s*id|medical\s*record\s*(no|number|#)|diagnosis|MRN)\s*[:#\-]?\s*[A-Za-z0-9\-]{3,}", re.IGNORECASE),
        None,
    ),
]


def scan_text(text: str, source_name: str = "document"):
    """Run all detectors against `text`, return a list of finding dicts."""
    findings = []
    seen = set()  # dedupe identical (category, match, line)

    for category, severity, pattern, validator in PATTERNS:
        for m in pattern.finditer(text):
            raw = m.group(0)
            if validator is not None and not validator(raw):
                continue
            line = _line_number(text, m.start())
            key = (category, raw, line)
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "category": category,
                "severity": severity,
                "match": _redact(raw),
                "context": _context(text, m.start(), m.end()),
                "line": line,
                "source": source_name,
            })
    return findings


def score_findings(findings):
    """Aggregate findings into an overall 0-100 risk score + breakdowns."""
    if not findings:
        return {
            "score": 0,
            "level": "Low",
            "by_category": {},
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "total": 0,
        }

    by_category = {}
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    raw = 0
    for f in findings:
        by_category[f["category"]] = by_category.get(f["category"], 0) + 1
        by_severity[f["severity"]] += 1
        raw += SEVERITY_WEIGHT[f["severity"]]

    # Normalize: diminishing returns so score saturates near 100 instead of
    # blowing past it on large documents.
    score = round(100 * (1 - pow(2.718281828, -raw / 40)))
    score = max(1, min(100, score))

    if score >= 75:
        level = "Critical"
    elif score >= 50:
        level = "High"
    elif score >= 25:
        level = "Medium"
    else:
        level = "Low"

    return {
        "score": score,
        "level": level,
        "by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
        "by_severity": by_severity,
        "total": len(findings),
    }
