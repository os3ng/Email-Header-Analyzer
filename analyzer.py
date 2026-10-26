"""Read email headers and report simple, explainable risk indicators.

This is a teaching/demo tool. It does not independently verify SPF, DKIM, or
DMARC; it only reads claims found in Authentication-Results headers.
"""

from email import policy
from email.parser import BytesHeaderParser
from email.utils import parseaddr
import re
from brand_detector import detect_brand_spoofing


def address_domain(value: str) -> str:
    """Extract a domain from an email address in a header field."""
    address = parseaddr(value or "")[1].lower()
    return address.rsplit("@", 1)[-1] if "@" in address else ""


def authentication_status(header: str, mechanism: str) -> str:
    """Read a reported authentication status, not verify it."""
    match = re.search(rf"\b{re.escape(mechanism)}\s*=\s*([a-z]+)\b", header, re.I)
    return match.group(1).lower() if match else "unknown"


def analyze_email_headers(raw: bytes) -> dict:
    """Analyze the headers of an .eml file or copied email source."""
    if not raw.strip():
        raise ValueError("Email data is empty.")

    # Header parser avoids reading email attachments/body into the analysis.
    message = BytesHeaderParser(policy=policy.default).parsebytes(raw)

    sender = str(message.get("From", ""))
    reply_to = str(message.get("Reply-To", ""))
    return_path = str(message.get("Return-Path", ""))
    subject = str(message.get("Subject", ""))
    from_domain = address_domain(sender)
    reply_domain = address_domain(reply_to)
    return_domain = address_domain(return_path)

    # MVP only uses the first (topmost) Authentication-Results header.
    # A downloaded/copied email header is untrusted input: even this entry
    # could be forged. No authentication is performed by this script.
    auth_headers = message.get_all("Authentication-Results", [])
    auth_text = str(auth_headers[0]) if auth_headers else ""
    auth_server = auth_text.split(";", 1)[0].strip() if auth_text else "unknown"
    checks = {
        key.upper(): authentication_status(auth_text, key)
        for key in ("spf", "dkim", "dmarc")
    }

    reasons = []
    score = 0
    brand_findings = detect_brand_spoofing(sender)
    for finding in brand_findings:
        score += finding["points"]
        reasons.append(
            f"Possible {finding['brand']} impersonation: {finding['finding']}. "
            f"Observed: {finding['sender_domain']}; reference: {finding['reference']}."
        )
    if checks["DMARC"] == "fail":
        score += 60
        reasons.append("DMARC reported FAIL: sender-domain alignment/authentication did not pass.")

    # SPF or DKIM may fail individually while DMARC still passes, for example
    # when a legitimate sender relies on the other aligned method.
    if checks["DMARC"] != "pass":
        if checks["SPF"] == "fail":
            score += 20
            reasons.append("SPF reported FAIL: sending server may not be authorized.")
        elif checks["SPF"] == "softfail":
            score += 10
            reasons.append("SPF reported SOFTFAIL: investigate sender authorization.")
        if checks["DKIM"] == "fail":
            score += 20
            reasons.append("DKIM reported FAIL: signature did not validate.")

    if from_domain and reply_domain and from_domain != reply_domain:
        score += 15
        reasons.append(
            f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain}). "
            "This can be legitimate, but deserves review."
        )

    score = min(score, 100)
    known_auth = any(status != "unknown" for status in checks.values())
    if score >= 60:
        verdict = "High risk indicators"
    elif score >= 15:
        verdict = "Needs review"
    elif not known_auth:
        verdict = "Insufficient authentication data"
    else:
        verdict = "Low risk indicators found"

    if not reasons:
        reasons.append(
            "No scored warning detected. This does not prove the email is safe."
        )

    return {
        "verdict": verdict,
        "score": score,
        "from": sender or "(missing)",
        "from_domain": from_domain or "unknown",
        "reply_to": reply_to or "(not specified)",
        "return_path": return_path or "(not specified)",
        "return_path_domain": return_domain or "unknown",
        "subject": subject or "(no subject)",
        "auth_server": auth_server,
        "checks": checks,
        "reasons": reasons,
        "brand_findings": brand_findings,
        "received_hops": len(message.get_all("Received", [])),
    }
