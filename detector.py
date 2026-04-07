import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {".zip", ".mov", ".xyz", ".top", ".click"}
BRAND_KEYWORDS = ["microsoft", "paypal", "apple", "google", "amazon", "dhl", "fedex", "bank"]
FREE_EMAIL_DOMAINS = {
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "proton.me", "protonmail.com"
}


def _contains_ip_url(text: str) -> bool:
    return bool(re.search(r"https?://(\d{1,3}\.){3}\d{1,3}", text))


def _contains_punycode(text: str) -> bool:
    return "xn--" in (text or "").lower()


def _extract_urls(text: str):
    return re.findall(r"https?://\S+|www\.\S+", (text or "").lower())


def _has_suspicious_tld(url: str) -> bool:
    url = (url or "").lower()
    for tld in SUSPICIOUS_TLDS:
        if url.endswith(tld) or (tld + "/") in url:
            return True
    return False


def _get_domain(value: str) -> str:
    """
    Extract domain from things like:
    From: "PayPal" <support@paypal.com>
    Reply-To: support@something.xyz
    """
    if not value:
        return ""
    # extract email inside <>
    m = re.search(r"<([^>]+)>", value)
    email = m.group(1) if m else value
    m2 = re.search(r"@([a-zA-Z0-9\.\-]+)", email)
    return (m2.group(1).lower().strip() if m2 else "")


def _parse_email_headers_and_body(raw: str):
    """
    Very simple email parser:
    - Headers are before first blank line
    - Body is after first blank line
    Accepts pasted email like:
      Subject: ...
      From: ...
      Reply-To: ...
      (blank line)
      body...
    """
    raw = raw or ""
    lines = raw.splitlines()

    headers = {}
    body_lines = []
    in_headers = True

    for ln in lines:
        if in_headers and ln.strip() == "":
            in_headers = False
            continue

        if in_headers:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()
            else:
                in_headers = False
                body_lines.append(ln)
        else:
            body_lines.append(ln)

    body = "\n".join(body_lines).strip()
    return headers, body


def analyse_text(text: str):
    headers, body = _parse_email_headers_and_body(text or "")

    subject = headers.get("subject", "")
    from_h = headers.get("from", "")
    reply_to = headers.get("reply-to", "")

    t_all = (text or "").lower()
    t_body = (body or "").lower()
    t_subject = (subject or "").lower()
    t_from = (from_h or "").lower()
    t_reply = (reply_to or "").lower()

    score = 0
    reasons = []


    subject_urgency_terms = ["urgent", "immediately", "within 24 hours", "act now", "final warning", "suspended", "locked"]
    subj_hits = 0
    for term in subject_urgency_terms:
        if term in t_subject:
            score += 1
            subj_hits += 1
            reasons.append(f"Header(Subject) urgency: '{term}' (+1)")
            if subj_hits >= 2:
                break

    from_domain = _get_domain(from_h)
    reply_domain = _get_domain(reply_to)
    if from_domain and reply_domain and from_domain != reply_domain:
        score += 2
        reasons.append(f"Header mismatch: From domain '{from_domain}' != Reply-To domain '{reply_domain}' (+2)")

    
    if from_domain in FREE_EMAIL_DOMAINS and any(b in t_all for b in BRAND_KEYWORDS):
        score += 2
        reasons.append(f"Header suspicious sender: free email domain '{from_domain}' used with brand mention (+2)")

    if from_domain and any(from_domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 1
        reasons.append(f"Header suspicious sender TLD: '{from_domain}' (+1)")

    if _contains_punycode(from_h) or _contains_punycode(reply_to):
        score += 2
        reasons.append("Header contains punycode (possible spoof) (+2)")

    urgency_terms = [
        "urgent", "immediately", "within 24 hours", "act now",
        "final warning", "suspended", "locked"
    ]
    urgency_hits = 0
    for term in urgency_terms:
        if term in t_body:
            urgency_hits += 1
            reasons.append(f"Body urgency language: '{term}' (+1)")
            score += 1
            if urgency_hits >= 2:
                break

    credential_terms = [
        "verify your account", "confirm your account", "password",
        "login to", "sign in", "reset your password"
    ]
    if any(term in t_body for term in credential_terms):
        score += 2
        reasons.append("Body requests credentials / account verification (+2)")

    finance_terms = ["bank", "payment", "invoice", "transfer", "refund", "credit card", "billing"]
    if any(term in t_body for term in finance_terms):
        score += 1
        reasons.append("Body financial/payment related pressure (+1)")

    urls = _extract_urls(text or "")
    link_score_added = 0
    if urls:
        for url in urls:
            if _contains_ip_url(url):
                score += 2
                link_score_added += 2
                reasons.append(f"URL uses IP address: {url} (+2)")
            if _contains_punycode(url):
                score += 2
                link_score_added += 2
                reasons.append(f"URL contains punycode (possible spoof): {url} (+2)")
            if _has_suspicious_tld(url):
                score += 2
                link_score_added += 2
                reasons.append(f"Suspicious TLD in URL: {url} (+2)")
            if link_score_added >= 4:
                break

    attachment_terms = [".exe", ".js", ".vbs", ".scr", ".zip", "enable macros", "macro-enabled"]
    if any(term in t_body for term in attachment_terms):
        score += 2
        reasons.append("Suspicious attachment / macro instruction (+2)")

    generic_greetings = ["dear user", "dear customer", "valued customer", "hello user", "dear customer,"]
    if any(b in t_all for b in BRAND_KEYWORDS) and any(g in t_all for g in generic_greetings):
        score += 1
        reasons.append("Brand mention with generic greeting (possible impersonation) (+1)")

    if t_body.count("!") >= 3:
        score += 1
        reasons.append("Excessive exclamation marks / pressure tone (+1)")

    if score >= 6:
        label = "PHISHING"
    elif score >= 2:
        label = "SUSPICIOUS"
    else:
        label = "LEGIT"

    if not reasons:
        reasons.append("No suspicious indicators matched.")

    return label, score, reasons


if __name__ == "__main__":
    user_input = input("Paste FULL email (headers + body): ")
    label, score, reasons = analyse_text(user_input)
    print("\nResult:", label)
    print("Score:", score)
    print("Reasons:")
    for r in reasons:
        print("-", r)