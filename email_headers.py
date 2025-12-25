# backend/email_headers.py
import re
from urllib.parse import urlparse
from .schemas import CheckResult

def _extract_domain(email_addr: str) -> str:
    if not email_addr:
        return ""
    email_addr = email_addr.strip().strip("<>").split()[-1]
    if "@" in email_addr:
        return email_addr.split("@")[-1].lower()
    # Если это URL
    try:
        netloc = urlparse(email_addr).netloc
        if netloc:
            return netloc.lower()
    except Exception:
        pass
    return email_addr.lower()


def analyze_email_headers(raw: str) -> CheckResult:
    """Простая эвристика анализа заголовков: SPF/DKIM/DMARC и несоответствия From/Return-Path/Reply-To."""
    if not raw:
        return CheckResult(check_name="Email Headers Analysis", is_suspicious=False, details="Заголовки не предоставлены.")

    lower = raw.lower()

    # SPF/DKIM/DMARC из Authentication-Results
    spf_match = re.search(r"spf=\s*(pass|fail|softfail|neutral|none|permerror|temperror)", lower)
    dkim_match = re.search(r"dkim=\s*(pass|fail|none|temperror|permerror)", lower)
    dmarc_match = re.search(r"dmarc=\s*(pass|fail|none|temperror|permerror)", lower)

    # From / Return-Path / Reply-To
    from_match = re.search(r"^from:\s*(.+)$", raw, flags=re.IGNORECASE | re.MULTILINE)
    return_path_match = re.search(r"^return-path:\s*(.+)$", raw, flags=re.IGNORECASE | re.MULTILINE)
    reply_to_match = re.search(r"^reply-to:\s*(.+)$", raw, flags=re.IGNORECASE | re.MULTILINE)

    from_domain = _extract_domain(from_match.group(1)) if from_match else ""
    rp_domain = _extract_domain(return_path_match.group(1)) if return_path_match else ""
    rt_domain = _extract_domain(reply_to_match.group(1)) if reply_to_match else ""

    issues = []
    suspicious = False

    if spf_match:
        spf_res = spf_match.group(1)
        if spf_res not in ("pass", "neutral", "none"):
            issues.append(f"SPF: {spf_res}")
            suspicious = True
    else:
        issues.append("SPF: нет информации")

    if dkim_match:
        dkim_res = dkim_match.group(1)
        if dkim_res not in ("pass", "none"):
            issues.append(f"DKIM: {dkim_res}")
            suspicious = True
    else:
        issues.append("DKIM: нет информации")

    if dmarc_match:
        dmarc_res = dmarc_match.group(1)
        if dmarc_res not in ("pass", "none"):
            issues.append(f"DMARC: {dmarc_res}")
            suspicious = True
    else:
        issues.append("DMARC: нет информации")

    # Несоответствия в адресах
    if from_domain and rp_domain and (from_domain != rp_domain):
        issues.append(f"Несоответствие From ({from_domain}) и Return-Path ({rp_domain})")
        suspicious = True
    if rt_domain and from_domain and (rt_domain != from_domain):
        issues.append(f"Несоответствие From ({from_domain}) и Reply-To ({rt_domain})")
        suspicious = True

    details = "; ".join(issues) if issues else "Нарушений не обнаружено."
    return CheckResult(check_name="Email Headers Analysis", is_suspicious=suspicious, details=details)
