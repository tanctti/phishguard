# backend/url_analyzer.py
import os
import re
import socket
import ssl
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
import tldextract
import whois
import Levenshtein  # Для вычисления "расстояния" между строками

from .brands import KNOWN_BRANDS
from .schemas import CheckResult

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
ENABLE_EXTERNAL_INTEL = os.getenv("ENABLE_EXTERNAL_INTEL", "true").lower() in ("1", "true", "yes")

# Подозрительные TLD часто используемые в фишинге/скаме
SUSPICIOUS_TLDS = {
    "live", "top", "xyz", "site", "online", "club", "click", "link",
    "cam", "buzz", "space", "fun", "pw", "work", "shop", "rest", "fit",
    "gq", "cf", "ml", "tk", "ga"
}

# Ключевые слова в субдоменах, часто используемые как "приманка"
SUSPICIOUS_SUBDOMAIN_KEYWORDS = [
    "promocode", "promo", "bonus", "gift", "free", "win", "lucky", "giveaway",
    "support", "security", "verify", "account", "login", "signin", "secure",
    "update", "billing", "prize"
]

# Подозрительные индикаторы в пути/параметрах URL
SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "verify", "verification", "reset", "billing",
    "gift", "free", "promo", "promocode", "bonus", "win", "award"
]

BASE64_LIKE_REGEX = re.compile(r'(?i)(?:^|[/?&=])([A-Za-z0-9+/]{32,}={0,2})(?:$|[&/?#])')


def _extract(url: str):
    ext = tldextract.extract(url)
    registrable = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    return ext, registrable


def _host_port_scheme(url: str):
    p = urlparse(url)
    return p.hostname, p.port, p.scheme, p.path, p.query


def is_ip_address_host(url: str) -> bool:
    host, _, _, _, _ = _host_port_scheme(url)
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def get_port(url: str):
    _, port, scheme, _, _ = _host_port_scheme(url)
    if port:
        return port
    return 443 if scheme == "https" else 80


def check_domain_age(url: str) -> CheckResult:
    """Проверяет возраст домена. Новые домены подозрительны."""
    try:
        _, registrable = _extract(url)
        domain_info = whois.whois(registrable)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age = (datetime.now(timezone.utc) - creation_date.replace(tzinfo=timezone.utc)).days
            if age < 180:
                return CheckResult(
                    check_name="Domain Age",
                    is_suspicious=True,
                    details=f"Домен очень новый! Он существует всего {age} дней. Это частый признак фишинга."
                )
            return CheckResult(check_name="Domain Age", is_suspicious=False, details=f"Домен существует {age} дней.")
    except Exception as e:
        return CheckResult(check_name="Domain Age", is_suspicious=True,
                           details=f"Не удалось получить информацию о домене: {e}")
    return CheckResult(check_name="Domain Age", is_suspicious=False, details="Информация о возрасте домена не найдена.")


def check_short_registration_period(url: str) -> CheckResult:
    """Проверяет, зарегистрирован ли домен на короткий срок (менее 1 года)."""
    try:
        _, registrable = _extract(url)
        domain_info = whois.whois(registrable)
        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if creation_date and expiration_date:
            term_days = (expiration_date - creation_date).days
            if term_days < 365:
                return CheckResult(
                    check_name="Registration Term",
                    is_suspicious=True,
                    details=f"Домен зарегистрирован на короткий срок: {term_days} дней. Это часто признак одноразовых схем."
                )
            return CheckResult(
                check_name="Registration Term",
                is_suspicious=False,
                details=f"Срок регистрации домена нормальный: {term_days} дней."
            )

        return CheckResult(
            check_name="Registration Term",
            is_suspicious=False,
            details="Не удалось определить срок регистрации (WHOIS неполный)."
        )
    except Exception as e:
        return CheckResult(
            check_name="Registration Term",
            is_suspicious=False,
            details=f"Не удалось получить данные WHOIS о сроке регистрации: {e}"
        )


def check_lexical_features(url: str) -> CheckResult:
    """Анализирует URL на наличие подозрительных признаков (длина, символы и т.д.)."""
    extracted = tldextract.extract(url)
    domain = extracted.domain + ('.' + extracted.suffix if extracted.suffix else '')

    if len(url) > 75:
        return CheckResult(check_name="URL Length", is_suspicious=True,
                           details="URL слишком длинный, что может маскировать реальный адрес.")
    if "@" in url:
        return CheckResult(check_name="URL Symbols", is_suspicious=True,
                           details="URL содержит символ '@', что может вводить в заблуждение.")
    if domain.startswith("xn--"):
        return CheckResult(check_name="Punycode", is_suspicious=True,
                           details="URL использует Punycode, что может скрывать поддельный домен (омографическая атака).")

    return CheckResult(check_name="Lexical Analysis", is_suspicious=False,
                       details="Подозрительных лексических признаков не найдено.")


def check_typesquatting(url: str) -> CheckResult:
    """Проверяет домен на схожесть с известными брендами (тайпсквоттинг)."""
    try:
        extracted = tldextract.extract(url)
        domain = extracted.domain
        for brand in KNOWN_BRANDS:
            distance = Levenshtein.distance(domain, brand)
            if 0 < distance <= 2 and abs(len(domain) - len(brand)) <= 1:
                return CheckResult(
                    check_name="Typesquatting Alert",
                    is_suspicious=True,
                    details=f"Домен '{domain}' очень похож на известный бренд '{brand}'. Высокий риск фишинга!"
                )
    except Exception:
        return CheckResult(check_name="Typesquatting Alert", is_suspicious=False,
                           details="Анализ на тайпсквоттинг не удался.")

    return CheckResult(check_name="Typesquatting Alert", is_suspicious=False,
                       details="Признаков тайпсквоттинга не обнаружено.")


def check_suspicious_subdomain(url: str) -> CheckResult:
    """Флаги подозрительных слов в субдомене (например, promocode.)."""
    extracted = tldextract.extract(url)
    sub = extracted.subdomain.lower()
    if not sub:
        return CheckResult(check_name="Subdomain Analysis", is_suspicious=False, details="Субдомен отсутствует.")
    tokens = [part for part in sub.split('.') if part]
    matched = sorted({kw for kw in SUSPICIOUS_SUBDOMAIN_KEYWORDS for t in tokens if kw in t})
    if matched:
        return CheckResult(
            check_name="Subdomain Analysis",
            is_suspicious=True,
            details=f"В субдомене обнаружены приманки: {', '.join(matched)}. Это часто используется в фишинге."
        )
    return CheckResult(check_name="Subdomain Analysis", is_suspicious=False, details="Подозрительных слов в субдомене нет.")


def check_suspicious_tld(url: str) -> CheckResult:
    """Проверяет TLD на предмет частого злоупотребления (например, .live)."""
    extracted = tldextract.extract(url)
    tld = extracted.suffix.lower()
    if tld in SUSPICIOUS_TLDS:
        return CheckResult(
            check_name="TLD Reputation",
            is_suspicious=True,
            details=f"TLD '.{tld}' часто используется в мошеннических схемах. Будьте осторожны."
        )
    return CheckResult(check_name="TLD Reputation", is_suspicious=False, details=f"TLD '.{tld}' не в списке часто злоупотребляемых.")


def check_random_looking_domain(url: str) -> CheckResult:
    """Выявляет 'рандомные'/аббревиатурные домены (короткие, мало гласных), напр. 'pfm'."""
    extracted = tldextract.extract(url)
    core = extracted.domain.lower()
    if not core:
        return CheckResult(check_name="Domain Pattern", is_suspicious=True, details="Не удалось извлечь домен.")
    vowels = set("aeiouy")
    vowel_count = sum(1 for ch in core if ch in vowels)
    ratio = vowel_count / max(len(core), 1)
    if len(core) <= 3 or (len(core) <= 5 and ratio < 0.25):
        return CheckResult(
            check_name="Domain Pattern",
            is_suspicious=True,
            details=f"Основной домен выглядит как аббревиатура ('{core}', гласных {vowel_count}/{len(core)})."
        )
    return CheckResult(check_name="Domain Pattern", is_suspicious=False, details=f"Паттерн домена выглядит естественно ('{core}').")


def check_protocol(url: str) -> CheckResult:
    """Проверяет использование протокола."""
    try:
        scheme = urlparse(url).scheme.lower()
        if scheme == "http":
            return CheckResult(
                check_name="Protocol",
                is_suspicious=True,
                details="Используется незащищенный протокол HTTP. Рекомендуется HTTPS."
            )
        return CheckResult(check_name="Protocol", is_suspicious=False, details=f"Протокол: {scheme.upper()}.")
    except Exception as e:
        return CheckResult(check_name="Protocol", is_suspicious=True, details=f"Не удалось определить протокол: {e}")


def check_ip_or_port(url: str) -> CheckResult:
    """Проверка на IP-адрес в URL и нестандартный порт."""
    host, port, scheme, _, _ = _host_port_scheme(url)
    issues = []
    suspicious = False
    if not host:
        return CheckResult(check_name="Host/Port", is_suspicious=True, details="Не удалось определить хост.")
    try:
        ipaddress.ip_address(host)
        issues.append("В URL указан IP-адрес (вместо домена)")
        suspicious = True
    except ValueError:
        pass
    if port and port not in (80, 443):
        issues.append(f"Указан нестандартный порт: {port}")
        suspicious = True
    if not issues:
        return CheckResult(check_name="Host/Port", is_suspicious=False, details=f"Хост: {host}, порт: {port or ('443' if scheme=='https' else '80')}.")
    return CheckResult(check_name="Host/Port", is_suspicious=suspicious, details="; ".join(issues))


def check_path_indicators(url: str) -> CheckResult:
    """Проверяет подозрительные слова в пути/параметрах, base64-подобные строки и чрезмерные параметры."""
    p = urlparse(url)
    path_lower = (p.path or "").lower()
    query_lower = (p.query or "").lower()

    matched = sorted({kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in path_lower or kw in query_lower})

    base64_hits = BASE64_LIKE_REGEX.findall(p.path + "?" + p.query if p.query else p.path)
    long_query = len(p.query) > 200
    many_params = p.query.count("&") + p.query.count("=") > 12 if p.query else False

    issues = []
    if matched:
        issues.append(f"Найдены слова-приманки в пути/параметрах: {', '.join(matched)}")
    if base64_hits:
        issues.append("Выявлены длинные base64-подобные фрагменты")
    if long_query:
        issues.append("Очень длинная строка параметров")
    if many_params:
        issues.append("Слишком много параметров запроса")

    if issues:
        return CheckResult(check_name="URL Path/Query", is_suspicious=True, details="; ".join(issues))
    return CheckResult(check_name="URL Path/Query", is_suspicious=False, details="Явных приманок в пути/параметрах не обнаружено.")


async def check_redirects(url: str) -> CheckResult:
    """Проверяет чрезмерные/междоменные редиректы."""
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            resp = await client.get(url)
            history = resp.history or []
            steps = len(history)
            if steps == 0:
                return CheckResult(check_name="Redirects", is_suspicious=False, details="Редиректы отсутствуют.")

            # Сбор доменов по цепочке
            domains = []
            for h in history:
                loc = h.headers.get("location")
                if loc:
                    try:
                        ext, reg = _extract(loc)
                        if reg:
                            domains.append(reg)
                    except Exception:
                        pass
            # Добавляем финальный домен
            try:
                ext_final, reg_final = _extract(str(resp.url))
                if reg_final:
                    domains.append(reg_final)
            except Exception:
                pass

            unique_domains = list(dict.fromkeys(domains))
            cross_domain = len(set(unique_domains)) > 1
            too_many = steps >= 4

            if cross_domain or too_many:
                issues = []
                if cross_domain:
                    issues.append(f"Редиректы между разными доменами: {' → '.join(unique_domains)}")
                if too_many:
                    issues.append(f"Слишком длинная цепочка редиректов: {steps} шагов")
                return CheckResult(check_name="Redirects", is_suspicious=True, details="; ".join(issues))

            return CheckResult(check_name="Redirects", is_suspicious=False, details=f"Редиректов: {steps}, домен не менялся.")
    except Exception as e:
        return CheckResult(check_name="Redirects", is_suspicious=False, details=f"Не удалось проверить редиректы: {e}")


def check_tls_certificate(url: str) -> CheckResult:
    """Проверяет TLS-сертификат: валидность, SAN/CN соответствие, свежесть выдачи."""
    host, port, scheme, _, _ = _host_port_scheme(url)
    if scheme != "https" or not host:
        return CheckResult(check_name="TLS Certificate", is_suspicious=False,
                           details="HTTPS не используется или хост не определен.")

    try:
        ctx = ssl.create_default_context()
        # Устанавливаем таймаут и оборачиваем сокет
        with socket.create_connection((host, port or 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            return CheckResult(check_name="TLS Certificate", is_suspicious=True,
                               details="Не удалось получить сертификат (пустой ответ).")

        not_after = cert.get("notAfter")
        not_before = cert.get("notBefore")
        san = [v for (k, v) in cert.get("subjectAltName", []) if k == "DNS"]

        # Надежное извлечение Common Name (CN)
        cn = None
        subject = cert.get("subject", [])
        for item in subject:
            # subject - это список RDN (Relative Distinguished Names).
            # Каждый RDN - это кортеж кортежей атрибутов.
            # Обычно: ((('commonName', 'example.com'),),)
            for attribute in item:
                if attribute[0] == 'commonName':
                    cn = attribute[1]
                    break
            if cn:
                break

        fmt = "%b %d %H:%M:%S %Y %Z"
        now = datetime.now(timezone.utc)

        days_to_exp = None
        days_since_issue = None
        issues = []
        suspicious = False

        if not_after:
            try:
                exp_dt = datetime.strptime(not_after, fmt).replace(tzinfo=timezone.utc)
                days_to_exp = (exp_dt - now).days
                if days_to_exp < 7:
                    issues.append(f"Сертификат скоро истекает (через {days_to_exp} дней)")
                    suspicious = True
            except ValueError:
                pass  # Ошибка парсинга даты

        if not_before:
            try:
                start_dt = datetime.strptime(not_before, fmt).replace(tzinfo=timezone.utc)
                days_since_issue = (now - start_dt).days
                if days_since_issue <= 2:
                    issues.append("Сертификат выдан совсем недавно (менее 2 дней)")
                    suspicious = True
            except ValueError:
                pass

        # Проверка соответствия хосту
        # SAN (Subject Alternative Name) - основной способ проверки в современном Web
        host_in_san = False
        if san:
            host_in_san = any(
                h.lower() == host.lower() or
                (h.startswith("*.") and host.lower().endswith(h[1:].lower()))
                for h in san
            )

        # Если в SAN нет, проверяем CN (устаревший метод, но иногда нужен)
        host_matches_cn = False
        if cn:
            host_matches_cn = (cn.lower() == host.lower()) or (
                        cn.startswith("*.") and host.lower().endswith(cn[1:].lower()))

        if not host_in_san and not host_matches_cn:
            issues.append(f"Имя хоста '{host}' не найдено в сертификате (CN: {cn}, SAN: {san})")
            suspicious = True

        if not issues:
            return CheckResult(check_name="TLS Certificate", is_suspicious=False,
                               details="Сертификат валиден и соответствует домену.")

        return CheckResult(check_name="TLS Certificate", is_suspicious=suspicious, details="; ".join(issues))

    except Exception as e:
        # Ловим ошибку, чтобы не положить весь анализ, но сообщаем о ней
        return CheckResult(check_name="TLS Certificate", is_suspicious=True,
                           details=f"Ошибка проверки сертификата: {e}")


async def check_hsts(url: str) -> CheckResult:
    """Проверяет наличие заголовка HSTS на HTTPS."""
    p = urlparse(url)
    if p.scheme != "https":
        return CheckResult(check_name="HSTS", is_suspicious=True, details="HSTS не применим без HTTPS.")
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            r = await client.get(url)
            hsts = r.headers.get("strict-transport-security")
            if hsts:
                return CheckResult(check_name="HSTS", is_suspicious=False, details=f"HSTS включен: {hsts[:120]}...")
            return CheckResult(check_name="HSTS", is_suspicious=True, details="Заголовок HSTS отсутствует.")
    except Exception as e:
        return CheckResult(check_name="HSTS", is_suspicious=False, details=f"Не удалось проверить HSTS: {e}")


async def check_google_safe_browsing(url: str) -> CheckResult:
    """Проверяет URL по базе Google Safe Browsing."""
    if not ENABLE_EXTERNAL_INTEL:
        return CheckResult(check_name="Google Safe Browsing", is_suspicious=False, details="Проверка отключена (ENABLE_EXTERNAL_INTEL=false).")
    if not GOOGLE_API_KEY:
        return CheckResult(check_name="Google Safe Browsing", is_suspicious=False, details="Ключ API не задан. Проверка пропущена.")

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    payload = {
        "client": {"clientId": "phishguard-ai", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(api_url, json=payload, timeout=5)
            if response.status_code == 200 and response.json():
                threat_type = response.json()['matches'][0]['threatType']
                return CheckResult(
                    check_name="Google Safe Browsing",
                    is_suspicious=True,
                    details=f"URL найден в черном списке Google как {threat_type}!"
                )
        except Exception:
            return CheckResult(check_name="Google Safe Browsing", is_suspicious=False,
                               details="Не удалось проверить по базе Google.")

    return CheckResult(check_name="Google Safe Browsing", is_suspicious=False,
                       details="URL не найден в черных списках Google.")


async def check_urlhaus(url: str) -> CheckResult:
    """Проверка URL по базе URLHaus (abuse.ch)."""
    if not ENABLE_EXTERNAL_INTEL:
        return CheckResult(check_name="URLHaus Blacklist", is_suspicious=False, details="Проверка отключена (ENABLE_EXTERNAL_INTEL=false).")
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    try:
        async with httpx.AsyncClient(timeout=6) as client:
            resp = await client.post(api_url, data={"url": url})
            data = resp.json()
            if data.get("query_status") == "ok" and data.get("url_status") in {"online", "offline"}:
                return CheckResult(
                    check_name="URLHaus Blacklist",
                    is_suspicious=True,
                    details=f"URL найден в базе URLHaus (status: {data.get('url_status')})."
                )
            return CheckResult(check_name="URLHaus Blacklist", is_suspicious=False, details="URL не найден в базе URLHaus.")
    except Exception as e:
        return CheckResult(check_name="URLHaus Blacklist", is_suspicious=False, details=f"Ошибка проверки URLHaus: {e}")