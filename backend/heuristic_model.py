# backend/heuristic_model.py
from .schemas import CheckResult

# Веса признаков (эвристика)
FEATURE_WEIGHTS = {
    # Базовые
    'is_new_domain': 25,
    'is_punycode': 30,
    'has_at_symbol': 15,
    'is_long_url': 5,
    'has_password_form': 25,
    'is_http': 15,
    'is_typesquatting': 40,
    'in_google_blacklist': 50,
    'has_text_triggers': 25,

    # Новые URL/домен
    'has_ip_in_url': 30,
    'has_non_standard_port': 15,
    'is_suspicious_tld': 35,
    'has_suspicious_subdomain': 40,
    'looks_random_domain': 35,
    'short_registration_period': 25,
    'has_suspicious_path_keywords': 20,
    'has_excessive_redirects': 20,

    # Инфраструктура/интеграции
    'in_urlhaus_blacklist': 55,
    'tls_issues': 20,
    'no_hsts': 10,

    # Контент
    'form_action_mismatch': 35,
    'external_scripts_suspicious': 20,
    'exec_download_links': 35,
    'hidden_iframes': 15,

    # --- НОВЫЕ ВЕСА ДЛЯ EMAIL-ЗАГОЛОВКОВ ---
    'header_spf_fail': 30,         # Сбой SPF - серьезный признак подделки
    'header_dkim_fail': 25,        # Сбой DKIM - признак того, что письмо было изменено
    'header_dmarc_fail': 35,       # Сбой DMARC - домен явно не разрешает такую отправку
    'header_mismatch': 40,         # Несоответствие адресов From и Return-Path - классика фишинга
}


def predict_phishing_probability(features: dict) -> CheckResult:
    """Вычисляет вероятность фишинга на основе словаря признаков."""
    phishing_score = 0
    activated_factors = []

    for feature_name, is_activated in features.items():
        if is_activated:
            weight = FEATURE_WEIGHTS.get(feature_name, 0)
            if weight > 0:
                phishing_score += weight
                activated_factors.append(f"{feature_name} (+{weight})")


    # Базовая вероятностная оценка
    baseline = 70
    probability = int(100 * (phishing_score / (phishing_score + baseline))) if phishing_score > 0 else 0
    probability = min(probability, 99)

    # Усиливаем "критические комбинации":
    critical_flags = [
        features.get('has_suspicious_subdomain', False),
        features.get('is_suspicious_tld', False),
        features.get('looks_random_domain', False),
        features.get('is_new_domain', False),
        features.get('short_registration_period', False),
        features.get('header_mismatch', False),
    ]
    critical_count = sum(1 for f in critical_flags if f)

    if critical_count >= 3:
        probability = max(probability, 92)
    elif critical_count >= 2:
        probability = max(probability, 85)

    is_suspicious = probability > 50

    details = f"heuristic-модель оценила вероятность фишинга в {probability}%."
    if activated_factors and probability > 30:
        details += f" Основные факторы: {', '.join(activated_factors)}."


    return CheckResult(
        check_name="Heuristic Analysis",
        is_suspicious=is_suspicious,
        details=details
    )
