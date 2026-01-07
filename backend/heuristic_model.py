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

    # Email-заголовки
    'header_spf_fail': 30,
    'header_dkim_fail': 25,
    'header_dmarc_fail': 35,
    'header_mismatch': 40,
}

# Названия признаков для отчёта
FEATURE_LABELS_RU = {
    'is_new_domain': 'Новый домен (молодой возраст)',
    'is_punycode': 'Punycode/омографическая маскировка',
    'has_at_symbol': 'Символ @ в URL',
    'is_long_url': 'Слишком длинный URL',
    'has_password_form': 'Форма ввода пароля на странице',
    'is_http': 'Незащищённый протокол HTTP',
    'is_typesquatting': 'Тайпсквоттинг (похож на бренд)',
    'in_google_blacklist': 'Найдено в базе Google Safe Browsing',
    'has_text_triggers': 'Социальная инженерия в тексте (триггеры)',

    'has_ip_in_url': 'IP-адрес вместо домена',
    'has_non_standard_port': 'Нестандартный порт в URL',
    'is_suspicious_tld': 'Подозрительная доменная зона (TLD)',
    'has_suspicious_subdomain': 'Подозрительный поддомен (приманки)',
    'looks_random_domain': 'Случайное/аббревиатурное имя домена',
    'short_registration_period': 'Короткий срок регистрации домена',
    'has_suspicious_path_keywords': 'Подозрительные слова в пути/параметрах',
    'has_excessive_redirects': 'Подозрительная цепочка редиректов',

    'in_urlhaus_blacklist': 'Найдено в базе URLHaus',
    'tls_issues': 'Проблемы TLS/сертификата',
    'no_hsts': 'Нет HSTS',

    'form_action_mismatch': 'Форма отправляет данные на другой домен',
    'external_scripts_suspicious': 'Подозрительные внешние скрипты',
    'exec_download_links': 'Ссылки на исполняемые файлы',
    'hidden_iframes': 'Скрытые iframe',

    'header_spf_fail': 'SPF не прошёл проверку',
    'header_dkim_fail': 'DKIM не прошёл проверку',
    'header_dmarc_fail': 'DMARC не прошёл проверку',
    'header_mismatch': 'Несоответствие From / Reply-To / Return-Path',
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
                label = FEATURE_LABELS_RU.get(feature_name, feature_name)
                activated_factors.append((label, weight))

    # Базовая вероятностная оценка
    baseline = 70
    probability = int(100 * (phishing_score / (phishing_score + baseline))) if phishing_score > 0 else 0
    probability = min(probability, 99)

    # Усиливаем "критические комбинации"
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

    # Формируем описание
    details = f"Эвристическая модель оценила вероятность фишинга в {probability}%."
    if activated_factors and probability > 30:
        # Сортируем по весу, чтобы в отчёте были самые важные причины
        activated_factors.sort(key=lambda x: x[1], reverse=True)
        top = activated_factors[:6]
        factors_str = ", ".join([f"{name} (+{w})" for name, w in top])
        details += f" Основные факторы: {factors_str}."

    return CheckResult(
        check_name="Heuristic Analysis",
        is_suspicious=is_suspicious,
        details=details
    )
