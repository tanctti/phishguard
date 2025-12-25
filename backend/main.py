# backend/main.py

import asyncio
from dotenv import load_dotenv  # 1. Импорт

load_dotenv()  # 2. Загрузка ДО импортов модулей!

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .schemas import AnalysisRequest, AnalysisReport, CheckResult, HeadersRequest
from . import url_analyzer, content_analyzer, heuristic_model, text_analyzer
from .email_headers import analyze_email_headers

app = FastAPI(
    title="PhishGuard API",
    description="API для анализа URL, текста и email на предмет фишинга.",
    version="1.6.0"
)

# CORS
trusted_origins = [
    "https://mail.google.com",
    "https://outlook.live.com",
    "https://outlook.office.com",
    "https://mail.yahoo.com",
    "https://mail.yandex.ru",
    # Убедись, что ID совпадает с твоим расширением
    "chrome-extension://gjiocbpbjkfhgbgjijpamnpdmggmaaao",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=trusted_origins,
    allow_credentials=False,
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


@app.post("/analyze", response_model=AnalysisReport)
async def analyze_request(request: AnalysisRequest):
    """Основной эндпоинт для комплексного анализа URL, текста и/или email-заголовков."""
    url = request.url
    text = request.text
    raw_headers = request.raw_headers
    results = []

    # Флаг, чтобы не анализировать заголовки дважды (из текста и из raw_headers)
    is_header_found_in_text = False

    if not url and not text and not raw_headers:
        raise HTTPException(status_code=400, detail="Необходимо предоставить url, текст или заголовки для анализа.")

    # --- 1. Анализ текста и поиск в нем заголовков ---
    if text:
        text_res = text_analyzer.analyze_email_text(text)
        results.append(text_res)

        # Ключевые слова для поиска заголовков (русские и английские)
        header_keywords = [
            "Received:", "DKIM-Signature:", "Return-Path:", "Authentication-Results:",
            "Получено:", "DKIM-подпись:", "Путь возврата:", "Аутентификация-результаты:", "От:", "Кому:"
        ]

        if any(keyword in text for keyword in header_keywords):
            is_header_found_in_text = True

            # Нормализация: заменяем русские термины на английские
            normalized_text = text
            replacements = {
                "Получено:": "Received:",
                "DKIM-подпись:": "DKIM-Signature:",
                "путь возврата:": "Return-Path:",
                "Путь возврата:": "Return-Path:",
                "Аутентификация-результаты:": "Authentication-Results:",
                "От:": "From:",
                "Кому:": "To:",
                "Дата:": "Date:",
                "Тема:": "Subject:",
                "сбой": "fail",
                "пройти": "pass",
                "нейтрально": "neutral",
                "нет": "none"
            }

            for rus, eng in replacements.items():
                normalized_text = normalized_text.replace(rus, eng)

            # Анализируем найденные в тексте заголовки
            headers_res_from_text = analyze_email_headers(normalized_text)
            results.append(headers_res_from_text)

            # Если raw_headers пуст, используем найденные заголовки для ML-модели
            if not raw_headers:
                raw_headers = normalized_text

    else:
        text_res = CheckResult(check_name="Text Analysis", is_suspicious=False, details="Текст не предоставлен.")

    # --- 2. Анализ переданных raw_headers ---
    # Запускаем, только если заголовки пришли отдельно И мы их еще не нашли в тексте
    if request.raw_headers and not is_header_found_in_text:
        headers_res = analyze_email_headers(request.raw_headers)
        results.append(headers_res)

    # --- 3. Анализ URL ---
    if url:
        # Синхронные проверки
        reg_age_res = url_analyzer.check_domain_age(url)
        lexical_res = url_analyzer.check_lexical_features(url)
        typesquat_res = url_analyzer.check_typesquatting(url)
        subdomain_res = url_analyzer.check_suspicious_subdomain(url)
        tld_res = url_analyzer.check_suspicious_tld(url)
        protocol_res = url_analyzer.check_protocol(url)
        domain_pattern_res = url_analyzer.check_random_looking_domain(url)
        host_port_res = url_analyzer.check_ip_or_port(url)
        path_res = url_analyzer.check_path_indicators(url)
        tls_res = url_analyzer.check_tls_certificate(url)

        results.extend([
            reg_age_res, lexical_res, typesquat_res, subdomain_res,
            tld_res, protocol_res, domain_pattern_res, host_port_res, path_res,
            tls_res
        ])

        # Асинхронные проверки
        gsb_task = url_analyzer.check_google_safe_browsing(url)
        redirects_task = url_analyzer.check_redirects(url)
        hsts_task = url_analyzer.check_hsts(url)
        content_task = content_analyzer.analyze_page_content(url)
        urlhaus_task = url_analyzer.check_urlhaus(url)

        gsb_res, redirects_res, hsts_res, content_results, urlhaus_res = await asyncio.gather(
            gsb_task, redirects_task, hsts_task, content_task, urlhaus_task
        )

        results.extend([gsb_res, redirects_res, hsts_res, urlhaus_res])
        results.extend(content_results)

        # Признаки для ML из URL
        is_punycode = lexical_res.check_name == "Punycode" and lexical_res.is_suspicious
        has_at_symbol = lexical_res.check_name == "URL Symbols" and lexical_res.is_suspicious
        is_long_url = lexical_res.check_name == "URL Length" and lexical_res.is_suspicious

        def has_check(name_prefix: str) -> bool:
            return any((r.check_name.startswith(name_prefix) and r.is_suspicious) for r in content_results)

        features_for_heuristic = {
            'is_new_domain': reg_age_res.is_suspicious,
            'is_punycode': is_punycode,
            'has_at_symbol': has_at_symbol,
            'is_long_url': is_long_url,
            'has_password_form': has_check("Page Content: Password Form"),
            'is_typesquatting': typesquat_res.is_suspicious,
            'in_google_blacklist': gsb_res.is_suspicious,
            'is_http': protocol_res.is_suspicious,
            'has_text_triggers': text_res.is_suspicious,
            'has_ip_in_url': url_analyzer.is_ip_address_host(url),
            'has_non_standard_port': (url_analyzer.get_port(url) not in (80, 443)),
            'is_suspicious_tld': tld_res.is_suspicious,
            'has_suspicious_subdomain': subdomain_res.is_suspicious,
            'looks_random_domain': domain_pattern_res.is_suspicious,
            'has_suspicious_path_keywords': path_res.is_suspicious,
            'has_excessive_redirects': redirects_res.is_suspicious,
            'tls_issues': tls_res.is_suspicious,
            'no_hsts': hsts_res.is_suspicious,
            'in_urlhaus_blacklist': urlhaus_res.is_suspicious,
            'form_action_mismatch': has_check("Page Content: Form Action Mismatch"),
            'external_scripts_suspicious': has_check("Page Content: External Scripts"),
            'exec_download_links': has_check("Page Content: Executable Downloads"),
            'hidden_iframes': has_check("Page Content: Hidden Iframes"),
        }
    else:
        # Если URL нет, анализируем только текст
        features_for_heuristic = {
            'has_text_triggers': text_res.is_suspicious,
        }

    # --- 4. Признаки заголовков для ML ---
    # Ищем результат анализа заголовков в общем списке (он уже добавлен выше)
    header_check_results = next((r for r in results if r.check_name.startswith("Email Headers")), None)

    if header_check_results and header_check_results.is_suspicious:
        details_lower = header_check_results.details.lower()
        features_for_heuristic.update({
            'header_spf_fail': 'spf: fail' in details_lower or 'spf: softfail' in details_lower,
            'header_dkim_fail': 'dkim: fail' in details_lower,
            'header_dmarc_fail': 'dmarc: fail' in details_lower,
            'header_mismatch': 'несоответствие' in details_lower,
        })

    # --- ML-результат ---
    heuristic_result = heuristic_model.predict_phishing_probability(features_for_heuristic)
    results.append(heuristic_result)

    # --- Вердикт ---
    try:
        score_str = heuristic_result.details.split(' в ')[1].split('%')[0]
        score = int(score_str)
    except (IndexError, ValueError):
        score = sum(1 for r in results if r.is_suspicious) * 5

    verdict = "Информация"
    if url:
        verdict = "Безопасно"

    if 30 <= score < 70:
        verdict = "Подозрительно"
    elif score >= 70:
        verdict = "ОПАСНО! Высокая вероятность фишинга!"

    if not url and text:
        verdict = f"Анализ текста: {verdict}"

    return AnalysisReport(
        final_verdict=verdict,
        overall_score=score,
        results=results
    )


@app.post("/analyze_headers", response_model=CheckResult)
def analyze_headers(req: HeadersRequest):
    return analyze_email_headers(req.raw_headers)


@app.get("/")
def read_root():
    return {"message": "PhishGuard Analyzer is running."}
