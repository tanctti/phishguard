# backend/content_analyzer.py
import httpx
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import tldextract
from .schemas import CheckResult

SUSPICIOUS_TLDS = {
    "live", "top", "xyz", "site", "online", "club", "click", "link",
    "cam", "buzz", "space", "fun", "pw", "work", "shop", "rest", "fit",
    "gq", "cf", "ml", "tk", "ga"
}

EXEC_EXTENSIONS = ("exe", "msi", "apk", "dmg", "pkg", "bat", "ps1", "js", "scr", "jar", "vbs", "reg")


async def analyze_page_content(url: str):
    """Анализирует HTML-контент страницы. Возвращает список CheckResult."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36'
    }
    results = []
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            response = await client.get(url, headers=headers)
            html = response.text
    except Exception as e:
        return [CheckResult(check_name="Page Content", is_suspicious=True,
                            details=f"Не удалось загрузить или проанализировать страницу: {e}")]

    soup = BeautifulSoup(html, 'html.parser')
    ext = tldextract.extract(url)
    current_registrable = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

    # 1) Наличие формы ввода пароля
    pwd_inputs = soup.find_all('input', {'type': 'password'})
    if pwd_inputs:
        results.append(CheckResult(
            check_name="Page Content: Password Form",
            is_suspicious=True,
            details="На странице найдена форма для ввода пароля. Будьте осторожны!"
        ))

    # 2) Несоответствие доменов form action
    mismatched = set()
    for form in soup.find_all('form'):
        action = (form.get('action') or "").strip()
        if not action:
            continue
        absolute = urljoin(url, action)
        aext = tldextract.extract(absolute)
        action_reg = f"{aext.domain}.{aext.suffix}" if aext.suffix else aext.domain
        if action_reg and action_reg != current_registrable:
            mismatched.add(action_reg)
    if mismatched:
        results.append(CheckResult(
            check_name="Page Content: Form Action Mismatch",
            is_suspicious=True,
            details=f"Формы отправляют данные на другие домены: {', '.join(sorted(mismatched))}"
        ))

    # 3) Внешние скрипты с подозрительных TLD
    bad_scripts = []
    for s in soup.find_all('script', src=True):
        src_url = urljoin(url, s['src'])
        se = tldextract.extract(src_url)
        tld = se.suffix.lower()
        if tld in SUSPICIOUS_TLDS:
            reg = f"{se.domain}.{se.suffix}"
            bad_scripts.append(reg)
    if bad_scripts:
        results.append(CheckResult(
            check_name="Page Content: External Scripts",
            is_suspicious=True,
            details=f"Подключены внешние скрипты с подозрительных доменов: {', '.join(sorted(set(bad_scripts)))}"
        ))

    # 4) Ссылки на исполняемые файлы
    exec_links = []
    for a in soup.find_all('a', href=True):
        href = urljoin(url, a['href'])
        lower = href.lower()
        for extn in EXEC_EXTENSIONS:
            if lower.endswith("." + extn) or f".{extn}?" in lower:
                exec_links.append(href)
                break
    if exec_links:
        results.append(CheckResult(
            check_name="Page Content: Executable Downloads",
            is_suspicious=True,
            details=f"Найдены ссылки на исполняемые файлы ({len(exec_links)}). Это может быть опасно."
        ))

    # 5) Скрытые iframes
    hidden_iframes = 0
    for iframe in soup.find_all('iframe'):
        hidden = False
        style = (iframe.get('style') or "").lower()
        if 'display:none' in style or 'visibility:hidden' in style or 'opacity:0' in style:
            hidden = True
        width = iframe.get('width') or ""
        height = iframe.get('height') or ""
        try:
            w = int(width) if width.isdigit() else None
            h = int(height) if height.isdigit() else None
            if (w is not None and w <= 3) or (h is not None and h <= 3):
                hidden = True
        except Exception:
            pass
        if iframe.has_attr('hidden'):
            hidden = True
        if hidden:
            hidden_iframes += 1
    if hidden_iframes > 0:
        results.append(CheckResult(
            check_name="Page Content: Hidden Iframes",
            is_suspicious=True,
            details=f"Обнаружены скрытые iframe: {hidden_iframes}."
        ))

    if not results:
        results.append(CheckResult(check_name="Page Content", is_suspicious=False,
                                   details="Подозрительных элементов на странице не найдено."))

    return results
