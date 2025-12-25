// content.js — Финальная версия (единый голубо‑фиолетовый стиль, без эмодзи, цветные метки, tooltip в том же стиле)

// --- Утилиты ---
function escapeHTML(s) {
    return (s || "").toString()
        .replace(/&/g, "&amp;").replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// --- Связь с background.js для выполнения анализа ---
async function analyzeViaBackground(payload) { // payload: {url, text?}
    return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: "ANALYZE_REQUEST", payload }, (resp) => {
            if (!resp || !resp.ok) {
                showError((resp && resp.error) || "Ошибка запроса к локальному API");
                return resolve(null);
            }
            showReport(resp.report);
            resolve(resp.report);
        });
    });
}

// --- UI: Основной оверлей для отчета ---
let overlay = null;

function ensureOverlay() {
    if (overlay && document.body.contains(overlay)) return overlay;

    overlay = document.createElement("div");
    overlay.id = "pg_overlay";

    overlay.style.cssText = [
        "position:fixed",
        "top:18px",
        "right:18px",
        "z-index:2147483647",
        "max-width:420px",
        "width:420px",
        "background:#5e72e4",
        "border:1px solid rgba(255,255,255,0.25)",
        "border-radius:14px",
        "box-shadow:0 14px 30px rgba(17,24,39,0.22)",
        "overflow:hidden",
        "font:14px/1.4 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Arial,sans-serif"
    ].join(";") + ";";

    overlay.innerHTML = `
    <div style="
        padding:12px 12px;
        display:flex;
        justify-content:space-between;
        align-items:center;
        color:#fff;
      ">
      <div style="
          font-size:18px;
          font-weight:900;
          letter-spacing:0.3px;
          font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Arial, sans-serif;
        ">PhishGuard</div>
      <button id="pg_close" style="
          border:1px solid rgba(255,255,255,0.55);
          background:rgba(255,255,255,0.14);
          color:#fff;
          border-radius:10px;
          padding:6px 10px;
          cursor:pointer;
          font-weight:700;
        ">Закрыть</button>
    </div>

    <div id="pg_body" style="
        padding:12px;
        max-height:60vh;
        overflow:auto;
        background:transparent;
      ">
      <div style="
          background:rgba(255,255,255,0.94);
          border:1px solid rgba(255,255,255,0.35);
          border-radius:12px;
          padding:10px;
          color:#111827;
        ">Готовлюсь к анализу…</div>
    </div>
  `;

    overlay.querySelector("#pg_close").addEventListener("click", () => overlay.remove());
    document.body.appendChild(overlay);
    return overlay;
}

function renderReport(report) {
    const scoreRaw = report && typeof report.overall_score !== "undefined" ? Number(report.overall_score) : NaN;
    const score = Number.isFinite(scoreRaw) ? scoreRaw : 0;

    // Статус считаем по score (так не будет рассинхрона)
    let badgeText = "БЕЗОПАСНО";
    let badgeBg = "#22c55e";
    let badgeColor = "#052e16";

    if (score >= 70) {
        badgeText = "ОПАСНО";
        badgeBg = "#fb7185";
        badgeColor = "#4c0519";
    } else if (score >= 30) {
        badgeText = "ПОДОЗРИТЕЛЬНО";
        badgeBg = "#fbbf24";
        badgeColor = "#422006";
    }

    const verdict = (report && report.final_verdict ? String(report.final_verdict) : "").trim();

    // Убираем дубли: если вердикт — просто "Безопасно/Подозрительно/Опасно", то не показываем его второй раз
    const normalized = verdict.toLowerCase().replace(/^анализ текста:\s*/i, "").trim();
    const redundant =
        normalized === "безопасно" ||
        normalized === "подозрительно" ||
        normalized === "опасно";

    const verdictComment = (!verdict || redundant) ? "" : verdict;

    let html = `
      <div style="
          background:rgba(255,255,255,0.94);
          border:1px solid rgba(255,255,255,0.35);
          border-radius:12px;
          padding:10px;
          margin-bottom:10px;
        ">
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
          <span style="
              display:inline-block;
              padding:3px 10px;
              border-radius:999px;
              background:${badgeBg};
              color:${badgeColor};
              font-weight:900;
              font-size:12px;
              letter-spacing:0.2px;
            ">${badgeText}</span>

          <div style="color:#111827;font-weight:800;">
            Уровень опасности: <b>${score}/100</b>
          </div>
        </div>

        ${verdictComment ? `
          <div style="margin-top:6px;color:#111827;font-size:13px;">
            <b>Комментарий:</b> ${escapeHTML(verdictComment)}
          </div>
        ` : ``}
      </div>

      <div style="font-weight:800;margin:10px 0 8px;color:#ffffff;">
        Детальный отчет
      </div>
    `;

    // Цветная полоска слева: зелёная (OK) / жёлтая (suspicious)
    for (const r of (report.results || [])) {
        const barColor = r.is_suspicious ? "#fbbf24" : "#22c55e";
        html += `
          <div style="
              background:rgba(255,255,255,0.94);
              border:1px solid rgba(255,255,255,0.35);
              border-left:5px solid ${barColor};
              border-radius:12px;
              padding:8px 10px;
              margin:6px 0;
            ">
            <div style="font-weight:900;color:#111827;">
              ${escapeHTML(r.check_name)}
            </div>
            <div style="color:#334155;font-size:13px;margin-top:2px;">
              ${escapeHTML(r.details)}
            </div>
          </div>
        `;
    }

    return html;
}

function showError(message) {
    const ov = ensureOverlay();
    ov.querySelector("#pg_body").innerHTML = `
      <div style="
          background:rgba(255,255,255,0.94);
          border:1px solid rgba(255,255,255,0.35);
          border-radius:12px;
          padding:10px;
          color:#b00020;
          font-weight:800;
        ">${escapeHTML(message)}</div>
    `;
}

function showReport(report) {
    const ov = ensureOverlay();
    ov.querySelector("#pg_body").innerHTML = renderReport(report);
}

// Получаем результаты/ошибки от background.js (для контекстного меню)
chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === "ANALYZE_RESULT" && msg.report) {
        showReport(msg.report);
    }
    if (msg && msg.type === "ANALYZE_ERROR") {
        showError(msg.message || "Неизвестная ошибка");
    }
});


// --- Подсказка возле ссылок (tooltip) ---
let tooltip, currentLink, hideTooltipTimeout;

function createTooltip() {
    const existing = document.getElementById('pg_tooltip');
    if (existing) {
        tooltip = existing;
        return;
    }

    tooltip = document.createElement('div');
    tooltip.id = 'pg_tooltip';

    tooltip.style.cssText = `
        position: absolute;
        z-index: 2147483646;
        background: #5e72e4;
        color: #ffffff;
        padding: 10px 12px;
        border-radius: 12px;
        font-size: 13px;
        display: flex;
        align-items: center;
        gap: 10px;
        opacity: 0;
        visibility: hidden;
        transition: opacity 0.15s, visibility 0.15s;
        box-shadow: 0 10px 22px rgba(17,24,39,0.22);
        border: 1px solid rgba(255,255,255,0.28);
        pointer-events: none;
    `;

    tooltip.innerHTML = `
        <span style="font-weight:800;">Проверить ссылку?</span>
        <button id="pg_check_btn" style="
            background: rgba(255,255,255,0.92);
            color: #1f2a44;
            border: 1px solid rgba(255,255,255,0.55);
            padding: 6px 10px;
            border-radius: 10px;
            cursor: pointer;
            font-weight: 900;
          ">Проверить</button>
        <button id="pg_close_btn" style="
            background: rgba(255,255,255,0.14);
            border: 1px solid rgba(255,255,255,0.45);
            color: white;
            font-size: 16px;
            cursor: pointer;
            padding: 4px 9px;
            border-radius: 10px;
            line-height: 1;
            font-weight: 900;
          ">&times;</button>
    `;

    document.body.appendChild(tooltip);

    tooltip.querySelector('#pg_check_btn').addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (currentLink) {
            analyzeViaBackground({ url: currentLink.href, text: currentLink.innerText });
            hideTooltip(true);
        }
    });

    tooltip.querySelector('#pg_close_btn').addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        hideTooltip(true);
    });

    tooltip.addEventListener('mouseenter', () => clearTimeout(hideTooltipTimeout));
    tooltip.addEventListener('mouseleave', () => hideTooltip());
}

function showTooltip(linkElement) {
    clearTimeout(hideTooltipTimeout);

    if (!tooltip) createTooltip();
    if (!tooltip) return;

    if (linkElement === currentLink && tooltip.style.visibility === 'visible') {
        return;
    }

    currentLink = linkElement;

    const rect = linkElement.getBoundingClientRect();
    tooltip.style.left = `${rect.left + window.scrollX}px`;
    tooltip.style.top = `${rect.bottom + window.scrollY + 6}px`;

    tooltip.style.visibility = 'visible';
    tooltip.style.opacity = '1';
    tooltip.style.pointerEvents = 'auto';
}

function hideTooltip(immediate = false) {
    clearTimeout(hideTooltipTimeout);

    if (!tooltip) {
        currentLink = null;
        return;
    }

    const hideAction = () => {
        if (!tooltip) return;
        tooltip.style.opacity = '0';
        tooltip.style.visibility = 'hidden';
        tooltip.style.pointerEvents = 'none';
        currentLink = null;
    };

    if (immediate) {
        hideAction();
    } else {
        hideTooltipTimeout = setTimeout(hideAction, 200);
    }
}

// --- Инициализация ---
function initialize() {
    createTooltip();

    document.addEventListener('mouseover', (e) => {
        const link = e.target.closest('a[href]');
        if (link && !link.closest('#pg_overlay')) {
            showTooltip(link);
        }
    });

    document.addEventListener('mouseout', (e) => {
        const link = e.target.closest('a[href]');
        if (link) {
            hideTooltip();
        }
    });
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
} else {
    initialize();
}
