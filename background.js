// background.js
const API_BASE = "http://127.0.0.1:8000";

function extractFirstURL(text) {
  if (!text) return null;
  const urlRegex = /(https?:\/\/[^\s"'<>]+)|([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(\/[^\s"'<>]*)?)/i;
  const match = text.match(urlRegex);
  if (!match) return null;

  let url = match[0];
  if (!url.startsWith('http')) {
    url = 'http://' + url;
  }
  return url;
}

async function analyzeViaAPI(payload) {
  const resp = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    // Отправляем только те поля, которые существуют, чтобы избежать null в JSON
    body: JSON.stringify(payload)
  });
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`Ошибка сервера (HTTP ${resp.status}): ${body.slice(0, 500)}`);
  }
  return await resp.json();
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "pg_link",
    title: "Проверить ссылку (PhishGuard)",
    contexts: ["link"]
  });
  chrome.contextMenus.create({
    id: "pg_selection",
    title: "Проверить выделенный текст (PhishGuard)",
    contexts: ["selection"]
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (!tab || !tab.id) return;

  try {
    let payload = {};
    if (info.menuItemId === "pg_link" && info.linkUrl) {
      // Для ссылки анализируем и URL, и текст ссылки
      payload = { url: info.linkUrl, text: info.linkUrl };
    } else if (info.menuItemId === "pg_selection" && info.selectionText) {
      // Для выделения анализируем текст и пытаемся извлечь URL
      payload.text = info.selectionText;
      const extractedUrl = extractFirstURL(info.selectionText);
      if (extractedUrl) {
        payload.url = extractedUrl;
      }
    }

    // Отправляем запрос только если есть что анализировать
    if (payload.url || payload.text) {
      const report = await analyzeViaAPI(payload);
      chrome.tabs.sendMessage(tab.id, { type: "ANALYZE_RESULT", report });
    } else {
      // Если в выделенном тексте ничего не нашлось
      chrome.tabs.sendMessage(tab.id, { type: "ANALYZE_ERROR", message: "В выделенном тексте не найден URL или подозрительные слова." });
    }
  } catch (e) {
    chrome.tabs.sendMessage(tab.id, { type: "ANALYZE_ERROR", message: String(e) });
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === "ANALYZE_REQUEST") {
    (async () => {
      try {
        const report = await analyzeViaAPI(msg.payload);
        sendResponse({ ok: true, report });
      } catch (e) {
        sendResponse({ ok: false, error: String(e) });
      }
    })();
    return true;
  }
});