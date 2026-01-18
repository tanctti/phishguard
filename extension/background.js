// background.js

// Твой URL на Render
const API_BASE = "https://phishguard-a43g.onrender.com";

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
  try {
    const resp = await fetch(`${API_BASE}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    if (!resp.ok) {
      const body = await resp.text();
      throw new Error(`Ошибка сервера (HTTP ${resp.status}): ${body.slice(0, 200)}`);
    }
    return await resp.json();
  } catch (err) {
    throw new Error(`Не удалось связаться с сервером: ${err.message}`);
  }
}

// 1. Создание меню при установке/обновлении
chrome.runtime.onInstalled.addListener(() => {
  // Удаляем старые пункты, чтобы не дублировались при перезагрузке (на всякий случай)
  chrome.contextMenus.removeAll(() => {
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
});

// 2. Обработка клика по меню
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (!tab || !tab.id) return;

  // Вспомогательная функция для безопасной отправки сообщения
  const safeSendMessage = (tabId, message) => {
    chrome.tabs.sendMessage(tabId, message, () => {
      if (chrome.runtime.lastError) {
        console.warn("PhishGuard: Не удалось отправить сообщение во вкладку.", chrome.runtime.lastError.message);
        // Здесь можно было бы попытаться программно внедрить скрипт (scripting.executeScript),
        // но обычно достаточно просто обновить страницу.
      }
    });
  };

  try {
    let payload = {};
    if (info.menuItemId === "pg_link" && info.linkUrl) {
      payload = { url: info.linkUrl, text: info.linkUrl };
    } else if (info.menuItemId === "pg_selection" && info.selectionText) {
      payload.text = info.selectionText;
      const extractedUrl = extractFirstURL(info.selectionText);
      if (extractedUrl) {
        payload.url = extractedUrl;
      }
    }

    if (payload.url || payload.text) {
      // Можно отправить "заглушку" пользователю, что процесс пошел (опционально)
      // safeSendMessage(tab.id, { type: "ANALYZE_START" }); // если поддерживается в content.js

      const report = await analyzeViaAPI(payload);
      safeSendMessage(tab.id, { type: "ANALYZE_RESULT", report });
    } else {
      safeSendMessage(tab.id, { type: "ANALYZE_ERROR", message: "В выделенном тексте не найден URL или текст." });
    }
  } catch (e) {
    safeSendMessage(tab.id, { type: "ANALYZE_ERROR", message: String(e) });
  }
});

// 3. Обработка сообщений от content.js (подсказка)
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
    return true; // Важно для асинхронного ответа
  }
});
