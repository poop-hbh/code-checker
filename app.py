# -*- coding: utf-8 -*-
"""
Веб-версия Code Checker.
Запуск: python app.py
Открыть: http://127.0.0.1:8000
"""

import ast
import os
import tempfile
import uvicorn

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from collections import defaultdict
from time import time

# Импортируем наш анализатор
from checker import analyze


app = FastAPI(title="Code Checker")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# ---------- Rate limiting ----------
RATE_LIMIT = 20
RATE_WINDOW = 60
_rate_store = defaultdict(list)


def check_rate(ip: str) -> bool:
    now = time()
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_WINDOW]
    if len(_rate_store[ip]) >= RATE_LIMIT:
        return False
    _rate_store[ip].append(now)
    return True


# ---------- Модель запроса ----------
class CodeRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=50000)


# ---------- HTML ----------
HTML_PAGE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Code Checker</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: system-ui, sans-serif;
            background: #0f0f0f;
            color: #eee;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        header {
            padding: 20px;
            background: #1a1a1a;
            border-bottom: 1px solid #333;
            text-align: center;
        }
        header h1 { font-size: 24px; margin-bottom: 6px; }
        header p { font-size: 14px; color: #888; }
        main {
            flex: 1;
            max-width: 1100px;
            margin: 0 auto;
            padding: 20px;
            width: 100%;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        @media (max-width: 900px) { main { grid-template-columns: 1fr; } }
        .panel {
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 12px;
            padding: 16px;
            display: flex;
            flex-direction: column;
        }
        .panel h2 {
            font-size: 16px;
            margin-bottom: 12px;
            color: #ccc;
        }
        textarea {
            flex: 1;
            min-height: 400px;
            background: #0f0f0f;
            color: #eee;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 12px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 13px;
            resize: vertical;
            outline: none;
        }
        textarea:focus { border-color: #4a7ba7; }
        button {
            margin-top: 12px;
            padding: 12px;
            background: #2b5278;
            color: #fff;
            border: none;
            border-radius: 8px;
            font-size: 15px;
            cursor: pointer;
            font-weight: 600;
        }
        button:hover { background: #3a6b9a; }
        button:disabled { opacity: 0.5; cursor: not-allowed; }
        #result {
            flex: 1;
            min-height: 400px;
            overflow-y: auto;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 13px;
            white-space: pre-wrap;
        }
        .problem {
            padding: 10px;
            margin-bottom: 8px;
            border-radius: 6px;
            background: #2a1a1a;
            border-left: 3px solid #e74c3c;
        }
        .problem.high { background: #2a2a1a; border-left-color: #f1c40f; }
        .problem .line { color: #888; font-size: 11px; margin-bottom: 4px; }
        .problem .msg { color: #eee; }
        .ok {
            padding: 20px;
            text-align: center;
            color: #2ecc71;
            font-size: 16px;
        }
        .summary {
            padding: 10px;
            margin-bottom: 12px;
            background: #1f2a1f;
            border-radius: 6px;
            color: #2ecc71;
            font-size: 13px;
        }
        .error {
            padding: 10px;
            background: #2a1a1a;
            border-left: 3px solid #e74c3c;
            border-radius: 6px;
            color: #e74c3c;
        }
    </style>
</head>
<body>
    <header>
        <h1>🔍 Code Checker</h1>
        <p>Находит 5 критичных проблем в Python-коде</p>
    </header>

    <main>
        <div class="panel">
            <h2>Вставь свой код:</h2>
            <textarea id="code" placeholder="Вставь Python-код сюда..." maxlength="50000"></textarea>
            <button id="check">Проверить</button>
        </div>

        <div class="panel">
            <h2>Результат:</h2>
            <div id="result">
                <div class="ok">Здесь появится отчёт</div>
            </div>
        </div>
    </main>

    <script>
        const codeEl = document.getElementById('code');
        const checkBtn = document.getElementById('check');
        const resultEl = document.getElementById('result');

        async function checkCode() {
            const code = codeEl.value.trim();
            if (!code) {
                resultEl.innerHTML = '<div class="error">Вставь код для проверки.</div>';
                return;
            }

            checkBtn.disabled = true;
            resultEl.innerHTML = '<div class="ok">Анализирую...</div>';

            try {
                const res = await fetch('/check', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({code: code})
                });

                if (res.status === 429) {
                    resultEl.innerHTML = '<div class="error">Слишком много запросов. Подожди минуту.</div>';
                    return;
                }
                if (res.status === 422) {
                    resultEl.innerHTML = '<div class="error">Код слишком длинный (макс. 50 000 символов) или пустой.</div>';
                    return;
                }
                if (!res.ok) {
                    resultEl.innerHTML = '<div class="error">Ошибка сервера: ' + res.status + '</div>';
                    return;
                }

                const data = await res.json();

                if (data.error) {
                    resultEl.innerHTML = '<div class="error">' + escapeHtml(data.error) + '</div>';
                    return;
                }

                if (data.problems.length === 0) {
                    resultEl.innerHTML = '<div class="ok">✅ Критичных проблем не найдено. Молодец!</div>';
                    return;
                }

                let html = '<div class="summary">Найдено проблем: ' + data.problems.length + '</div>';
                for (const p of data.problems) {
                    const cls = p.severity === 'CRITICAL' ? 'problem' : 'problem high';
                    const marker = p.severity === 'CRITICAL' ? '🔴' : '🟡';
                    html += '<div class="' + cls + '">';
                    html += '<div class="line">' + marker + ' Строка ' + p.line + '</div>';
                    html += '<div class="msg">' + escapeHtml(p.message) + '</div>';
                    html += '</div>';
                }
                resultEl.innerHTML = html;

            } catch (e) {
                resultEl.innerHTML = '<div class="error">Ошибка: ' + escapeHtml(e.message) + '</div>';
            } finally {
                checkBtn.disabled = false;
            }
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        checkBtn.addEventListener('click', checkCode);
    </script>
</body>
</html>
"""


# ---------- Эндпоинты ----------
@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML_PAGE


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/check")
async def check_code(payload: CodeRequest, request: Request):
    # Rate limit
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests")

    code = payload.code
    if not code.strip():
        return {"problems": [], "error": "Пустой код"}

    # Проверяем синтаксис до анализа
    try:
        ast.parse(code)
    except SyntaxError as e:
        return {
            "problems": [],
            "error": f"Синтаксическая ошибка: строка {e.lineno}, {e.msg}"
        }

    # Сохраняем во временный файл и анализируем
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(code)
            tmp_path = f.name

        if tmp_path is None:
            return {"problems": [], "error": "Не удалось создать временный файл"}

        problems = analyze(tmp_path)
        return {"problems": problems, "error": None}

    except Exception as e:
        print(f"[ERROR] analyze failed: {e}")
        return {"problems": [], "error": f"Ошибка анализа: {str(e)}"}

    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# ---------- Запуск ----------
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
