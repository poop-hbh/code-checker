# -*- coding: utf-8 -*-
"""
Веб-версия Code Checker. Python + C++ + HTML + JavaScript.
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

from checker import analyze


app = FastAPI(title="Code Checker")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

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


class CodeRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=50000)
    filename: str = Field(default="code.py", max_length=200)


HTML_PAGE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Code Checker — Python + C++ + HTML + JS</title>
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
        .lang-switch {
            margin-top: 12px;
            display: flex;
            justify-content: center;
            gap: 8px;
            flex-wrap: wrap;
        }
        .lang-switch button {
            padding: 6px 14px;
            background: #1f1f1f;
            color: #ccc;
            border: 1px solid #333;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            margin: 0;
            font-weight: normal;
        }
        .lang-switch button.active {
            background: #2b5278;
            color: #fff;
            border-color: #3a6b9a;
        }
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
        button.check-btn {
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
        button.check-btn:hover { background: #3a6b9a; }
        button.check-btn:disabled { opacity: 0.5; cursor: not-allowed; }
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
        .problem.medium { background: #2a201a; border-left-color: #e67e22; }
        .problem.low { background: #1a1a1a; border-left-color: #95a5a6; }
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
        .hint {
            padding: 12px;
            background: #2a2a1a;
            border-left: 3px solid #f1c40f;
            border-radius: 6px;
            color: #f1c40f;
            font-size: 13px;
            margin-bottom: 12px;
        }
    </style>
</head>
<body>
    <header>
        <h1>🔍 Code Checker</h1>
        <p>60+ проверок: Python + C++ + HTML + JavaScript</p>
        <div class="lang-switch">
            <button id="lang-py" class="active" onclick="setLang('py')">Python</button>
            <button id="lang-cpp" onclick="setLang('cpp')">C++</button>
            <button id="lang-html" onclick="setLang('html')">HTML</button>
            <button id="lang-js" onclick="setLang('js')">JavaScript</button>
        </div>
    </header>

    <main>
        <div class="panel">
            <h2 id="input-title">Вставь Python-код:</h2>
            <textarea id="code" placeholder="Вставь код сюда..." maxlength="50000"></textarea>
            <button class="check-btn" id="check">Проверить</button>
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
        const inputTitle = document.getElementById('input-title');
        const btnPy = document.getElementById('lang-py');
        const btnCpp = document.getElementById('lang-cpp');
        const btnHtml = document.getElementById('lang-html');
        const btnJs = document.getElementById('lang-js');

        let currentLang = 'py';
        let currentFilename = 'code.py';

        function setLang(lang) {
            currentLang = lang;
            btnPy.classList.remove('active');
            btnCpp.classList.remove('active');
            btnHtml.classList.remove('active');
            btnJs.classList.remove('active');

            if (lang === 'py') {
                currentFilename = 'code.py';
                inputTitle.textContent = 'Вставь Python-код:';
                codeEl.placeholder = 'Вставь Python-код сюда...';
                btnPy.classList.add('active');
            } else if (lang === 'cpp') {
                currentFilename = 'code.cpp';
                inputTitle.textContent = 'Вставь C++-код:';
                codeEl.placeholder = 'Вставь C++-код сюда...';
                btnCpp.classList.add('active');
            } else if (lang === 'html') {
                currentFilename = 'code.html';
                inputTitle.textContent = 'Вставь HTML-код:';
                codeEl.placeholder = 'Вставь HTML-код сюда...';
                btnHtml.classList.add('active');
            } else if (lang === 'js') {
                currentFilename = 'code.js';
                inputTitle.textContent = 'Вставь JavaScript-код:';
                codeEl.placeholder = 'Вставь JavaScript-код сюда...';
                btnJs.classList.add('active');
            }
        }

        function detectLang(text) {
            const head = text.substring(0, 500).toLowerCase();
            if (head.includes('#include') || head.includes('std::') ||
                head.includes('using namespace') || head.includes('cout <<')) {
                return 'cpp';
            }
            if (head.includes('<!doctype html') || head.includes('<html') ||
                head.includes('<body') || head.includes('<div')) {
                return 'html';
            }
            if (head.includes('function ') || head.includes('const ') ||
                head.includes('let ') || head.includes('document.')) {
                return 'js';
            }
            if (head.includes('def ') || head.includes('import ') ||
                head.includes('print(')) {
                return 'py';
            }
            return null;
        }

        codeEl.addEventListener('input', function() {
            const text = codeEl.value;
            const detected = detectLang(text);
            if (detected && detected !== currentLang) {
                setLang(detected);
            }
        });

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
                    body: JSON.stringify({code: code, filename: currentFilename})
                });

                if (res.status === 429) {
                    resultEl.innerHTML = '<div class="error">Слишком много запросов. Подожди минуту.</div>';
                    return;
                }
                if (res.status === 422) {
                    resultEl.innerHTML = '<div class="error">Код слишком длинный или пустой.</div>';
                    return;
                }
                if (!res.ok) {
                    resultEl.innerHTML = '<div class="error">Ошибка сервера: ' + res.status + '</div>';
                    return;
                }

                const data = await res.json();

                if (data.error) {
                    if (data.error.includes('Синтаксическая ошибка') && currentLang === 'py') {
                        const detected = detectLang(code);
                        if (detected && detected !== 'py') {
                            setLang(detected);
                            resultEl.innerHTML =
                                '<div class="hint">Похоже, это ' + detected.toUpperCase() +
                                '-код. Я переключил язык. Проверьте ещё раз.</div>';
                            checkBtn.disabled = false;
                            return;
                        }
                    }
                    resultEl.innerHTML = '<div class="error">' + escapeHtml(data.error) + '</div>';
                    return;
                }

                if (data.problems.length === 0) {
                    resultEl.innerHTML = '<div class="ok">✅ Критичных проблем не найдено. Молодец!</div>';
                    return;
                }

                let html = '<div class="summary">Найдено проблем: ' + data.problems.length + '</div>';
                for (const p of data.problems) {
                    let cls = 'problem';
                    if (p.severity === 'HIGH') cls = 'problem high';
                    else if (p.severity === 'MEDIUM') cls = 'problem medium';
                    else if (p.severity === 'LOW') cls = 'problem low';

                    let marker = '🔴';
                    if (p.severity === 'HIGH') marker = '🟡';
                    else if (p.severity === 'MEDIUM') marker = '🟠';
                    else if (p.severity === 'LOW') marker = '⚪';

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


# ============ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ============

def _validate_python(code: str):
    """Проверяет синтаксис Python. Возвращает None, если всё ок."""
    try:
        ast.parse(code)
        return None
    except SyntaxError as e:
        return f"Синтаксическая ошибка: строка {e.lineno}, {e.msg}"
    except RecursionError:
        return "Слишком сложный код."


def _get_suffix(filename: str) -> str:
    """Определяет расширение файла по имени."""
    suffix_map = {
        ".py": ".py",
        ".cpp": ".cpp", ".cc": ".cpp", ".cxx": ".cpp",
        ".c": ".cpp", ".h": ".cpp", ".hpp": ".cpp",
        ".html": ".html", ".htm": ".html",
        ".js": ".js", ".mjs": ".js",
    }
    for key, val in suffix_map.items():
        if filename.endswith(key):
            return val
    return ".py"


async def _save_and_analyze(code: str, suffix: str):
    """Сохраняет код в tmp-файл и анализирует."""
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False, encoding="utf-8"
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
            except OSError as e:
                print(f"[WARN] Не удалось удалить временный файл: {e}")


# ============ ЭНДПОИНТЫ ============

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML_PAGE


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/check")
async def check_code(payload: CodeRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests")

    code = payload.code
    if not code.strip():
        return {"problems": [], "error": "Пустой код"}

    filename = payload.filename or "code.py"
    if filename.endswith(".py"):
        error = _validate_python(code)
        if error:
            return {"problems": [], "error": error}

    suffix = _get_suffix(filename)
    return await _save_and_analyze(code, suffix)


# ============ ЗАПУСК ============

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
