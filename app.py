# -*- coding: utf-8 -*-
"""
Веб-версия Code Checker. Python + C++ + HTML + JavaScript.
Запуск: python app.py
Открыть: http://127.0.0.1:8000
"""

import asyncio
import os
import logging
import tempfile
import uvicorn

from pathlib import Path
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from collections import defaultdict
from time import time

from checker import analyze


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s",
)
logger = logging.getLogger("CodeCheckerWeb")


app = FastAPI(title="Code Checker")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

RATE_LIMIT = 20
RATE_WINDOW = 60
RATE_CLEANUP_EVERY = 100

_rate_store = defaultdict(list)
_rate_counter = [0]

SELF_CHECK_FILES = ("app.py", "checker.py")
BASE_DIR = Path(__file__).resolve().parent


def _cleanup_rate_store():
    now = time()
    dead = [ip for ip, times in _rate_store.items()
            if not times or now - times[-1] > RATE_WINDOW]
    for ip in dead:
        del _rate_store[ip]


def check_rate(ip: str) -> bool:
    now = time()
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_WINDOW]
    if len(_rate_store[ip]) >= RATE_LIMIT:
        return False
    _rate_store[ip].append(now)

    _rate_counter[0] += 1
    if _rate_counter[0] >= RATE_CLEANUP_EVERY:
        _rate_counter[0] = 0
        _cleanup_rate_store()

    return True


class CodeRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=20000)
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
        .lang-switch button.self-check {
            background: #1a3a2a;
            color: #7fe0a0;
            border-color: #2a5a3a;
        }
        .lang-switch button.self-check:hover {
            background: #2a5a3a;
        }
        .lang-switch button.self-check:disabled {
            opacity: 0.5;
            cursor: not-allowed;
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
        .result-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }
        .result-header h2 {
            margin-bottom: 0;
        }
        .copy-btn {
            padding: 6px 12px;
            background: #1f2a1f;
            color: #7fe0a0;
            border: 1px solid #2a5a3a;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
            transition: background 0.2s;
        }
        .copy-btn:hover {
            background: #2a5a3a;
        }
        .copy-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .copy-btn.copied {
            background: #2a5a3a;
            color: #fff;
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
        .problem.info { background: #1a2a3a; border-left-color: #3498db; }
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
            background: #1a2a3a;
            border-left: 3px solid #3498db;
            border-radius: 6px;
            color: #7fb3d5;
            font-size: 14px;
            margin-bottom: 12px;
        }
        .file-header {
            padding: 10px 14px;
            background: #2a3a2a;
            border-radius: 6px;
            color: #7fe0a0;
            font-weight: 600;
            font-size: 14px;
            margin: 16px 0 10px 0;
        }
        .file-header:first-child { margin-top: 0; }
        .file-block { margin-bottom: 20px; }
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
            <button id="self-check" class="self-check" onclick="checkSelf()">🪞 Проверить себя</button>
        </div>
    </header>

    <main>
        <div class="panel">
            <h2 id="input-title">Вставь Python-код:</h2>
            <textarea id="code" placeholder="Вставь код сюда..." maxlength="20000"></textarea>
            <button class="check-btn" id="check">Проверить</button>
        </div>

        <div class="panel">
            <div class="result-header">
                <h2>Результат:</h2>
                <button class="copy-btn" id="copy" onclick="copyReport()" disabled>📋 Копировать</button>
            </div>
            <div id="result">
                <div class="ok">Здесь появится отчёт</div>
            </div>
        </div>
    </main>

    <script>
        const codeEl = document.getElementById('code');
        const checkBtn = document.getElementById('check');
        const copyBtn = document.getElementById('copy');
        const resultEl = document.getElementById('result');
        const inputTitle = document.getElementById('input-title');
        const btnPy = document.getElementById('lang-py');
        const btnCpp = document.getElementById('lang-cpp');
        const btnHtml = document.getElementById('lang-html');
        const btnJs = document.getElementById('lang-js');
        const btnSelf = document.getElementById('self-check');

        let currentLang = 'py';
        let currentFilename = 'code.py';

        let lastProblems = [];
        let lastSourceName = '';

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

        // ФИКС v12.0: если код начинается с "<" — это HTML (фрагмент без <html>)
        function detectLang(text) {
            const trimmed = text.trimStart();
            const head = text.substring(0, 2000).toLowerCase();

            // 1. C++
            if (head.includes('#include') || head.includes('std::') ||
                head.includes('using namespace') || head.includes('cout <<')) {
                return 'cpp';
            }

            // 2. HTML — если код начинается с "<"
            if (trimmed.startsWith('<')) {
                return 'html';
            }

            // 3. HTML — по тегам в начале
            if (head.includes('<!doctype html') || head.includes('<html') ||
                head.includes('<head') || head.includes('<body')) {
                return 'html';
            }

            // 4. JS
            if (head.includes('function ') || head.includes('var ') ||
                head.includes('console.log') || head.includes('document.') ||
                head.includes('=>')) {
                return 'js';
            }

            // 5. Python
            if (head.includes('def ') || head.includes('import ') ||
                head.includes('print(')) {
                return 'py';
            }
            return null;
        }

        let debounceTimer = null;
        function handleInputDebounced() {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(function() {
                const text = codeEl.value;
                const detected = detectLang(text);
                if (detected && detected !== currentLang) {
                    setLang(detected);
                }
            }, 300);
        }

        codeEl.addEventListener('input', handleInputDebounced);
        codeEl.addEventListener('paste', function() {
            setTimeout(handleInputDebounced, 50);
        });

        const LANG_NAMES = {
            'py': 'Python',
            'cpp': 'C++',
            'html': 'HTML',
            'js': 'JavaScript'
        };

        function renderProblems(data, container, sourceName) {
            if (data.error) {
                container.innerHTML = '<div class="error">' + escapeHtml(data.error) + '</div>';
                copyBtn.disabled = true;
                return;
            }

            if (!data.problems || data.problems.length === 0) {
                container.innerHTML = '<div class="ok">✅ Критичных проблем не найдено. Молодец!</div>';
                copyBtn.disabled = true;
                return;
            }

            const onlyInfo = data.problems.every(function(p) {
                return p.severity === 'INFO';
            });

            if (onlyInfo) {
                let html = '';
                for (const p of data.problems) {
                    html += '<div class="hint">ℹ️ ' + escapeHtml(p.message) + '</div>';
                }
                container.innerHTML = html;
                copyBtn.disabled = true;
                return;
            }

            lastProblems = data.problems;
            lastSourceName = sourceName || 'code';
            copyBtn.disabled = false;

            let html = '<div class="summary">Найдено проблем: ' + data.problems.length + '</div>';
            for (const p of data.problems) {
                let cls = 'problem';
                if (p.severity === 'CRITICAL') cls = 'problem';
                else if (p.severity === 'HIGH') cls = 'problem high';
                else if (p.severity === 'MEDIUM') cls = 'problem medium';
                else if (p.severity === 'LOW') cls = 'problem low';
                else if (p.severity === 'INFO') cls = 'problem info';

                let marker = '🔴';
                if (p.severity === 'CRITICAL') marker = '🔴';
                else if (p.severity === 'HIGH') marker = '🟡';
                else if (p.severity === 'MEDIUM') marker = '🟠';
                else if (p.severity === 'LOW') marker = '⚪';
                else if (p.severity === 'INFO') marker = 'ℹ️';

                html += '<div class="' + cls + '">';
                html += '<div class="line">' + marker + ' Строка ' + p.line + '</div>';
                html += '<div class="msg">' + escapeHtml(p.message) + '</div>';
                html += '</div>';
            }
            container.innerHTML = html;
        }

        async function checkCode() {
            const code = codeEl.value.trim();
            if (!code) {
                resultEl.innerHTML = '<div class="error">Вставь код для проверки.</div>';
                copyBtn.disabled = true;
                return;
            }

            const detected = detectLang(code);
            if (detected && detected !== currentLang) {
                setLang(detected);
            }

            checkBtn.disabled = true;
            resultEl.innerHTML = '<div class="ok">Анализирую...</div>';
            copyBtn.disabled = true;

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
                renderProblems(data, resultEl, LANG_NAMES[currentLang] || 'код');

            } catch (e) {
                resultEl.innerHTML = '<div class="error">Ошибка: ' + escapeHtml(e.message) + '</div>';
                copyBtn.disabled = true;
            } finally {
                checkBtn.disabled = false;
            }
        }

        async function checkSelf() {
            btnSelf.disabled = true;
            resultEl.innerHTML = '<div class="ok">🔍 Проверяю свои файлы...</div>';
            copyBtn.disabled = true;

            try {
                const res = await fetch('/check-self', {method: 'GET'});

                if (res.status === 429) {
                    resultEl.innerHTML = '<div class="error">Слишком много запросов. Подожди минуту.</div>';
                    return;
                }
                if (!res.ok) {
                    resultEl.innerHTML = '<div class="error">Ошибка сервера: ' + res.status + '</div>';
                    return;
                }

                const data = await res.json();

                if (!data.results) {
                    resultEl.innerHTML = '<div class="error">Сервер вернул неверный ответ.</div>';
                    return;
                }

                let allProblems = [];
                let html = '';
                for (const item of data.results) {
                    html += '<div class="file-header">📄 ' + escapeHtml(item.file) +
                            ' (' + item.problems.length + ' проблем)</div>';
                    html += '<div class="file-block">';

                    const tmp = document.createElement('div');
                    renderProblems({problems: item.problems, error: null}, tmp, item.file);
                    html += tmp.innerHTML;

                    html += '</div>';

                    for (const p of item.problems) {
                        allProblems.push({
                            line: p.line,
                            severity: p.severity,
                            message: '[' + item.file + '] ' + p.message
                        });
                    }
                }

                resultEl.innerHTML = html;

                if (allProblems.length > 0) {
                    lastProblems = allProblems;
                    lastSourceName = 'self-check (app.py + checker.py)';
                    copyBtn.disabled = false;
                }

            } catch (e) {
                resultEl.innerHTML = '<div class="error">Ошибка: ' + escapeHtml(e.message) + '</div>';
            } finally {
                btnSelf.disabled = false;
            }
        }

        async function copyReport() {
            if (!lastProblems || lastProblems.length === 0) {
                return;
            }

            const MARKERS = {
                'CRITICAL': '🔴',
                'HIGH': '🟡',
                'MEDIUM': '🟠',
                'LOW': '⚪',
                'INFO': 'ℹ️',
            };

            let text = '';
            text += 'Code Checker — отчёт\\n';
            text += 'Файл: ' + lastSourceName + '\\n';
            text += 'Найдено проблем: ' + lastProblems.length + '\\n';
            text += '\\n';

            for (const p of lastProblems) {
                const marker = MARKERS[p.severity] || '•';
                text += marker + ' Строка ' + p.line + ': ' + p.message + '\\n';
            }

            function showCopied() {
                copyBtn.textContent = '✅ Скопировано!';
                copyBtn.classList.add('copied');
                setTimeout(function() {
                    copyBtn.textContent = '📋 Копировать';
                    copyBtn.classList.remove('copied');
                }, 2000);
            }

            function showError() {
                copyBtn.textContent = '❌ Не удалось';
                setTimeout(function() {
                    copyBtn.textContent = '📋 Копировать';
                }, 2000);
            }

            if (navigator.clipboard && navigator.clipboard.writeText) {
                try {
                    await navigator.clipboard.writeText(text);
                    showCopied();
                    return;
                } catch (e) {
                    // падаем в fallback
                }
            }

            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.left = '-9999px';
            document.body.appendChild(ta);
            ta.select();

            let ok = false;
            try {
                ok = document.execCommand('copy');
            } catch (err) {
                ok = false;
            }

            document.body.removeChild(ta);

            if (ok) {
                showCopied();
            } else {
                showError();
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

def _detect_language_from_code(code: str, filename: str = "code.py") -> str:
    """
    ФИКС v12.0: если код начинается с "<" — это HTML.
    Приоритет: явное расширение -> начинается с "<" (HTML) -> эвристика.
    """
    ext = Path(filename).suffix.lower()

    if ext in (".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"):
        return "cpp"
    if ext == ".py":
        return "python"
    if ext in (".html", ".htm"):
        return "html"
    if ext in (".js", ".mjs"):
        return "js"

    head = code[:2000].lower()
    trimmed = code.lstrip()

    if "#include" in head or "std::" in head or "using namespace" in head:
        return "cpp"

    # ФИКС: HTML-фрагмент начинается с "<"
    if trimmed.startswith("<"):
        return "html"

    if ("<!doctype html" in head or "<html" in head or
            "<head" in head or "<body" in head):
        return "html"

    if ("function " in head or "var " in head or
            "console.log" in head or "document." in head or
            "=>" in head):
        return "js"

    return "python"


def _get_suffix(lang: str) -> str:
    suffix_map = {
        "python": ".py",
        "cpp": ".cpp",
        "html": ".html",
        "js": ".js",
    }
    return suffix_map.get(lang, ".py")


async def _save_and_analyze(code: str, suffix: str):
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False, encoding="utf-8"
        ) as f:
            f.write(code)
            tmp_path = f.name

        if tmp_path is None:
            return {"problems": [], "error": "Не удалось создать временный файл"}

        problems = await asyncio.to_thread(analyze, tmp_path)
        return {"problems": problems, "error": None}

    except Exception as e:
        logger.error(f"analyze failed: {e}")
        return {"problems": [], "error": f"Ошибка анализа: {str(e)}"}

    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError as e:
                logger.warning(f"Не удалось удалить временный файл: {e}")


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

    real_lang = _detect_language_from_code(code, payload.filename)
    logger.info(f"Detected language: {real_lang} (filename={payload.filename})")

    suffix = _get_suffix(real_lang)
    return await _save_and_analyze(code, suffix)


@app.get("/check-self")
async def check_self(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests")

    results = []
    for filename in SELF_CHECK_FILES:
        filepath = BASE_DIR / filename
        if not filepath.exists():
            results.append({
                "file": filename,
                "problems": [{"line": 1, "severity": "INFO",
                              "message": f"Файл не найден: {filename}"}],
            })
            continue

        try:
            problems = await asyncio.to_thread(analyze, str(filepath))
            results.append({"file": filename, "problems": problems})
        except Exception as e:
            logger.error(f"check-self failed for {filename}: {e}")
            results.append({
                "file": filename,
                "problems": [{"line": 1, "severity": "CRITICAL",
                              "message": f"Ошибка анализа: {str(e)}"}],
            })

    return {"results": results}


# ============ ЗАПУСК ============

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
