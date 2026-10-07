# -*- coding: utf-8 -*-
"""
Веб-версия Code Checker v17.10.2. Python + C++ + HTML + JavaScript + Go.
Запуск: python app.py
Открыть: http://127.0.0.1:8000

Изменения v17.10.2:
  - Подключена Яндекс.Метрика (счётчик 113541969)
  - Цели: code_checked, self_check, zip_uploaded,
          report_downloaded, json_downloaded, report_copied
"""

import asyncio
import os
import io
import zipfile
import logging
import tempfile
import fnmatch
import uvicorn

from pathlib import Path
from fastapi import FastAPI, Request, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
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

STATIC_DIR = Path(__file__).resolve().parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
else:
    logger.warning("Папка static/ не найдена — favicon работать не будет")

ALLOWED_ORIGINS = [
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "https://code-checker.relaxdev.ru",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
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
CHECKERIGNORE_FILE = BASE_DIR / ".checkerignore"

TMP_DIR = BASE_DIR / "tmp"
TMP_DIR.mkdir(exist_ok=True)


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
    code: str = Field(..., min_length=1, max_length=100000)
    filename: str = Field(default="code.py", max_length=200)


class CheckerignoreRequest(BaseModel):
    content: str = Field(..., max_length=10000)


HTML_PAGE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
    <title>Code Checker — Python + C++ + HTML + JS + Go</title>
    <!-- Yandex.Metrika counter -->
    <script type="text/javascript">
        (function(m,e,t,r,i,k,a){
            m[i]=m[i]||function(){(m[i].a=m[i].a||[]).push(arguments)};
            m[i].l=1*new Date();
            for (var j = 0; j < document.scripts.length; j++) {if (document.scripts[j].src === r) { return; }}
            k=e.createElement(t),a=e.getElementsByTagName(t)[0],k.async=1,k.src=r,a.parentNode.insertBefore(k,a)
        })(window, document,'script','https://mc.yandex.ru/metrika/tag.js?id=113541969', 'ym');

        ym(113541969, 'init', {ssr:true, webvisor:true, clickmap:true, ecommerce:"dataLayer", referrer: document.referrer, url: location.href, accurateTrackBounce:true, trackLinks:true});
    </script>
    <noscript><div><img src="https://mc.yandex.ru/watch/113541969" style="position:absolute; left:-9999px;" alt="" /></div></noscript>
    <!-- /Yandex.Metrika counter -->
    <style>
        :root {
            --bg: #0f0f0f;
            --bg-panel: #1a1a1a;
            --bg-input: #0f0f0f;
            --border: #333;
            --text: #eee;
            --text-dim: #888;
            --text-mid: #ccc;
            --accent: #2b5278;
            --accent-hover: #3a6b9a;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: system-ui, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        header {
            padding: 20px;
            background: var(--bg-panel);
            border-bottom: 1px solid var(--border);
            text-align: center;
            position: relative;
        }
        header h1 { font-size: 24px; margin-bottom: 6px; }
        header p { font-size: 14px; color: var(--text-dim); }
        .lang-switch {
            margin-top: 12px;
            display: flex;
            justify-content: center;
            gap: 8px;
            flex-wrap: wrap;
        }
        .lang-switch button {
            padding: 6px 14px;
            background: var(--bg);
            color: var(--text-mid);
            border: 1px solid var(--border);
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            margin: 0;
            font-weight: normal;
        }
        .lang-switch button.active {
            background: var(--accent);
            color: #fff;
            border-color: var(--accent-hover);
        }
        .lang-switch button.self-check {
            background: #1a3a2a;
            color: #7fe0a0;
            border-color: #2a5a3a;
        }
        .lang-switch button.self-check:hover { background: #2a5a3a; }
        .lang-switch button.self-check:disabled { opacity: 0.5; cursor: not-allowed; }
        .disclaimer {
            max-width: 1100px;
            margin: 16px auto 0;
            padding: 14px 18px;
            background: #1a2a3a;
            border-left: 4px solid #3498db;
            border-radius: 8px;
            color: #ffffff;
            font-size: 13px;
            line-height: 1.6;
            width: calc(100% - 40px);
        }
        .disclaimer summary {
            cursor: pointer;
            color: #66ccff;
            font-weight: 600;
            font-size: 14px;
            list-style: none;
            outline: none;
        }
        .disclaimer summary::-webkit-details-marker { display: none; }
        .disclaimer summary:before { content: "\\1F4A1  "; }
        .disclaimer[open] summary { margin-bottom: 10px; }
        .disclaimer b { color: #66ccff; }
        .disclaimer ul { margin: 6px 0 10px 20px; }
        .disclaimer li { margin-bottom: 3px; }
        .disclaimer .warn { color: #e67e22; font-weight: 600; margin-top: 10px; }
        .disclaimer code {
            background: #0f1a26;
            color: #a0d0ff;
            padding: 1px 5px;
            border-radius: 3px;
            font-size: 12px;
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
            background: var(--bg-panel);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px;
            display: flex;
            flex-direction: column;
            position: relative;
        }
        .panel h2 { font-size: 16px; margin-bottom: 12px; color: var(--text-mid); }
        .result-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
            gap: 6px;
            flex-wrap: wrap;
        }
        .result-header h2 { margin-bottom: 0; }
        .header-buttons { display: flex; gap: 6px; flex-wrap: wrap; }
        .copy-btn, .download-btn, .json-btn {
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
        .copy-btn:hover, .download-btn:hover, .json-btn:hover { background: #2a5a3a; }
        .copy-btn:disabled, .download-btn:disabled, .json-btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .copy-btn.copied { background: #2a5a3a; color: #fff; }
        .download-btn { background: #1f1f2f; color: #a0c0ff; border-color: #2a3a5a; }
        .download-btn:hover { background: #2a3a5a; }
        .json-btn { background: #2a1f3a; color: #d0a0ff; border-color: #4a2a5a; }
        .json-btn:hover { background: #4a2a5a; }
        .drop-zone { position: relative; margin-bottom: 12px; }
        .drop-zone.dragover textarea {
            border-color: var(--accent-hover);
            background: rgba(58, 107, 154, 0.1);
        }
        .drop-overlay {
            position: absolute;
            inset: 0;
            display: none;
            align-items: center;
            justify-content: center;
            background: rgba(43, 82, 120, 0.85);
            color: #fff;
            font-size: 18px;
            font-weight: 700;
            border-radius: 8px;
            pointer-events: none;
            z-index: 10;
        }
        .drop-zone.dragover .drop-overlay { display: flex; }
        textarea {
            flex: 1;
            min-height: 400px;
            background: var(--bg-input);
            color: var(--text);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 13px;
            resize: vertical;
            outline: none;
            width: 100%;
            transition: border-color 0.2s, background 0.2s;
        }
        textarea:focus { border-color: var(--accent-hover); }
        .code-info {
            padding: 6px 10px;
            margin-top: 8px;
            background: var(--bg);
            border-radius: 6px;
            color: var(--text-dim);
            font-size: 12px;
            font-family: 'Consolas', 'Monaco', monospace;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }
        .code-info b { color: var(--text-mid); font-weight: 600; }
        .code-info .limit-warn { color: #e67e22; }
        .code-info .limit-over { color: #e74c3c; }
        .code-info .limit-ok { color: #2ecc71; }
        .file-name { color: #7fe0a0; font-size: 12px; margin-top: 4px; font-style: italic; }
        .btn-row { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; }
        button.check-btn {
            flex: 1;
            min-width: 120px;
            padding: 12px;
            background: var(--accent);
            color: #fff;
            border: none;
            border-radius: 8px;
            font-size: 15px;
            cursor: pointer;
            font-weight: 600;
        }
        button.check-btn:hover { background: var(--accent-hover); }
        button.check-btn:disabled { opacity: 0.5; cursor: not-allowed; }
        button.clear-btn, button.upload-btn, button.zip-btn {
            padding: 12px 16px;
            background: var(--bg);
            color: var(--text-mid);
            border: 1px solid var(--border);
            border-radius: 8px;
            font-size: 14px;
            cursor: pointer;
            font-weight: 600;
            transition: background 0.2s;
        }
        button.clear-btn:hover, button.upload-btn:hover { background: var(--accent); color: #fff; }
        button.upload-btn { background: #2a1f3a; color: #d0a0ff; border-color: #4a2a5a; }
        button.upload-btn:hover { background: #4a2a5a; color: #fff; }
        button.zip-btn { background: #3a2a1a; color: #ffa94d; border-color: #5a3a1a; }
        button.zip-btn:hover { background: #5a3a1a; color: #fff; }
        #fileInput, #zipInput { display: none; }
        #result {
            flex: 1;
            min-height: 400px;
            overflow-y: auto;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 13px;
            white-space: pre-wrap;
        }
        .search-box {
            padding: 8px 12px;
            margin-bottom: 12px;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text);
            font-size: 13px;
            width: 100%;
            outline: none;
        }
        .search-box:focus { border-color: var(--accent-hover); }
        .problem {
            padding: 10px;
            margin-bottom: 8px;
            border-radius: 6px;
            background: #2a1a1a;
            border-left: 3px solid #e74c3c;
            cursor: pointer;
            transition: transform 0.1s;
            color: #f0f0f0;
        }
        .problem:hover { transform: translateX(3px); }
        .problem.high { background: #2a2a1a; border-left-color: #f1c40f; }
        .problem.medium { background: #2a201a; border-left-color: #e67e22; }
        .problem.low { background: #1a1a1a; border-left-color: #95a5a6; }
        .problem.info { background: #1a2a3a; border-left-color: #3498db; }
        .problem .line { color: #b0b0b0; font-size: 11px; margin-bottom: 4px; }
        .problem .msg { color: #ffffff; }
        .problem.copied { background: #2a5a3a !important; }
        .ok {
            padding: 20px;
            text-align: center;
            color: #2ecc71;
            font-size: 16px;
            font-weight: 600;
        }
        .error {
            padding: 10px;
            background: #2a1a1a;
            border-left: 3px solid #e74c3c;
            border-radius: 6px;
            color: #ff8080;
        }
        .hint {
            padding: 12px;
            background: #1a2a3a;
            border-left: 3px solid #3498db;
            border-radius: 6px;
            color: #ffffff;
            font-size: 14px;
            margin-bottom: 12px;
            line-height: 1.5;
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
        .file-block { margin-bottom: 20px; }
        .no-problems {
            padding: 16px;
            background: #1a2a3a;
            border-left: 3px solid #3498db;
            border-radius: 6px;
            color: #ffffff;
            font-size: 14px;
            line-height: 1.6;
        }
        .no-problems b { color: #66ccff; font-weight: 700; }
        .severity-header {
            padding: 10px 14px;
            margin: 16px 0 10px 0;
            border-radius: 6px;
            font-weight: 700;
            font-size: 14px;
            letter-spacing: 0.3px;
        }
        .severity-header.critical { background: #3a1a1a; color: #ff6b6b; border-left: 4px solid #e74c3c; }
        .severity-header.high { background: #3a3a1a; color: #ffd93d; border-left: 4px solid #f1c40f; }
        .severity-header.medium { background: #3a2a1a; color: #ffa94d; border-left: 4px solid #e67e22; }
        .severity-header.low { background: #2a2a2a; color: #b0b0b0; border-left: 4px solid #95a5a6; }
        .severity-header.info { background: #1a2a3a; color: #7fb3d5; border-left: 4px solid #3498db; }
        .category-header {
            padding: 6px 12px;
            margin: 10px 0 6px 0;
            background: var(--bg);
            border-radius: 4px;
            color: var(--text-mid);
            font-size: 12px;
            font-weight: 600;
            letter-spacing: 0.5px;
        }
        .counter-bar {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            padding: 12px;
            margin-bottom: 14px;
            background: var(--bg);
            border-radius: 8px;
            border: 1px solid var(--border);
        }
        .counter-item {
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.1s, opacity 0.2s;
            user-select: none;
            border: 2px solid transparent;
        }
        .counter-item:hover { transform: scale(1.05); }
        .counter-item.active { border-color: var(--text); }
        .counter-item.critical { background: #3a1a1a; color: #ff6b6b; }
        .counter-item.high { background: #3a3a1a; color: #ffd93d; }
        .counter-item.medium { background: #3a2a1a; color: #ffa94d; }
        .counter-item.low { background: #2a2a2a; color: #b0b0b0; }
        .counter-item.info { background: #1a2a3a; color: #7fb3d5; }
        .counter-item.total { background: var(--accent); color: #fff; }
        .category-counters {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            padding: 10px 12px;
            margin-bottom: 14px;
            background: var(--bg);
            border-radius: 8px;
            border: 1px solid var(--border);
        }
        .category-chip {
            padding: 4px 10px;
            background: var(--bg-panel);
            color: var(--text-mid);
            border-radius: 12px;
            font-size: 12px;
            cursor: pointer;
            user-select: none;
            transition: background 0.2s;
        }
        .category-chip:hover { background: var(--accent); color: #fff; }
        .category-chip.active { background: var(--accent); color: #fff; }
        .modal-overlay {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(0,0,0,0.7);
            z-index: 100;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .modal-overlay.show { display: flex; }
        .modal {
            background: var(--bg-panel);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            max-width: 700px;
            width: 100%;
            max-height: 80vh;
            overflow-y: auto;
        }
        .modal h2 { margin-bottom: 14px; font-size: 18px; }
        .modal-close {
            float: right;
            padding: 4px 10px;
            background: var(--bg);
            color: var(--text);
            border: 1px solid var(--border);
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
        }
        .modal-close:hover { background: #e74c3c; color: #fff; }
        .modal code {
            background: #0f1a26;
            color: #a0d0ff;
            padding: 1px 5px;
            border-radius: 3px;
            font-size: 12px;
        }
        .history-item {
            padding: 10px 12px;
            margin-bottom: 8px;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            cursor: pointer;
            transition: background 0.2s;
        }
        .history-item:hover { background: var(--accent); color: #fff; }
        .history-item .h-lang { font-weight: 700; color: #7fe0a0; }
        .history-item:hover .h-lang { color: #fff; }
        .history-item .h-time { color: var(--text-dim); font-size: 12px; margin-left: 8px; }
        .history-item .h-summary { color: var(--text-mid); font-size: 12px; margin-top: 4px; }
        .history-item:hover .h-time,
        .history-item:hover .h-summary { color: #fff; }
        .history-empty { color: var(--text-dim); text-align: center; padding: 20px; }
        .toast {
            position: fixed;
            bottom: 24px;
            right: 24px;
            padding: 12px 20px;
            background: #2a5a3a;
            color: #fff;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            opacity: 0;
            transform: translateY(20px);
            transition: opacity 0.3s, transform 0.3s;
            pointer-events: none;
            z-index: 200;
        }
        .toast.show { opacity: 1; transform: translateY(0); }
    </style>
</head><body>    <header>
        <h1>🔍 Code Checker</h1>
        <p>60+ проверок: Python + C++ + HTML + JavaScript + Go</p>
        <div class="lang-switch">
            <button id="lang-py" class="active" onclick="setLang('py')">Python</button>
            <button id="lang-cpp" onclick="setLang('cpp')">C++</button>
            <button id="lang-html" onclick="setLang('html')">HTML</button>
            <button id="lang-js" onclick="setLang('js')">JavaScript</button>
            <button id="lang-go" onclick="setLang('go')">Go</button>
            <button id="self-check" class="self-check" onclick="checkSelf()">🪞 Проверить себя</button>
        </div>
    </header>

    <details class="disclaimer">
        <summary>Как это работает и чего ждать от помощника</summary>

        <p>Это <b>как проверка орфографии, только для кода</b>. Вставляешь свой код → жмёшь «Проверить» → видишь список проблем. Никаких настроек, никаких зависимостей — всё работает в браузере.</p>

        <p><b>🚀 Как проверить код — 3 шага:</b></p>
        <ul>
            <li><b>1.</b> Вставь код в левое окно (или перетащи файл — он сам подхватится)</li>
            <li><b>2.</b> Нажми <code>Проверить</code> или <code>Ctrl+Enter</code></li>
            <li><b>3.</b> Смотри отчёт справа — проблемы сгруппированы по важности</li>
        </ul>

        <p><b>🎨 Что значат цвета в отчёте:</b></p>
        <ul>
            <li>🔴 <b>Критично</b> — дыра в безопасности, чинить срочно (например, пароль в коде)</li>
            <li>🟡 <b>Высоко</b> — серьёзная проблема, желательно чинить (например, SQL-инъекция)</li>
            <li>🟠 <b>Средне</b> — стоит посмотреть (например, <code>open()</code> без <code>with</code>)</li>
            <li>⚪ <b>Низко</b> — стиль и мелочи (длинная функция, TODO)</li>
            <li>ℹ️ <b>Инфо</b> — заметка или оценка кода (не проблема)</li>
        </ul>

        <p><b>✅ Что находит:</b></p>
        <ul>
            <li><b>Секреты в коде</b> — пароли, API-ключи, токены (Stripe, AWS, GitHub, OpenAI, JWT, Telegram, Slack, Discord и ещё 20+)</li>
            <li><b>SQL-инъекции</b> — f-строки, конкатенация, %-формат. Плюс <b>цепочки через переменные</b> (прослеживаем данные от <code>request.args</code> до <code>execute()</code>)</li>
            <li><b>Shell-инъекции (RCE)</b> — <code>os.system</code>, <code>subprocess</code> с <code>shell=True</code>, <code>exec.Command("sh", "-c", ...)</code> в Go</li>
            <li><b>XSS / SSTI</b> — <code>eval</code>, <code>innerHTML</code>, <code>document.write</code>, <code>render_template_string</code>, Jinja2/Mako без санитайза</li>
            <li><b>Обфускация</b> — <code>exec(base64...)</code>, <code>exec(chr()+chr())</code>, <code>exec(bytes.fromhex())</code>, rot13</li>
            <li><b>Подмена builtins</b> — <code>setattr(builtins, ...)</code>, <code>getattr(__builtins__, ...)</code>, <code>globals()[]</code></li>
            <li><b>Рефлексия</b> — <code>sys._getframe()</code>, доступ к <code>f_globals</code>/<code>f_locals</code>, <code>inspect.get*()</code></li>
            <li><b>Опасные функции</b> — <code>pickle.load</code>, <code>yaml.load</code> без SafeLoader, XXE, <code>marshal.load</code></li>
            <li><b>Framework-специфика</b> — Django (<code>mark_safe</code>, <code>@csrf_exempt</code>, <code>.raw()</code>), Flask (<code>debug=True</code>, <code>send_file</code>), SQLAlchemy (<code>text()</code>)</li>
            <li><b>SSRF</b> — URL из переменной в <code>requests.get()</code></li>
            <li><b>Утечки ресурсов</b> — <code>Session</code>, <code>socket</code>, <code>sqlite3</code>, файлы без <code>with</code></li>
            <li><b>Слабую криптографию</b> — <code>md5</code>, <code>sha1</code>, <code>random</code> для токенов</li>
            <li><b>Хардкод путей</b> — <code>C:\\...</code>, <code>/etc/...</code> (не работает на другом ПК)</li>
            <li><b>Обработку ошибок</b> — голый <code>except:</code>, пустой <code>except: pass</code></li>
            <li><b>Стиль и логику</b> — длинные функции, <code>== None</code>, <code>if x == True</code>, <code>x = x</code>, мёртвый код</li>
            <li><b>C++</b> — <code>strcpy</code>, <code>gets</code>, <code>sprintf</code>, use-after-free, возврат локальной переменной</li>
            <li><b>Go</b> — <code>http.Get</code> без timeout, <code>InsecureSkipVerify</code>, утечки горутин, <code>math/rand</code> для крипто</li>
            <li><b>JavaScript</b> — <code>eval</code>, <code>new Function</code>, токены в <code>localStorage</code>, <code>==</code> вместо <code>===</code></li>
            <li><b>HTML</b> — <code>iframe</code> без <code>sandbox</code>, mixed content, <code>javascript:</code> в ссылках</li>
        </ul>

        <p><b>🎁 Бонус — умный taint-анализ:</b></p>
        <p>Помощник <b>прослеживает данные</b> от источника до опасного места. Например:</p>
        <ul>
            <li><code>x = request.args.get("id")</code> → источник</li>
            <li><code>q = "SELECT ... " + x</code> → данные текут</li>
            <li><code>execute(q)</code> → сток 🔴 <b>найдено!</b></li>
        </ul>
        <p>И знает <b>санитайзеры</b>: если ты обернул вход в <code>int()</code>, <code>escape()</code>, <code>shlex.quote()</code> — тревоги не будет, потому что данные безопасны.</p>

        <p><b>❌ Что НЕ находит:</b></p>
        <ul>
            <li><b>Логические ошибки</b> — гонки, deadlock, неверные условия (нужен человек)</li>
            <li><b>Алгоритмические баги</b> — неправильная формула, потеря точности</li>
            <li><b>Архитектуру</b> — проблемы между файлами, мёртвый код (пока не умеем)</li>
            <li><b>Целенаправленный обход</b> — если специально хитро спрятал уязвимость</li>
            <li><b>Runtime-проблемы</b> — что вылезает только при запуске (гонки, утечки памяти в динамике)</li>
            <li><b>Производительность</b> — медленные алгоритмы, лишние копирования</li>
        </ul>

        <p><b>⚙️ Как читать отчёт:</b></p>
        <ul>
            <li><b>Кликни на проблему</b> — скопируется в буфер одной строкой</li>
            <li><b>Фильтры сверху</b> — по важности (🔴 🟡 🟠 ⚪) и по категории (секреты, SQL, XSS...)</li>
            <li><b>Поиск 🔍</b> — ищет по тексту проблемы</li>
            <li><b>📋 Копировать / 📥 TXT / 📋 JSON</b> — экспорт всего отчёта</li>
            <li><b>📜 История</b> — последние 10 проверок (только в твоём браузере)</li>
        </ul>

        <p><b>🛠️ Продвинутое (для любопытных):</b></p>
        <ul>
            <li><b>📁 Файл</b> — загрузить один файл. Язык определяется по расширению</li>
            <li><b>📦 ZIP</b> — проверить весь проект. Пропускает <code>node_modules/</code>, <code>.git/</code>, <code>__pycache__/</code>. Лимиты: 5 МБ, 100 файлов</li>
            <li><b>🚫 Игнор</b> — редактировать <code>.checkerignore</code> (формат как <code>.gitignore</code>)</li>
            <li><b>🪞 Проверить себя</b> — прогнать сам анализатор (для любопытных)</li>
            <li><b>Ctrl+Enter</b> — проверить · <b>Ctrl+L</b> — очистить · <b>Ctrl+S</b> — скачать · <b>Esc</b> — закрыть окно</li>
        </ul>

        <p class="warn">💡 0 проблем ≠ идеальный код. Помощник — это <b>первый фильтр</b>, а не замена ревью и аудиту. Он ловит <b>типовые</b> проблемы, но <b>не заменяет</b> голову программиста. Проверь код вручную — особенно логику, архитектуру и работу с данными.</p>
    </details>

    <main>
        <div class="panel">
            <h2 id="input-title">Вставь Python-код:</h2>
            <div class="drop-zone" id="dropZone">
                <textarea id="code" placeholder="Вставь код сюда или перетащи файл..." maxlength="100000"></textarea>
                <div class="drop-overlay">📁 Отпусти файл сюда</div>
            </div>
            <div class="code-info">
                <span>Строк: <b id="info-lines">0</b> · Символов: <b id="info-chars">0</b> / 100000</span>
                <span id="info-limit"></span>
            </div>
            <div class="file-name" id="fileName"></div>
            <div class="btn-row">
                <button class="check-btn" id="check" title="Ctrl+Enter">Проверить</button>
                <button class="upload-btn" id="upload" onclick="document.getElementById('fileInput').click()" title="Загрузить файл">📁 Файл</button>
                <button class="zip-btn" id="uploadZip" onclick="document.getElementById('zipInput').click()" title="Загрузить ZIP">📦 ZIP</button>
                <button class="clear-btn" id="ignore" onclick="openIgnore()" title=".checkerignore">🚫 Игнор</button>
                <button class="clear-btn" id="clear" onclick="clearAll()" title="Ctrl+L">🗑 Очистить</button>
                <button class="clear-btn" id="history" onclick="openHistory()" title="История">📜 История</button>
            </div>
            <input type="file" id="fileInput" accept=".py,.cpp,.cc,.cxx,.c,.h,.hpp,.html,.htm,.js,.mjs,.go,.txt" onchange="handleFileSelect(event)">
            <input type="file" id="zipInput" accept=".zip" onchange="handleZipSelect(event)">
            <p style="color: var(--text-dim); font-size: 11px; margin-top: 8px; text-align: center;">
                Ctrl+Enter — проверить · Ctrl+L — очистить · Ctrl+S — скачать · Esc — закрыть
            </p>
        </div>

        <div class="panel">
            <div class="result-header">
                <h2>Результат:</h2>
                <div class="header-buttons">
                    <button class="json-btn" id="jsonBtn" onclick="downloadJSON()" disabled>📋 JSON</button>
                    <button class="download-btn" id="download" onclick="downloadReport()" disabled title="Ctrl+S">📥 TXT</button>
                    <button class="copy-btn" id="copy" onclick="copyReport()" disabled>📋 Копировать</button>
                </div>
            </div>
            <div id="result">
                <div class="ok">Здесь появится отчёт</div>
            </div>
        </div>
    </main>

    <div class="modal-overlay" id="historyModal" onclick="if (event.target === this) closeHistory()">
        <div class="modal">
            <button class="modal-close" onclick="closeHistory()">✕</button>
            <h2>📜 История проверок</h2>
            <div id="historyList"><div class="history-empty">Пока пусто</div></div>
        </div>
    </div>

    <div class="modal-overlay" id="ignoreModal" onclick="if (event.target === this) closeIgnore()">
        <div class="modal">
            <button class="modal-close" onclick="closeIgnore()">✕</button>
            <h2>🚫 Настройки .checkerignore</h2>
            <p style="color: var(--text-mid); font-size: 13px; margin-bottom: 12px; line-height: 1.5;">
                Паттерны — по одному на строку. Формат как в <code>.gitignore</code>:
                <br>• <code>tests/</code> — вся папка
                <br>• <code>*.min.js</code> — все min.js файлы
                <br>• <code>node_modules/</code> — из любого места
                <br>• <code># комментарий</code> — игнорируется
            </p>
            <textarea id="ignoreText" placeholder="tests/&#10;migrations/&#10;*.min.js&#10;node_modules/" style="min-height: 250px; font-family: 'Consolas', monospace;"></textarea>
            <div class="btn-row" style="margin-top: 12px;">
                <button class="check-btn" onclick="saveIgnore()" style="flex: 1;">💾 Сохранить</button>
                <button class="clear-btn" onclick="closeIgnore()">Отмена</button>
            </div>
        </div>
    </div>

    <div class="toast" id="toast"></div>

    <script>
        var codeEl = document.getElementById('code');
        var checkBtn = document.getElementById('check');
        var copyBtn = document.getElementById('copy');
        var downloadBtn = document.getElementById('download');
        var jsonBtn = document.getElementById('jsonBtn');
        var resultEl = document.getElementById('result');
        var inputTitle = document.getElementById('input-title');
        var btnPy = document.getElementById('lang-py');
        var btnCpp = document.getElementById('lang-cpp');
        var btnHtml = document.getElementById('lang-html');
        var btnJs = document.getElementById('lang-js');
        var btnGo = document.getElementById('lang-go');
        var btnSelf = document.getElementById('self-check');
        var infoLines = document.getElementById('info-lines');
        var infoChars = document.getElementById('info-chars');
        var infoLimit = document.getElementById('info-limit');
        var fileNameEl = document.getElementById('fileName');
        var toastEl = document.getElementById('toast');
        var dropZone = document.getElementById('dropZone');

        var currentLang = 'py';
        var currentFilename = 'code.py';
        var currentFileName = '';

        var lastProblems = [];
        var lastSourceName = '';
        var currentFilter = 'ALL';
        var currentCategoryFilter = null;
        var currentSearchQuery = '';

        var SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
        var SEVERITY_LABELS = {
            'CRITICAL': '🔴 Критичные',
            'HIGH': '🟡 Высокие',
            'MEDIUM': '🟠 Средние',
            'LOW': '⚪ Низкие',
            'INFO': 'ℹ️ Информационные'
        };
        var SEVERITY_MARKERS = {
            'CRITICAL': '🔴',
            'HIGH': '🟡',
            'MEDIUM': '🟠',
            'LOW': '⚪',
            'INFO': 'ℹ️'
        };
        var CATEGORY_MAP = {
            'secrets': '🔑 Секреты',
            'sql': '💉 SQL-инъекции',
            'shell': '💻 Shell-инъекции',
            'dangerous_calls': '⚠️ Опасные вызовы',
            'deserialization': '📦 Десериализация',
            'crypto': '🔐 Криптография',
            'error_handling': '🚨 Обработка ошибок',
            'assert': '🧪 Assert',
            'files': '📂 Файлы',
            'network': '🌐 Сеть',
            'paths': '📁 Пути',
            'comparisons': '🔍 Сравнения',
            'style': '📐 Стиль',
            'notes': '📝 Заметки',
            'imports': '📥 Импорты',
            'logging': '🖨️ Логирование',
            'fstrings': '📝 F-строки',
            'line_length': '📏 Длина строк',
            'memory': '💾 Память',
            'xss': '🎯 XSS',
            'obfuscation': '🕵️ Обфускация',
            'logic': '🧠 Логика',
            'resources': '🔋 Ресурсы',
            'taint': '🌊 Taint-анализ',
            'other': '📌 Прочее'
        };
        var CATEGORY_ORDER = [
            'secrets', 'sql', 'shell', 'dangerous_calls', 'deserialization',
            'crypto', 'error_handling', 'assert', 'files', 'network',
            'paths', 'comparisons', 'style', 'notes', 'imports',
            'logging', 'fstrings', 'line_length', 'memory', 'xss',
            'obfuscation', 'logic', 'resources', 'taint', 'other'
        ];

        var toastTimer = null;
        function showToast(text, color) {
            toastEl.textContent = text;
            toastEl.style.background = color || '#2a5a3a';
            toastEl.classList.add('show');
            clearTimeout(toastTimer);
            toastTimer = setTimeout(function() {
                toastEl.classList.remove('show');
            }, 2000);
        }

        function escapeAttr(s) {
            return String(s)
                .replace(/&/g, '&amp;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;');
        }

        function escapeHtml(text) {
            var div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function copyToClipboard(text) {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                return navigator.clipboard.writeText(text).catch(function() {
                    fallbackCopy(text);
                });
            }
            fallbackCopy(text);
            return Promise.resolve();
        }

        function fallbackCopy(text) {
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.left = '-9999px';
            document.body.appendChild(ta);
            ta.select();
            try { document.execCommand('copy'); } catch(e) {}
            document.body.removeChild(ta);
        }

        resultEl.addEventListener('click', function(e) {
            var el = e.target.closest('.problem');
            if (!el || !el.dataset.problem) return;
            var encoded = el.dataset.problem;
            try {
                var item = JSON.parse(decodeURIComponent(encoded));
                var marker = SEVERITY_MARKERS[item.severity] || '•';
                var text = marker + ' Строка ' + item.line + ': ' + item.message;
                copyToClipboard(text).then(function() {
                    el.classList.add('copied');
                    setTimeout(function() { el.classList.remove('copied'); }, 600);
                    showToast('📋 Скопировано');
                });
            } catch (err) {
                showToast('❌ Не удалось скопировать', '#a02020');
            }
        });

        var HISTORY_KEY = 'cc_history';
        var HISTORY_MAX = 10;
        function getHistory() {
            try {
                var raw = localStorage.getItem(HISTORY_KEY);
                return raw ? JSON.parse(raw) : [];
            } catch(e) { return []; }
        }
        function pushHistory(entry) {
            var list = getHistory();
            list.unshift(entry);
            if (list.length > HISTORY_MAX) list = list.slice(0, HISTORY_MAX);
            try { localStorage.setItem(HISTORY_KEY, JSON.stringify(list)); } catch(e) {}
        }
        function openHistory() {
            var list = getHistory();
            var container = document.getElementById('historyList');
            if (list.length === 0) {
                container.innerHTML = '<div class="history-empty">Пока пусто — прогони код и появится запись</div>';
            } else {
                var html = '';
                for (var i = 0; i < list.length; i++) {
                    var e = list[i];
                    html += '<div class="history-item" onclick="loadHistory(' + i + ')">';
                    html += '<span class="h-lang">' + escapeHtml(e.filename || 'код') + '</span>';
                    html += '<span class="h-time">' + escapeHtml(e.time) + '</span>';
                    html += '<div class="h-summary">Проблем: ' + e.count +
                            ' · 🔴 ' + (e.critical || 0) +
                            ' · 🟡 ' + (e.high || 0) +
                            ' · 🟠 ' + (e.medium || 0) +
                            ' · ⚪ ' + (e.low || 0) + '</div>';
                    html += '</div>';
                }
                container.innerHTML = html;
            }
            document.getElementById('historyModal').classList.add('show');
        }
        function closeHistory() {
            document.getElementById('historyModal').classList.remove('show');
        }
        function loadHistory(idx) {
            var list = getHistory();
            if (!list[idx]) return;
            var e = list[idx];
            codeEl.value = e.code || '';
            updateCodeInfo();
            setLang(e.lang || 'py');
            lastProblems = e.problems || [];
            lastSourceName = e.filename || 'история';
            currentFilter = 'ALL';
            currentCategoryFilter = null;
            currentSearchQuery = '';
            copyBtn.disabled = lastProblems.length === 0;
            downloadBtn.disabled = lastProblems.length === 0;
            jsonBtn.disabled = lastProblems.length === 0;
            renderProblemsInternal({problems: lastProblems, error: null}, resultEl, lastSourceName);
            closeHistory();
            showToast('📜 Загружено из истории');
        }

        async function openIgnore() {
            document.getElementById('ignoreModal').classList.add('show');
            var ta = document.getElementById('ignoreText');
            ta.value = 'Загружаю...';
            try {
                var res = await fetch('/checkerignore');
                var data = await res.json();
                ta.value = data.content || '';
            } catch (e) {
                ta.value = '';
                showToast('❌ Не удалось загрузить', '#a02020');
            }
        }
        function closeIgnore() {
            document.getElementById('ignoreModal').classList.remove('show');
        }
        async function saveIgnore() {
            var ta = document.getElementById('ignoreText');
            try {
                var res = await fetch('/checkerignore', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({content: ta.value})
                });
                var data = await res.json();
                if (data.status === 'ok') {
                    showToast('💾 Сохранено в .checkerignore');
                    closeIgnore();
                } else {
                    showToast('❌ Ошибка: ' + (data.error || 'неизвестно'), '#a02020');
                }
            } catch (e) {
                showToast('❌ Ошибка: ' + e.message, '#a02020');
            }
        }

        function handleFileSelect(event) {
            var file = event.target.files[0];
            if (!file) return;
            readFile(file);
            event.target.value = '';
        }

        function readFile(file) {
            var reader = new FileReader();
            reader.onload = function(e) {
                var text = e.target.result;
                var truncated = false;
                if (text.length > 100000) {
                    text = text.substring(0, 100000);
                    truncated = true;
                }
                codeEl.value = text;
                currentFileName = file.name;
                fileNameEl.textContent = '📄 ' + file.name + (truncated ? ' (обрезан до 100k)' : '');
                updateCodeInfo();
                var name = file.name.toLowerCase();
                if (name.endsWith('.py')) { setLang('py'); }
                else if (name.endsWith('.cpp') || name.endsWith('.cc') ||
                         name.endsWith('.cxx') || name.endsWith('.c') ||
                         name.endsWith('.h') || name.endsWith('.hpp')) { setLang('cpp'); }
                else if (name.endsWith('.html') || name.endsWith('.htm')) { setLang('html'); }
                else if (name.endsWith('.js') || name.endsWith('.mjs')) { setLang('js'); }
                else if (name.endsWith('.go')) { setLang('go'); }
                else {
                    var detected = detectLang(text);
                    if (detected) setLang(detected);
                }
                if (truncated) {
                    showToast('⚠ Файл обрезан до 100 000 символов', '#a06020');
                } else {
                    showToast('📁 Файл загружен: ' + file.name);
                }
            };
            reader.onerror = function() {
                showToast('❌ Не удалось прочитать файл', '#a02020');
            };
            reader.readAsText(file, 'UTF-8');
        }

        function handleZipSelect(event) {
            var file = event.target.files[0];
            if (!file) return;
            uploadZip(file);
            event.target.value = '';
        }

        async function uploadZip(file) {
            if (file.size > 5 * 1024 * 1024) {
                showToast('❌ ZIP больше 5 MB', '#a02020');
                return;
            }
            resultEl.innerHTML = '<div class="ok">📦 Анализирую ZIP-архив...</div>';
            checkBtn.disabled = true;
            copyBtn.disabled = true;
            downloadBtn.disabled = true;
            jsonBtn.disabled = true;
            lastProblems = [];

            try {
                var formData = new FormData();
                formData.append('file', file);
                var res = await fetch('/check-zip', {
                    method: 'POST',
                    body: formData
                });

                if (res.status === 429) {
                    resultEl.innerHTML = '<div class="error">Слишком много запросов. Подожди минуту.</div>';
                    return;
                }
                if (!res.ok) {
                    resultEl.innerHTML = '<div class="error">Ошибка сервера: ' + res.status + '</div>';
                    return;
                }

                var data = await res.json();
                if (typeof ym === 'function') { ym(113541969, 'reachGoal', 'zip_uploaded'); }

                if (data.error) {
                    resultEl.innerHTML = '<div class="error">' + escapeHtml(data.error) + '</div>';
                    return;
                }

                if (!data.results || data.results.length === 0) {
                    resultEl.innerHTML = '<div class="no-problems">📦 В архиве не найдено поддерживаемых файлов</div>';
                    return;
                }

                var allProblems = [];
                var html = '';

                var sum = data.summary || {};
                html += '<div class="hint">📦 <b>Архив:</b> ' + escapeHtml(file.name) + '<br>' +
                        'Файлов: <b>' + (sum.total_files || data.results.length) + '</b> · ' +
                        'Проблем всего: <b>' + (sum.total_problems || 0) + '</b>' +
                        (sum.truncated ? ' <b style="color:#e67e22">(проверено не всё)</b>' : '') +
                        '</div>';

                for (var i = 0; i < data.results.length; i++) {
                    var item = data.results[i];
                    html += '<div class="file-header">📄 ' + escapeHtml(item.file) +
                            ' (' + item.problems.length + ' проблем)</div>';
                    html += '<div class="file-block">';

                    var tmp = document.createElement('div');
                    renderProblems({problems: item.problems, error: null}, tmp, item.file);
                    html += tmp.innerHTML;
                    html += '</div>';

                    for (var j = 0; j < item.problems.length; j++) {
                        var p = item.problems[j];
                        allProblems.push({
                            line: p.line,
                            severity: p.severity,
                            category: p.category || 'other',
                            message: '[' + item.file + '] ' + p.message
                        });
                    }
                }

                resultEl.innerHTML = html;

                if (allProblems.length > 0) {
                    lastProblems = allProblems;
                    lastSourceName = 'ZIP: ' + file.name;
                    copyBtn.disabled = false;
                    downloadBtn.disabled = false;
                    jsonBtn.disabled = false;
                }

                showToast('📦 Готово: ' + allProblems.length + ' проблем');

            } catch (e) {
                resultEl.innerHTML = '<div class="error">Ошибка: ' + escapeHtml(e.message) + '</div>';
            } finally {
                checkBtn.disabled = false;
            }
        }

        ['dragenter', 'dragover'].forEach(function(evt) {
            dropZone.addEventListener(evt, function(e) {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.add('dragover');
            });
        });
        ['dragleave', 'drop'].forEach(function(evt) {
            dropZone.addEventListener(evt, function(e) {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.remove('dragover');
            });
        });
        dropZone.addEventListener('drop', function(e) {
            var files = e.dataTransfer.files;
            if (files && files.length > 0) {
                readFile(files[0]);
            }
        });

        function getVisibleProblems() {
            var filtered = lastProblems;
            if (currentFilter !== 'ALL') {
                filtered = filtered.filter(function(p) { return p.severity === currentFilter; });
            }
            if (currentCategoryFilter) {
                filtered = filtered.filter(function(p) {
                    return (p.category || 'other') === currentCategoryFilter;
                });
            }
            if (currentSearchQuery) {
                var q = currentSearchQuery.toLowerCase();
                filtered = filtered.filter(function(p) {
                    return (p.message || '').toLowerCase().indexOf(q) !== -1;
                });
            }
            return filtered;
        }
        function setSearchQuery(q) {
            currentSearchQuery = q || '';
            rerender();
        }

        function setLang(lang) {
            currentLang = lang;
            btnPy.classList.remove('active');
            btnCpp.classList.remove('active');
            btnHtml.classList.remove('active');
            btnJs.classList.remove('active');
            btnGo.classList.remove('active');

            if (lang === 'py') {
                currentFilename = 'code.py';
                inputTitle.textContent = 'Вставь Python-код:';
                codeEl.placeholder = 'Вставь Python-код сюда или перетащи файл...';
                btnPy.classList.add('active');
            } else if (lang === 'cpp') {
                currentFilename = 'code.cpp';
                inputTitle.textContent = 'Вставь C++-код:';
                codeEl.placeholder = 'Вставь C++-код сюда или перетащи файл...';
                btnCpp.classList.add('active');
            } else if (lang === 'html') {
                currentFilename = 'code.html';
                inputTitle.textContent = 'Вставь HTML-код:';
                codeEl.placeholder = 'Вставь HTML-код сюда или перетащи файл...';
                btnHtml.classList.add('active');
            } else if (lang === 'js') {
                currentFilename = 'code.js';
                inputTitle.textContent = 'Вставь JavaScript-код:';
                codeEl.placeholder = 'Вставь JavaScript-код сюда или перетащи файл...';
                btnJs.classList.add('active');
            } else if (lang === 'go') {
                currentFilename = 'code.go';
                inputTitle.textContent = 'Вставь Go-код:';
                codeEl.placeholder = 'Вставь Go-код сюда или перетащи файл...';
                btnGo.classList.add('active');
            }
        }

        function detectLang(text) {
            var trimmed = text.trimStart();
            var head = text.substring(0, 2000).toLowerCase();

            if (head.indexOf('#include') !== -1 || head.indexOf('std::') !== -1 ||
                head.indexOf('using namespace') !== -1 || head.indexOf('cout <<') !== -1) {
                return 'cpp';
            }
            if (trimmed.charAt(0) === '<') return 'html';
            if (head.indexOf('<!doctype html') !== -1 || head.indexOf('<html') !== -1 ||
                head.indexOf('<head') !== -1 || head.indexOf('<body') !== -1) {
                return 'html';
            }
            if (head.indexOf('function ') !== -1 || head.indexOf('var ') !== -1 ||
                head.indexOf('console.log') !== -1 || head.indexOf('document.') !== -1 ||
                head.indexOf('=>') !== -1) {
                return 'js';
            }
            if (head.indexOf('package main') !== -1 ||
                (head.indexOf('package ') !== -1 && head.indexOf('func ') !== -1) ||
                head.indexOf(':= ') !== -1) {
                return 'go';
            }
            if (head.indexOf('def ') !== -1 || head.indexOf('print(') !== -1 ||
                head.indexOf('import ') !== -1) {
                return 'py';
            }
            return null;
        }

        var debounceTimer = null;
        function handleInputDebounced() {
            updateCodeInfo();
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(function() {
                var text = codeEl.value;
                var detected = detectLang(text);
                if (detected && detected !== currentLang) {
                    setLang(detected);
                }
            }, 300);
        }

        function updateCodeInfo() {
            var text = codeEl.value;
            var lines = text === '' ? 0 : text.split('\\n').length;
            var chars = text.length;
            infoLines.textContent = lines;
            infoChars.textContent = chars;
            if (chars > 100000) {
                infoLimit.textContent = '⚠ Превышен лимит';
                infoLimit.className = 'limit-over';
            } else if (chars === 100000) {
                infoLimit.textContent = '🚧 Дальше нельзя';
                infoLimit.className = 'limit-ok';
            } else if (chars > 90000) {
                infoLimit.textContent = '⚠ Близко к лимиту';
                infoLimit.className = 'limit-warn';
            } else {
                infoLimit.textContent = '';
                infoLimit.className = '';
            }
        }

        function clearAll() {
            codeEl.value = '';
            updateCodeInfo();
            resultEl.innerHTML = '<div class="ok">Здесь появится отчёт</div>';
            copyBtn.disabled = true;
            downloadBtn.disabled = true;
            jsonBtn.disabled = true;
            lastProblems = [];
            lastSourceName = '';
            currentFilter = 'ALL';
            currentCategoryFilter = null;
            currentSearchQuery = '';
            currentFileName = '';
            fileNameEl.textContent = '';
            codeEl.focus();
            showToast('🗑 Очищено');
        }

        codeEl.addEventListener('input', handleInputDebounced);
        codeEl.addEventListener('paste', function() {
            setTimeout(handleInputDebounced, 50);
        });

        var LANG_NAMES = {
            'py': 'Python', 'cpp': 'C++', 'html': 'HTML',
            'js': 'JavaScript', 'go': 'Go'
        };

        function categoryLabel(key) {
            return CATEGORY_MAP[key] || CATEGORY_MAP['other'];
        }

        function sortCategories(categories) {
            var known = {};
            for (var i = 0; i < CATEGORY_ORDER.length; i++) {
                known[CATEGORY_ORDER[i]] = i;
            }
            return categories.sort(function(a, b) {
                var ai = known.hasOwnProperty(a) ? known[a] : 999;
                var bi = known.hasOwnProperty(b) ? known[b] : 999;
                return ai - bi;
            });
        }

        function buildCounters(problems) {
            var counts = { 'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0 };
            for (var i = 0; i < problems.length; i++) {
                var sev = problems[i].severity;
                if (counts.hasOwnProperty(sev)) counts[sev]++;
            }
            var html = '<div class="counter-bar">';
            var totalActive = currentFilter === 'ALL' ? ' active' : '';
            html += '<div class="counter-item total' + totalActive + '" onclick="setFilter(\\'ALL\\')">Всего: ' + problems.length + '</div>';
            for (var j = 0; j < SEVERITY_ORDER.length; j++) {
                var s = SEVERITY_ORDER[j];
                if (counts[s] > 0) {
                    var cls = s.toLowerCase();
                    var label = SEVERITY_LABELS[s].replace(/^[^ ]+ /, '');
                    var active = currentFilter === s ? ' active' : '';
                    html += '<div class="counter-item ' + cls + active + '" onclick="setFilter(\\'' + s + '\\')">' +
                            SEVERITY_MARKERS[s] + ' ' + label + ': ' + counts[s] + '</div>';
                }
            }
            html += '</div>';
            return html;
        }

        function buildCategoryCounters(problems) {
            var counts = {};
            for (var i = 0; i < problems.length; i++) {
                var cat = problems[i].category || 'other';
                counts[cat] = (counts[cat] || 0) + 1;
            }
            var keys = sortCategories(Object.keys(counts));
            if (keys.length === 0) return '';
            var html = '<div class="category-counters">';
            for (var j = 0; j < keys.length; j++) {
                var k = keys[j];
                var active = currentCategoryFilter === k ? ' active' : '';
                html += '<div class="category-chip' + active + '" onclick="setCategoryFilter(\\'' + k + '\\')">' +
                        categoryLabel(k) + ': ' + counts[k] + '</div>';
            }
            html += '</div>';
            return html;
        }

        function setFilter(sev) {
            currentFilter = sev;
            currentCategoryFilter = null;
            rerender();
        }
        function setCategoryFilter(cat) {
            if (currentCategoryFilter === cat) {
                currentCategoryFilter = null;
            } else {
                currentCategoryFilter = cat;
                currentFilter = 'ALL';
            }
            rerender();
        }
        function rerender() {
            if (!lastProblems || lastProblems.length === 0) return;
            var filtered = getVisibleProblems();
            renderProblemsInternal({problems: filtered, error: null}, resultEl, lastSourceName);
        }

        function renderProblems(data, container, sourceName) {
            if (data.error) {
                container.innerHTML = '<div class="error">' + escapeHtml(data.error) + '</div>';
                copyBtn.disabled = true;
                downloadBtn.disabled = true;
                jsonBtn.disabled = true;
                return;
            }

            if (!data.problems || data.problems.length === 0) {
                container.innerHTML =
                    '<div class="no-problems">' +
                    '<b>✅ Критичных проблем не найдено.</b><br><br>' +
                    'Это <b>не значит</b>, что код идеален. Помощник ловит <b>типовые</b> проблемы ' +
                    'по паттернам, эвристике и taint-анализу, но <b>не заменяет</b> ревью человеком и аудит. ' +
                    'Проверь код вручную — особенно логику, архитектуру и работу с данными.' +
                    '</div>';
                copyBtn.disabled = true;
                downloadBtn.disabled = true;
                jsonBtn.disabled = true;
                return;
            }

            var onlyInfo = true;
            for (var i = 0; i < data.problems.length; i++) {
                if (data.problems[i].severity !== 'INFO') { onlyInfo = false; break; }
            }

            if (onlyInfo) {
                var hintHtml = '';
                for (var k = 0; k < data.problems.length; k++) {
                    hintHtml += '<div class="hint">ℹ️ ' + escapeHtml(data.problems[k].message) + '</div>';
                }
                container.innerHTML = hintHtml;
                copyBtn.disabled = true;
                downloadBtn.disabled = true;
                jsonBtn.disabled = true;
                return;
            }

            lastProblems = data.problems;
            lastSourceName = sourceName || 'code';
            currentFilter = 'ALL';
            currentCategoryFilter = null;
            currentSearchQuery = '';
            copyBtn.disabled = false;
            downloadBtn.disabled = false;
            jsonBtn.disabled = false;

            var counts = { 'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0 };
            for (var hi = 0; hi < data.problems.length; hi++) {
                var s = data.problems[hi].severity;
                if (counts.hasOwnProperty(s)) counts[s]++;
            }
            pushHistory({
                time: new Date().toLocaleString('ru-RU'),
                filename: sourceName || 'код',
                lang: currentLang,
                code: codeEl.value,
                count: data.problems.length,
                critical: counts['CRITICAL'],
                high: counts['HIGH'],
                medium: counts['MEDIUM'],
                low: counts['LOW'],
                problems: data.problems
            });

            renderProblemsInternal(data, container, sourceName);
        }

        function renderProblemsInternal(data, container, sourceName) {
            var problems = data.problems || [];
            var grouped = {};
            for (var si = 0; si < SEVERITY_ORDER.length; si++) {
                grouped[SEVERITY_ORDER[si]] = {};
            }
            for (var pi = 0; pi < problems.length; pi++) {
                var p = problems[pi];
                var sev = SEVERITY_ORDER.indexOf(p.severity) !== -1 ? p.severity : 'INFO';
                var cat = p.category || 'other';
                if (!grouped[sev][cat]) grouped[sev][cat] = [];
                grouped[sev][cat].push(p);
            }

            var html = '';
            html += '<input class="search-box" type="text" placeholder="🔍 Найти в отчёте..." value="' +
                    escapeAttr(currentSearchQuery) + '" oninput="setSearchQuery(this.value)">';
            html += buildCounters(lastProblems);
            html += buildCategoryCounters(lastProblems);

            if (problems.length === 0) {
                html += '<div class="no-problems">По выбранному фильтру ничего нет. Нажми <b>Всего</b> или очисти поиск.</div>';
                container.innerHTML = html;
                return;
            }

            for (var s = 0; s < SEVERITY_ORDER.length; s++) {
                var sevKey = SEVERITY_ORDER[s];
                var cats = grouped[sevKey];
                var totalInSev = 0;
                for (var catKey in cats) {
                    if (cats.hasOwnProperty(catKey)) totalInSev += cats[catKey].length;
                }
                if (totalInSev === 0) continue;

                html += '<div class="severity-header ' + sevKey.toLowerCase() + '">' +
                        SEVERITY_LABELS[sevKey] + ' — ' + totalInSev + '</div>';

                var sortedCats = sortCategories(Object.keys(cats));
                for (var ci = 0; ci < sortedCats.length; ci++) {
                    var cname = sortedCats[ci];
                    var items = cats[cname];
                    html += '<div class="category-header">' + categoryLabel(cname) + ' — ' + items.length + '</div>';
                    for (var ii = 0; ii < items.length; ii++) {
                        var item = items[ii];
                        var cls2 = 'problem';
                        if (item.severity === 'HIGH') cls2 = 'problem high';
                        else if (item.severity === 'MEDIUM') cls2 = 'problem medium';
                        else if (item.severity === 'LOW') cls2 = 'problem low';
                        else if (item.severity === 'INFO') cls2 = 'problem info';

                        var marker = SEVERITY_MARKERS[item.severity] || '•';
                        var encoded = encodeURIComponent(JSON.stringify(item));

                        html += '<div class="' + cls2 + '" data-problem="' + escapeAttr(encoded) + '" title="Клик — копировать">';
                        html += '<div class="line">' + marker + ' Строка ' + item.line + '</div>';
                        html += '<div class="msg">' + escapeHtml(item.message) + '</div>';
                        html += '</div>';
                    }
                }
            }
            container.innerHTML = html;
        }

        async function checkCode() {
            var code = codeEl.value.trim();
            if (!code) {
                resultEl.innerHTML = '<div class="error">Вставь код для проверки.</div>';
                copyBtn.disabled = true;
                downloadBtn.disabled = true;
                jsonBtn.disabled = true;
                return;
            }

            if (code.length > 100000) {
                code = code.substring(0, 100000);
                showToast('⚠ Код обрезан до 100 000 символов', '#a06020');
            }

            var detected = detectLang(code);
            if (detected && detected !== currentLang) {
                setLang(detected);
            }

            checkBtn.disabled = true;
            resultEl.innerHTML = '<div class="ok">Анализирую...</div>';
            copyBtn.disabled = true;
            downloadBtn.disabled = true;
            jsonBtn.disabled = true;

            try {
                var res = await fetch('/check', {
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

                var data = await res.json();
                if (typeof ym === 'function') { ym(113541969, 'reachGoal', 'code_checked'); }
                var srcName = currentFileName || LANG_NAMES[currentLang] || 'код';
                renderProblems(data, resultEl, srcName);
                if (data.problems && data.problems.length > 0) {
                    showToast('✅ Готово: ' + data.problems.length + ' проблем');
                } else {
                    showToast('✅ Проблем не найдено', '#2a5a3a');
                }

            } catch (e) {
                resultEl.innerHTML = '<div class="error">Ошибка: ' + escapeHtml(e.message) + '</div>';
                copyBtn.disabled = true;
                downloadBtn.disabled = true;
                jsonBtn.disabled = true;
            } finally {
                checkBtn.disabled = false;
            }
        }

        async function checkSelf() {
            btnSelf.disabled = true;
            resultEl.innerHTML = '<div class="ok">🔍 Проверяю свои файлы...</div>';
            copyBtn.disabled = true;
            downloadBtn.disabled = true;
            jsonBtn.disabled = true;

            try {
                var res = await fetch('/check-self', {method: 'GET'});
                if (res.status === 429) {
                    resultEl.innerHTML = '<div class="error">Слишком много запросов. Подожди минуту.</div>';
                    return;
                }
                if (!res.ok) {
                    resultEl.innerHTML = '<div class="error">Ошибка сервера: ' + res.status + '</div>';
                    return;
                }

                var data = await res.json();
                if (typeof ym === 'function') { ym(113541969, 'reachGoal', 'self_check'); }
                if (!data.results) {
                    resultEl.innerHTML = '<div class="error">Сервер вернул неверный ответ.</div>';
                    return;
                }

                var allProblems = [];
                var html = '';
                for (var i = 0; i < data.results.length; i++) {
                    var item = data.results[i];
                    html += '<div class="file-header">📄 ' + escapeHtml(item.file) +
                            ' (' + item.problems.length + ' проблем)</div>';
                    html += '<div class="file-block">';

                    var tmp = document.createElement('div');
                    renderProblems({problems: item.problems, error: null}, tmp, item.file);
                    html += tmp.innerHTML;
                    html += '</div>';

                    for (var j = 0; j < item.problems.length; j++) {
                        var p = item.problems[j];
                        allProblems.push({
                            line: p.line,
                            severity: p.severity,
                            category: p.category || 'other',
                            message: '[' + item.file + '] ' + p.message
                        });
                    }
                }

                resultEl.innerHTML = html;

                if (allProblems.length > 0) {
                    lastProblems = allProblems;
                    lastSourceName = 'self-check (app.py + checker.py)';
                    copyBtn.disabled = false;
                    downloadBtn.disabled = false;
                    jsonBtn.disabled = false;
                } else {
                    copyBtn.disabled = true;
                    downloadBtn.disabled = true;
                    jsonBtn.disabled = true;
                }

            } catch (e) {
                resultEl.innerHTML = '<div class="error">Ошибка: ' + escapeHtml(e.message) + '</div>';
            } finally {
                btnSelf.disabled = false;
            }
        }

        function buildReportText() {
            if (!lastProblems || lastProblems.length === 0) return '';
            var counts = { 'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0 };
            for (var i = 0; i < lastProblems.length; i++) {
                var sev = lastProblems[i].severity;
                if (counts.hasOwnProperty(sev)) counts[sev]++;
            }

            var text = '';
            text += 'Code Checker — отчёт\\n';
            text += 'Файл: ' + lastSourceName + '\\n';
            text += 'Дата: ' + new Date().toLocaleString('ru-RU') + '\\n';
            text += 'Всего проблем: ' + lastProblems.length + '\\n';
            text += '  CRITICAL: ' + counts['CRITICAL'] + '\\n';
            text += '  HIGH: ' + counts['HIGH'] + '\\n';
            text += '  MEDIUM: ' + counts['MEDIUM'] + '\\n';
            text += '  LOW: ' + counts['LOW'] + '\\n';
            if (counts['INFO'] > 0) {
                text += '  INFO: ' + counts['INFO'] + '\\n';
            }
            text += '\\n';
            text += '------------------------------------------------------------\\n\\n';

            for (var k = 0; k < lastProblems.length; k++) {
                var p = lastProblems[k];
                var marker = SEVERITY_MARKERS[p.severity] || '•';
                text += marker + ' Строка ' + p.line + ': ' + p.message + '\\n';
            }
            return text;
        }

        async function copyReport() {
            var text = buildReportText();
            if (!text) return;
            if (typeof ym === 'function') { ym(113541969, 'reachGoal', 'report_copied'); }
            await copyToClipboard(text);
            copyBtn.textContent = '✅ Скопировано!';
            copyBtn.classList.add('copied');
            setTimeout(function() {
                copyBtn.textContent = '📋 Копировать';
                copyBtn.classList.remove('copied');
            }, 2000);
            showToast('📋 Отчёт скопирован');
        }

        function downloadReport() {
            var text = buildReportText();
            if (!text) return;
            if (typeof ym === 'function') { ym(113541969, 'reachGoal', 'report_downloaded'); }
            var d = new Date();
            var pad = function(n) { return n < 10 ? '0' + n : '' + n; };
            var stamp = d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
                        '_' + pad(d.getHours()) + '-' + pad(d.getMinutes()) + '-' + pad(d.getSeconds());
            var filename = 'code_checker_report_' + stamp + '.txt';
            var blob = new Blob([text], {type: 'text/plain;charset=utf-8'});
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
            showToast('📥 Файл скачан');
        }

        function downloadJSON() {
            if (!lastProblems || lastProblems.length === 0) return;
            if (typeof ym === 'function') { ym(113541969, 'reachGoal', 'json_downloaded'); }
            var counts = { 'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0 };
            for (var i = 0; i < lastProblems.length; i++) {
                var sev = lastProblems[i].severity;
                if (counts.hasOwnProperty(sev)) counts[sev]++;
            }
            var report = {
                tool: 'Code Checker',
                version: 'v17.10.2',
                date: new Date().toISOString(),
                source: lastSourceName,
                language: currentLang,
                total: lastProblems.length,
                summary: counts,
                problems: lastProblems
            };
            var text = JSON.stringify(report, null, 2);
            var d = new Date();
            var pad = function(n) { return n < 10 ? '0' + n : '' + n; };
            var stamp = d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
                        '_' + pad(d.getHours()) + '-' + pad(d.getMinutes()) + '-' + pad(d.getSeconds());
            var filename = 'code_checker_report_' + stamp + '.json';
            var blob = new Blob([text], {type: 'application/json;charset=utf-8'});
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
            showToast('📋 JSON скачан');
        }

        document.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                e.preventDefault(); checkCode();
            }
            if ((e.ctrlKey || e.metaKey) && (e.key === 'l' || e.key === 'L' || e.key === 'д' || e.key === 'Д')) {
                e.preventDefault(); clearAll();
            }
            if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.key === 'S' || e.key === 'ы' || e.key === 'Ы')) {
                e.preventDefault();
                if (!downloadBtn.disabled) downloadReport();
            }
            if (e.key === 'Escape') {
                closeHistory(); closeIgnore();
            }
        });

        checkBtn.addEventListener('click', checkCode);
        updateCodeInfo();
    </script>
</body>
</html>
"""
# ============ .checkerignore ============

def _load_checkerignore():
    if not CHECKERIGNORE_FILE.exists():
        return []
    try:
        text = CHECKERIGNORE_FILE.read_text(encoding="utf-8")
    except Exception as e:
        logger.warning(f"Не удалось прочитать .checkerignore: {e}")
        return []
    patterns = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    return patterns


def _is_ignored(name, patterns):
    if not patterns:
        return False
    normalized = name.replace("\\", "/")
    parts = normalized.split("/")
    for pat in patterns:
        p = pat.rstrip("/")
        if "/" in p:
            if fnmatch.fnmatch(normalized, p) or fnmatch.fnmatch(normalized, p + "/*"):
                return True
            if fnmatch.fnmatch(normalized, pat):
                return True
        else:
            for part in parts:
                if fnmatch.fnmatch(part, p):
                    return True
        if fnmatch.fnmatch(normalized, pat):
            return True
    return False


# ============ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ============

def _detect_language_from_code(code: str, filename: str = "code.py") -> str:
    ext = Path(filename).suffix.lower()

    if ext in (".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"):
        return "cpp"
    if ext == ".py":
        return "python"
    if ext in (".html", ".htm"):
        return "html"
    if ext in (".js", ".mjs"):
        return "js"
    if ext == ".go":
        return "go"

    head = code[:2000].lower()
    trimmed = code.lstrip()

    if "#include" in head or "std::" in head or "using namespace" in head:
        return "cpp"

    if trimmed.startswith("<"):
        return "html"

    if ("<!doctype html" in head or "<html" in head or
            "<head" in head or "<body" in head):
        return "html"

    if ("function " in head or "var " in head or
            "console.log" in head or "document." in head or
            "=>" in head):
        return "js"

    if "package " in head and "func " in head:
        return "go"

    return "python"


def _get_suffix(lang: str) -> str:
    suffix_map = {
        "python": ".py", "cpp": ".cpp", "html": ".html",
        "js": ".js", "go": ".go",
    }
    return suffix_map.get(lang, ".py")


async def _save_and_analyze(code: str, suffix: str):
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False, encoding="utf-8",
            dir=str(TMP_DIR),
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
                              "message": f"Файл не найден: {filename}",
                              "category": "other"}],
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
                              "message": f"Ошибка анализа: {str(e)}",
                              "category": "other"}],
            })

    return {"results": results}


@app.get("/checkerignore")
async def get_checkerignore():
    if not CHECKERIGNORE_FILE.exists():
        return {"content": "", "exists": False}
    try:
        text = CHECKERIGNORE_FILE.read_text(encoding="utf-8")
        return {"content": text, "exists": True}
    except Exception as e:
        return {"content": "", "exists": False, "error": str(e)}


@app.post("/checkerignore")
async def save_checkerignore(payload: CheckerignoreRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests")
    try:
        CHECKERIGNORE_FILE.write_text(payload.content, encoding="utf-8")
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ============ ZIP-АНАЛИЗ ============

ZIP_MAX_SIZE = 5 * 1024 * 1024
ZIP_MAX_FILES = 100
ZIP_MAX_FILE_SIZE = 100000
ZIP_MAX_TOTAL_UNPACKED = 50 * 1024 * 1024

ZIP_SKIP_DIRS = {
    "node_modules", "__pycache__", ".git", ".venv", "venv", "env",
    "dist", "build", ".idea", ".vscode", "target", "bin", "obj",
    ".next", ".nuxt", ".pytest_cache", ".mypy_cache", "coverage",
}

ZIP_ALLOWED_EXTS = {
    ".py", ".cpp", ".cc", ".cxx", ".c", ".h", ".hpp",
    ".html", ".htm", ".js", ".mjs", ".go",
}


def _should_skip_zip_entry(name, patterns):
    """Проверяет, надо ли пропустить файл из архива."""
    if name.endswith("/"):
        return True
    normalized = name.replace("\\", "/")
    parts = normalized.split("/")
    if any(p.startswith(".") or p in ZIP_SKIP_DIRS for p in parts):
        return True
    if _is_ignored(normalized, patterns):
        return True
    ext = Path(name).suffix.lower()
    if ext not in ZIP_ALLOWED_EXTS:
        return True
    return False


def _zip_collect_files(zf):
    """
    Возвращает (collected, truncated).
    Защита от zip-бомб: размер распакованного файла проверяется по заголовку
    ДО вызова zf.read(), плюс общий лимит на суммарный распакованный объём.
    """
    collected = []
    truncated = False
    patterns = _load_checkerignore()
    total_unpacked = 0

    for name in zf.namelist():
        if _should_skip_zip_entry(name, patterns):
            continue
        if len(collected) >= ZIP_MAX_FILES:
            truncated = True
            break

        try:
            info = zf.getinfo(name)
        except KeyError:
            continue

        if info.file_size > ZIP_MAX_FILE_SIZE:
            logger.warning(
                f"Пропущен {name}: распакованный размер "
                f"{info.file_size} байт > {ZIP_MAX_FILE_SIZE}"
            )
            continue

        total_unpacked += info.file_size
        if total_unpacked > ZIP_MAX_TOTAL_UNPACKED:
            logger.warning(
                f"Суммарный распакованный объём превышен: "
                f"{total_unpacked} > {ZIP_MAX_TOTAL_UNPACKED}"
            )
            truncated = True
            break

        try:
            raw = zf.read(name)
            content = raw.decode("utf-8", errors="replace")
        except Exception as e:
            logger.warning(f"Не удалось прочитать {name}: {e}")
            continue

        normalized = name.replace("\\", "/")
        collected.append((normalized, content, Path(name).suffix.lower()))

    return collected, truncated


async def _zip_analyze_one(name, content, ext):
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=ext, delete=False, encoding="utf-8",
            dir=str(TMP_DIR),
        ) as tf:
            tf.write(content)
            tmp_path = tf.name
        return await asyncio.to_thread(analyze, tmp_path)
    except Exception as e:
        logger.error(f"ZIP analyze failed for {name}: {e}")
        return [{"line": 1, "severity": "CRITICAL",
                 "message": f"Ошибка анализа: {e}",
                 "category": "other"}]
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError as e:
                logger.warning(f"Не удалось удалить {tmp_path}: {e}")


@app.post("/check-zip")
async def check_zip_endpoint(request: Request, file: UploadFile = File(...)):
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests")

    if file is None or not file.filename:
        return {"error": "Файл не передан"}

    try:
        data = await file.read()
    except Exception as e:
        return {"error": f"Не удалось прочитать файл: {e}"}

    if len(data) > ZIP_MAX_SIZE:
        return {"error": f"ZIP слишком большой ({len(data) // 1024} KB > 5 MB)"}

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return {"error": "Это не ZIP-архив"}

    try:
        files, truncated = _zip_collect_files(zf)
    finally:
        zf.close()

    results = []
    total_problems = 0
    for name, content, ext in files:
        problems = await _zip_analyze_one(name, content, ext)
        results.append({"file": name, "problems": problems})
        total_problems += len(problems)

    logger.info(f"ZIP analyzed: {file.filename} — files={len(files)}, problems={total_problems}")

    return {
        "results": results,
        "summary": {
            "total_files": len(files),
            "total_problems": total_problems,
            "truncated": truncated,
        },
    }


# ============ ЗАПУСК ============

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000, workers=1)
