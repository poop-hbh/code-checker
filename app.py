# -*- coding: utf-8 -*-
"""
Веб-версия Code Checker v16.10. Python + C++ + HTML + JavaScript + Go.
Запуск: python app.py
Открыть: http://127.0.0.1:8000
"""

import asyncio
import os
import io
import zipfile
import logging
import tempfile
import uvicorn

from pathlib import Path
from fastapi import FastAPI, Request, HTTPException, UploadFile, File
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

from fastapi.staticfiles import StaticFiles
app.mount("/static", StaticFiles(directory="static"), name="static")

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
    code: str = Field(..., min_length=1, max_length=100000)
    filename: str = Field(default="code.py", max_length=200)


HTML_PAGE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Code Checker — Python + C++ + HTML + JS + Go</title>
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
        .disclaimer .warn {
            color: #e67e22;
            font-weight: 600;
            margin-top: 10px;
        }
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
        .panel h2 {
            font-size: 16px;
            margin-bottom: 12px;
            color: var(--text-mid);
        }
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
        .drop-zone {
            position: relative;
            margin-bottom: 12px;
        }
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
        .file-name {
            color: #7fe0a0;
            font-size: 12px;
            margin-top: 4px;
            font-style: italic;
        }
        .btn-row {
            display: flex;
            gap: 8px;
            margin-top: 12px;
            flex-wrap: wrap;
        }
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
        button.upload-btn {
            background: #2a1f3a;
            color: #d0a0ff;
            border-color: #4a2a5a;
        }
        button.upload-btn:hover { background: #4a2a5a; color: #fff; }
        button.zip-btn {
            background: #3a2a1a;
            color: #ffa94d;
            border-color: #5a3a1a;
        }
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
        .no-problems b {
            color: #66ccff;
            font-weight: 700;
        }
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
        .history-empty {
            color: var(--text-dim);
            text-align: center;
            padding: 20px;
        }
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
</head>
<body>
    <header>
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
        <p>Этот помощник — <b>статический анализатор кода</b>. Ищет типовые проблемы по паттернам и эвристике. Работает локально, код никуда не уходит.</p>

        <p><b>Что находит:</b></p>
        <ul>
            <li>Хардкод секретов — пароли, API-ключи, токены (Stripe, AWS, GitHub, OpenAI, JWT и др.)</li>
            <li>SQL-инъекции — f-строки, конкатенация, %-формат, <code>fmt.Sprintf</code> в Go</li>
            <li>Shell-инъекции — os.system, subprocess, <code>exec.Command("sh", "-c", ...)</code></li>
            <li>XSS — eval, innerHTML, outerHTML, document.write, inline-обработчики</li>
            <li>Опасные функции — eval, exec, pickle.load, yaml.load без SafeLoader, XXE</li>
            <li>HTTP без timeout — <code>http.Get</code>, <code>http.Post</code> в Go</li>
            <li>Устаревшие хеши — md5, sha1</li>
            <li>Хардкод путей — Windows и Linux</li>
            <li>Стилевые проблемы — длинные функции, TODO/FIXME, global, lambda, panic()</li>
            <li>Эвристика по имени переменной — если имя содержит TOKEN/KEY/SECRET/PASS</li>
        </ul>

        <p><b>Что НЕ находит:</b></p>
        <ul>
            <li>Логические ошибки — гонки, deadlock, неверные условия</li>
            <li>Сложные утечки памяти</li>
            <li>Архитектурные проблемы и проблемы между файлами</li>
            <li>Обфускацию (chr/ord, цепочки base64 → exec)</li>
            <li>Подмену builtins через setattr, метаклассы, рефлексию</li>
            <li>Целенаправленный обход правил</li>
        </ul>

        <p><b>Как пользоваться:</b></p>
        <ul>
            <li><b>📁 Файл</b> — выбрать файл на компьютере. Язык определится по расширению. Файл больше 100 000 символов — обрежется.</li>
            <li><b>📦 ZIP</b> — загрузить <code>.zip</code>, проверить весь проект. Пропускает <code>node_modules/</code>, <code>.git/</code>, <code>__pycache__/</code>, скрытые папки. Лимиты: 5 МБ, 100 файлов.</li>
            <li><b>Drag &amp; drop</b> — перетащи файл в поле ввода.</li>
            <li><b>Проверить</b> — запускает анализ. <code>Ctrl+Enter</code> — то же самое.</li>
            <li><b>🗑 Очистить</b> — сброс. <code>Ctrl+L</code>.</li>
            <li><b>📜 История</b> — последние 10 проверок.</li>
            <li><b>📋 Копировать</b> / <b>📥 TXT</b> / <b>📋 JSON</b> — экспорт отчёта.</li>
            <li><b>Клик на проблему</b> — скопировать одну строку.</li>
            <li><b>🔍 Поиск</b> + <b>фильтры</b> — по severity и категориям.</li>
            <li><b>Esc</b> — закрыть окно истории.</li>
        </ul>

        <p class="warn">💡 0 проблем ≠ идеальный код. Помощник — это первый фильтр, а не замена ревью и аудиту. Всегда проверяй код вручную.</p>
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
                <button class="zip-btn" id="uploadZip" onclick="document.getElementById('zipInput').click()" title="Загрузить ZIP-архив">📦 ZIP</button>
                <button class="clear-btn" id="clear" onclick="clearAll()" title="Ctrl+L">🗑 Очистить</button>
                <button class="clear-btn" id="history" onclick="openHistory()" title="История проверок">📜 История</button>
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
            'other': '📌 Прочее'
        };
        var CATEGORY_ORDER = [
            'secrets', 'sql', 'shell', 'dangerous_calls', 'deserialization',
            'crypto', 'error_handling', 'assert', 'files', 'network',
            'paths', 'comparisons', 'style', 'notes', 'imports',
            'logging', 'fstrings', 'line_length', 'memory', 'xss', 'other'
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
            if (head.indexOf('def ') !== -1 || head.indexOf('print(') !== -1) {
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
            'py': 'Python',
            'cpp': 'C++',
            'html': 'HTML',
            'js': 'JavaScript',
            'go': 'Go'
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
                    'Это <b>не значит</b>, что код идеален. Помощник проверяет <b>60+ типовых</b> проблем ' +
                    'по паттернам и эвристике. Он <b>не заменяет</b> ревью человеком и аудит. ' +
                    'Проверь код вручную — особенно логику, архитектуру и работу с данными.' +
                    '</div>';
                copyBtn.disabled = true;
                downloadBtn.disabled = true;
                jsonBtn.disabled = true;
                return;
            }

            var onlyInfo = true;
            for (var i = 0; i < data.problems.length; i++) {
                if (data.problems[i].severity !== 'INFO') {
                    onlyInfo = false;
                    break;
                }
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
                    escapeHtml(currentSearchQuery) + '" oninput="setSearchQuery(this.value)">';
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
                        var itemJson = encodeURIComponent(JSON.stringify(item));

                        html += '<div class="' + cls2 + '" onclick="copyOneProblem(this, \\'' + itemJson + '\\')" title="Клик — копировать">';
                        html += '<div class="line">' + marker + ' Строка ' + item.line + '</div>';
                        html += '<div class="msg">' + escapeHtml(item.message) + '</div>';
                        html += '</div>';
                    }
                }
            }
            container.innerHTML = html;
        }

        function copyOneProblem(el, encoded) {
            try {
                var item = JSON.parse(decodeURIComponent(encoded));
                var text = SEVERITY_MARKERS[item.severity] + ' Строка ' + item.line + ': ' + item.message;
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(text).then(function() {
                        el.classList.add('copied');
                        setTimeout(function() { el.classList.remove('copied'); }, 600);
                        showToast('📋 Скопировано');
                    }).catch(function() {
                        fallbackCopy(text);
                        el.classList.add('copied');
                        setTimeout(function() { el.classList.remove('copied'); }, 600);
                    });
                } else {
                    fallbackCopy(text);
                    el.classList.add('copied');
                    setTimeout(function() { el.classList.remove('copied'); }, 600);
                    showToast('📋 Скопировано');
                }
            } catch (e) {
                showToast('❌ Не удалось', '#a02020');
            }
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
                codeEl.value = code;
                updateCodeInfo();
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
            if (navigator.clipboard && navigator.clipboard.writeText) {
                try {
                    await navigator.clipboard.writeText(text);
                    copyBtn.textContent = '✅ Скопировано!';
                    copyBtn.classList.add('copied');
                    setTimeout(function() {
                        copyBtn.textContent = '📋 Копировать';
                        copyBtn.classList.remove('copied');
                    }, 2000);
                    showToast('📋 Отчёт скопирован');
                    return;
                } catch (e) {}
            }
            fallbackCopy(text);
            showToast('📋 Отчёт скопирован');
        }

        function downloadReport() {
            var text = buildReportText();
            if (!text) return;
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
            var counts = { 'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0 };
            for (var i = 0; i < lastProblems.length; i++) {
                var sev = lastProblems[i].severity;
                if (counts.hasOwnProperty(sev)) counts[sev]++;
            }
            var report = {
                tool: 'Code Checker',
                version: 'v16.10',
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

        function escapeHtml(text) {
            var div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        document.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                e.preventDefault();
                checkCode();
            }
            if ((e.ctrlKey || e.metaKey) && (e.key === 'l' || e.key === 'L' || e.key === 'д' || e.key === 'Д')) {
                e.preventDefault();
                clearAll();
            }
            if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.key === 'S' || e.key === 'ы' || e.key === 'Ы')) {
                e.preventDefault();
                if (!downloadBtn.disabled) downloadReport();
            }
            if (e.key === 'Escape') {
                closeHistory();
            }
        });

        checkBtn.addEventListener('click', checkCode);
        updateCodeInfo();
    </script>
</body>
</html>
"""


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
        "python": ".py",
        "cpp": ".cpp",
        "html": ".html",
        "js": ".js",
        "go": ".go",
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


# ============ ZIP-АНАЛИЗ ============

ZIP_MAX_SIZE = 5 * 1024 * 1024
ZIP_MAX_FILES = 100
ZIP_MAX_FILE_SIZE = 100000

ZIP_SKIP_DIRS = {
    "node_modules", "__pycache__", ".git", ".venv", "venv", "env",
    "dist", "build", ".idea", ".vscode", "target", "bin", "obj",
    ".next", ".nuxt", ".pytest_cache", ".mypy_cache", "coverage",
}

ZIP_ALLOWED_EXTS = {
    ".py", ".cpp", ".cc", ".cxx", ".c", ".h", ".hpp",
    ".html", ".htm", ".js", ".mjs", ".go",
}


def _zip_collect_files(zf):
    collected = []
    truncated = False
    for name in zf.namelist():
        if name.endswith("/"):
            continue
        normalized = name.replace("\\", "/")
        parts = normalized.split("/")
        if any(p.startswith(".") or p in ZIP_SKIP_DIRS for p in parts):
            continue
        ext = Path(name).suffix.lower()
        if ext not in ZIP_ALLOWED_EXTS:
            continue
        if len(collected) >= ZIP_MAX_FILES:
            truncated = True
            break
        try:
            raw = zf.read(name)
            content = raw.decode("utf-8", errors="replace")
        except Exception as e:
            logger.warning(f"Не удалось прочитать {name}: {e}")
            continue
        if len(content) > ZIP_MAX_FILE_SIZE:
            content = content[:ZIP_MAX_FILE_SIZE]
        collected.append((normalized, content, ext))
    return collected, truncated


async def _zip_analyze_one(name, content, ext):
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=ext, delete=False, encoding="utf-8"
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
    uvicorn.run(app, host="127.0.0.1", port=8000)
