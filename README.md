<p align="center">
  <img src="cc_logo.svg" alt="Code Checker" width="200"/>
</p>

<h1 align="center">🔍 Code Checker</h1>
<p align="center">Анализатор кода: Python + C++ + HTML + JavaScript + Go</p>

---

## Что это

Code Checker — статический анализатор кода с 60+ проверками. Работает локально, код никуда не уходит.

## Что находит

- Хардкод секретов — пароли, API-ключи, токены (Stripe, AWS, GitHub, OpenAI, JWT и др.)
- SQL-инъекции — f-строки, конкатенация, %-формат, `fmt.Sprintf` в Go
- Shell-инъекции — `os.system`, `subprocess`, `exec.Command("sh", "-c", ...)`
- XSS — `eval`, `innerHTML`, `outerHTML`, `document.write`
- Опасные функции — `eval`, `exec`, `pickle.load`, `yaml.load` без `SafeLoader`, XXE
- HTTP без timeout — `http.Get`, `http.Post` в Go
- Устаревшие хеши — md5, sha1
- Хардкод путей — Windows и Linux
- Стилевые проблемы — длинные функции, TODO/FIXME, `global`, lambda, `panic()`

## Поддерживаемые языки

Python · C++ · HTML · JavaScript · Go

## Установка

```bash
pip install -r requirements.txt
python app.py
