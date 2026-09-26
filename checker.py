# -*- coding: utf-8 -*-
"""Code Checker v14.0 — Python + C++ + HTML + JS"""

import ast
import re
import sys
from pathlib import Path

MAX_FUNCTION_LINES = 50
MAX_LINE_LENGTH = 120

FSTRING_TYPES = (ast.JoinedStr,)
if hasattr(ast, "TemplateStr"):
    FSTRING_TYPES = FSTRING_TYPES + (ast.TemplateStr,)

SECRET_PATTERNS = [
    (r'(?i)(?:^|[_\W])(api[_-]?key|apikey)\s*[:=]\s*["\']([^"\']{10,})["\']', "API-ключ", 2),
    (r'(?i)(?:^|[_\W])(password|passwd|pwd|db_?pass|db_?password)\s*[:=]\s*["\']([^"\']{4,})["\']', "Пароль", 2),
    (r'(?i)(?:^|[_\W])(secret|token)\s*[:=]\s*["\']([^"\']{8,})["\']', "Секрет/токен", 2),
    (r'((?:sk|pk)[-_](?:proj[-_])?(?:test[-_]|live[-_])?[a-zA-Z0-9_\-]{20,})', "OpenAI/Stripe-ключ", 1),
    (r'(AIza[a-zA-Z0-9_\-]{30,})', "Google API-ключ", 1),
    (r'(?i)Bearer\s+([A-Za-z0-9\-_\.]{20,})', "Bearer-токен", 1),
    (r'(AKIA[0-9A-Z]{16})', "AWS Access Key", 1),
    (r'(gh[opusr]_[a-zA-Z0-9]{20,})', "GitHub-токен", 1),
    (r'(-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY-----)', "SSH/приватный ключ", 1),
    (r'(django-insecure-[a-zA-Z0-9_\-]+)', "Django SECRET_KEY", 1),
    (r'(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})', "JWT-токен", 1),
    (r'([a-z]+://[^:/\s]+:[^@/\s]+@[^\s"\']+)', "URL с паролем", 1),
    (r'(https://hooks\.slack\.com/services/[A-Z0-9/]+)', "Slack webhook", 1),
    # ФИКС v14.0: обобщённые префиксы популярных сервисов
    (r'(xox[baprs]-[a-zA-Z0-9\-]{10,})', "Slack-токен", 1),
    (r'(AC[a-f0-9]{32})', "Twilio SID", 1),
    (r'(SG\.[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,})', "SendGrid-ключ", 1),
    (r'(dop_v1_[a-f0-9]{64})', "DigitalOcean-токен", 1),
    (r'(npm_[a-zA-Z0-9]{36,})', "npm-токен", 1),
    (r'(hf_[a-zA-Z0-9]{30,})', "HuggingFace-токен", 1),
    (r'(pk\.eyJ[a-zA-Z0-9_\-]{20,})', "Mapbox-токен", 1),
    (r'(ya29\.[a-zA-Z0-9_\-]{20,})', "Google OAuth-токен", 1),
]

SECRET_FUNC_WORDS = ("password", "passwd", "pwd", "secret", "token", "api_key", "apikey")

# ФИКС v14.0: слова, указывающие на секрет в имени переменной (эвристика)
SECRET_VAR_WORDS = re.compile(
    r'(?i)(?:^|[_\W])(?:.*?(?:TOKEN|KEY|SECRET|PASS|SID|CREDENTIAL|AUTH|APIKEY).*?)(?:[_\W]|$)'
)

SAFE_VALUES = {
    "test", "tests", "dummy", "example", "sample", "fake",
    "changeme", "your_key_here", "xxx", "yyy", "placeholder",
    "", "none", "null",
}

PY_SQL_PATTERNS = [
    (r'\w*execute\w*\s*\(\s*f["\']', "SQL через f-строку"),
    (r'\w*execute\w*\s*\(\s*["\'][^"\']*["\']\s*\+', "SQL через конкатенацию"),
    (r'\w*execute\w*\s*\(\s*["\'][^"\']*["\']\s*%', "SQL через %-форматирование"),
]

PY_DANGEROUS_CALLS = {
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.head",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete",
    "httpx.patch", "httpx.head",
}

PY_DANGEROUS_SHELL = {
    "os.system", "os.popen",
    "subprocess.run", "subprocess.call", "subprocess.Popen",
}

PY_WEAK_CRYPTO = {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}

PY_PATH_PATTERNS = [
    (r'["\']C:\\\\[^"\']+["\']', "Хардкод пути Windows"),
    (r'["\']D:\\\\[^"\']+["\']', "Хардкод пути Windows"),
    (r'["\']E:\\\\[^"\']+["\']', "Хардкод пути Windows"),
    (r'["\']C:\\[^"\']+["\']', "Хардкод пути Windows"),
    (r'["\']D:\\[^"\']+["\']', "Хардкод пути Windows"),
    (r'["\']\\\\Users\\\\[^"\']+["\']', "Хардкод пути Windows"),
    (r'["\']/(?:etc|root|home)/[^"\']+["\']', "Хардкод Linux-пути"),
    (r'["\']/var/(?:log|www)/[^"\']+["\']', "Хардкод Linux-пути"),
]

PY_TODO_PATTERNS = [
    (r'#\s*TODO\b', "TODO"), (r'#\s*FIXME\b', "FIXME"),
    (r'#\s*XXX\b', "XXX"), (r'#\s*HACK\b', "HACK"),
]

CPP_SQL_PATTERNS = [
    (r'sprintf\s*\([^,]+,\s*"[^"]*%s[^"]*SELECT', "SQL через sprintf"),
    (r'sprintf\s*\([^,]+,\s*"[^"]*%s[^"]*(INSERT|UPDATE|DELETE)', "SQL через sprintf"),
]

CPP_DANGEROUS_FUNCS = {"system", "popen", "execl", "execlp", "execle", "execv", "execvp"}

CPP_UNSAFE_PATTERNS = [
    (r'\bgets\s*\(', "`gets()` — опасно (переполнение)"),
    (r'\bstrcpy\s*\(', "`strcpy()` — опасно (переполнение)"),
    (r'\bstrcat\s*\(', "`strcat()` — опасно (переполнение)"),
    (r'\bsprintf\s*\(', "`sprintf()` — опасно (переполнение)"),
    (r'\bscanf\s*\(', "`scanf()` — опасно (переполнение)"),
]

CPP_PATH_PATTERNS = [
    (r'"[A-Z]:\\\\[^"]*"', "Хардкод пути Windows"),
    (r'"[A-Z]:\\[^"]*"', "Хардкод пути Windows"),
    (r'"(?:/etc|/root|/home)/[^"]*"', "Хардкод Linux-пути"),
    (r'"/var/(?:log|www)/[^"]*"', "Хардкод Linux-пути"),
]

CPP_TODO_PATTERNS = [
    (r'//\s*TODO\b', "TODO"), (r'//\s*FIXME\b', "FIXME"),
    (r'//\s*XXX\b', "XXX"), (r'//\s*HACK\b', "HACK"),
]

CPP_STYLE_PATTERNS = [
    (r'\busing namespace std;', "`using namespace std;` — плохо", "MEDIUM"),
    (r'\bprintf\s*\(', "`printf` вместо `std::cout`", "LOW"),
    (r'\bNULL\b', "`NULL` вместо `nullptr`", "LOW"),
    (r'\bvoid\s+main\s*\(', "`void main()` — нужно `int main()`", "HIGH"),
]

HTML_PATTERNS = [
    (r'<iframe(?![^>]*sandbox)[^>]*>', "`<iframe>` без `sandbox`", "HIGH", re.IGNORECASE),
    (r'<marquee\b', "`<marquee>` — устаревший тег", "LOW", re.IGNORECASE),
    (r'<blink\b', "`<blink>` — устаревший тег", "LOW", re.IGNORECASE),
    (r'<font\b', "`<font>` — устаревший тег", "LOW", re.IGNORECASE),
    (r'<center\b', "`<center>` — устаревший тег", "LOW", re.IGNORECASE),
    (r'document\.write\s*\(', "`document.write()` — плохо", "MEDIUM", re.IGNORECASE),
    (r'(?<!outer)innerHTML\s*=', "`innerHTML` — XSS", "HIGH", re.IGNORECASE),
]

HTML_INLINE_EVAL_PATTERN = re.compile(
    r'\b(on\w+)\s*=\s*["\'][^"\']*eval\s*\(', re.IGNORECASE)

HTML_TODO_PATTERNS = [
    (r'<!--\s*TODO\b', "TODO"), (r'<!--\s*FIXME\b', "FIXME"),
    (r'<!--\s*XXX\b', "XXX"), (r'<!--\s*HACK\b', "HACK"),
]

JS_PATTERNS = [
    (r'\beval\s*\(', "`eval()` — опасно (RCE)", "CRITICAL"),
    (r'(?<!new\s)\bFunction\s*\(', "`Function()` — опасно (как eval)", "CRITICAL"),
    (r'\bnew\s+Function\s*\(', "`new Function()` — опасно", "CRITICAL"),
    (r'document\.write\s*\(', "`document.write()` — плохо", "MEDIUM"),
    (r'innerHTML\s*=', "`innerHTML` — XSS", "HIGH"),
    (r'outerHTML\s*=', "`outerHTML` — XSS", "HIGH"),
    (r'insertAdjacentHTML\s*\(', "`insertAdjacentHTML` — XSS", "HIGH"),
    (r'\bvar\s+\w+', "`var` вместо `let`/`const`", "LOW"),
    (r'console\.log\s*\(', "`console.log` в проде", "LOW"),
    (r'debugger\s*;', "`debugger` в коде", "MEDIUM"),
]

JS_TODO_PATTERNS = [
    (r'//\s*TODO\b', "TODO"), (r'//\s*FIXME\b', "FIXME"),
    (r'//\s*XXX\b', "XXX"), (r'//\s*HACK\b', "HACK"),
]


def _looks_like_python(source):
    head = source[:1000]
    markers = ["def ", "import ", "from ", "print(", "class ",
               "__name__", "self.", "elif ", "lambda ", "yield ",
               "with ", "try:", "except ", "finally:"]
    if any(m in head for m in markers):
        return True
    try:
        ast.parse(source)
        return True
    except (SyntaxError, RecursionError):
        return False


def _looks_like_cpp(source):
    head = source[:1000]
    markers = ["#include", "std::", "using namespace", "int main", "void main",
               "cout <<", "cin >>", "template<", "template <", "::", "->",
               "printf(", "scanf(", "new ", "delete ", "public:", "private:",
               "protected:", "namespace ", "nullptr", "bool "]
    return any(m in head for m in markers)


def _looks_like_html(source):
    head = source[:1000].lower()
    markers = ["<!doctype html", "<html", "<head", "<body", "<div",
               "<span", "<p>", "<p ", "<a ", "<script", "<style",
               "<meta", "<link", "<ul", "<ol", "<li", "<table",
               "<form", "<input", "<button", "<h1", "<h2", "<h3"]
    return any(m in head for m in markers)


def _looks_like_js(source):
    head = source[:1000]
    markers = ["function ", "var ", "=>", "console.log", "document.",
               "window.", "require(", "module.exports", "===", "!==",
               "alert(", "prompt(", "confirm(", "addEventListener",
               "querySelector", "getElementById", "JSON."]
    return any(m in head for m in markers)


def _get_language_hint(source):
    if _looks_like_cpp(source): return "C++"
    if _looks_like_html(source): return "HTML"
    if _looks_like_js(source): return "JavaScript"
    if _looks_like_python(source): return "Python"
    return "неизвестный язык"


def _get_call_name(node):
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts = []
        cur = node.func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _is_safe_value(value):
    if value is None: return True
    if value.lower() in SAFE_VALUES: return True
    if len(value) < 4: return True
    return False


def _is_random_looking(value):
    """ФИКС v14.0: похоже ли значение на случайный токен."""
    if len(value) < 20:
        return False
    if " " in value or "\t" in value:
        return False
    has_digit = any(c.isdigit() for c in value)
    has_letter = any(c.isalpha() for c in value)
    has_special = any(c in "-_./+=:" for c in value)
    return has_letter and (has_digit or has_special)


def _has_main_block(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            test = node.test
            if (isinstance(test, ast.Compare)
                    and isinstance(test.left, ast.Name)
                    and test.left.id == "__name__"
                    and len(test.comparators) == 1
                    and isinstance(test.comparators[0], ast.Constant)
                    and test.comparators[0].value == "__main__"):
                return True
    return False


def _is_test_file(filepath):
    if not filepath: return False
    name = Path(filepath).name.lower()
    return (name.startswith("test_") or name.endswith("_test.py") or
            name == "tests.py" or "test" in name.split(".")[0].lower().split("_"))


def _detect_language(source, filepath):
    ext = Path(filepath).suffix.lower()
    if ext in (".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"): return "cpp"
    if ext == ".py": return "python"
    if ext in (".html", ".htm"): return "html"
    if ext in (".js", ".mjs"): return "js"
    head = source[:500].lower()
    if "#include" in head or "std::" in head or "using namespace" in head:
        return "cpp"
    if "<!doctype html" in head or "<html" in head: return "html"
    if ("function " in head or "var " in head or "console.log" in head or
            "document." in head or "=>" in head):
        return "js"
    if "def " in head or "import " in head: return "python"
    return "unknown"


def _deduplicate(problems):
    seen = set()
    unique = []
    for p in problems:
        key = (p["line"], p["message"])
        if key not in seen:
            seen.add(key)
            unique.append(p)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    unique.sort(key=lambda p: (severity_order.get(p["severity"], 99), p["line"]))
    return unique


class PythonChecker(ast.NodeVisitor):
    def __init__(self, filepath=None):
        self.problems = []
        self.imports = []
        self.used_names = set()
        self.filepath = filepath
        self.is_test = _is_test_file(filepath)

    def add(self, line_no, severity, message):
        self.problems.append({"line": line_no, "severity": severity, "message": message})

    def visit_Try(self, node):
        for handler in node.handlers:
            if handler.type is None:
                self.add(handler.lineno, "CRITICAL",
                         "Голый `except:` — ловит ВСЁ. Укажи тип ошибки.")
        self.generic_visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            if node.args and not isinstance(node.args[0], ast.Constant):
                self.add(node.lineno, "CRITICAL",
                         f"`{node.func.id}()` на не-константе — опасно.")
        elif (isinstance(node.func, ast.Attribute)
              and node.func.attr in ("eval", "exec")
              and isinstance(node.func.value, ast.Name)
              and node.func.value.id == "builtins"):
            if node.args and not isinstance(node.args[0], ast.Constant):
                self.add(node.lineno, "CRITICAL",
                         f"`builtins.{node.func.attr}()` — опасно.")
        call_name = _get_call_name(node)
        if call_name in PY_DANGEROUS_SHELL:
            is_shell = False
            for kw in node.keywords:
                if kw.arg == "shell":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        is_shell = True
            if is_shell or call_name in ("os.system", "os.popen"):
                self.add(node.lineno, "CRITICAL",
                         f"`{call_name}` с shell — опасно (RCE).")
        if isinstance(node.func, ast.Name):
            self.used_names.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                self.used_names.add(node.func.value.id)
        self.generic_visit(node)

    def visit_Name(self, node):
        self.used_names.add(node.id)
        self.generic_visit(node)

    def visit_Subscript(self, node):
        if isinstance(node.value, ast.Name):
            self.used_names.add(node.value.id)
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if isinstance(node.value, ast.Name):
            self.used_names.add(node.value.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        for sub in ast.walk(node.annotation):
            if isinstance(sub, ast.Name):
                self.used_names.add(sub.id)
        self.generic_visit(node)

    def visit_arg(self, node):
        if node.annotation:
            for sub in ast.walk(node.annotation):
                if isinstance(sub, ast.Name):
                    self.used_names.add(sub.id)
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            self.imports.append((name, node.lineno))
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            name = alias.asname or alias.name
            self.imports.append((name, node.lineno))
            if alias.name == "*":
                self.add(node.lineno, "MEDIUM", "`from ... import *` — неясно.")
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self._check_len(node)
        self._check_global(node)
        self._check_return_secret(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self._check_len(node)
        self._check_global(node)
        self._check_return_secret(node)
        self.generic_visit(node)

    def _check_len(self, node):
        if hasattr(node, "end_lineno") and node.end_lineno:
            length = node.end_lineno - node.lineno
            if length > MAX_FUNCTION_LINES:
                self.add(node.lineno, "MEDIUM",
                         f"Функция `{node.name}` длиной {length} строк.")

    def _check_global(self, node):
        for child in ast.walk(node):
            if isinstance(child, ast.Global):
                self.add(child.lineno, "MEDIUM",
                         f"`global {', '.join(child.names)}` — избегай.")

    def _check_return_secret(self, node):
        name_lower = node.name.lower()
        if not any(w in name_lower for w in SECRET_FUNC_WORDS):
            return
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value is not None:
                val = child.value
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    if not _is_safe_value(val.value):
                        self.add(child.lineno, "CRITICAL",
                                 "Хардкод секрета в `return` — используй .env")

    def visit_Assert(self, node):
        if not self.is_test:
            self.add(node.lineno, "HIGH", "`assert` может быть отключён.")
        self.generic_visit(node)

    def visit_Lambda(self, node):
        body = node.body
        if isinstance(body, (ast.IfExp, ast.Compare, ast.BoolOp,
                              ast.ListComp, ast.DictComp, ast.SetComp)):
            self.add(node.lineno, "MEDIUM", "`lambda` со сложной логикой.")
        self.generic_visit(node)

    def visit_While(self, node):
        if isinstance(node.test, ast.Constant) and node.test.value is True:
            has_break = False
            for child in ast.walk(node):
                if isinstance(child, (ast.Break, ast.Return)):
                    has_break = True
                    break
            if not has_break:
                self.add(node.lineno, "MEDIUM", "`while True:` без `break`.")
        self.generic_visit(node)

    def visit_If(self, node):
        test = node.test
        if isinstance(test, ast.Compare):
            self._check_name(test, node)
            self._check_none(test, node)
            self._check_bool(test, node)
        self._check_empty_if(node)
        self.generic_visit(node)

    def _check_name(self, test, node):
        if not (test.ops and isinstance(test.ops[0], ast.Eq)): return
        if isinstance(test.left, ast.Name) and test.left.id == "__name__":
            for comp in test.comparators:
                if not (isinstance(comp, ast.Constant) and comp.value == "__main__"):
                    self.add(node.lineno, "HIGH", "`__name__` не с `__main__`.")

    def _check_none(self, test, node):
        if not test.ops: return
        if isinstance(test.ops[0], ast.Eq):
            for comp in test.comparators:
                if isinstance(comp, ast.Constant) and comp.value is None:
                    self.add(node.lineno, "HIGH", "`== None` — используй `is None`.")
        if isinstance(test.ops[0], ast.NotEq):
            for comp in test.comparators:
                if isinstance(comp, ast.Constant) and comp.value is None:
                    self.add(node.lineno, "HIGH", "`!= None` — используй `is not None`.")

    def _check_bool(self, test, node):
        if not test.ops: return
        if isinstance(test.ops[0], ast.Eq):
            for comp in test.comparators:
                if isinstance(comp, ast.Constant) and isinstance(comp.value, bool):
                    self.add(node.lineno, "HIGH",
                             f"`== {comp.value}` — используй `if x:`.")

    def _check_empty_if(self, node):
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self.add(node.lineno, "MEDIUM", "`pass` в `if` — пусто.")

    def visit_Compare(self, node):
        if (isinstance(node.left, ast.Call)
                and isinstance(node.left.func, ast.Name)
                and node.left.func.id == "type"):
            for op in node.ops:
                if isinstance(op, ast.Eq):
                    self.add(node.lineno, "HIGH",
                             "`type() ==` — используй `isinstance()`.")
        self.generic_visit(node)

    def visit_JoinedStr(self, node):
        has = False
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                has = True
                break
        if not has:
            self.add(node.lineno, "LOW", "f-string без переменных.")
        self.generic_visit(node)


def _py_secrets(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("#") or "# noqa" in line or "# nosec" in line:
            continue
        found_here = set()
        for pattern, name, gidx in SECRET_PATTERNS:
            m = re.search(pattern, line)
            if not m: continue
            if name in found_here: continue
            try:
                value = m.group(gidx) if gidx <= (m.lastindex or 0) else ""
            except IndexError:
                value = ""
            if gidx == 1:
                problems.append({"line": i, "severity": "CRITICAL",
                                 "message": f"Хардкод {name} — .env"})
                found_here.add(name)
            elif not _is_safe_value(value):
                problems.append({"line": i, "severity": "CRITICAL",
                                 "message": f"Хардкод {name} — .env"})
                found_here.add(name)
    return problems


def _py_heuristic_secrets(lines):
    """
    ФИКС v14.0: эвристика — если имя переменной содержит TOKEN/KEY/SECRET/PASS/SID/CRED/AUTH,
    а значение — длинная случайная строка (≥20 символов), ругаемся.
    Ловит ЛЮБОЙ новый сервис без отдельного паттерна.
    """
    problems = []
    pattern = re.compile(
        r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*["\']([^"\']{20,})["\']',
        re.MULTILINE
    )
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("#") or "# noqa" in line or "# nosec" in line:
            continue
        m = pattern.match(line)
        if not m:
            continue
        var_name = m.group(1)
        value = m.group(2)
        # имя переменной должно содержать секретное слово
        if not SECRET_VAR_WORDS.search(var_name):
            continue
        # значение должно выглядеть как случайный токен
        if not _is_random_looking(value):
            continue
        # не безопасное значение
        if _is_safe_value(value):
            continue
        problems.append({
            "line": i,
            "severity": "CRITICAL",
            "message": f"Похоже на хардкод секрета (`{var_name}`) — .env",
        })
    return problems


def _py_sql(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("#") or "# noqa" in line: continue
        for pattern, name in PY_SQL_PATTERNS:
            if re.search(pattern, line):
                problems.append({"line": i, "severity": "CRITICAL",
                                 "message": f"{name} — параметры запроса"})
                break
    return problems


def _sql_extract_text(node):
    try:
        return ast.unparse(node)
    except Exception:
        parts = []
        for sub in ast.walk(node):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                parts.append(sub.value)
        return "".join(parts)


def _collect_binop_text(node):
    parts = []
    def _visit(n):
        if isinstance(n, FSTRING_TYPES):
            parts.append(_sql_extract_text(n))
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            parts.append(n.value)
        elif isinstance(n, ast.BinOp):
            _visit(n.left)
            _visit(n.right)
    _visit(node)
    return "".join(parts)


def _sql_get_text_from_value(value):
    if isinstance(value, FSTRING_TYPES):
        return _sql_extract_text(value)
    if (isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "format"
            and isinstance(value.func.value, ast.Constant)):
        return value.func.value.value
    if isinstance(value, ast.BinOp):
        return _collect_binop_text(value)
    return None


class _SQLAstFinder(ast.NodeVisitor):
    def __init__(self):
        self.problems = []
        self.sql_vars_stack = [{}]

    @property
    def sql_vars(self):
        return self.sql_vars_stack[-1]

    def _push_scope(self):
        self.sql_vars_stack.append({})

    def _pop_scope(self):
        if len(self.sql_vars_stack) > 1:
            self.sql_vars_stack.pop()

    def visit_FunctionDef(self, node):
        self._push_scope()
        self.generic_visit(node)
        self._pop_scope()

    def visit_AsyncFunctionDef(self, node):
        self._push_scope()
        self.generic_visit(node)
        self._pop_scope()

    def visit_Assign(self, node):
        text = _sql_get_text_from_value(node.value)
        if text and isinstance(text, str):
            upper = text.upper()
            if any(kw in upper for kw in ("SELECT", "INSERT", "UPDATE", "DELETE")):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.sql_vars[target.id] = node.lineno
        self.generic_visit(node)

    def visit_Call(self, node):
        call_name = None
        if isinstance(node.func, ast.Name):
            call_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            call_name = node.func.attr
        is_execute = (call_name == "execute" or call_name == "executemany"
                      or (call_name and call_name.endswith("execute"))
                      or (call_name and call_name.endswith("executemany")))
        if is_execute and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Name) and arg.id in self.sql_vars:
                self.problems.append({
                    "line": node.lineno, "severity": "CRITICAL",
                    "message": f"SQL через f-строку/форматирование (переменная `{arg.id}`) — параметры запроса",
                })
            elif isinstance(arg, FSTRING_TYPES):
                text = _sql_extract_text(arg)
                if any(kw in text.upper() for kw in ("SELECT", "INSERT", "UPDATE", "DELETE")):
                    self.problems.append({
                        "line": node.lineno, "severity": "CRITICAL",
                        "message": "SQL через f-строку — параметры запроса",
                    })
        self.generic_visit(node)


def _py_sql_ast(tree):
    finder = _SQLAstFinder()
    finder.visit(tree)
    return finder.problems


def _py_long_lines(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_LENGTH:
            problems.append({"line": i, "severity": "LOW",
                             "message": f"Строка длиной {len(line)} (> {MAX_LINE_LENGTH})."})
    return problems


def _py_paths(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("#") or "# noqa" in line: continue
        for pattern, name in PY_PATH_PATTERNS:
            if re.search(pattern, line):
                problems.append({"line": i, "severity": "HIGH",
                                 "message": f"{name} — не работает на другом ПК"})
                break
    return problems


def _py_todo(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        for pattern, name in PY_TODO_PATTERNS:
            if re.search(pattern, line):
                problems.append({"line": i, "severity": "LOW",
                                 "message": f"Найден `{name}`."})
                break
    return problems


def _py_dangerous(tree):
    problems = []
    protected = set()
    class Collector(ast.NodeVisitor):
        def visit_Try(self, node):
            for child in node.body:
                for sub in ast.walk(child):
                    if hasattr(sub, "lineno"):
                        protected.add(sub.lineno)
            self.generic_visit(node)
    Collector().visit(tree)
    class Finder(ast.NodeVisitor):
        def visit_Call(self, node):
            name = _get_call_name(node)
            if name in PY_DANGEROUS_CALLS:
                if node.lineno not in protected:
                    problems.append({"line": node.lineno, "severity": "HIGH",
                                     "message": f"`{name}()` без try/except"})
            self.generic_visit(node)
    Finder().visit(tree)
    return problems


def _py_open_without_with(tree):
    problems = []
    with_lines = set()
    class Collector(ast.NodeVisitor):
        def visit_With(self, node):
            for item in node.items:
                if isinstance(item.context_expr, ast.Call):
                    name = _get_call_name(item.context_expr)
                    if name == "open":
                        with_lines.add(item.context_expr.lineno)
            self.generic_visit(node)
    Collector().visit(tree)
    class Finder(ast.NodeVisitor):
        def visit_Call(self, node):
            name = _get_call_name(node)
            if name == "open" and node.lineno not in with_lines:
                problems.append({"line": node.lineno, "severity": "MEDIUM",
                                 "message": "`open()` без `with` — файл может не закрыться"})
            self.generic_visit(node)
    Finder().visit(tree)
    return problems


def _py_weak_crypto(tree):
    problems = []
    class Finder(ast.NodeVisitor):
        def visit_Call(self, node):
            name = _get_call_name(node)
            if name in PY_WEAK_CRYPTO:
                problems.append({"line": node.lineno, "severity": "MEDIUM",
                                 "message": f"`{name}` — устаревший хеш, используй `sha256`+"})
            self.generic_visit(node)
    Finder().visit(tree)
    return problems


def _py_yaml(tree):
    problems = []
    class Finder(ast.NodeVisitor):
        def visit_Call(self, node):
            name = _get_call_name(node)
            if name == "yaml.load":
                safe = False
                for kw in node.keywords:
                    if kw.arg in ("Loader", "loader"):
                        if isinstance(kw.value, ast.Attribute):
                            if kw.value.attr == "SafeLoader":
                                safe = True
                        elif isinstance(kw.value, ast.Name):
                            if kw.value.id == "SafeLoader":
                                safe = True
                if not safe:
                    problems.append({"line": node.lineno, "severity": "HIGH",
                                     "message": "`yaml.load` без `safe_load` — небезопасно"})
            self.generic_visit(node)
    Finder().visit(tree)
    return problems


def _py_pickle(tree):
    problems = []
    class Finder(ast.NodeVisitor):
        def visit_Call(self, node):
            name = _get_call_name(node)
            if name in ("pickle.loads", "pickle.load"):
                problems.append({"line": node.lineno, "severity": "HIGH",
                                 "message": f"`{name}` — небезопасно, десериализует всё"})
            self.generic_visit(node)
    Finder().visit(tree)
    return problems


def _py_print(tree):
    problems = []
    if _has_main_block(tree): return problems
    class Finder(ast.NodeVisitor):
        def visit_Call(self, node):
            if isinstance(node.func, ast.Name) and node.func.id == "print":
                problems.append({"line": node.lineno, "severity": "LOW",
                                 "message": "`print()` вместо `logging`."})
            self.generic_visit(node)
    Finder().visit(tree)
    return problems


def _py_print_loop(tree):
    problems = []
    if _has_main_block(tree): return problems
    class Finder(ast.NodeVisitor):
        def _scan(self, node):
            for child in ast.walk(node):
                if (isinstance(child, ast.Call)
                        and isinstance(child.func, ast.Name)
                        and child.func.id == "print"):
                    problems.append({"line": child.lineno, "severity": "LOW",
                                     "message": "`print()` в цикле."})
                    break
        def visit_For(self, node):
            self._scan(node)
            self.generic_visit(node)
        def visit_While(self, node):
            self._scan(node)
            self.generic_visit(node)
    Finder().visit(tree)
    return problems


def _py_empty_except(tree):
    problems = []
    class Finder(ast.NodeVisitor):
        def visit_Try(self, node):
            for handler in node.handlers:
                body = handler.body
                if len(body) == 1 and isinstance(body[0], ast.Pass):
                    problems.append({"line": handler.lineno, "severity": "CRITICAL",
                                     "message": "Пустой `except: pass`."})
            self.generic_visit(node)
    Finder().visit(tree)
    return problems


def _py_unused_imports(checker):
    problems = []
    for name, line in checker.imports:
        if name not in checker.used_names and name != "*":
            problems.append({"line": line, "severity": "LOW",
                             "message": f"Импорт `{name}` не используется."})
    return problems


def analyze_python(source, filepath):
    if not _looks_like_python(source):
        hint = _get_language_hint(source)
        return [{"line": 1, "severity": "INFO",
                 "message": f"Код не похож на Python. Возможно, это {hint}. Проверьте выбранный язык."}]
    lines = source.splitlines()
    problems = []
    problems.extend(_py_secrets(lines))
    problems.extend(_py_heuristic_secrets(lines))
    problems.extend(_py_sql(lines))
    problems.extend(_py_long_lines(lines))
    problems.extend(_py_paths(lines))
    problems.extend(_py_todo(lines))
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return [{"line": e.lineno or 1, "severity": "CRITICAL",
                 "message": f"Синтаксическая ошибка: {e.msg}"}]
    except RecursionError:
        return [{"line": 1, "severity": "CRITICAL", "message": "Слишком сложный код."}]
    checker = PythonChecker(filepath)
    checker.visit(tree)
    problems.extend(checker.problems)
    problems.extend(_py_dangerous(tree))
    problems.extend(_py_open_without_with(tree))
    problems.extend(_py_weak_crypto(tree))
    problems.extend(_py_yaml(tree))
    problems.extend(_py_pickle(tree))
    problems.extend(_py_print(tree))
    problems.extend(_py_print_loop(tree))
    problems.extend(_py_empty_except(tree))
    problems.extend(_py_unused_imports(checker))
    problems.extend(_py_sql_ast(tree))
    return _deduplicate(problems)


def _cpp_find_string_end(line, start):
    i = start + 1
    n = len(line)
    while i < n:
        if line[i] == '\\' and i + 1 < n:
            i += 2
            continue
        if line[i] == '"':
            return i + 1
        i += 1
    return n


def _cpp_find_char_end(line, start):
    i = start + 1
    n = len(line)
    while i < n:
        if line[i] == '\\' and i + 1 < n:
            i += 2
            continue
        if line[i] == "'":
            return i + 1
        i += 1
    return n


def _strip_cpp_for_braces(line, in_block_comment):
    result = []
    i = 0
    n = len(line)
    while i < n:
        if in_block_comment:
            end = line.find("*/", i)
            if end == -1:
                return "".join(result), True
            i = end + 2
            in_block_comment = False
            continue
        if line.startswith("/*", i):
            in_block_comment = True
            i += 2
            continue
        if line.startswith("//", i):
            break
        if line[i] == '"':
            result.append('"')
            i = _cpp_find_string_end(line, i)
            result.append('"')
            continue
        if line[i] == "'":
            result.append("'")
            i = _cpp_find_char_end(line, i)
            result.append("'")
            continue
        result.append(line[i])
        i += 1
    return "".join(result), in_block_comment


def _cpp_secrets(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("//") or "// noqa" in line: continue
        found_here = set()
        for pattern, name, gidx in SECRET_PATTERNS:
            m = re.search(pattern, line)
            if not m: continue
            if name in found_here: continue
            try:
                value = m.group(gidx) if gidx <= (m.lastindex or 0) else ""
            except IndexError:
                value = ""
            if gidx == 1:
                problems.append({"line": i, "severity": "CRITICAL",
                                 "message": f"Хардкод {name} — .env"})
                found_here.add(name)
            elif not _is_safe_value(value):
                problems.append({"line": i, "severity": "CRITICAL",
                                 "message": f"Хардкод {name} — .env"})
                found_here.add(name)
    return problems


def _cpp_sql(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("//") or "// noqa" in line: continue
        for pattern, name in CPP_SQL_PATTERNS:
            if re.search(pattern, line):
                problems.append({"line": i, "severity": "CRITICAL",
                                 "message": f"{name} — параметры запроса"})
                break
    return problems


def _cpp_dangerous(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("//") or "// noqa" in line: continue
        for func in CPP_DANGEROUS_FUNCS:
            if re.search(r'\b' + re.escape(func) + r'\s*\(', line):
                problems.append({"line": i, "severity": "CRITICAL",
                                 "message": f"`{func}()` — опасно."})
                break
    return problems


def _cpp_unsafe(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("//") or "// noqa" in line: continue
        for pattern, name in CPP_UNSAFE_PATTERNS:
            if re.search(pattern, line):
                problems.append({"line": i, "severity": "HIGH", "message": name})
                break
    return problems


def _cpp_paths(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("//") or "// noqa" in line: continue
        for pattern, name in CPP_PATH_PATTERNS:
            if re.search(pattern, line):
                problems.append({"line": i, "severity": "HIGH",
                                 "message": f"{name} — не работает на другом ПК"})
                break
    return problems


def _cpp_todo(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        for pattern, name in CPP_TODO_PATTERNS:
            if re.search(pattern, line):
                problems.append({"line": i, "severity": "LOW",
                                 "message": f"Найден `{name}`."})
                break
    return problems


def _cpp_style(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("//") or "// noqa" in line: continue
        for pattern, name, severity in CPP_STYLE_PATTERNS:
            if re.search(pattern, line):
                problems.append({"line": i, "severity": severity, "message": name})
                break
    return problems


def _cpp_leaks(lines):
    problems = []
    smart_markers = ("unique_ptr", "shared_ptr", "make_unique",
                     "make_shared", "weak_ptr", "auto_ptr")
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("//") or "// noqa" in line: continue
        if any(marker in line for marker in smart_markers): continue
        if re.search(r'\bnew\s+\w+', line) and "delete" not in line:
            problems.append({"line": i, "severity": "MEDIUM",
                             "message": "`new` без `delete` — утечка."})
    return problems


def _cpp_long_lines(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_LENGTH:
            problems.append({"line": i, "severity": "LOW",
                             "message": f"Строка длиной {len(line)} (> {MAX_LINE_LENGTH})."})
    return problems


def _cpp_long_functions(lines):
    problems = []
    in_func = False
    func_start = 0
    func_name = ""
    brace_count = 0
    in_block_comment = False
    keywords = {"if", "for", "while", "switch", "catch", "else"}
    for i, line in enumerate(lines, start=1):
        clean, in_block_comment = _strip_cpp_for_braces(line, in_block_comment)
        if not in_func:
            m = re.search(r'\b(\w+)\s*\([^)]*\)\s*\{', clean)
            if m:
                kw = m.group(1)
                if kw not in keywords:
                    in_func = True
                    func_start = i
                    func_name = kw
                    brace_count = clean.count("{") - clean.count("}")
                    continue
        if in_func:
            brace_count += clean.count("{") - clean.count("}")
            if brace_count <= 0:
                length = i - func_start
                if length > MAX_FUNCTION_LINES:
                    problems.append({"line": func_start, "severity": "MEDIUM",
                                     "message": f"Функция `{func_name}` длиной {length} строк."})
                in_func = False
    return problems


def analyze_cpp(source, filepath):
    if not _looks_like_cpp(source):
        hint = _get_language_hint(source)
        return [{"line": 1, "severity": "INFO",
                 "message": f"Код не похож на C++. Возможно, это {hint}. Проверьте выбранный язык."}]
    lines = source.splitlines()
    problems = []
    problems.extend(_cpp_secrets(lines))
    problems.extend(_cpp_sql(lines))
    problems.extend(_cpp_dangerous(lines))
    problems.extend(_cpp_unsafe(lines))
    problems.extend(_cpp_paths(lines))
    problems.extend(_cpp_todo(lines))
    problems.extend(_cpp_style(lines))
    problems.extend(_cpp_leaks(lines))
    problems.extend(_cpp_long_lines(lines))
    problems.extend(_cpp_long_functions(lines))
    return _deduplicate(problems)


def _html_check(source):
    problems = []
    for pattern, name, severity, flags in HTML_PATTERNS:
        for m in re.finditer(pattern, source, flags):
            line_no = source[:m.start()].count("\n") + 1
            problems.append({"line": line_no, "severity": severity, "message": name})
    return problems


def _html_inline_eval(source):
    problems = []
    for m in HTML_INLINE_EVAL_PATTERN.finditer(source):
        attr = m.group(1)
        line_no = source[:m.start()].count("\n") + 1
        problems.append({"line": line_no, "severity": "CRITICAL",
                         "message": f"`{attr}=\"eval()\"` — XSS"})
    return problems


def _html_todo(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        for pattern, name in HTML_TODO_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                problems.append({"line": i, "severity": "LOW",
                                 "message": f"Найден `{name}`."})
                break
    return problems


def _html_scripts_js(source):
    problems = []
    pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL)
    for m in pattern.finditer(source):
        body = m.group(1)
        if not body.strip(): continue
        start_offset = m.start(1)
        start_line = source[:start_offset].count("\n") + 1
        for pattern_js, name, severity in JS_PATTERNS:
            for mm in re.finditer(pattern_js, body):
                inner_line = body[:mm.start()].count("\n")
                line_no = start_line + inner_line
                problems.append({"line": line_no, "severity": severity, "message": name})
    return problems


def _html_secrets(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("<!--") or "<!-- noqa" in line: continue
        found_here = set()
        for pattern, name, gidx in SECRET_PATTERNS:
            m = re.search(pattern, line)
            if not m: continue
            if name in found_here: continue
            try:
                value = m.group(gidx) if gidx <= (m.lastindex or 0) else ""
            except IndexError:
                value = ""
            if gidx == 1:
                problems.append({"line": i, "severity": "CRITICAL",
                                 "message": f"Хардкод {name} — .env"})
                found_here.add(name)
            elif not _is_safe_value(value):
                problems.append({"line": i, "severity": "CRITICAL",
                                 "message": f"Хардкод {name} — .env"})
                found_here.add(name)
    return problems


def _html_long_lines(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_LENGTH:
            problems.append({"line": i, "severity": "LOW",
                             "message": f"Строка длиной {len(line)} (> {MAX_LINE_LENGTH})."})
    return problems


def analyze_html(source, filepath):
    if not _looks_like_html(source):
        hint = _get_language_hint(source)
        return [{"line": 1, "severity": "INFO",
                 "message": f"Код не похож на HTML. Возможно, это {hint}. Проверьте выбранный язык."}]
    lines = source.splitlines()
    problems = []
    problems.extend(_html_check(source))
    problems.extend(_html_inline_eval(source))
    problems.extend(_html_scripts_js(source))
    problems.extend(_html_todo(lines))
    problems.extend(_html_secrets(lines))
    problems.extend(_html_long_lines(lines))
    return _deduplicate(problems)


def _js_check(source):
    problems = []
    for pattern, name, severity in JS_PATTERNS:
        for m in re.finditer(pattern, source):
            line_no = source[:m.start()].count("\n") + 1
            problems.append({"line": line_no, "severity": severity, "message": name})
    return problems


def _js_secrets(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("//") or "// noqa" in line: continue
        found_here = set()
        for pattern, name, gidx in SECRET_PATTERNS:
            m = re.search(pattern, line)
            if not m: continue
            if name in found_here: continue
            try:
                value = m.group(gidx) if gidx <= (m.lastindex or 0) else ""
            except IndexError:
                value = ""
            if gidx == 1:
                problems.append({"line": i, "severity": "CRITICAL",
                                 "message": f"Хардкод {name} — .env"})
                found_here.add(name)
            elif not _is_safe_value(value):
                problems.append({"line": i, "severity": "CRITICAL",
                                 "message": f"Хардкод {name} — .env"})
                found_here.add(name)
    return problems


def _js_todo(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        for pattern, name in JS_TODO_PATTERNS:
            if re.search(pattern, line):
                problems.append({"line": i, "severity": "LOW",
                                 "message": f"Найден `{name}`."})
                break
    return problems


def _js_long_lines(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_LENGTH:
            problems.append({"line": i, "severity": "LOW",
                             "message": f"Строка длиной {len(line)} (> {MAX_LINE_LENGTH})."})
    return problems


def analyze_js(source, filepath):
    if not _looks_like_js(source):
        hint = _get_language_hint(source)
        return [{"line": 1, "severity": "INFO",
                 "message": f"Код не похож на JavaScript. Возможно, это {hint}. Проверьте выбранный язык."}]
    lines = source.splitlines()
    problems = []
    problems.extend(_js_check(source))
    problems.extend(_js_secrets(lines))
    problems.extend(_js_todo(lines))
    problems.extend(_js_long_lines(lines))
    return _deduplicate(problems)


def analyze(filepath):
    path = Path(filepath)
    if not path.exists():
        return [{"line": 1, "severity": "CRITICAL",
                 "message": f"Файл не найден: {filepath}"}]
    try:
        try:
            source = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            source = path.read_text(encoding="cp1251")
    except Exception as e:
        return [{"line": 1, "severity": "CRITICAL",
                 "message": f"Не удалось прочитать: {e}"}]
    lang = _detect_language(source, filepath)
    if lang == "python": return analyze_python(source, filepath)
    elif lang == "cpp": return analyze_cpp(source, filepath)
    elif lang == "html": return analyze_html(source, filepath)
    elif lang == "js": return analyze_js(source, filepath)
    else:
        return [{"line": 1, "severity": "INFO",
                 "message": "Поддерживаются: Python, C++, HTML, JavaScript"}]


def print_report(filepath, problems):
    print(f"\n{'=' * 60}")
    print(f"Анализ файла: {filepath}")
    print(f"{'=' * 60}\n")
    if not problems:
        print("✅ Критичных проблем не найдено. Молодец!")
        print(f"\n{'=' * 60}\n")
        return
    print(f"Найдено проблем: {len(problems)}\n")
    for p in problems:
        marker = {"CRITICAL": "🔴", "HIGH": "🟡", "MEDIUM": "🟠",
                  "LOW": "⚪", "INFO": "ℹ️"}.get(p["severity"], "•")
        print(f"{marker} Строка {p['line']}: {p['message']}")
    print(f"\n{'=' * 60}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: python checker.py <файл>")
        sys.exit(1)
    filepath = sys.argv[1]
    problems = analyze(filepath)
    print_report(filepath, problems)
