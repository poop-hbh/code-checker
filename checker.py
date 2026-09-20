# -*- coding: utf-8 -*-
"""
Анализатор кода. Ищет 5 критичных проблем.
Запуск: python checker.py <файл.py>
"""

import ast
import re
import sys
from pathlib import Path


# ============ КОНСТАНТЫ ============

SECRET_PATTERNS = [
    # (паттерн, имя, номер_группы_со_значением)
    (r'(?i)\b(api[_-]?key|apikey)\s*[:=]\s*["\']([^"\']{10,})["\']', "API-ключ", 2),
    (r'(?i)\b(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']', "Пароль", 2),
    (r'(?i)\b(secret|token)\s*[:=]\s*["\']([^"\']{8,})["\']', "Секрет/токен", 2),
    (r'(sk-[a-zA-Z0-9]{20,})', "OpenAI-подобный ключ", 1),
    (r'(AIza[a-zA-Z0-9_\-]{30,})', "Google API-ключ", 1),
]

SAFE_VALUES = {
    "test", "tests", "dummy", "example", "sample", "fake",
    "changeme", "your_key_here", "xxx", "yyy", "placeholder",
    "", "none", "null",
}

SQL_PATTERNS = [
    (r'execute\s*\(\s*f["\']', "SQL через f-строку"),
    (r'execute\s*\(\s*["\'][^"\']*["\']\s*\+', "SQL через конкатенацию"),
    (r'execute\s*\(\s*["\'][^"\']*["\']\s*%', "SQL через %-форматирование"),
]

DANGEROUS_CALLS = {
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.head",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete",
    "httpx.patch", "httpx.head",
    "open",
}


# ============ AST-АНАЛИЗ ============

class CodeChecker(ast.NodeVisitor):
    def __init__(self):
        self.problems = []

    def add(self, line_no: int, severity: str, message: str):
        self.problems.append({
            "line": line_no,
            "severity": severity,
            "message": message,
        })

    def visit_Try(self, node: ast.Try):
        for handler in node.handlers:
            if handler.type is None:
                self.add(
                    handler.lineno,
                    "CRITICAL",
                    "Голый `except:` — ловит ВСЁ. Укажи тип ошибки.",
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            if node.args and not isinstance(node.args[0], ast.Constant):
                self.add(
                    node.lineno,
                    "CRITICAL",
                    f"`{node.func.id}()` на не-константе — опасно.",
                )
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in ("eval", "exec")
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "builtins"
        ):
            if node.args and not isinstance(node.args[0], ast.Constant):
                self.add(
                    node.lineno,
                    "CRITICAL",
                    f"`builtins.{node.func.attr}()` на не-константе — опасно.",
                )
        self.generic_visit(node)


# ============ ПРОВЕРКА СЕКРЕТОВ (БАГ 1 и 2 ИСПРАВЛЕНЫ) ============

def _is_safe_value(value: str) -> bool:
    if value is None:
        return True
    if value.lower() in SAFE_VALUES:
        return True
    if len(value) < 4:
        return True
    return False


def check_secrets(lines: list) -> list:
    problems = []
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "# noqa" in line or "# nosec" in line:
            continue

        for pattern, name, group_idx in SECRET_PATTERNS:
            match = re.search(pattern, line)
            if match:
                try:
                    value = (
                        match.group(group_idx)
                        if group_idx <= (match.lastindex or 0)
                        else ""
                    )
                except IndexError:
                    value = ""

                # Одно-групповые паттерны (sk-, AIza) — сразу добавляем
                if group_idx == 1:
                    problems.append({
                        "line": i,
                        "severity": "CRITICAL",
                        "message": f"Хардкод {name} в коде — вынеси в .env",
                    })
                    break

                # Двух-групповые — проверяем значение
                if not _is_safe_value(value):
                    problems.append({
                        "line": i,
                        "severity": "CRITICAL",
                        "message": f"Хардкод {name} в коде — вынеси в .env",
                    })
                    break
    return problems


# ============ ПРОВЕРКА SQL ============

def check_sql(lines: list) -> list:
    problems = []
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "# noqa" in line or "# nosec" in line:
            continue

        for pattern, name in SQL_PATTERNS:
            if re.search(pattern, line):
                problems.append({
                    "line": i,
                    "severity": "CRITICAL",
                    "message": f"{name} — используй параметры запроса",
                })
                break
    return problems


# ============ ОПАСНЫЕ ВЫЗОВЫ (БАГ 3 ИСПРАВЛЕН) ============

def _get_call_name(node: ast.Call) -> str | None:
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


def check_dangerous_without_try(tree: ast.AST) -> list:
    problems = []
    protected_lines = set()
    with_lines = set()

    class Collector(ast.NodeVisitor):
        def visit_Try(self, node: ast.Try):
            for child in node.body:
                for sub in ast.walk(child):
                    if hasattr(sub, "lineno"):
                        protected_lines.add(sub.lineno)
            self.generic_visit(node)

        def visit_With(self, node: ast.With):
            # Собираем ВСЕ строки внутри with (включая вложенные)
            for child in ast.walk(node):
                if hasattr(child, "lineno"):
                    with_lines.add(child.lineno)
            self.generic_visit(node)

    Collector().visit(tree)

    class Finder(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call):
            func_name = _get_call_name(node)
            if func_name in DANGEROUS_CALLS:
                # open() внутри with — не ругаем
                if func_name == "open" and node.lineno in with_lines:
                    self.generic_visit(node)
                    return
                if node.lineno not in protected_lines:
                    problems.append({
                        "line": node.lineno,
                        "severity": "HIGH",
                        "message": f"`{func_name}()` без try/except — может упасть",
                    })
            self.generic_visit(node)

    Finder().visit(tree)
    return problems


# ============ ГЛАВНАЯ (БАГ 4 ИСПРАВЛЕН) ============

def analyze(filepath: str) -> list:
    path = Path(filepath)
    if not path.exists():
        print(f"Файл не найден: {filepath}")
        sys.exit(1)

    try:
        source = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        print(f"Не удалось прочитать файл (не UTF-8): {filepath}")
        sys.exit(1)

    lines = source.splitlines()
    all_problems = []

    all_problems.extend(check_secrets(lines))
    all_problems.extend(check_sql(lines))

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"Синтаксическая ошибка в коде: {e}")
        sys.exit(1)

    checker = CodeChecker()
    checker.visit(tree)
    all_problems.extend(checker.problems)
    all_problems.extend(check_dangerous_without_try(tree))

    # Дедупликация
    seen = set()
    unique = []
    for p in all_problems:
        key = (p["line"], p["message"])
        if key not in seen:
            seen.add(key)
            unique.append(p)

    # Сортировка: CRITICAL → HIGH, внутри — по строке
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    unique.sort(key=lambda p: (severity_order.get(p["severity"], 99), p["line"]))
    return unique


def print_report(filepath: str, problems: list):
    print(f"\n{'=' * 60}")
    print(f"Анализ файла: {filepath}")
    print(f"{'=' * 60}\n")

    if not problems:
        print("✅ Критичных проблем не найдено. Молодец!")
        print(f"\n{'=' * 60}\n")
        return

    print(f"Найдено проблем: {len(problems)}\n")

    for p in problems:
        marker = "🔴" if p["severity"] == "CRITICAL" else "🟡"
        print(f"{marker} Строка {p['line']}: {p['message']}")

    print(f"\n{'=' * 60}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: python checker.py <файл.py>")
        sys.exit(1)

    filepath = sys.argv[1]
    problems = analyze(filepath)
    print_report(filepath, problems)
