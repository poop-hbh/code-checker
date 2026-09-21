# -*- coding: utf-8 -*-
"""
Анализатор кода. Ищет проблемы в Python-коде.
Запуск: python checker.py <файл.py>

Версия 3.2 — финальная:
- Хардкод секретов
- Голый except
- SQL-инъекции
- eval/exec
- Опасные вызовы без try
- Длинные функции
- Длинные строки
- print() вместо logging
- Пустой except: pass
- Хардкод путей
- Опечатка в __name__
- Неиспользуемые импорты
- assert вне тестов
- os.system / subprocess с shell=True
- Исправлено: убран try/except: pass в MainFinder
"""

import ast
import re
import sys
from pathlib import Path


# ============ КОНСТАНТЫ ============

SECRET_PATTERNS = [
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

MAX_FUNCTION_LINES = 50
MAX_LINE_LENGTH = 120

PATH_PATTERNS = [
    (r'["\']C:\\\\[^"\']+["\']', "Хардкод пути Windows"),
    (r'["\']D:\\\\[^"\']+["\']', "Хардкод пути Windows"),
    (r'["\']E:\\\\[^"\']+["\']', "Хардкод пути Windows"),
    (r'["\']C:\\[^"\']+["\']', "Хардкод пути Windows"),
    (r'["\']D:\\[^"\']+["\']', "Хардкод пути Windows"),
    (r'["\']\\\\Users\\\\[^"\']+["\']', "Хардкод пути Windows"),
]

DANGEROUS_SHELL_CALLS = {
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
}


# ============ УТИЛИТЫ ============

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


def _is_safe_value(value: str) -> bool:
    if value is None:
        return True
    if value.lower() in SAFE_VALUES:
        return True
    if len(value) < 4:
        return True
    return False


# ============ AST-АНАЛИЗ ============

class CodeChecker(ast.NodeVisitor):
    def __init__(self):
        self.problems = []
        self.imports = []
        self.used_names = set()

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
        # eval / exec
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

        # os.system / subprocess с shell=True
        call_name = _get_call_name(node)
        if call_name in DANGEROUS_SHELL_CALLS:
            is_shell = False
            for kw in node.keywords:
                if kw.arg == "shell":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        is_shell = True
            if is_shell or call_name in ("os.system", "os.popen"):
                self.add(
                    node.lineno,
                    "CRITICAL",
                    f"`{call_name}` с shell — опасно (RCE).",
                )

        # Сбор использованных имён
        if isinstance(node.func, ast.Name):
            self.used_names.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                self.used_names.add(node.func.value.id)

        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        self.used_names.add(node.id)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        if isinstance(node.value, ast.Name):
            self.used_names.add(node.value.id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        if isinstance(node.value, ast.Name):
            self.used_names.add(node.value.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if isinstance(node.annotation, ast.Name):
            self.used_names.add(node.annotation.id)
        self.generic_visit(node)

    def visit_arg(self, node: ast.arg):
        if node.annotation:
            if isinstance(node.annotation, ast.Name):
                self.used_names.add(node.annotation.id)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            self.imports.append((name, node.lineno))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        for alias in node.names:
            name = alias.asname or alias.name
            self.imports.append((name, node.lineno))
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._check_function_length(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._check_function_length(node)
        self.generic_visit(node)

    def _check_function_length(self, node):
        if hasattr(node, "end_lineno") and node.end_lineno:
            length = node.end_lineno - node.lineno
            if length > MAX_FUNCTION_LINES:
                self.add(
                    node.lineno,
                    "MEDIUM",
                    f"Функция `{node.name}` длиной {length} строк (> {MAX_FUNCTION_LINES}).",
                )

    def visit_Assert(self, node: ast.Assert):
        self.add(
            node.lineno,
            "HIGH",
            "`assert` может быть отключён (флаг `-O`).",
        )
        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        test = node.test
        if isinstance(test, ast.Compare):
            if (isinstance(test.left, ast.Name)
                    and test.left.id == "__name__"):
                for comp in test.comparators:
                    if not (isinstance(comp, ast.Constant)
                            and comp.value == "__main__"):
                        self.add(
                            node.lineno,
                            "HIGH",
                            "`__name__` сравнивается не с `__main__` — опечатка?",
                        )
        self.generic_visit(node)


# ============ ПРОВЕРКИ (регулярки) ============

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

                if group_idx == 1:
                    problems.append({
                        "line": i,
                        "severity": "CRITICAL",
                        "message": f"Хардкод {name} в коде — вынеси в .env",
                    })
                    break

                if not _is_safe_value(value):
                    problems.append({
                        "line": i,
                        "severity": "CRITICAL",
                        "message": f"Хардкод {name} в коде — вынеси в .env",
                    })
                    break
    return problems


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


def check_long_lines(lines: list) -> list:
    problems = []
    for i, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_LENGTH:
            problems.append({
                "line": i,
                "severity": "LOW",
                "message": f"Строка длиной {len(line)} символов (> {MAX_LINE_LENGTH}).",
            })
    return problems


def check_hardcoded_paths(lines: list) -> list:
    problems = []
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "# noqa" in line or "# nosec" in line:
            continue

        for pattern, name in PATH_PATTERNS:
            if re.search(pattern, line):
                problems.append({
                    "line": i,
                    "severity": "HIGH",
                    "message": f"{name} — не работает на другом компе",
                })
                break
    return problems


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
            for child in ast.walk(node):
                if hasattr(child, "lineno"):
                    with_lines.add(child.lineno)
            self.generic_visit(node)

    Collector().visit(tree)

    class Finder(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call):
            func_name = _get_call_name(node)
            if func_name in DANGEROUS_CALLS:
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


def check_print_statements(tree: ast.AST) -> list:
    problems = []
    main_block_lines = set()

    class MainFinder(ast.NodeVisitor):
        def visit_If(self, node: ast.If):
            # ИСПРАВЛЕНО: убран try/except: pass
            if (
                isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name)
                and node.test.left.id == "__name__"
                and len(node.test.comparators) == 1
                and isinstance(node.test.comparators[0], ast.Constant)
                and node.test.comparators[0].value == "__main__"
            ):
                for child in ast.walk(node):
                    if hasattr(child, "lineno"):
                        main_block_lines.add(child.lineno)
            self.generic_visit(node)

    MainFinder().visit(tree)

    class PrintFinder(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "print":
                if node.lineno not in main_block_lines:
                    problems.append({
                        "line": node.lineno,
                        "severity": "LOW",
                        "message": "`print()` вместо `logging` — в проде плохо",
                    })
            self.generic_visit(node)

    PrintFinder().visit(tree)
    return problems


def check_empty_except(tree: ast.AST) -> list:
    problems = []

    class EmptyExceptFinder(ast.NodeVisitor):
        def visit_Try(self, node: ast.Try):
            for handler in node.handlers:
                body = handler.body
                if len(body) == 1 and isinstance(body[0], ast.Pass):
                    problems.append({
                        "line": handler.lineno,
                        "severity": "CRITICAL",
                        "message": "Пустой `except: pass` — скрывает ошибки.",
                    })
            self.generic_visit(node)

    EmptyExceptFinder().visit(tree)
    return problems


def check_unused_imports(checker: CodeChecker) -> list:
    problems = []
    for name, line in checker.imports:
        if name not in checker.used_names and name != "*":
            problems.append({
                "line": line,
                "severity": "LOW",
                "message": f"Импорт `{name}` не используется — удали.",
            })
    return problems


# ============ ГЛАВНАЯ ============

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
    all_problems.extend(check_long_lines(lines))
    all_problems.extend(check_hardcoded_paths(lines))

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"Синтаксическая ошибка в коде: {e}")
        sys.exit(1)

    checker = CodeChecker()
    checker.visit(tree)
    all_problems.extend(checker.problems)

    all_problems.extend(check_dangerous_without_try(tree))
    all_problems.extend(check_print_statements(tree))
    all_problems.extend(check_empty_except(tree))
    all_problems.extend(check_unused_imports(checker))

    seen = set()
    unique = []
    for p in all_problems:
        key = (p["line"], p["message"])
        if key not in seen:
            seen.add(key)
            unique.append(p)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
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
        marker = {
            "CRITICAL": "🔴",
            "HIGH": "🟡",
            "MEDIUM": "🟠",
            "LOW": "⚪",
        }.get(p["severity"], "•")
        print(f"{marker} Строка {p['line']}: {p['message']}")

    print(f"\n{'=' * 60}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: python checker.py <файл.py>")
        sys.exit(1)

    filepath = sys.argv[1]
    problems = analyze(filepath)
    print_report(filepath, problems)
