# -*- coding: utf-8 -*-
"""
Анализатор кода. Python + C++.
Запуск: python checker.py <файл>

Версия 6.2:
- Автоопределение языка (Python / C++)
- Python: 28 проверок
- C++: 30+ проверок
- Все длинные строки разбиты
"""

import ast
import re
import sys
from pathlib import Path


# ============ КОНСТАНТЫ ============

MAX_FUNCTION_LINES = 50
MAX_LINE_LENGTH = 120

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

PY_SQL_PATTERNS = [
    (r'execute\s*\(\s*f["\']', "SQL через f-строку"),
    (r'execute\s*\(\s*["\'][^"\']*["\']\s*\+', "SQL через конкатенацию"),
    (r'execute\s*\(\s*["\'][^"\']*["\']\s*%', "SQL через %-форматирование"),
]

PY_DANGEROUS_CALLS = {
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.head",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete",
    "httpx.patch", "httpx.head",
    "open",
}

PY_DANGEROUS_SHELL = {
    "os.system", "os.popen",
    "subprocess.run", "subprocess.call", "subprocess.Popen",
}

PY_PATH_PATTERNS = [
    (r'["\']C:\\\\[^"\']+["\']', "Хардкод пути Windows"),
    (r'["\']D:\\\\[^"\']+["\']', "Хардкод пути Windows"),
    (r'["\']E:\\\\[^"\']+["\']', "Хардкод пути Windows"),
    (r'["\']C:\\[^"\']+["\']', "Хардкод пути Windows"),
    (r'["\']D:\\[^"\']+["\']', "Хардкод пути Windows"),
    (r'["\']\\\\Users\\\\[^"\']+["\']', "Хардкод пути Windows"),
]

PY_TODO_PATTERNS = [
    (r'#\s*TODO\b', "TODO"),
    (r'#\s*FIXME\b', "FIXME"),
    (r'#\s*XXX\b', "XXX"),
    (r'#\s*HACK\b', "HACK"),
]

CPP_SQL_PATTERNS = [
    (r'sprintf\s*\([^,]+,\s*"[^"]*%s[^"]*SELECT', "SQL через sprintf"),
    (r'sprintf\s*\([^,]+,\s*"[^"]*%s[^"]*(INSERT|UPDATE|DELETE)', "SQL через sprintf"),
]

CPP_DANGEROUS_FUNCS = {
    "gets", "strcpy", "strcat", "sprintf", "scanf",
    "system", "popen",
    "execl", "execlp", "execle", "execv", "execvp",
}

CPP_UNSAFE_PATTERNS = [
    (r'\bgets\s*\(', "`gets()` — опасно (переполнение буфера)"),
    (r'\bstrcpy\s*\(', "`strcpy()` — опасно (переполнение)"),
    (r'\bstrcat\s*\(', "`strcat()` — опасно (переполнение)"),
    (r'\bsprintf\s*\(', "`sprintf()` — опасно (переполнение)"),
    (r'\bscanf\s*\(', "`scanf()` — опасно (переполнение)"),
]

CPP_PATH_PATTERNS = [
    (r'"[C-Z]:\\\\[^"]*"', "Хардкод пути Windows"),
    (r'"[C-Z]:\\[^"]*"', "Хардкод пути Windows"),
]

CPP_TODO_PATTERNS = [
    (r'//\s*TODO\b', "TODO"),
    (r'//\s*FIXME\b', "FIXME"),
    (r'//\s*XXX\b', "XXX"),
    (r'//\s*HACK\b', "HACK"),
]

CPP_STYLE_PATTERNS = [
    (r'\busing namespace std;', "`using namespace std;` — плохо", "MEDIUM"),
    (r'\bprintf\s*\(', "`printf` вместо `std::cout`", "LOW"),
    (r'\bNULL\b', "`NULL` вместо `nullptr`", "LOW"),
    (r'\bvoid\s+main\s*\(', "`void main()` — нужно `int main()`", "HIGH"),
]


# ============ УТИЛИТЫ ============

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
    if value is None:
        return True
    if value.lower() in SAFE_VALUES:
        return True
    if len(value) < 4:
        return True
    return False


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


def _detect_language(source, filepath):
    ext = Path(filepath).suffix.lower()
    if ext in (".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"):
        return "cpp"
    if ext == ".py":
        return "python"

    head = source[:500]
    if "#include" in head or "std::" in head or "using namespace" in head:
        return "cpp"
    if "def " in head or "import " in head:
        return "python"

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
    unique.sort(
        key=lambda p: (severity_order.get(p["severity"], 99), p["line"])
    )
    return unique


# ============ PYTHON: AST ============

class PythonChecker(ast.NodeVisitor):
    def __init__(self):
        self.problems = []
        self.imports = []
        self.used_names = set()

    def add(self, line_no, severity, message):
        self.problems.append({
            "line": line_no,
            "severity": severity,
            "message": message,
        })

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
        if isinstance(node.annotation, ast.Name):
            self.used_names.add(node.annotation.id)
        self.generic_visit(node)

    def visit_arg(self, node):
        if node.annotation and isinstance(node.annotation, ast.Name):
            self.used_names.add(node.annotation.id)
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            self.imports.append((name, node.lineno))
            if alias.name == "*":
                self.add(node.lineno, "MEDIUM",
                         "`import *` — неясно, что импортируется.")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            name = alias.asname or alias.name
            self.imports.append((name, node.lineno))
            if alias.name == "*":
                self.add(node.lineno, "MEDIUM",
                         "`from ... import *` — неясно, что импортируется.")
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self._check_len(node)
        self._check_global(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self._check_len(node)
        self._check_global(node)
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

    def visit_Assert(self, node):
        self.add(node.lineno, "HIGH",
                 "`assert` может быть отключён (флаг `-O`).")
        self.generic_visit(node)

    def visit_Lambda(self, node):
        body = node.body
        if isinstance(body, (ast.IfExp, ast.Compare, ast.BoolOp,
                              ast.ListComp, ast.DictComp, ast.SetComp)):
            self.add(node.lineno, "MEDIUM",
                     "`lambda` со сложной логикой — используй функцию.")
        self.generic_visit(node)

    def visit_While(self, node):
        if isinstance(node.test, ast.Constant) and node.test.value is True:
            has_break = False
            for child in ast.walk(node):
                if isinstance(child, (ast.Break, ast.Return)):
                    has_break = True
                    break
            if not has_break:
                self.add(node.lineno, "MEDIUM",
                         "`while True:` без `break` — бесконечный цикл?")
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
        if isinstance(test.left, ast.Name) and test.left.id == "__name__":
            for comp in test.comparators:
                if not (isinstance(comp, ast.Constant) and comp.value == "__main__"):
                    self.add(node.lineno, "HIGH",
                             "`__name__` сравнивается не с `__main__`.")

    def _check_none(self, test, node):
        if test.ops and isinstance(test.ops[0], ast.Eq):
            for comp in test.comparators:
                if isinstance(comp, ast.Constant) and comp.value is None:
                    self.add(node.lineno, "HIGH", "`== None` — используй `is None`.")
        if test.ops and isinstance(test.ops[0], ast.NotEq):
            for comp in test.comparators:
                if isinstance(comp, ast.Constant) and comp.value is None:
                    self.add(node.lineno, "HIGH", "`!= None` — используй `is not None`.")

    def _check_bool(self, test, node):
        if test.ops and isinstance(test.ops[0], ast.Eq):
            for comp in test.comparators:
                if isinstance(comp, ast.Constant) and isinstance(comp.value, bool):
                    self.add(node.lineno, "HIGH",
                             f"`== {comp.value}` — используй `if x:`.")

    def _check_empty_if(self, node):
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self.add(node.lineno, "MEDIUM",
                     "`pass` в `if` — пустой блок.")

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


# ============ PYTHON: регулярки ============

def _py_secrets(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("#") or "# noqa" in line or "# nosec" in line:
            continue
        for pattern, name, gidx in SECRET_PATTERNS:
            m = re.search(pattern, line)
            if m:
                try:
                    value = m.group(gidx) if gidx <= (m.lastindex or 0) else ""
                except IndexError:
                    value = ""
                if gidx == 1:
                    problems.append({"line": i, "severity": "CRITICAL",
                                     "message": f"Хардкод {name} — вынеси в .env"})
                    break
                if not _is_safe_value(value):
                    problems.append({"line": i, "severity": "CRITICAL",
                                     "message": f"Хардкод {name} — вынеси в .env"})
                    break
    return problems


def _py_sql(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("#") or "# noqa" in line or "# nosec" in line:
            continue
        for pattern, name in PY_SQL_PATTERNS:
            if re.search(pattern, line):
                problems.append({"line": i, "severity": "CRITICAL",
                                 "message": f"{name} — параметры запроса"})
                break
    return problems


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
        if s.startswith("#") or "# noqa" in line or "# nosec" in line:
            continue
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
    with_lines = set()

    class Collector(ast.NodeVisitor):
        def visit_Try(self, node):
            for child in node.body:
                for sub in ast.walk(child):
                    if hasattr(sub, "lineno"):
                        protected.add(sub.lineno)
            self.generic_visit(node)

        def visit_With(self, node):
            for child in ast.walk(node):
                if hasattr(child, "lineno"):
                    with_lines.add(child.lineno)
            self.generic_visit(node)

    Collector().visit(tree)

    class Finder(ast.NodeVisitor):
        def visit_Call(self, node):
            name = _get_call_name(node)
            if name in PY_DANGEROUS_CALLS:
                if name == "open" and node.lineno in with_lines:
                    self.generic_visit(node)
                    return
                if node.lineno not in protected:
                    problems.append({"line": node.lineno, "severity": "HIGH",
                                     "message": f"`{name}()` без try/except"})
            self.generic_visit(node)

    Finder().visit(tree)
    return problems


def _py_print(tree):
    problems = []
    if _has_main_block(tree):
        return problems

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
    if _has_main_block(tree):
        return problems

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
    lines = source.splitlines()
    problems = []

    problems.extend(_py_secrets(lines))
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
        return [{"line": 1, "severity": "CRITICAL",
                 "message": "Слишком сложный код (рекурсия)."}]

    checker = PythonChecker()
    checker.visit(tree)
    problems.extend(checker.problems)

    problems.extend(_py_dangerous(tree))
    problems.extend(_py_print(tree))
    problems.extend(_py_print_loop(tree))
    problems.extend(_py_empty_except(tree))
    problems.extend(_py_unused_imports(checker))

    return _deduplicate(problems)


# ============ C++: проверки ============

def _cpp_secrets(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("//") or "// noqa" in line:
            continue
        for pattern, name, gidx in SECRET_PATTERNS:
            m = re.search(pattern, line)
            if m:
                try:
                    value = m.group(gidx) if gidx <= (m.lastindex or 0) else ""
                except IndexError:
                    value = ""
                if gidx == 1:
                    problems.append({"line": i, "severity": "CRITICAL",
                                     "message": f"Хардкод {name} — .env"})
                    break
                if not _is_safe_value(value):
                    problems.append({"line": i, "severity": "CRITICAL",
                                     "message": f"Хардкод {name} — .env"})
                    break
    return problems


def _cpp_sql(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("//") or "// noqa" in line:
            continue
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
        if s.startswith("//") or "// noqa" in line:
            continue
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
        if s.startswith("//") or "// noqa" in line:
            continue
        for pattern, name in CPP_UNSAFE_PATTERNS:
            if re.search(pattern, line):
                problems.append({"line": i, "severity": "HIGH", "message": name})
                break
    return problems


def _cpp_paths(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("//") or "// noqa" in line:
            continue
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
        if s.startswith("//") or "// noqa" in line:
            continue
        for pattern, name, severity in CPP_STYLE_PATTERNS:
            if re.search(pattern, line):
                problems.append({"line": i, "severity": severity, "message": name})
                break
    return problems


def _cpp_leaks(lines):
    problems = []
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("//") or "// noqa" in line:
            continue
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
    keywords = {"if", "for", "while", "switch", "catch", "else"}

    for i, line in enumerate(lines, start=1):
        if not in_func:
            m = re.search(r'\b(\w+)\s*\([^)]*\)\s*\{', line)
            if m:
                kw = m.group(1)
                if kw not in keywords:
                    in_func = True
                    func_start = i
                    func_name = kw
                    brace_count = line.count("{") - line.count("}")
                    continue

        if in_func:
            brace_count += line.count("{") - line.count("}")
            if brace_count <= 0:
                length = i - func_start
                if length > MAX_FUNCTION_LINES:
                    problems.append({"line": func_start, "severity": "MEDIUM",
                                     "message": f"Функция `{func_name}` длиной {length} строк."})
                in_func = False

    return problems


def analyze_cpp(source, filepath):
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


# ============ ГЛАВНАЯ ============

def analyze(filepath):
    path = Path(filepath)
    if not path.exists():
        print(f"Файл не найден: {filepath}")
        sys.exit(1)

    try:
        source = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            source = path.read_text(encoding="cp1251")
        except Exception:
            print(f"Не удалось прочитать: {filepath}")
            sys.exit(1)

    lang = _detect_language(source, filepath)

    if lang == "python":
        return analyze_python(source, filepath)
    elif lang == "cpp":
        return analyze_cpp(source, filepath)
    else:
        return [{"line": 1, "severity": "INFO",
                 "message": "Поддерживаются: Python, C++"}]


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
        marker = {
            "CRITICAL": "🔴",
            "HIGH": "🟡",
            "MEDIUM": "🟠",
            "LOW": "⚪",
            "INFO": "ℹ️",
        }.get(p["severity"], "•")
        print(f"{marker} Строка {p['line']}: {p['message']}")

    print(f"\n{'=' * 60}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: python checker.py <файл>")
        sys.exit(1)

    filepath = sys.argv[1]
    problems = analyze(filepath)
    print_report(filepath, problems)
