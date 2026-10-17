"""Unit tests for Module A: AST Security Scanner."""

from pathlib import Path
from repoguard.scanners.ast_scanner import ASTScanner
from repoguard.core.models import Severity


def test_ast_scanner_catches_dangerous_calls(tmp_path: Path):
    vuln_file = tmp_path / "vuln.py"
    vuln_file.write_text("""
import os
import subprocess

def test():
    eval("1 + 1")
    exec("print('hello')")
    os.system("ls -la")
    subprocess.Popen("echo test", shell=True)
""", encoding="utf-8")

    scanner = ASTScanner()
    issues = scanner.scan_repository(tmp_path)

    rule_ids = [i.id for i in issues]
    assert "AST-SEC-001" in rule_ids  # eval
    assert "AST-SEC-002" in rule_ids  # exec
    assert "AST-SEC-003" in rule_ids  # os.system
    assert "AST-SEC-005" in rule_ids  # shell=True

    for issue in issues:
        assert issue.severity == Severity.CRITICAL
        assert issue.line_number is not None
        assert issue.code_snippet is not None


def test_ast_scanner_catches_sql_injections(tmp_path: Path):
    sql_file = tmp_path / "sql_vuln.py"
    sql_file.write_text("""
def query_db(cursor, val):
    cursor.execute("SELECT * FROM t WHERE a = " + val)
    cursor.execute("SELECT * FROM t WHERE a = '%s'" % val)
    cursor.execute(f"SELECT * FROM t WHERE a = {val}")
    cursor.execute("SELECT * FROM t WHERE a = {}".format(val))
""", encoding="utf-8")

    scanner = ASTScanner()
    issues = scanner.scan_repository(tmp_path)

    sql_issues = [i for i in issues if i.id == "AST-SQL-001"]
    assert len(sql_issues) == 4
    for issue in sql_issues:
        assert issue.severity == Severity.CRITICAL
        assert "Unparameterized SQL" in issue.title


def test_ast_scanner_catches_pickle_deserialization(tmp_path: Path):
    pickle_file = tmp_path / "deser.py"
    pickle_file.write_text("""
import pickle

def load_data(raw):
    return pickle.loads(raw)
""", encoding="utf-8")

    scanner = ASTScanner()
    issues = scanner.scan_repository(tmp_path)

    deser_issues = [i for i in issues if i.id == "AST-DESER-001"]
    assert len(deser_issues) == 1
    assert deser_issues[0].severity == Severity.CRITICAL


def test_ast_scanner_clean_code(tmp_path: Path):
    clean_file = tmp_path / "clean.py"
    clean_file.write_text("""
import ast
import subprocess

def safe_calc(val):
    return ast.literal_eval(val)

def safe_cmd():
    return subprocess.run(["ping", "127.0.0.1"], shell=False)

def safe_sql(cursor, val):
    cursor.execute("SELECT * FROM t WHERE a = ?", (val,))
""", encoding="utf-8")

    scanner = ASTScanner()
    issues = scanner.scan_repository(tmp_path)
    assert len(issues) == 0
