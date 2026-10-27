import pytest
from pathlib import Path
from devsecops_agent.context.extractor import ContextExtractor
from devsecops_agent.schemas.vulnerability import OWASPCategory


SAMPLE_DIFF = """diff --git a/app.py b/app.py
index abc1234..def5678 100644
--- a/app.py
+++ b/app.py
@@ -14,3 +14,4 @@
 def query_data(user_id):
-    return db.query(user_id)
+    query = f"SELECT * FROM items WHERE id = '{user_id}'"
+    return db.execute(query)
"""


def test_parse_diff_hunks(tmp_path):
    extractor = ContextExtractor(str(tmp_path))
    hunks = extractor.parse_diff_hunks(SAMPLE_DIFF)
    assert "app.py" in hunks
    assert len(hunks["app.py"]) == 1
    start, count, content = hunks["app.py"][0]
    assert start == 14
    assert count == 4


def test_parse_diff_hunks_flushes_file_boundary(tmp_path):
    second_diff = """diff --git a/second.py b/second.py
index abc1234..def5678 100644
--- a/second.py
+++ b/second.py
@@ -1,1 +1,2 @@
-old_value = 1
+query = "SELECT * FROM users WHERE username = 'x'"
+execute(query)
"""
    extractor = ContextExtractor(str(tmp_path))
    hunks = extractor.parse_diff_hunks(SAMPLE_DIFF + second_diff)

    assert len(hunks["app.py"]) == 1
    assert "SELECT" in hunks["app.py"][0][2]
    assert len(hunks["second.py"]) == 1
    assert "execute(query)" in hunks["second.py"][0][2]


def test_extract_ast_context(tmp_path):
    file_content = """import sqlite3
from flask import Flask

app = Flask(__name__)

def helper():
    return 42

def vulnerable_route(user_input):
    conn = sqlite3.connect("db.sqlite")
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return conn.execute(query)
"""
    app_file = tmp_path / "app.py"
    app_file.write_text(file_content, encoding="utf-8")

    extractor = ContextExtractor(str(tmp_path))
    context = extractor.extract_ast_context("app.py", target_lines=[10, 11])

    assert context.enclosing_function_name == "vulnerable_route"
    assert "sqlite3" in context.imports[0]
    assert "vulnerable_route" in context.enclosing_function_source


def test_extract_candidates_from_diff(tmp_path):
    extractor = ContextExtractor(str(tmp_path))
    candidates = extractor.extract_candidates_from_diff(SAMPLE_DIFF)
    assert len(candidates) == 1
    cand = candidates[0]
    assert cand.target_file == "app.py"
    assert cand.owasp_category == OWASPCategory.A03_INJECTION
    assert cand.cwe_id == "CWE-89"
