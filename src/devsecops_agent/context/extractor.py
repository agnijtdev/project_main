import ast
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from devsecops_agent.schemas.vulnerability import CodeContext, VulnerabilityCandidate, OWASPCategory, Severity


class ContextExtractor:
    """
    Extracts modified code context (Δ) from git diffs and AST dependency inspection.
    Isolates modified lines and their enclosing functions to prevent context bloat.
    """

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()

    def get_git_diff(self, base_ref: Optional[str] = None, head_ref: Optional[str] = None) -> str:
        """
        Extracts PR diff natively from Git repository history or branches.
        """
        import subprocess
        cmd = ["git", "diff"]
        if base_ref and head_ref:
            cmd.append(f"{base_ref}...{head_ref}")
        elif base_ref:
            cmd.append(base_ref)
        else:
            # Check for working tree or staged diff first
            diff_res = subprocess.run(["git", "diff", "HEAD"], cwd=str(self.repo_path), capture_output=True, text=True)
            if diff_res.stdout.strip():
                return diff_res.stdout
            cmd.append("HEAD~1")

        res = subprocess.run(cmd, cwd=str(self.repo_path), capture_output=True, text=True)
        return res.stdout

    def parse_diff_hunks(self, diff_text: str) -> Dict[str, List[Tuple[int, int, str]]]:
        """
        Parses a unified diff into modified file paths and their changed line ranges.
        Returns: {file_path: [(start_line, count, hunk_text), ...]}
        """
        files_modified: Dict[str, List[Tuple[int, int, str]]] = {}
        current_file: Optional[str] = None
        current_hunk_lines: List[str] = []
        current_start = 0
        current_count = 0

        diff_header_pattern = re.compile(r"^\+\+\+ b/(.*)$")
        hunk_header_pattern = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

        for line in diff_text.splitlines():
            file_match = diff_header_pattern.match(line)
            if file_match:
                if current_file and current_hunk_lines:
                    files_modified[current_file].append((current_start, current_count, "\n".join(current_hunk_lines)))
                    current_hunk_lines = []
                current_file = file_match.group(1).strip()
                files_modified.setdefault(current_file, [])
                continue

            hunk_match = hunk_header_pattern.match(line)
            if hunk_match and current_file:
                if current_hunk_lines:
                    files_modified[current_file].append((current_start, current_count, "\n".join(current_hunk_lines)))
                    current_hunk_lines = []

                current_start = int(hunk_match.group(1))
                current_count = int(hunk_match.group(2)) if hunk_match.group(2) else 1
                current_hunk_lines.append(line)
                continue

            if current_file and current_hunk_lines:
                current_hunk_lines.append(line)

        if current_file and current_hunk_lines:
            files_modified[current_file].append((current_start, current_count, "\n".join(current_hunk_lines)))

        return files_modified

    def extract_ast_context(self, file_path: str, target_lines: List[int]) -> CodeContext:
        """
        Parses Python AST of target file to locate enclosing functions and imports.
        """
        full_path = self.repo_path / file_path
        if not full_path.exists():
            return CodeContext(file_path=file_path, modified_lines=target_lines)

        source_code = full_path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source_code, filename=str(full_path))
        except SyntaxError:
            return CodeContext(
                file_path=file_path,
                modified_lines=target_lines,
                diff_hunk=source_code[:500]
            )

        imports: List[str] = []
        enclosing_function_name: Optional[str] = None
        enclosing_function_source: Optional[str] = None
        dependent_functions: Dict[str, str] = {}

        source_lines = source_code.splitlines()

        # Collect imports and locate functions
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                names = ", ".join(a.name for a in node.names)
                imports.append(f"from {module} import {names}")

        # Find enclosing functions for modified lines
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start_line = getattr(node, "lineno", 0)
                end_line = getattr(node, "end_lineno", start_line)

                # Check if any target line falls in this function
                if any(start_line <= line <= end_line for line in target_lines):
                    enclosing_function_name = node.name
                    func_slice = source_lines[start_line - 1: end_line]
                    enclosing_function_source = "\n".join(func_slice)
                else:
                    # Keep other functions as potential dependent references
                    if len(dependent_functions) < 3:
                        func_slice = source_lines[start_line - 1: end_line]
                        dependent_functions[node.name] = "\n".join(func_slice)

        return CodeContext(
            file_path=file_path,
            modified_lines=target_lines,
            enclosing_function_name=enclosing_function_name,
            enclosing_function_source=enclosing_function_source,
            dependent_code_snippets=dependent_functions,
            imports=imports
        )

    def extract_candidates_from_diff(self, diff_text: str) -> List[VulnerabilityCandidate]:
        """
        Transforms a git diff into candidate vulnerability records for multi-agent evaluation.
        """
        parsed_diffs = self.parse_diff_hunks(diff_text)
        candidates: List[VulnerabilityCandidate] = []
        candidate_counter = 1

        for rel_file, hunks in parsed_diffs.items():
            norm_path = rel_file.replace("\\", "/").lower()
            if not rel_file.endswith(".py"):
                continue
            if norm_path.startswith("test_") or "/test" in norm_path or norm_path.endswith("_test.py"):
                continue

            all_lines: List[int] = []
            combined_hunk: List[str] = []

            for start, count, hunk_str in hunks:
                all_lines.extend(range(start, start + count))
                combined_hunk.append(hunk_str)

            context = self.extract_ast_context(rel_file, all_lines)
            context.diff_hunk = "\n".join(combined_hunk)

            # Heuristic OWASP categorization from static diff inspection
            category, cwe, title = self._heuristic_category(context.diff_hunk)

            candidate = VulnerabilityCandidate(
                id=f"VULN-PR-{candidate_counter:03d}",
                title=title,
                target_file=rel_file,
                line_numbers=all_lines,
                owasp_category=category,
                cwe_id=cwe,
                severity=Severity.HIGH,
                static_summary=f"Diff modified lines {all_lines} in {rel_file} under function '{context.enclosing_function_name}'.",
                context=context
            )
            candidates.append(candidate)
            candidate_counter += 1

        return candidates

    def _heuristic_category(self, hunk_str: str) -> Tuple[OWASPCategory, str, str]:
        lower = hunk_str.lower()
        if "select" in lower or "where" in lower or "execute(" in lower:
            return OWASPCategory.A03_INJECTION, "CWE-89", "Potential SQL Injection Flaw"
        elif "subprocess" in lower or "system(" in lower or "popen" in lower or "os.system" in lower:
            return OWASPCategory.A03_INJECTION, "CWE-78", "Potential OS Command Injection Flaw"
        elif "requests.get" in lower or "urllib" in lower or "httpx" in lower:
            return OWASPCategory.A10_SSRF, "CWE-918", "Potential Server-Side Request Forgery"
        elif "open(" in lower or "filepath" in lower or "filename" in lower:
            return OWASPCategory.A01_BROKEN_ACCESS_CONTROL, "CWE-22", "Potential Path Traversal Flaw"
        else:
            return OWASPCategory.A04_INSECURE_DESIGN, "CWE-699", "Unverified Code Modification"
