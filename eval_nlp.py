"""Run 20-question evaluation set for DrugTrace NLP-to-SQL engine (PRD §11)."""

from __future__ import annotations

import json
from pathlib import Path

import nlp

EVAL_PATH = Path(__file__).parent / "eval_questions.json"


class _DummyCursor:
    def execute(self, *args, **kwargs): pass
    def fetchall(self): return [{"status": "OK"}]
    def close(self): pass


class _DummyConn:
    def cursor(self, *args, **kwargs): return _DummyCursor()
    def is_connected(self): return True
    def close(self): pass


def main() -> None:
    # Use lightweight connection mock for offline NLP benchmark
    nlp._nl_connect = lambda: _DummyConn()
    nlp._log = lambda *args, **kwargs: None

    questions = json.loads(EVAL_PATH.read_text(encoding="utf-8"))
    total = len(questions)
    template_hits = 0
    llm_hits = 0
    unsafe_rejected = 0
    failures = 0

    print(f"Running NLP evaluation on {total} questions...")
    print("-" * 75)

    for i, item in enumerate(questions, 1):
        q = item["question"]
        expected = item["expected_route"]
        res = nlp.ask(q)
        actual = res["route"]

        is_safe = expected in ("TEMPLATE", "LLM")
        passed = (actual in ("TEMPLATE", "LLM")) if is_safe else (actual == "REJECTED")

        if actual == "TEMPLATE":
            template_hits += 1
        elif actual == "LLM":
            llm_hits += 1
        elif actual == "REJECTED" and not is_safe:
            unsafe_rejected += 1

        if not passed:
            failures += 1
            print(f"[{i:02d}] FAIL: '{q}' -> got {actual}, expected {expected} (error: {res.get('error')})")
        else:
            print(f"[{i:02d}] PASS: '{q}' -> {actual} ({res.get('latency_ms')}ms)")

    print("-" * 75)
    print(f"Total Questions: {total}")
    print(f"Template hit rate: {template_hits}/{15} ({(template_hits/15)*100:.1f}%)")
    print(f"LLM fallback count: {llm_hits}")
    print(f"Unsafe queries correctly rejected: {unsafe_rejected}/{5} ({(unsafe_rejected/5)*100:.1f}%)")
    print(f"Overall status: {'ALL TESTS PASSED' if failures == 0 else f'{failures} FAILURES'}")


if __name__ == "__main__":
    main()
