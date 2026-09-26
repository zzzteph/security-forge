"""Codex integration checks without a login, network requests or model usage."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "webapp"))

import orchestrate
from scripts import codex_cli
import db
import reportgen
import runner


class CodexCommandTests(unittest.TestCase):
    def test_blank_model_and_effort_reuse_local_configuration(self):
        cmd = codex_cli.command(executable="codex")
        self.assertNotIn("--model", cmd)
        self.assertNotIn("-c", cmd)
        self.assertIn("--json", cmd)
        self.assertIn("--skip-git-repo-check", cmd)
        self.assertEqual(cmd[-1], "-")

    def test_model_effort_and_paths_are_separate_arguments(self):
        cmd = codex_cli.command("chosen-model", "max", "C:/Program Files/Codex/codex.exe",
                                writable_dirs=[ROOT / "data with spaces"],
                                output_file=ROOT / "report with spaces.md")
        self.assertEqual(cmd[0], "C:/Program Files/Codex/codex.exe")
        self.assertEqual(cmd[cmd.index("--model") + 1], "chosen-model")
        self.assertIn('model_reasoning_effort="high"', cmd)
        self.assertEqual(cmd[cmd.index("--add-dir") + 1], str((ROOT / "data with spaces").resolve()))

    def test_provider_default_does_not_override_effort(self):
        self.assertNotIn("-c", codex_cli.command(effort="off"))

    def test_codex_is_builtin_without_presets(self):
        args = SimpleNamespace(backend="codex", agent_cmd="", agent_effort="low", codex=None)
        backend = orchestrate.resolve_backend(args, {})
        self.assertIsInstance(backend, orchestrate.CodexBackend)
        self.assertEqual(backend.effort, "low")

    def test_legacy_codex_preset_does_not_select_claude_parser(self):
        args = SimpleNamespace(backend="codex", agent_cmd="", agent_effort="", codex=None)
        cfg = {"backends": {"codex": {"command": "old command", "output": "jsonl"}}}
        backend = orchestrate.resolve_backend(args, cfg)
        self.assertIsInstance(backend.progress(Path("unused")), orchestrate._CodexProgress)

    def test_explicit_command_override_remains_available(self):
        args = SimpleNamespace(backend="codex", agent_cmd="custom-codex {prompt}", agent_output="text")
        backend = orchestrate.resolve_backend(args, {})
        self.assertIsInstance(backend, orchestrate.CliAdapterBackend)

    def test_login_status_uses_cli_exit_status(self):
        with patch.object(codex_cli.subprocess, "run", return_value=SimpleNamespace(returncode=1)):
            self.assertFalse(codex_cli.authenticated())


class CodexEventsTests(unittest.TestCase):
    def test_native_usage_and_tool_events(self):
        events = codex_cli.Events()
        events.feed({"type": "turn.started"})
        item = {"id": "tool-1", "type": "command_execution", "command": "rg auth target"}
        events.feed({"type": "item.started", "item": item})
        events.feed({"type": "item.completed", "item": item})
        events.feed({"type": "turn.completed", "usage": {
            "input_tokens": 100, "cached_input_tokens": 80,
            "output_tokens": 20, "reasoning_output_tokens": 5}})
        events.feed({"type": "turn.started"})
        events.feed({"type": "turn.completed", "usage": {"input_tokens": 30, "output_tokens": 10}})
        self.assertEqual(events.tools, 1)
        self.assertEqual(events.turns, 2)
        self.assertEqual(events.usage(), {"input_tokens": 130, "cached_input_tokens": 80,
                                         "output_tokens": 30, "reasoning_output_tokens": 5})

    def test_failure_is_reported_and_transient_error_can_recover(self):
        events = codex_cli.Events()
        events.feed({"type": "error", "message": "retrying"})
        self.assertIsNone(events.error)
        events.feed({"type": "turn.failed", "error": {"message": "quota exhausted"}})
        self.assertEqual(events.error, "quota exhausted")
        events.feed({"type": "turn.completed", "usage": {}})
        self.assertIsNone(events.error)

    def test_long_unicode_prompt_reaches_child_over_stdin(self):
        prompt = "scan source — 東京\n" * 5000
        class FakeCodex(orchestrate.CodexBackend):
            def build_command(self, _prompt, _model):
                script = ("import json,sys; text=sys.stdin.buffer.read().decode('utf-8'); "
                          "print(json.dumps({'type':'turn.completed','usage': "
                          "{'input_tokens':len(text),'output_tokens':3}}))")
                return [sys.executable, "-c", script]
        with tempfile.TemporaryDirectory(prefix="secforge-codex-test-") as work:
            self.assertTrue(Path(work).resolve().is_relative_to(Path(tempfile.gettempdir()).resolve()))
            log = Path(work) / "events.jsonl"
            console = io.StringIO()
            with contextlib.redirect_stdout(console):
                rc = orchestrate.run_session(prompt, {}, FakeCodex(), "", 10, log)
            self.assertEqual(rc, 0)
            progress = orchestrate._CodexProgress(log)
            progress.update()
            self.assertEqual(progress.tin, len(prompt))
            self.assertIn('[orch] usage {"input_tokens":', console.getvalue())

    def test_zero_exit_without_completed_event_is_failure(self):
        class IncompleteCodex(orchestrate.CodexBackend):
            def build_command(self, _prompt, _model):
                return [sys.executable, "-c", "print('no completion')"]
        with tempfile.TemporaryDirectory(prefix="secforge-codex-test-") as work:
            self.assertTrue(Path(work).resolve().is_relative_to(Path(tempfile.gettempdir()).resolve()))
            rc = orchestrate.run_session("test", {}, IncompleteCodex(), "", 10,
                                         Path(work) / "events.jsonl", quiet=True)
            self.assertEqual(rc, 1)


class CodexWebTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="secforge-codex-db-test-")
        self.data = Path(self.temp.name).resolve()
        self.assertTrue(self.data.is_relative_to(Path(tempfile.gettempdir()).resolve()))
        self.addCleanup(self.temp.cleanup)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for module, name, value in [(db, "DATA_ROOT", self.data),
                                    (db, "DB_PATH", self.data / "db" / "ui.db"),
                                    (runner, "DATA_ROOT", self.data)]:
            self.stack.enter_context(patch.object(module, name, value))
        original_connect = db.connect
        @contextlib.contextmanager
        def closing_connect():
            c = original_connect()
            try:
                with c:
                    yield c
            finally:
                c.close()
        self.stack.enter_context(patch.object(db, "connect", closing_connect))
        with contextlib.redirect_stdout(io.StringIO()):
            db.init()
        self.rid = db.upsert_repo({"url": "https://example.invalid/team/repo.git"})
        self.slug = db.get_repo(self.rid)["slug"]

    def test_migration_preserves_existing_scans(self):
        sid = db.create_scan(self.rid, self.slug)
        db.update_scan(sid, usage_json='{"input_tokens":100}')
        db.init()
        self.assertEqual(json.loads(db.get_scan(sid)["usage_json"])["input_tokens"], 100)

    def test_scan_records_native_usage_and_unknown_cost(self):
        sid = db.create_scan(self.rid, self.slug)
        db.set_setting("defaults", {"backend": "codex", "model": ""})
        usage = {"input_tokens": 100, "cached_input_tokens": 60,
                 "output_tokens": 20, "reasoning_output_tokens": 5}
        stdout = io.StringIO('[orch] usage ' + json.dumps(usage) + '\n'
                            f'[orch] done. {self.slug} -> analyzed\n')
        process = SimpleNamespace(stdout=stdout, returncode=0, wait=lambda: 0)
        with patch.object(runner.subprocess, "Popen", return_value=process):
            runner._run_scan(self.rid, sid)
        row = db.get_scan(sid)
        self.assertEqual(row["status"], "done")
        self.assertEqual(json.loads(row["usage_json"]), usage)
        self.assertIsNone(row["cost_usd"])

    def test_skipped_scan_does_not_reconcile_findings(self):
        sid = db.create_scan(self.rid, self.slug)
        db.set_setting("defaults", {"backend": "codex"})
        process = SimpleNamespace(stdout=io.StringIO(f'[orch] done. {self.slug} -> skipped\n'),
                                  returncode=0, wait=lambda: 0)
        with patch.object(runner.subprocess, "Popen", return_value=process), \
             patch.object(db, "reconcile_findings") as reconcile:
            runner._run_scan(self.rid, sid)
        reconcile.assert_not_called()
        self.assertEqual(db.get_scan(sid)["status"], "error")

    def test_auto_scan_selects_local_codex(self):
        sid = db.create_scan(self.rid, self.slug)
        db.set_setting("defaults", {"backend": "auto", "model": "ChatGPT 5.4"})
        process = SimpleNamespace(stdout=io.StringIO(f'[orch] done. {self.slug} -> analyzed\n'),
                                  returncode=0, wait=lambda: 0)
        with patch.object(runner.subprocess, "Popen", return_value=process) as launch:
            runner._run_scan(self.rid, sid)
        command = launch.call_args.args[0]
        self.assertEqual(command[command.index("--backend") + 1], "codex")
        self.assertIsNone(db.get_scan(sid)["cost_usd"])

    def test_auto_report_selects_codex_and_normalizes_model(self):
        with patch.object(reportgen, "_codex_narrative", return_value=("report", "gpt-5.4", None)) as generate:
            reportgen._llm_narrative([], "test", "", "", {"backend": "auto", "model": "ChatGPT 5.4"})
        self.assertEqual(generate.call_args.args[1]["model"], "gpt-5.4")
        self.assertEqual(generate.call_args.args[1]["backend"], "codex")

    def test_report_uses_codex_with_no_litellm_model_or_api_call(self):
        def complete(prompt, env, backend, model, timeout, log, quiet):
            self.assertEqual(backend.sandbox, "read-only")
            self.assertEqual(model, "")
            backend.output_file.write_text("## Executive summary\nNo findings.", encoding="utf-8")
            return 0
        with patch.object(orchestrate, "run_session", side_effect=complete):
            text, model, cost = reportgen._llm_narrative([], "test", "", "", {"backend": "codex"})
        self.assertIn("Executive summary", text)
        self.assertEqual(model, "Codex configured default")
        self.assertIsNone(cost)


if __name__ == "__main__":
    unittest.main()
