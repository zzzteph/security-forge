"""Model routing and alias checks without starting agents or using tokens."""
import unittest
from types import SimpleNamespace

import orchestrate
from scripts import codex_cli, model_names as models


class ModelNamesTests(unittest.TestCase):
    def test_claude_aliases(self):
        for alias in ("opus4.8", "OPUS 4.8", "Opus_4_8", "claude-opus-4-8"):
            with self.subTest(alias=alias):
                self.assertEqual(models.infer_backend(alias), "claude-code")
                self.assertEqual(models.normalize_claude(alias), "claude-opus-4-8")
        self.assertEqual(models.normalize_claude("SONNET"), "sonnet")
        self.assertEqual(models.normalize_claude("opus5[1m]"), "claude-opus-5[1m]")

    def test_codex_aliases(self):
        for alias, expected in {
            "GPT5.4": "gpt-5.4", "ChatGPT 5.4": "gpt-5.4",
            "gpt_5_4": "gpt-5.4", "GPT-5.3-CODEX": "gpt-5.3-codex",
            "gpt5.3codex": "gpt-5.3-codex", "openai/gpt-5": "gpt-5",
            "gpt4o-mini": "gpt-4o-mini", "O3": "o3",
            "chatgpt": "", "codex": "", "gpt": "",
        }.items():
            with self.subTest(alias=alias):
                self.assertEqual(models.infer_backend(alias), "codex")
                self.assertEqual(models.normalize_codex(alias), expected)

    def test_exact_ids_and_unknowns_are_preserved(self):
        for name in ("gpt-4o-2024-08-06", "gpt-5-2025-08-07",
                     "gpt-5.4-2026-03-05", "chatgpt-4o-latest", "my-custom-Model"):
            self.assertEqual(models.normalize_codex(name), name)
        for name in ("my-custom-Model", "ollama/llama3", "gptish", "opus-custom"):
            # Unknown model IDs remain unchanged even if a family prefix routes them.
            self.assertEqual(models.normalize_codex(name), name)

    def test_selection_precedence(self):
        self.assertEqual(models.select_backend("gpt5.4", fallback="litellm"), "codex")
        self.assertEqual(models.select_backend("opus4.8", "auto", "litellm"), "claude-code")
        self.assertEqual(models.select_backend("openai/gpt-5", "litellm"), "litellm")
        self.assertEqual(models.select_backend("gpt5", agent_cmd="custom"), "cli-adapter")
        self.assertEqual(models.select_backend("my-deployment", fallback="litellm"), "litellm")
        self.assertEqual(models.select_backend("", fallback="codex"), "codex")

    def test_resolver_and_command_use_inferred_model(self):
        args = SimpleNamespace(backend="", model="ChatGPT 5.4", agent_cmd="", agent_effort="", codex=None)
        backend = orchestrate.resolve_backend(args, {"backend": "litellm"})
        self.assertIsInstance(backend, orchestrate.CodexBackend)
        command = backend.build_command("prompt", backend.normalize_model(args.model))
        self.assertEqual(command[command.index("--model") + 1], "gpt-5.4")
        args.model = ""
        self.assertIsInstance(orchestrate.resolve_backend(args, {"model": "gpt5"}), orchestrate.CodexBackend)
        self.assertNotIn("--model", codex_cli.command("chatgpt"))


if __name__ == "__main__":
    unittest.main()
