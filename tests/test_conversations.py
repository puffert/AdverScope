from __future__ import annotations

import unittest
import tempfile
from pathlib import Path

from osai_security.conversations import (
    STRUCTURED_HISTORY,
    TARGET_SESSION,
    TRANSCRIPT_REPLAY,
    UNVERIFIED_MULTI_TURN,
    conversation_transport,
    has_conversation_continuity,
    materialize_conversation_prompt,
    materialize_conversation_request,
)
from osai_security.config import AppConfig
from osai_security.db import Repository
from osai_security.http_app import Application
from osai_security.targets import validate_conversation_config


class ConversationTransportTests(unittest.TestCase):
    def test_multi_request_capability_is_not_continuity_by_itself(self) -> None:
        capabilities = {"multi_turn": True}
        self.assertEqual(UNVERIFIED_MULTI_TURN, conversation_transport(capabilities))
        self.assertFalse(has_conversation_continuity(capabilities))

    def test_explicit_target_session_and_transcript_replay_are_valid_transports(self) -> None:
        self.assertEqual(TARGET_SESSION, conversation_transport({"multi_turn": True, "memory": True}))
        self.assertEqual(TRANSCRIPT_REPLAY, conversation_transport({"multi_turn": True, "transcript_replay": True}))
        self.assertTrue(has_conversation_continuity({"multi_turn": True, "memory": True}))
        self.assertTrue(has_conversation_continuity({"multi_turn": True, "transcript_replay": True}))

    def test_target_managed_session_prevents_duplicate_transcript_replay(self) -> None:
        capabilities = {"multi_turn": True, "memory": True, "transcript_replay": True}
        self.assertEqual(TARGET_SESSION, conversation_transport(capabilities))
        sent, record = materialize_conversation_prompt(
            capabilities,
            [{"prompt": "prior user request", "response": "prior target response"}],
            "current request",
        )
        self.assertEqual("current request", sent)
        self.assertEqual(TARGET_SESSION, record["transport"])
        self.assertEqual(1, record["history_turns"])

    def test_structured_request_history_is_explicit_and_schema_driven(self) -> None:
        config = validate_conversation_config({
            "enabled": True,
            "history_field": "conversation_history",
            "role_field": "speaker",
            "content_field": "text",
            "user_role": "human",
            "assistant_role": "bot",
            "max_history_turns": 2,
        }, request_template={"message": "{{prompt}}"})
        target = {
            "capabilities": {"multi_turn": True, "structured_history": True},
            "conversation_config": config,
        }
        sent, overrides, record = materialize_conversation_request(target, [
            {"prompt": "discarded", "response": "old"},
            {"prompt": "first", "response": "answer one"},
            {"prompt": "second", "response": "answer two"},
        ], "current")
        self.assertEqual("current", sent)
        self.assertEqual(STRUCTURED_HISTORY, record["transport"])
        self.assertEqual(2, record["history_turns"])
        self.assertEqual(4, record["history_messages"])
        self.assertEqual([
            {"speaker": "human", "text": "first"},
            {"speaker": "bot", "text": "answer one"},
            {"speaker": "human", "text": "second"},
            {"speaker": "bot", "text": "answer two"},
        ], overrides["conversation_history"])
        self.assertNotIn("discarded", str(overrides))

    def test_structured_history_rejects_ambiguous_or_unbounded_schema(self) -> None:
        with self.assertRaisesRegex(ValueError, "history field cannot also be"):
            validate_conversation_config({
                "enabled": True, "history_field": "message", "role_field": "role",
                "content_field": "content", "user_role": "user", "assistant_role": "assistant",
                "max_history_turns": 12,
            }, request_template={"message": "{{prompt}}"})
        with self.assertRaisesRegex(ValueError, "between 1 and 50"):
            validate_conversation_config({
                "enabled": True, "history_field": "history", "role_field": "role",
                "content_field": "content", "user_role": "user", "assistant_role": "assistant",
                "max_history_turns": 500,
            }, request_template={"message": "{{prompt}}"})

    def test_transcript_replay_materializes_only_the_supplied_campaign_history(self) -> None:
        first_campaign = [{"prompt": "first user", "response": "first assistant"}]
        second_campaign = [{"prompt": "other user", "response": "other assistant"}]
        sent, record = materialize_conversation_prompt(
            {"multi_turn": True, "transcript_replay": True}, first_campaign, "second user"
        )
        self.assertIn("first user", sent)
        self.assertIn("first assistant", sent)
        self.assertIn("second user", sent)
        self.assertNotIn("other user", sent)
        self.assertNotIn("other assistant", sent)
        self.assertEqual(1, record["history_turns"])
        self.assertEqual(64, len(record["sent_prompt_sha256"]))
        self.assertNotEqual(record["original_prompt_sha256"], record["sent_prompt_sha256"])
        untouched, _ = materialize_conversation_prompt(
            {"multi_turn": True, "transcript_replay": True}, [], second_campaign[0]["prompt"]
        )
        self.assertEqual("other user", untouched)

    def test_http_run_boundary_rejects_unverified_multi_request_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = Repository(root / "assessment.sqlite3")
            try:
                project = repo.create_project(name="Conversation boundary")
                repo.add_document(project["id"], kind="scope", filename="scope.md", content="Authorized chatbot and bounded multi-turn testing.")
                repo.add_document(project["id"], kind="policy", filename="policy.md", content="Do not disclose protected context.")
                target = repo.add_target(
                    project["id"], name="Stateless target", kind="chatbot",
                    base_url="https://example.invalid", path="/chat", method="POST",
                    request_template={"message": "{{prompt}}"}, response_path="response",
                    capabilities={"multi_turn": True}, scope_confirmed=True,
                )
                repo.save_guardrail(
                    project["id"], target["id"], status="approved", max_requests=10,
                    max_runtime_seconds=60, max_consecutive_errors=2,
                    allow_active_recon=False, allow_multi_turn=True,
                    max_turns_per_objective=3, allow_reproduction=False,
                    allow_screenshots=False, stop_on_http_5xx=True,
                )
                app = Application(repo, config=AppConfig(database_path=root / "assessment.sqlite3", evidence_root=root / "projects"))
                with self.assertRaisesRegex(ValueError, "explicit target-managed session"):
                    app.dispatch("POST", f"/api/projects/{project['id']}/runs", {
                        "target_id": target["id"], "technique_ids": ["LLM01-DIRECT"],
                        "model_mode": "offline", "adaptive_turns": 2,
                    })
                persisted = repo.update_target_capabilities(
                    project["id"], target["id"], {"multi_turn": True, "transcript_replay": True}
                )
                self.assertTrue(persisted["capabilities"]["transcript_replay"])
            finally:
                repo.close()


if __name__ == "__main__":
    unittest.main()
