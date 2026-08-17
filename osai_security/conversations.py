from __future__ import annotations

import hashlib
from typing import Any, Iterable


SINGLE_TURN = "single-turn"
TARGET_SESSION = "target-managed-session"
TRANSCRIPT_REPLAY = "client-transcript-replay"
STRUCTURED_HISTORY = "structured-request-history"
UNVERIFIED_MULTI_TURN = "unverified-multi-turn"


def conversation_transport(capabilities: dict[str, Any] | None) -> str:
    """Return the explicitly configured conversation-continuity transport."""
    values = capabilities or {}
    if not values.get("multi_turn"):
        return SINGLE_TURN
    if values.get("structured_history"):
        return STRUCTURED_HISTORY
    if values.get("memory"):
        return TARGET_SESSION
    if values.get("transcript_replay"):
        return TRANSCRIPT_REPLAY
    return UNVERIFIED_MULTI_TURN


def has_conversation_continuity(capabilities: dict[str, Any] | None) -> bool:
    return conversation_transport(capabilities) in {TARGET_SESSION, TRANSCRIPT_REPLAY, STRUCTURED_HISTORY}


def render_transcript_prompt(history: Iterable[dict[str, Any]], current_prompt: str) -> str:
    """Serialize prior target exchanges into a deterministic prompt transcript.

    Enabling this target-agnostic serializer is an explicit Attack Surface
    decision. The complete materialized prompt is retained as request evidence.
    """
    turns = list(history)
    if not turns:
        return current_prompt
    lines = ["Conversation transcript (previous turns):"]
    for index, turn in enumerate(turns, start=1):
        lines.extend([
            f"[Turn {index} user]",
            str(turn.get("prompt") or ""),
            f"[Turn {index} assistant]",
            str(turn.get("response") or ""),
        ])
    lines.extend(["[Current user request]", current_prompt, "[Assistant response]"])
    return "\n".join(lines)


def materialize_conversation_prompt(
    capabilities: dict[str, Any] | None,
    history: Iterable[dict[str, Any]],
    current_prompt: str,
) -> tuple[str, dict[str, Any]]:
    turns = list(history)
    transport = conversation_transport(capabilities)
    sent_prompt = render_transcript_prompt(turns, current_prompt) if transport == TRANSCRIPT_REPLAY else current_prompt
    return sent_prompt, {
        "transport": transport,
        "history_turns": len(turns),
        "original_prompt_sha256": hashlib.sha256(current_prompt.encode("utf-8")).hexdigest(),
        "sent_prompt_sha256": hashlib.sha256(sent_prompt.encode("utf-8")).hexdigest(),
    }


def materialize_conversation_request(
    target: dict[str, Any],
    history: Iterable[dict[str, Any]],
    current_prompt: str,
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """Materialize one explicitly configured conversation request.

    Structured history is target-owned Attack Surface data.  This function
    never guesses a field name or message schema, and returns only the request
    override needed for the current campaign.  The caller retains the complete
    serialized request as evidence.
    """
    capabilities = target.get("capabilities") or {}
    config = target.get("conversation_config") or {}
    turns = list(history)
    transport = conversation_transport(capabilities)
    if transport != STRUCTURED_HISTORY:
        sent_prompt, record = materialize_conversation_prompt(capabilities, turns, current_prompt)
        return sent_prompt, {}, record

    if not config.get("enabled"):
        raise ValueError("structured request history is enabled without a configured Attack Surface adapter")
    maximum_turns = int(config.get("max_history_turns") or 12)
    bounded_turns = turns[-maximum_turns:]
    role_field = str(config["role_field"])
    content_field = str(config["content_field"])
    messages: list[dict[str, str]] = []
    for turn in bounded_turns:
        messages.extend([
            {
                role_field: str(config["user_role"]),
                content_field: str(turn.get("prompt") or ""),
            },
            {
                role_field: str(config["assistant_role"]),
                content_field: str(turn.get("response") or ""),
            },
        ])
    return current_prompt, {str(config["history_field"]): messages}, {
        "transport": STRUCTURED_HISTORY,
        "history_turns": len(bounded_turns),
        "history_messages": len(messages),
        "history_field": str(config["history_field"]),
        "original_prompt_sha256": hashlib.sha256(current_prompt.encode("utf-8")).hexdigest(),
        "sent_prompt_sha256": hashlib.sha256(current_prompt.encode("utf-8")).hexdigest(),
    }
