"""
Lab 11 — Helper Utilities
"""
from core.config import get_llm_provider, PROVIDER_OPENROUTER  # noqa: F401
from core.openai_runtime import OpenAIRunner


async def chat_with_agent(agent, runner, user_message: str, session_id=None):
    """Send a message to the agent and get the response.

    Works with OpenAIRunner (OpenAI Red / OpenRouter Blue) and Google ADK (Gemini Red).
    """
    provider = getattr(runner, "provider", None)
    if isinstance(runner, OpenAIRunner) or provider in ("openrouter", "openai"):
        text = await runner.chat(agent, user_message)
        return text, None

    import asyncio
    from google.genai import types

    user_id = "student"
    app_name = runner.app_name

    for attempt in range(4):
        try:
            session = None
            if session_id is not None:
                try:
                    session = await runner.session_service.get_session(
                        app_name=app_name, user_id=user_id, session_id=session_id
                    )
                except (ValueError, KeyError):
                    pass

            if session is None:
                session = await runner.session_service.create_session(
                    app_name=app_name, user_id=user_id
                )

            content = types.Content(
                role="user",
                parts=[types.Part.from_text(text=user_message)],
            )

            final_response = ""
            async for event in runner.run_async(
                user_id=user_id, session_id=session.id, new_message=content
            ):
                if hasattr(event, "content") and event.content and event.content.parts:
                    for part in event.content.parts:
                        if hasattr(part, "text") and part.text:
                            final_response += part.text

            return final_response, session
        except Exception as e:
            err_msg = str(e)
            if any(k in err_msg for k in ("503", "429", "UNAVAILABLE", "RESOURCE_EXHAUSTED")) and attempt < 3:
                wait_sec = 15 if ("429" in err_msg or "RESOURCE_EXHAUSTED" in err_msg) else 5
                print(f"  [API Retry] Temporary server issue ({err_msg[:45]}...), waiting {wait_sec}s...")
                await asyncio.sleep(wait_sec)
            else:
                raise
