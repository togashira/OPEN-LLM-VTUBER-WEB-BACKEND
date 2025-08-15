from typing import Union, List, Dict, Any, Optional
import asyncio
import json
from loguru import logger
import numpy as np
# single_conversation.py の先頭付近
from .prepost_hooks import postprocess_ai_text, preprocess_user_text  # <- 追加（自作フック）

from .conversation_utils import (
    create_batch_input,
    process_agent_output,
    send_conversation_start_signals,
    process_user_input,
    finalize_conversation_turn,
    cleanup_conversation,
    EMOJI_LIST,
)
from .types import WebSocketSend
from .tts_manager import TTSTaskManager
from ..chat_history_manager import store_message
from ..service_context import ServiceContext


async def process_single_conversation(
    logger.info(f"[DEBUG] process_single_conversation entry user_input type: {type(user_input)}, value: {repr(user_input)}")
    context: ServiceContext,
    websocket_send: WebSocketSend,
    client_uid: str,
    user_input: Union[str, np.ndarray],
    images: Optional[List[Dict[str, Any]]] = None,
    session_emoji: str = np.random.choice(EMOJI_LIST),
) -> str:
    """Process a single-user conversation turn

    Args:
        context: Service context containing all configurations and engines
        websocket_send: WebSocket send function
        client_uid: Client unique identifier
        user_input: Text or audio input from user
        images: Optional list of image data
        session_emoji: Emoji identifier for the conversation

    Returns:
        str: Complete response text
    """    
    
    import time
    from ..utils.debug_tools import trace, dbg, preview
    conv_id = getattr(context, "conv_id", None)
    input_text = None  # 先に初期化しておく
    async with trace("single_conversation", conv_id=conv_id, client_uid=client_uid):
        # まずASR/テキスト化
        input_text = await process_user_input(user_input, context.asr_engine, websocket_send)
        if not isinstance(input_text, str):
            input_text = ""
        # 配列文字列混入ガード（正規表現で厳密に判定）
        import re
        if re.search(r"\[.*?[-+]?\d+\.\d+.*?\]", input_text, re.DOTALL):
            logger.info("[GUARD] input_text looked like array, replaced with empty string.")
            input_text = ""

        # ② LLM固定/切替（必要なときだけ）
        try:
            provider = getattr(context, "forced_llm_provider", None)
            if provider and hasattr(context.agent_engine, "set_provider"):
                context.agent_engine.set_provider(provider)
                dbg("llm.provider.set", conv_id=conv_id, provider=provider)
            else:
                dbg("llm.provider.keep", conv_id=conv_id,
                    provider=getattr(context.agent_engine, "provider_name", "default"))
        except Exception as e:
            dbg("llm.provider.error", conv_id=conv_id, err=str(e))

        # 入力のプレビュー（ASR後のテキストを使う）
        dbg("llm.input", conv_id=conv_id, preview=preview(input_text))

        # ③ 実行タイミングを計測
        t0 = time.perf_counter()
        # BatchInputの生成（ASR後のテキストを使う）
        # input_textの型・値をDEBUG出力
        logger.info(f"[DEBUG] input_text type: {type(input_text)}, value: {repr(input_text)}")
        # AIプロンプト用にASR後テキストをpreprocess_user_textでラップ
        prompt_text = preprocess_user_text(input_text)
        logger.info(f"[DEBUG] prompt_text type: {type(prompt_text)}, value: {repr(prompt_text)}")
        batch_input = create_batch_input(
            prompt_text,
            images,
            context.character_config.human_name
        )
        # create_batch_inputの内容をDEBUG出力
        logger.info(f"[DEBUG] batch_input.texts: {batch_input.texts}")
        ai_text = ""
        try:
            async for output in context.agent_engine.chat(batch_input):
                ai_text += str(output)
        except Exception as e:
            dbg("llm.chat.error", conv_id=conv_id, err=str(e))
            raise
        llm_ms = round((time.perf_counter() - t0) * 1000, 2)
        dbg("llm.output", conv_id=conv_id, ms=llm_ms, preview=preview(ai_text))

        # ④ 出力前処理（HappiBoost等）
        try:
            ai_text = postprocess_ai_text(ai_text, happi=True)
            dbg("postprocess.done", conv_id=conv_id, preview=preview(ai_text))
        except Exception as e:
            dbg("postprocess.skip", conv_id=conv_id, err=str(e))

        # 送信
        payload = {"type": "ai-text", "text": ai_text, "emoji": session_emoji}
        dbg("ws.send", conv_id=conv_id, bytes=len(json.dumps(payload, ensure_ascii=False)))
        await websocket_send(json.dumps(payload, ensure_ascii=False))
    # Create TTSTaskManager for th#is conversation
    tts_manager = TTSTaskManager()

    try:
        # Send initial signals
        await send_conversation_start_signals(websocket_send)
        logger.info(f"New Conversation Chain {session_emoji} started!")

        # Process user input
        input_text = await process_user_input(
            user_input, context.asr_engine, websocket_send
        )

        # Create batch input
        batch_input = create_batch_input(
            input_text=input_text,
            images=images,
            from_name=context.character_config.human_name,
        )

        # Store user message
        if context.history_uid:
            store_message(
                conf_uid=context.character_config.conf_uid,
                history_uid=context.history_uid,
                role="human",
                content=input_text,
                name=context.character_config.human_name,
            )

        logger.info(f"User input: {input_text}")  # 必ずASR後テキストのみをログ出力
        if images:
            logger.info(f"With {len(images)} images")

        # Process agent response
        full_response = await process_agent_response(
            context=context,
            batch_input=batch_input,
            websocket_send=websocket_send,
            tts_manager=tts_manager,
        )

        # Wait for any pending TTS tasks
        if tts_manager.task_list:
            await asyncio.gather(*tts_manager.task_list)
            await websocket_send(json.dumps({"type": "backend-synth-complete"}))

        await finalize_conversation_turn(
            tts_manager=tts_manager,
            websocket_send=websocket_send,
            client_uid=client_uid,
        )

        if context.history_uid and full_response:
            store_message(
                conf_uid=context.character_config.conf_uid,
                history_uid=context.history_uid,
                role="ai",
                content=full_response,
                name=context.character_config.character_name,
                avatar=context.character_config.avatar,
            )
            logger.info(f"AI response: {full_response}")

        return full_response

    except asyncio.CancelledError:
        logger.info(f"🤡👍 Conversation {session_emoji} cancelled because interrupted.")
        raise
    except Exception as e:
        logger.error(f"Error in conversation chain: {e}")
        await websocket_send(
            json.dumps({"type": "error", "message": f"Conversation error: {str(e)}"})
        )
        raise
    finally:
        cleanup_conversation(tts_manager, session_emoji)


async def process_agent_response(
    context: ServiceContext,
    batch_input: Any,
    websocket_send: WebSocketSend,
    tts_manager: TTSTaskManager,
) -> str:
    """Process agent response and generate output

    Args:
        context: Service context containing all configurations and engines
        batch_input: Input data for the agent
        websocket_send: WebSocket send function
        tts_manager: TTSTaskManager for the conversation

    Returns:
        str: The complete response text
    """
    full_response = ""
    try:
        agent_output = context.agent_engine.chat(batch_input)
        async for output in agent_output:
            response_part = await process_agent_output(
                output=output,
                character_config=context.character_config,
                live2d_model=context.live2d_model,
                tts_engine=context.tts_engine,
                websocket_send=websocket_send,
                tts_manager=tts_manager,
                translate_engine=context.translate_engine,
            )
            full_response += response_part

    except Exception as e:
        logger.error(f"Error processing agent response: {e}")
        raise

    return full_response
