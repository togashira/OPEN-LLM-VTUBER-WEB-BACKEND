import numpy as np
from ..utils.debug_tools import info, preview
import uuid
from ..utils.debug_tools import trace, dbg, preview
import asyncio
import json
from typing import Dict, Optional, Callable

import numpy as np
from fastapi import WebSocket
from loguru import logger
# 先頭あたり
from .prepost_hooks import preprocess_user_text  # <- 追加（自作フック）
from ..chat_group import ChatGroupManager
from ..chat_history_manager import store_message
from ..service_context import ServiceContext
from .group_conversation import process_group_conversation
from .single_conversation import process_single_conversation
from .conversation_utils import EMOJI_LIST
from .types import GroupConversationState


async def handle_conversation_trigger(
    msg_type: str,
    data: dict,
    client_uid: str,
    context: ServiceContext,
    websocket: WebSocket,
    client_contexts: Dict[str, ServiceContext],
    client_connections: Dict[str, WebSocket],
    chat_group_manager: ChatGroupManager,
    received_data_buffers: Dict[str, np.ndarray],
    current_conversation_tasks: Dict[str, Optional[asyncio.Task]],
    broadcast_to_group: Callable,
) -> None:
    """Handle triggers that start a conversation"""

    conv_id = data.get("conv_id") or str(uuid.uuid4())
    async with trace("handle_conversation_trigger",
                     conv_id=conv_id, msg_type=msg_type, client_uid=client_uid):
        # 受信概要
        buf = received_data_buffers.get(client_uid)
        dbg("input.received",
            conv_id=conv_id, keys=list(data.keys()),
            buf_len=(int(buf.size) if isinstance(buf, np.ndarray) else None))

        if msg_type == "ai-speak-signal":
            user_input = ""
            await websocket.send_text(json.dumps({"type":"full-text","text":"AI wants to speak something..."}))
        elif msg_type == "text-input":
            user_input = data.get("text","")
            logger.info(f"[DEBUG] text-input user_input type: {type(user_input)}, repr: {repr(user_input)}")
        else:  # mic-audio-end
            user_input = received_data_buffers[client_uid]
            logger.info(f"[DEBUG] mic-audio-end user_input type: {type(user_input)}, repr: {repr(user_input)}")
            if isinstance(user_input, np.ndarray):
                logger.info(f"[DEBUG] mic-audio-end user_input.shape: {user_input.shape}, dtype: {user_input.dtype}")
            info("input.mic_audio_end", client_uid=client_uid, preview=preview(user_input) if isinstance(user_input, str) else "<audio-bytes>")
            dbg("[DEBUG] mic-audio-end user_input type(after): {} value: {}".format(type(user_input), repr(user_input)))
            received_data_buffers[client_uid] = np.array([])

        # user_input取得直後に配列部分除去ガード
        import re
        if isinstance(user_input, str):
            cleaned = re.sub(r"\[.*?[-+]?\d+\.\d+.*?\]", "", user_input, flags=re.DOTALL)
            if cleaned != user_input:
                dbg("[GUARD] conversation_handler: array-like part removed from user_input", preview=cleaned)
            user_input = cleaned

        # ★ 前処理フック（あなたが実装済み）
        from .prepost_hooks import preprocess_user_text
        try:
            user_ctx = getattr(context, "user_context", {}) or {}
            logger.info(f"[DEBUG] preprocess_user_text BEFORE type: {type(user_input)}, repr: {repr(user_input)}")
            dbg("preprocess.before", conv_id=conv_id,
                preview=preview(user_input) if isinstance(user_input,str) else "<audio-bytes>")
            user_input = preprocess_user_text(user_input, user_ctx)
            logger.info(f"[DEBUG] preprocess_user_text AFTER type: {type(user_input)}, repr: {repr(user_input)}")
            dbg("preprocess.after", conv_id=conv_id, preview=preview(user_input))
        except Exception as e:
            dbg("preprocess.skip", conv_id=conv_id, err=str(e))

        images = data.get("images")
        session_emoji = np.random.choice(EMOJI_LIST)
        group = chat_group_manager.get_client_group(client_uid)

        if group and len(group.members) > 1:
            task_key = group.group_id
            dbg("conversation.group.start", conv_id=conv_id,
                group_id=task_key, members=list(group.members))
            # 既存のcreate_task(...)はそのまま
        else:
            dbg("conversation.single.start", conv_id=conv_id, client_uid=client_uid)
            # 既存のcreate_task(...)はそのまま

    # ★ ここで独自DBなどを使ったユーザーの付加データ前処理（①）
    try:
        user_ctx = context.user_context if hasattr(context, "user_context") else {}
        user_input = preprocess_user_text(user_input, user_ctx)
    except Exception as e:
        logger.warning(f"preprocess skipped: {e}")
    # ★ここまで
    images = data.get("images")
    session_emoji = np.random.choice(EMOJI_LIST)

    group = chat_group_manager.get_client_group(client_uid)
    if group and len(group.members) > 1:
        # Use group_id as task key for group conversations
        task_key = group.group_id
        if (
            task_key not in current_conversation_tasks
            or current_conversation_tasks[task_key].done()
        ):
            logger.info(f"Starting new group conversation for {task_key}")

            current_conversation_tasks[task_key] = asyncio.create_task(
                process_group_conversation(
                    client_contexts=client_contexts,
                    client_connections=client_connections,
                    broadcast_func=broadcast_to_group,
                    group_members=group.members,
                    initiator_client_uid=client_uid,
                    user_input=user_input,
                    images=images,
                    session_emoji=session_emoji,
                )
            )
    else:
        # Use client_uid as task key for individual conversations
        logger.info(f"[DEBUG] process_single_conversation call user_input type: {type(user_input)}, value: {repr(user_input)}")
        current_conversation_tasks[client_uid] = asyncio.create_task(
            process_single_conversation(
                context=context,
                websocket_send=websocket.send_text,
                client_uid=client_uid,
                user_input=user_input,
                images=images,
                session_emoji=session_emoji,
            )
        )


async def handle_individual_interrupt(
    client_uid: str,
    current_conversation_tasks: Dict[str, Optional[asyncio.Task]],
    context: ServiceContext,
    heard_response: str,
):
    info("interrupt.individual", client_uid=client_uid, heard_preview=preview(heard_response))
    if client_uid in current_conversation_tasks:
        task = current_conversation_tasks[client_uid]
        if task and not task.done():
            task.cancel()
            logger.info("🛑 Conversation task was successfully interrupted")

        try:
            context.agent_engine.handle_interrupt(heard_response)
        except Exception as e:
            logger.error(f"Error handling interrupt: {e}")

        if context.history_uid:
            store_message(
                conf_uid=context.character_config.conf_uid,
                history_uid=context.history_uid,
                role="ai",
                content=heard_response,
                name=context.character_config.character_name,
                avatar=context.character_config.avatar,
            )
            store_message(
                conf_uid=context.character_config.conf_uid,
                history_uid=context.history_uid,
                role="system",
                content="[Interrupted by user]",
            )


async def handle_group_interrupt(
    group_id: str,
    heard_response: str,
    current_conversation_tasks: Dict[str, Optional[asyncio.Task]],
    chat_group_manager: ChatGroupManager,
    client_contexts: Dict[str, ServiceContext],
    broadcast_to_group: Callable,
) -> None:
    """Handles interruption for a group conversation"""
    info("interrupt.group", group_id=group_id, heard_preview=preview(heard_response))
    task = current_conversation_tasks.get(group_id)
    if not task or task.done():
        return

    # Get state and speaker info before cancellation
    state = GroupConversationState.get_state(group_id)
    current_speaker_uid = state.current_speaker_uid if state else None

    # Get context from current speaker
    context = None
    group = chat_group_manager.get_group_by_id(group_id)
    if current_speaker_uid:
        context = client_contexts.get(current_speaker_uid)
        logger.info(f"Found current speaker context for {current_speaker_uid}")
    if not context and group and group.members:
        logger.warning(f"No context found for group {group_id}, using first member")
        context = client_contexts.get(next(iter(group.members)))

    # Now cancel the task
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        logger.info(f"🛑 Group conversation {group_id} cancelled successfully.")

    current_conversation_tasks.pop(group_id, None)
    GroupConversationState.remove_state(group_id)  # Clean up state after we've used it

    # Store messages with speaker info
    if context and group:
        for member_uid in group.members:
            if member_uid in client_contexts:
                try:
                    member_ctx = client_contexts[member_uid]
                    member_ctx.agent_engine.handle_interrupt(heard_response)
                    store_message(
                        conf_uid=member_ctx.character_config.conf_uid,
                        history_uid=member_ctx.history_uid,
                        role="ai",
                        content=heard_response,
                        name=context.character_config.character_name,
                        avatar=context.character_config.avatar,
                    )
                    store_message(
                        conf_uid=member_ctx.character_config.conf_uid,
                        history_uid=member_ctx.history_uid,
                        role="system",
                        content="[Interrupted by user]",
                    )
                except Exception as e:
                    logger.error(f"Error handling interrupt for {member_uid}: {e}")

    await broadcast_to_group(
        list(group.members),
        {
            "type": "interrupt-signal",
            "text": "conversation-interrupted",
        },
    )
