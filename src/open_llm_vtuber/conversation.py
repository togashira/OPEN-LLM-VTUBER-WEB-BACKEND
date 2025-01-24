from datetime import datetime
import uuid
import json
import asyncio
from typing import AsyncIterator, List, Tuple
import numpy as np
from loguru import logger
from fastapi import WebSocket

from .live2d_model import Live2dModel
from .config_manager.tts_preprocessor import TTSPreprocessorConfig
from .asr.asr_interface import ASRInterface
from .agent.agents.agent_interface import AgentInterface, AgentOutputType
from .tts.tts_interface import TTSInterface
from .translate.translate_interface import TranslateInterface

from .utils.tts_preprocessor import tts_filter
from .utils.stream_audio import prepare_audio_payload
from .chat_history_manager import store_message


class TTSTaskManager:
    def __init__(self):
        self.task_list: List[asyncio.Task] = []
        self.next_index_to_play: int = 0

    def clear(self):
        self.task_list.clear()
        self.next_index_to_play = 0

    async def speak(
        self,
        sentence_to_speak: str,
        live2d_model: Live2dModel,
        tts_engine: TTSInterface,
        websocket_send: WebSocket.send,
        display_text: str | None = None,
    ) -> None:
        if not display_text:
            display_text = sentence_to_speak

        if not sentence_to_speak or not sentence_to_speak.strip():
            logger.error(
                f'TTS receives "{sentence_to_speak}", which is empty. So nothing to be spoken.'
            )
            return

        logger.debug(f"🏃Generating audio for '''{sentence_to_speak}'''...")
        emotion = live2d_model.extract_emotion(str_to_check=display_text)
        logger.debug(f"emotion: {emotion}, content: {sentence_to_speak}")

        current_task_index = len(self.task_list)
        tts_task = asyncio.create_task(
            tts_engine.async_generate_audio(
                text=sentence_to_speak,
                file_name_no_ext=f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{str(uuid.uuid4())[:8]}",
            )
        )
        self.task_list.append(tts_task)

        try:
            while current_task_index != self.next_index_to_play:
                await asyncio.sleep(0.01)

            audio_file_path = await tts_task

            try:
                audio_payload = prepare_audio_payload(
                    audio_path=audio_file_path,
                    expression_list=emotion,
                    display_text=display_text,
                )
                logger.debug("Sending Audio payload.")
                await websocket_send(json.dumps(audio_payload))

                tts_engine.remove_file(audio_file_path)
                logger.debug("Payload sent. Audio cache file cleaned.")

            except Exception as e:
                logger.error(f"Error preparing audio payload: {e}")
                tts_engine.remove_file(audio_file_path)

        except Exception as e:
            logger.error(f"Error in speak function: {e}")
        finally:
            self.next_index_to_play += 1

            if current_task_index == len(self.task_list) - 1:
                self.clear()


async def conversation_chain(
    user_input: str | np.ndarray,
    asr_engine: ASRInterface,
    agent_engine: AgentInterface,
    tts_engine: TTSInterface,
    live2d_model: Live2dModel,
    tts_preprocessor_config: TTSPreprocessorConfig,
    translate_engine: TranslateInterface | None,
    websocket_send: WebSocket.send,
    conf_uid: str = "",
    history_uid: str = "",
) -> str:
    """
    One iteration of the main conversation.
    1. Transcribe the user input (or use the input if it's already a string)
    2. Call the LLM with the user input
    3. Text to speech
    4. Send the audio via the websocket

    Parameters:
    - user_input (str, numpy array): The user input to be used in the conversation. If it's string, it will be considered as user input. If it's a numpy array, it will be transcribed. If it's None, we'll request input from the user.

    Returns:
    - str: The full response from the LLM
    """
    tts_manager = TTSTaskManager()
    full_response: str = ""

    try:
        session_emoji = np.random.choice(EMOJI_LIST)

        await websocket_send(
            json.dumps(
                {
                    "type": "control",
                    "text": "conversation-chain-start",
                }
            )
        )

        # Apply the color to the console output
        logger.info(f"New Conversation Chain {session_emoji} started!")

        # Process input based on agent's input type
        if user_input is None:
            logger.warning("❓User input is None. Aborting conversation.")
            return ""

        if isinstance(user_input, np.ndarray):
            logger.info("Transcribing audio input...")
            user_input = await asr_engine.async_transcribe_np(user_input)
            await websocket_send(
                json.dumps({"type": "user-input-transcription", "text": user_input})
            )

        store_message(conf_uid, history_uid, "human", user_input)
        logger.info(f"User input: {user_input}")

        # Process output based on agent's output type
        match agent_engine.output_type:
            case AgentOutputType.TEXT:
                chat_completion: AsyncIterator[str] = agent_engine.chat(user_input)
                async for sentence in chat_completion:
                    full_response += sentence
                    filtered_sentence = tts_filter(
                        text=sentence,
                        ignore_brackets=tts_preprocessor_config.ignore_brackets,
                        ignore_parentheses=tts_preprocessor_config.ignore_parentheses,
                        ignore_asterisks=tts_preprocessor_config.ignore_asterisks,
                        remove_special_char=tts_preprocessor_config.remove_special_char,
                        translator=translate_engine,
                    )
                    await tts_manager.speak(
                        display_text=sentence,
                        sentence_to_speak=filtered_sentence,
                        live2d_model=live2d_model,
                        tts_engine=tts_engine,
                        websocket_send=websocket_send,
                    )

            case AgentOutputType.AUDIO:
                chat_completion: AsyncIterator[Tuple[str, str]] = agent_engine.chat(
                    user_input
                )
                async for audio_file_path, text in chat_completion:
                    logger.info(
                        f"Received audio file path: {audio_file_path}, Received text: {text}"
                    )
                    full_response += text
                    audio_payload = prepare_audio_payload(
                        audio_path=audio_file_path,
                        display_text=text,
                        expression_list=[],
                    )
                    await websocket_send(json.dumps(audio_payload))

        if tts_manager.task_list:
            await asyncio.gather(*tts_manager.task_list)

    except asyncio.CancelledError:
        logger.info(f"🤡👍 Conversation {session_emoji} cancelled because interrupted.")
        # We need to store the partial response outside this function (because it's
        # a part of the interruption-signal from the frontend and we don't
        # have access to it here)

    finally:
        logger.debug(f"🧹 Clearing up conversation {session_emoji}.")
        tts_manager.clear()

        if full_response:
            store_message(conf_uid, history_uid, "ai", full_response)
            logger.info(f"💾 Stored AI message: '''{full_response}'''")

        await websocket_send(
            json.dumps(
                {
                    "type": "control",
                    "text": "conversation-chain-end",
                }
            )
        )
        logger.info(f"😎👍✅ Conversation Chain {session_emoji} completed!")
        return full_response


EMOJI_LIST = [
    "🐶",
    "🐱",
    "🐭",
    "🐹",
    "🐰",
    "🦊",
    "🐻",
    "🐼",
    "🐨",
    "🐯",
    "🦁",
    "🐮",
    "🐷",
    "🐸",
    "🐵",
    "🐔",
    "🐧",
    "🐦",
    "🐤",
    "🐣",
    "🐥",
    "🦆",
    "🦅",
    "🦉",
    "🦇",
    "🐺",
    "🐗",
    "🐴",
    "🦄",
    "🐝",
    "🌵",
    "🎄",
    "🌲",
    "🌳",
    "🌴",
    "🌱",
    "🌿",
    "☘️",
    "🍀",
    "🍂",
    "🍁",
    "🍄",
    "🌾",
    "💐",
    "🌹",
    "🌸",
    "🌛",
    "🌍",
    "⭐️",
    "🔥",
    "🌈",
    "🌩",
    "⛄️",
    "🎃",
    "🎄",
    "🎉",
    "🎏",
    "🎗",
    "🀄️",
    "🎭",
    "🎨",
    "🧵",
    "🪡",
    "🧶",
    "🥽",
    "🥼",
    "🦺",
    "👔",
    "👕",
    "👜",
    "👑",
]
