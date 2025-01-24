import base64
from pydub import AudioSegment
from pydub.utils import make_chunks


def _get_volume_by_chunks(audio: AudioSegment, chunk_length_ms: int) -> list:
    """
    Calculate the normalized volume (RMS) for each chunk of the audio.

    Parameters:
        audio (AudioSegment): The audio segment to process.
        chunk_length_ms (int): The length of each audio chunk in milliseconds.

    Returns:
        list: Normalized volumes for each chunk.
    """
    chunks = make_chunks(audio, chunk_length_ms)
    volumes = [chunk.rms for chunk in chunks]
    max_volume = max(volumes)
    if max_volume == 0:
        raise ValueError("Audio is empty or all zero.")
    return [volume / max_volume for volume in volumes]


def prepare_audio_payload(
    audio_path: str,
    chunk_length_ms: int = 20,
    display_text: str = None,
    expression_list: list = None,
) -> dict[str, any]:
    """
    Prepares the audio payload for sending to a broadcast endpoint.

    Parameters:
        audio_path (str): The path to the audio file to be processed.
        chunk_length_ms (int): The length of each audio chunk in milliseconds.
        display_text (str, optional): Text to be displayed with the audio.
        expression_list (list, optional): List of expressions associated with the audio.

    Returns:
        dict: The audio payload to be sent.
    """
    if not audio_path:
        raise ValueError("audio_path cannot be None or empty.")

    try:
        audio = AudioSegment.from_file(audio_path)
        audio_bytes = audio.export(format="wav").read()
    except Exception as e:
        raise ValueError(
            f"Error loading or converting generated audio file to wav file '{audio_path}': {e}"
        )
    audio_base64 = base64.b64encode(audio_bytes).decode("utf-8")
    volumes = _get_volume_by_chunks(audio, chunk_length_ms)

    payload = {
        "type": "audio",
        "audio": audio_base64,
        "volumes": volumes,
        "slice_length": chunk_length_ms,
        "text": display_text,
        "expressions": expression_list,
    }

    return payload


# Example usage:
# payload, duration = prepare_audio_payload("path/to/audio.mp3", display_text="Hello", expression_list=[0,1,2])
