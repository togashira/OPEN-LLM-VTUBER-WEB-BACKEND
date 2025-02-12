import os
import sys
import shutil
import locale
import atexit
import ctypes
import argparse
import platform
import subprocess
from pathlib import Path
import tomli
import uvicorn
from loguru import logger
from src.open_llm_vtuber.server import WebSocketServer
from src.open_llm_vtuber.config_manager import Config, read_yaml, validate_config

os.environ["HF_HOME"] = str(Path(__file__).parent / "models")
os.environ["MODELSCOPE_CACHE"] = str(Path(__file__).parent / "models")


def get_version() -> str:
    with open("pyproject.toml", "rb") as f:
        pyproject = tomli.load(f)
    return pyproject["project"]["version"]


def get_system_language():
    """Get system language using a combination of methods."""

    # Try to get the current locale
    current_locale = locale.getlocale(locale.LC_ALL)[0]
    if current_locale:
        lang = current_locale.split("_")[0]
        if lang.startswith("zh"):
            return "zh"

    # If locale.getlocale() fails, use platform-specific APIs
    os_name = platform.system()

    if os_name == "Windows":
        try:
            # Use Windows API to get the UI language
            windll = ctypes.windll.kernel32
            ui_lang = windll.GetUserDefaultUILanguage()
            lang_code = locale.windows_locale.get(ui_lang)
            if lang_code:
                lang = lang_code.split("_")[0]
                if lang.startswith("zh"):
                    return "zh"
        except Exception:
            pass

    elif os_name == "Darwin":  # macOS
        try:
            # Use defaults command to get the AppleLocale
            result = subprocess.run(
                ["defaults", "read", "-g", "AppleLocale"],
                capture_output=True,
                text=True,
            )
            lang = result.stdout.strip().split("_")[0]
            if lang.startswith("zh"):
                return "zh"
        except Exception:
            pass

    elif os_name == "Linux":
        # Check the LANG environment variable
        lang = os.environ.get("LANG")
        if lang:
            lang = lang.split("_")[0]
            if lang.startswith("zh"):
                return "zh"

    # Fallback to using locale.getpreferredencoding()
    encoding = locale.getpreferredencoding()
    if encoding.lower() in ("cp936", "gbk", "big5"):
        return "zh"

    return "en"


def init_logger(console_log_level: str = "INFO") -> None:
    logger.remove()
    # Console output
    logger.add(
        sys.stderr,
        level=console_log_level,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | {message}",
        colorize=True,
    )

    # File output
    logger.add(
        "logs/debug_{time:YYYY-MM-DD}.log",
        rotation="10 MB",
        retention="30 days",
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} | {message} | {extra}",
        backtrace=True,
        diagnose=True,
    )


def parse_args():
    parser = argparse.ArgumentParser(description="Open-LLM-VTuber Server")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument(
        "--hf_mirror", action="store_true", help="Use Hugging Face mirror"
    )
    return parser.parse_args()


def init_config():
    # If user config does not exist, copy from template based on system language
    if not os.path.exists("conf.yaml"):
        try:
            sys_lang = get_system_language()
        except Exception:
            sys_lang = ""
        template = (
            "config_templates/conf.ZH.default.yaml"
            if sys_lang.lower().startswith("zh")
            else "config_templates/conf.default.yaml"
        )
        if os.path.exists(template):
            shutil.copy2(template, "conf.yaml")
            print(f"Copied default configuration from {template} to conf.yaml")
        else:
            print(f"Error: Config Template file {template} not found.")
            sys.exit(1)


@logger.catch
def run(console_log_level: str):
    init_logger(console_log_level)
    logger.info(f"Open-LLM-VTuber, version v{get_version()}")

    atexit.register(WebSocketServer.clean_cache)

    # Load configurations from yaml file
    config: Config = validate_config(read_yaml("conf.yaml"))
    server_config = config.system_config
    # config["LIVE2D"] = True  # make sure the live2d is enabled

    # Initialize and run the WebSocket server
    server = WebSocketServer(config=config)
    uvicorn.run(
        app=server.app,
        host=server_config.host,
        port=server_config.port,
        log_level=console_log_level.lower(),
    )


if __name__ == "__main__":
    init_config()  # initialize configuration if needed
    args = parse_args()
    console_log_level = "DEBUG" if args.verbose else "INFO"
    if args.verbose:
        logger.info("Running in verbose mode")
    else:
        logger.info(
            "Running in standard mode. For detailed debug logs, use: uv run run_server.py --verbose"
        )
    if args.hf_mirror:
        os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"
    run(console_log_level=console_log_level)
