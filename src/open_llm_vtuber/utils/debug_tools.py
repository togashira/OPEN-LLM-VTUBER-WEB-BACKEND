import os, sys, time, json
from contextlib import asynccontextmanager
from loguru import logger

# ON/OFF スイッチ（例: HAPI_DEBUG=1）
DEBUG_ON = os.getenv("HAPI_DEBUG", "0").lower() in ("1","true","yes")

def _init_logger():
    logger.remove()
    logger.add(
        sys.stderr,
        level="DEBUG" if DEBUG_ON else "INFO",
        backtrace=False, diagnose=False,
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level:<5} | {message} | {extra}"
    )
_init_logger()

def preview(txt: str, n: int = int(os.getenv("HAPI_DEBUG_PREVIEW", "120"))):
    if not isinstance(txt, str): return str(type(txt))
    return txt.replace("\n", " ")[:n]

def dbg(msg: str, **extra):
    if DEBUG_ON:
        logger.bind(**extra).debug(msg)

def info(msg: str, **extra):
    logger.bind(**extra).info(msg)

def warn(msg: str, **extra):
    logger.bind(**extra).warning(msg)

def err(msg: str, **extra):
    logger.bind(**extra).error(msg)

@asynccontextmanager
async def trace(name: str, **extra):
    t0 = time.perf_counter()
    dbg(f"→ {name}.start", **extra)
    try:
        yield
        ms = round((time.perf_counter() - t0) * 1000, 2)
        dbg(f"← {name}.ok", ms=ms, **extra)
    except Exception as e:
        ms = round((time.perf_counter() - t0) * 1000, 2)
        logger.bind(ms=ms, err=str(e), **extra).exception(f"{name}.error")
        raise