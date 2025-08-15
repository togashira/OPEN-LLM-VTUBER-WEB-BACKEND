# prepost_hooks.py
import random
PERSONA_HINTS = [
    "ユーザーはコテコテの関西人です。",
    "ユーザーはゴリゴリの津軽弁です。",
    "ユーザーはアメリカ人です。",
]

def preprocess_user_text(raw, user_ctx: dict | None = None) -> str:
    # ndarrayが来た場合は空文字で返す（repr混入防止）
    import numpy as np
    from loguru import logger
    if isinstance(raw, np.ndarray):
        logger.warning("user_input is ndarray in preprocess_user_text, returning empty string")
        return ""
    # ① 入力にユーザー最新文脈やテスト用ペルソナを合成
    picked = "ユーザーはゴリゴリの津軽弁です。"  # 固定
    ctx = (user_ctx or {}).get("today_summary", "")
    prefix = "あなたはユーザーの背景に配慮して自然にコーチングします。"
    ctx_line = f"【最新】{ctx}\n" if ctx else ""
    return f"{prefix}\n【追加情報】{picked}\n{ctx_line}【入力】{raw}"

def postprocess_ai_text(ai_text: str, happi: bool = True) -> str:
    # ④ 出力の最終整形（HappiBoost風）。感情タグ付与などもここで。
    # AI出力の末尾に「（加工しちゃいまーす）」を付与
    from loguru import logger
    out = f"ありがとう！{ai_text}" if happi else ai_text
    out = out + "（加工しちゃいまーす）"
    logger.info(f"ここがアウトぷっとでーす: {out}")
    return out