# prepost_hooks.py
import random
PERSONA_HINTS = [
    "ユーザーはコテコテの関西人です。",
    "ユーザーはゴリゴリの津軽弁です。",
    "ユーザーはアメリカ人です。",
]

def preprocess_user_text(raw, user_ctx: dict | None = None) -> str:
    # ① 入力にユーザー最新文脈やテスト用ペルソナを合成
    picked = random.choice(PERSONA_HINTS)
    ctx = (user_ctx or {}).get("today_summary", "")
    prefix = "あなたはユーザーの背景に配慮して自然にコーチングします。"
    return f"{prefix}\n【追加情報】{picked}\n{f'【最新】{ctx}\n' if ctx else ''}【入力】{raw}"

def postprocess_ai_text(ai_text: str, happi: bool = True) -> str:
    # ④ 出力の最終整形（HappiBoost風）。感情タグ付与などもここで。
    return f"ありがとう！{ai_text}" if happi else ai_text