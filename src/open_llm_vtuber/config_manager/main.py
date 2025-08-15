
import os
from pydantic import BaseModel, Field
from typing import Dict, ClassVar
from .system import SystemConfig
from .character import CharacterConfig
from .i18n import I18nMixin, Description

print(f"[DEBUG][Config class] cwd: {os.getcwd()}")
print(f"[DEBUG][Config class] __file__: {__file__}")

from .character import CharacterConfig
from .i18n import I18nMixin, Description


class Config(I18nMixin, BaseModel):
    """
    Main configuration for the application.
    """

    system_config: SystemConfig = Field(default=None, alias="system_config")
    character_config: CharacterConfig = Field(..., alias="character_config")
    frontend: dict = Field(default=None, alias="frontend")

    DESCRIPTIONS: ClassVar[Dict[str, Description]] = {
        "system_config": Description(
            en="System configuration settings", zh="系统配置设置"
        ),
        "character_config": Description(
            en="Character configuration settings", zh="角色配置设置"
        ),
    }

    # デバッグ: カレントディレクトリとファイルパス（クラス外に移動済み）
