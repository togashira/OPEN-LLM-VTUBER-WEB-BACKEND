import sys
import logging
from ruamel.yaml import YAML

logger = logging.getLogger(__name__)

# Multilingual texts for merge_configs log messages
TEXTS_MERGE = {
    "zh": {
        "new_config_item": "[信息] 新增配置项: {key}",
    },
    "en": {
        "new_config_item": "[INFO] New config item: {key}",
    },
}


def merge_configs(
    user_path: str, default_path: str, log_path: str = "upgrade.log", lang: str = "en"
):
    yaml = YAML()
    yaml.preserve_quotes = True

    with open(user_path) as f:
        user_config = yaml.load(f)
    with open(default_path) as f:
        default_config = yaml.load(f)

    new_keys = []

    def merge(d_user, d_default, path=""):
        for k, v in d_default.items():
            current_path = f"{path}.{k}" if path else k
            if k not in d_user:
                d_user[k] = v
                new_keys.append(current_path)
            elif isinstance(v, dict) and isinstance(d_user.get(k), dict):
                merge(d_user[k], v, current_path)
        return d_user

    merged = merge(user_config, default_config)

    # Update conf_version from default_config without overriding other user settings
    version_value = (
        user_config["system_config"].get("conf_version")
        if "system_config" in user_config
        else ""
    )
    version_change_string = "conf_version: " + version_value

    if (
        "system_config" in default_config
        and "conf_version" in default_config["system_config"]
    ):
        merged.setdefault("system_config", {})
        merged["system_config"]["conf_version"] = default_config["system_config"][
            "conf_version"
        ]
        version_change_string = (
            version_change_string
            + " -> "
            + default_config["system_config"]["conf_version"]
        )

    with open(user_path, "w") as f:
        yaml.dump(merged, f)

    # Log upgrade details (replacing manual file writing)
    texts = TEXTS_MERGE.get(lang, TEXTS_MERGE["en"])
    logger.info(version_change_string)
    for key in new_keys:
        logger.info(texts["new_config_item"].format(key=key))
    return new_keys


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python merge_configs.py <user_config> <default_config>")
        sys.exit(1)
    merge_configs(sys.argv[1], sys.argv[2])
