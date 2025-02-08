import sys
from ruamel.yaml import YAML

# Multilingual texts for merge_configs log messages
TEXTS_MERGE = {
    "zh": {
        "new_config_item": "[信息] 新增配置项: {key}\n",
    },
    "en": {
        "new_config_item": "[INFO] New config item: {key}\n",
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

    with open(user_path, "w") as f:
        yaml.dump(merged, f)

    # Write new keys to upgrade log using multilingual messages
    texts = TEXTS_MERGE.get(lang, TEXTS_MERGE["en"])
    with open(log_path, "a") as log:
        for key in new_keys:
            log.write(texts["new_config_item"].format(key=key))
    return new_keys


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python merge_configs.py <user_config> <default_config>")
        sys.exit(1)
    merge_configs(sys.argv[1], sys.argv[2])
