import os

import yaml


def load_config(conf_path="vulnfy.yaml"):
    default_config = {
        "notifications": {"discord": {"enabled": False}, "telegram": {"enabled": False}}
    }

    if not os.path.exists(conf_path):
        return default_config

    try:
        with open(conf_path, "r") as f:
            user_conf = yaml.safe_load(f)
            if not user_conf:
                return default_config
            return {**default_config, **user_conf}

    except Exception as e:
        print(f"[!] Error while reading vulnfy.yaml: {e}")
        return default_config
