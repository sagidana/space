import json
import os
import pwd
from pathlib import Path

DEFAULTS = {
    "subnets": [],
    "group": "internet",
    "initialized": False,
    "wrapper_installed": False,
    "username": None,
}


def _real_home() -> Path:
    """Return the home directory of the invoking user, even under sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        return Path(pwd.getpwnam(sudo_user).pw_dir)
    return Path.home()


def _config_dir() -> Path:
    return _real_home() / ".config" / "space"


def load():
    config_file = _config_dir() / "config.json"
    if not config_file.exists():
        return DEFAULTS.copy()
    with open(config_file) as f:
        return {**DEFAULTS, **json.load(f)}


def save(config):
    config_dir = _config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    config_file = config_dir / "config.json"
    with open(config_file, "w") as f:
        json.dump(config, f, indent=2)
